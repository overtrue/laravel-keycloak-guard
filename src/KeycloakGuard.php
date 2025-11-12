<?php

namespace KeycloakGuard;

use Exception;
use Firebase\JWT\CachedKeySet;
use GuzzleHttp\Client;
use GuzzleHttp\Psr7\HttpFactory;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Traits\Macroable;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;
use KeycloakGuard\Exceptions\TokenException;
use KeycloakGuard\Exceptions\UserNotFoundException;

class KeycloakGuard implements Guard
{
    use GuardHelpers;
    use Macroable;

    protected array $config;

    protected Request $request;

    protected ?\stdClass $decodedToken = null;

    private bool $usingProxyUserinfo = false;

    private ?array $proxyUserinfo = null;

    public function __construct(UserProvider $provider, Request $request)
    {
        $this->config = config('keycloak');
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Get the token for the current request.
     */
    public function getTokenForRequest(): ?string
    {
        $inputKey = $this->config['input_key'] ?? '';

        $token = $this->request->query($inputKey);

        if (empty($token)) {
            $token = $this->request->bearerToken() ?? $this->request->header('X-Access-Token');
        }

        return $token;
    }

    /**
     * Get the currently authenticated user.
     *
     * @throws \Exception
     */
    public function user(): ?Authenticatable
    {
        if (! is_null($this->user)) {
            return $this->user;
        }

        $trustProxyUserinfo = $this->config['trust_proxy_userinfo'] ?? false;
        $header = $this->config['proxy_userinfo_header'] ?? 'x-userinfo';

        if ($trustProxyUserinfo && $this->request->hasHeader($header)) {
            $this->authenticateWithProxyUserinfo($header);
        } elseif ($token = $this->getTokenForRequest()) {
            $this->parseToken($token);

            if ($this->decodedToken) {
                $this->validateResources();
                $this->user = $this->retrieveFromToken($this->decodedToken);
            }
        }

        return $this->user;
    }

    /**
     * Returns full decoded JWT token from authenticated user
     *
     * @return mixed|null
     */
    public function token(): ?string
    {
        if (! $this->decodedToken) {
            if (! $token = $this->getTokenForRequest()) {
                return null;
            }

            $this->parseToken($token);
        }

        return json_encode($this->decodedToken);
    }

    protected function getRealmPublicKey(): string|CachedKeySet|null
    {
        // try to get public key from config
        if (!empty($this->config['realm_public_key'])) {
            return $this->config['realm_public_key'];
        }

        // try to get public key from Keycloak server
        if (empty($this->config['keycloak_base_url']) || empty($this->config['keycloak_realm'])) {
            Log::error('Keycloak base URL or realm is not configured.');

            return null;
        }

        $jwksUri = sprintf(
            '%s/realms/%s/protocol/openid-connect/certs',
            rtrim($this->config['keycloak_base_url'], '/'),
            trim($this->config['keycloak_realm'])
        );
        
        return new CachedKeySet(
            $jwksUri,
            httpClient: app(Client::class) ?? new Client(),
            httpFactory: new HttpFactory(),
            cache: app('cache.psr6'),
            expiresAfter: isset($this->config['jwks_cache_ttl']) ? (int) $this->config['jwks_cache_ttl'] : null,
            rateLimit: true,
            defaultAlg: $this->config['token_encryption_algorithm'] ?? null
        );
    }

    protected function authenticateWithProxyUserinfo(string $header)
    {
        $userinfo = $this->request->header($header);
        $decodedUserinfo = json_decode(base64_decode($userinfo), true);

        // try to decode userinfo without base64 encoding
        if (! $decodedUserinfo) {
            $decodedUserinfo = json_decode($userinfo, true);
        }

        if (! $decodedUserinfo) {
            Log::error("Failed to parse userinfo from proxy header: $header");

            return null;
        }

        $this->usingProxyUserinfo = true;
        $this->proxyUserinfo = $decodedUserinfo;
        $this->decodedToken = json_decode(json_encode($decodedUserinfo));
        $this->user = $this->retrieveFromToken($this->decodedToken);
    }

    public function retrieveFromToken(\stdClass $decodedToken)
    {
        $credentials = $this->mapTokenToCredentials($decodedToken);

        if ($this->config['load_user_from_database'] ?? false) {
            return $this->retrieveFromDatabase($credentials, $decodedToken);
        }

        return $this->createUserFromToken($credentials, $decodedToken);
    }

    protected function retrieveFromDatabase(array $credentials, \stdClass $decodedToken)
    {
        $methodOnProvider = $this->config['user_provider_custom_retrieve_method'] ?? null;

        if ($methodOnProvider && method_exists($this->provider, $methodOnProvider)) {
            $user = $this->provider->{$methodOnProvider}($decodedToken, $credentials);
        } else {
            $user = $this->provider->retrieveByCredentials($credentials);
        }

        if (! $user) {
            throw new UserNotFoundException('User not found. Credentials: '.json_encode($credentials));
        }

        return $user;
    }

    protected function createUserFromToken(array $credentials, \stdClass $decodedToken): User
    {
        $keyName = $this->config['user_provider_credential'] ?? 'sub';

        return new User($credentials[$keyName] ?? null, $decodedToken);
    }

    protected function mapTokenToCredentials(\stdClass $decodedToken): array
    {
        return [
            $this->config['user_provider_credential'] => $decodedToken->{$this->config['token_principal_attribute']},
        ];
    }

    /**
     * Validate a user's credentials.
     *
     * @throws \Exception
     */
    public function validate(array $credentials = []): bool
    {
        $this->validateResources();

        if (! $this->user && ! empty($credentials)) {
            $this->user = $this->retrieveFromToken($this->decodedToken);
        }

        return true;
    }

    /**
     * Validate if authenticated user has a valid resource
     */
    protected function validateResources(): void
    {
        if ($this->config['ignore_resources_validation']) {
            return;
        }

        $tokenResourceAccess = array_keys((array) ($this->decodedToken->resource_access ?? []));
        $allowedResources = explode(',', $this->config['allowed_resources']);

        if (count(array_intersect($tokenResourceAccess, $allowedResources)) == 0) {
            throw new ResourceAccessNotAllowedException('The decoded JWT token does not have a valid `resource_access` permission allowed by the API. Allowed resources: '.$this->config['allowed_resources'].'. Token resources: '.json_encode($tokenResourceAccess));
        }
    }

    /**
     * Set the current request instance.
     *
     * @return $this
     */
    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Check if authenticated user has a specific role into resource
     */
    public function hasRole(string $resource, string $role): bool
    {
        $tokenResourceAccess = (array) $this->decodedToken->resource_access;

        if (array_key_exists($resource, $tokenResourceAccess)) {
            $tokenResourceValues = (array) $tokenResourceAccess[$resource];

            if (array_key_exists('roles', $tokenResourceValues) &&
                in_array($role, $tokenResourceValues['roles'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if authenticated user has an any role into resource
     */
    public function hasAnyRole(string $resource, array $roles): bool
    {
        $tokenResourceAccess = (array) $this->decodedToken->resource_access;

        if (array_key_exists($resource, $tokenResourceAccess)) {
            $tokenResourceValues = (array) $tokenResourceAccess[$resource];

            if (array_key_exists('roles', $tokenResourceValues)) {
                foreach ($roles as $role) {
                    if (in_array($role, $tokenResourceValues['roles'])) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /**
     * Get scope(s)
     */
    public function scopes(): array
    {
        $scopes = $this->decodedToken->scope ?? null;

        if ($scopes) {
            return explode(' ', $scopes);
        }

        return [];
    }

    /**
     * Check if authenticated user has an especific scope
     */
    public function hasScope(string $scope): bool
    {
        $scopes = $this->scopes();

        if (in_array($scope, $scopes)) {
            return true;
        }

        return false;
    }

    /**
     * Check if authenticated user has an any scope
     */
    public function hasAnyScope(array|string $scopes): bool
    {
        return count(array_intersect(
            $this->scopes(),
            is_string($scopes) ? [$scopes] : $scopes
        )) > 0;
    }

    protected function parseToken(string $token): void
    {
        try {
            $publicKey = $this->getRealmPublicKey();

            if (empty($publicKey)) {
                throw new TokenException('Public key not found, please check your Keycloak configuration.');
            }

            $this->decodedToken = Token::decode($token, $publicKey, $this->config['leeway'], $this->config['token_encryption_algorithm']);
        } catch (Exception $e) {
            throw new TokenException('Error decoding token: '.$e->getMessage().' Please ensure the token is valid and not expired.', 0, $e);
        }
    }
}
