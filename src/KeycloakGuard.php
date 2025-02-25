<?php

namespace KeycloakGuard;

use Exception;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Traits\Macroable;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;
use KeycloakGuard\Exceptions\TokenException;
use KeycloakGuard\Exceptions\UserNotFoundException;

class KeycloakGuard implements Guard
{
    use GuardHelpers;
    use Macroable;

    protected array $config;

    protected $user = null;

    protected $provider;

    protected ?\stdClass $decodedToken = null;

    protected Request $request;

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

        $token = $this->getTokenForRequest();

        if (! $token) {
            return null;
        }

        $this->retrieveByToken($token);

        if ($this->user && $this->config['append_decoded_token']) {
            $this->user->token = $this->decodedToken;
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
            $token = $this->getTokenForRequest();

            if (! $token) {
                return null;
            }

            $this->parseToken($token);
        }

        return json_encode($this->decodedToken);
    }

    /**
     * @throws \Exception
     */
    public function retrieveByToken(string $token)
    {
        $this->parseToken($token);

        if ($this->decodedToken) {
            $this->validate([
                $this->config['user_provider_credential'] => $this->decodedToken->{$this->config['token_principal_attribute']},
            ]);
        }

        return $this->user;
    }

    /**
     * Validate a user's credentials.
     *
     * @throws \Exception
     */
    public function validate(array $credentials = []): bool
    {
        $this->validateResources();

        if ($this->config['load_user_from_database']) {
            $methodOnProvider = $this->config['user_provider_custom_retrieve_method'] ?? null;

            if ($methodOnProvider) {
                $user = $this->provider->{$methodOnProvider}($this->decodedToken, $credentials);
            } else {
                $user = $this->provider->retrieveByCredentials($credentials);
            }

            if (! $user) {
                throw new UserNotFoundException('User not found. Credentials: '.json_encode($credentials));
            }
        } else {
            $keyName = $this->config['user_provider_credential'];
            $user = new User($credentials[$keyName] ?? null, $this->decodedToken);
        }

        $this->setUser($user);

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
            $this->decodedToken = Token::decode($token, $this->config['realm_public_key'], $this->config['leeway'], $this->config['token_encryption_algorithm']);
        } catch (Exception $e) {
            throw new TokenException($e->getMessage());
        }
    }
}
