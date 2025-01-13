<?php

namespace KeycloakGuard;

use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;

trait ActingAsKeycloakUser
{
    protected array $jwtPayload = [];

    public function actingAs(Authenticatable|string $user, $guard = null): User|Authenticatable
    {
        $user = $this->actingAsKeycloakUser($user);

        parent::actingAs($user, $guard);

        return $user;
    }

    public function actingAsKeycloakUser(Authenticatable|string|null $user = null, $payload = []): User|Authenticatable
    {
        $principal = Config::get('keycloak.token_principal_attribute');

        if (!$user && !isset($payload[$principal]) && !isset($this->jwtPayload[$principal])) {
            Config::set('keycloak.load_user_from_database', false);
        }

        if (is_string($user)) {
            $user = $this->newUser($user);
        } else {
            $user ??= $this->newUser();
        }

        $token = $this->generateKeycloakToken($user, $payload);

        $this->withHeader('Authorization', 'Bearer '.$token);

        return $user;
    }

    public function newUser(string|null $principal = null, array $token = []): User
    {
        return new User($principal ?? Str::uuid()->toString(), (object) $token);
    }

    public function generateKeycloakToken($user = null, $payload = []): string
    {
        $privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 1024,
            'private_key_type' => OPENSSL_KEYTYPE_RSA
        ]);

        $publicKey = openssl_pkey_get_details($privateKey)['key'];

        $publicKey = Token::plainPublicKey($publicKey);

        Config::set('keycloak.realm_public_key', $publicKey);

        $iat = time();
        $exp = time() + 300;
        $resourceAccess = [config('keycloak.allowed_resources') => []];
        $principal = Config::get('keycloak.token_principal_attribute');
        $credential = Config::get('keycloak.user_provider_credential');

        $payload = array_merge([
            'iss' => 'https://keycloak.server/realms/laravel',
            'azp' => 'client-id',
            'aud' => 'phpunit',
            'iat' => $iat,
            'exp' => $exp,
            $principal => config('keycloak.preferred_username'),
            'resource_access' => $resourceAccess,
        ], $this->jwtPayload, $payload);

        if ($user) {
            $payload[$principal] = is_string($user) ? $user : $user->$credential;
        }

        return JWT::encode($payload, $privateKey, 'RS256');
    }
}
