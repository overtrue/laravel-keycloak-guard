<?php

namespace KeycloakGuard;

use Illuminate\Contracts\Auth\Authenticatable;
use stdClass;

class User implements Authenticatable
{
    public function __construct(public mixed $key, public stdClass $token)
    {
        //
    }

    public function id()
    {
        return $this->token->sub ?? $this->key;
    }

    protected function isProviderCredentialAttribute(string $key): mixed
    {
        return $key === config('keycloak.user_provider_credential');
    }

    public function __call(string $method, array $parameters): mixed
    {
        if ($this->isProviderCredentialAttribute($method)) {
            return $this->key;
        }

        throw new \BadMethodCallException("Method {$method} does not exist.");
    }

    public function __get(string $name): mixed
    {
        if ($name == 'id') {
            return $this->id();
        }

        if ($this->isProviderCredentialAttribute($name)) {
            return $this->key;
        }

        throw new \BadMethodCallException("Property {$name} does not exist.");
    }

    public function getAuthIdentifierName()
    {
        return config('keycloak.user_provider_credential', 'id');
    }

    public function getAuthIdentifier()
    {
        return $this->key;
    }

    public function getAuthPasswordName(): string
    {
        return '';
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): string
    {
        return '';
    }

    public function setRememberToken($value): string
    {
        return '';
    }

    public function getRememberTokenName(): string
    {
        return '';
    }
}
