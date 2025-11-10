<?php

return [
    'trust_proxy_userinfo' => env('KEYCLOAK_TRUST_PROXY_USERINFO', false),

    'proxy_userinfo_header' => env('KEYCLOAK_TRUST_PROXY_USERINFO_HEADER', 'x-userinfo'),

    'realm_public_key' => env('KEYCLOAK_REALM_PUBLIC_KEY', null),

    'keycloak_base_url' => env('KEYCLOAK_BASE_URL', null),

    'keycloak_realm' => env('KEYCLOAK_REALM', null),

    'token_encryption_algorithm' => env('KEYCLOAK_TOKEN_ENCRYPTION_ALGORITHM', 'RS256'),

    'load_user_from_database' => env('KEYCLOAK_LOAD_USER_FROM_DATABASE', true),

    'user_provider_custom_retrieve_method' => env('KEYCLOAK_USER_PROVIDER_CUSTOM_RETRIEVE_METHOD', null),

    'user_provider_credential' => env('KEYCLOAK_USER_PROVIDER_CREDENTIAL', 'username'),

    'token_principal_attribute' => env('KEYCLOAK_TOKEN_PRINCIPAL_ATTRIBUTE', 'preferred_username'),

    'allowed_resources' => env('KEYCLOAK_ALLOWED_RESOURCES', null),

    'ignore_resources_validation' => env('KEYCLOAK_IGNORE_RESOURCES_VALIDATION', true),

    'leeway' => env('KEYCLOAK_LEEWAY', 0),

    'input_key' => env('KEYCLOAK_TOKEN_INPUT_KEY', null),

    // TTL in seconds to cache JWKS fetched from Keycloak when realm_public_key is not set
    'jwks_cache_ttl' => env('KEYCLOAK_JWKS_CACHE_TTL', 3600),
];
