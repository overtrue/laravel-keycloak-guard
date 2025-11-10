<?php

namespace KeycloakGuard;

use Firebase\JWT\CachedKeySet;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Token
{
    /**
     * Decode a JWT token
     */
    public static function decode(?string $token, CachedKeySet|string $publicKeyOrKeySet, int $leeway = 0, string $algorithm = 'RS256'): ?\stdClass
    {
        JWT::$leeway = $leeway;

        if (! $token) {
            return null;
        }

        // If a string public key is provided, build it and decode using Key
        if (is_string($publicKeyOrKeySet)) {
            $publicKey = self::buildPublicKey($publicKeyOrKeySet);
            return JWT::decode($token, new Key($publicKey, $algorithm));
        }

        // Otherwise assume it's a CachedKeySet and pass through to JWT::decode
        return JWT::decode($token, $publicKeyOrKeySet);
    }

    /**
     * Build a valid public key from a string
     */
    private static function buildPublicKey(string $key): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".wordwrap($key, 64, "\n", true)."\n-----END PUBLIC KEY-----";
    }

    /**
     * Get the plain public key from a string
     */
    public static function plainPublicKey(string $key): string
    {
        $string = str_replace('-----BEGIN PUBLIC KEY-----', '', $key);
        $string = trim(str_replace('-----END PUBLIC KEY-----', '', $string));

        return str_replace('\n', '', $string);
    }
}
