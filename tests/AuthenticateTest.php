<?php

namespace KeycloakGuard\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use KeycloakGuard\ActingAsKeycloakUser;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;
use KeycloakGuard\Exceptions\TokenException;
use KeycloakGuard\Exceptions\UserNotFoundException;
use KeycloakGuard\KeycloakGuard;
use KeycloakGuard\Tests\Extensions\CustomUserProvider;
use KeycloakGuard\Tests\Factories\UserFactory;
use KeycloakGuard\Tests\Models\User;
use KeycloakGuard\Token;

class AuthenticateTest extends TestCase
{
    use ActingAsKeycloakUser;

    public function test_authenticates_the_user_when_requesting_a_private_endpoint_with_token()
    {
        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);

        $this->withKeycloakToken()->json('POST', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);

        $this->withKeycloakToken()->json('PUT', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);

        $this->withKeycloakToken()->json('PATCH', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);

        $this->withKeycloakToken()->json('DELETE', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    public function test_authenticates_the_user_when_requesting_an_public_endpoint_with_token()
    {
        $this->withKeycloakToken()->json('GET', '/foo/public');

        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    public function test_forbiden_when_request_a_protected_endpoint_without_token()
    {
        $this->expectException(AuthenticationException::class);
        $this->json('GET', '/foo/secret');
    }

    public function test_laravel_default_interface_for_authenticated_users()
    {
        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertEquals(Auth::hasUser(), true);
        $this->assertEquals(Auth::guest(), false);
        $this->assertEquals(Auth::id(), $this->user->id);
    }

    public function test_laravel_default_interface_for_unathenticated_users()
    {
        $this->json('GET', '/foo/public');

        $this->assertEquals(Auth::hasUser(), false);
        $this->assertEquals(Auth::guest(), true);
        $this->assertEquals(Auth::id(), null);
    }

    public function test_throws_a_exception_when_user_is_not_found()
    {
        $this->expectException(UserNotFoundException::class);

        $this->buildCustomToken([
            'preferred_username' => 'mary',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    public function test_does_not_load_user_from_database()
    {
        config(['keycloak.load_user_from_database' => false]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertInstanceOf(\KeycloakGuard\User::class, Auth::user());
        $this->assertSame($this->user->username, Auth::user()->username);
    }

    public function test_does_not_load_user_from_database_but_appends_decoded_token()
    {
        config(['keycloak.load_user_from_database' => false]);
        config(['keycloak.append_decoded_token' => true]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertInstanceOf(\KeycloakGuard\User::class, Auth::user());
        $this->assertSame($this->user->username, Auth::user()->username);
        $this->assertNotNull(Auth::user()->token);
    }

    public function test_throws_a_exception_when_resource_access_is_not_allowed_by_api()
    {
        $this->expectException(ResourceAccessNotAllowedException::class);

        $this->buildCustomToken([
            'resource_access' => ['some_resouce_not_allowed' => []],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    public function test_ignores_resources_validation()
    {
        config(['keycloak.ignore_resources_validation' => true]);

        $this->buildCustomToken([
            'resource_access' => ['some_resouce_not_allowed' => []],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $this->assertEquals(Auth::id(), $this->user->id);
    }

    public function test_check_user_has_role_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2',
                    ],
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2',
                    ],
                ],
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasRole('myapp-backend', 'myapp-backend-role1'));
    }

    public function test_check_user_no_has_role_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2',
                    ],
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2',
                    ],
                ],
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasRole('myapp-backend', 'myapp-backend-role3'));
    }

    public function test_prevent_cross_roles_resources()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2',
                    ],
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2',
                    ],
                ],
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasRole('myapp-backend', 'myapp-frontend-role1'));
    }

    public function test_check_user_has_any_role_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2',
                    ],
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2',
                    ],
                ],
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasAnyRole('myapp-backend', ['myapp-backend-role1', 'myapp-backend-role3']));
    }

    public function test_check_user_no_has_any_role_in_resource()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2',
                    ],
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2',
                    ],
                ],
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasAnyRole('myapp-backend', ['myapp-backend-role3', 'myapp-backend-role4']));
    }

    public function test_prevent_cross_roles_resources_with_any_role()
    {
        $this->buildCustomToken([
            'resource_access' => [
                'myapp-backend' => [
                    'roles' => [
                        'myapp-backend-role1',
                        'myapp-backend-role2',
                    ],
                ],
                'myapp-frontend' => [
                    'roles' => [
                        'myapp-frontend-role1',
                        'myapp-frontend-role2',
                    ],
                ],
            ],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasAnyRole('myapp-backend', ['myapp-frontend-role1', 'myapp-frontend-role2']));
    }

    public function test_check_user_has_scope()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasScope('scope-a'));
    }

    public function test_check_user_no_has_scope()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasScope('scope-d'));
    }

    public function test_check_user_has_any_scope()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::hasAnyScope(['scope-a', 'scope-c']));
    }

    public function test_check_user_no_has_any_scope()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertFalse(Auth::hasAnyScope(['scope-f', 'scope-k']));
    }

    public function test_check_user_scopes()
    {
        $this->buildCustomToken([
            'scope' => 'scope-a scope-b scope-c',
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');

        $expectedValues = ['scope-a', 'scope-b', 'scope-c'];
        foreach ($expectedValues as $value) {
            $this->assertContains($value, Auth::scopes());
        }
        $this->assertCount(count($expectedValues), Auth::scopes());
    }

    public function test_check_user_no_scopes()
    {
        $this->buildCustomToken([
            'scope' => null,
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertCount(0, Auth::scopes());
    }

    public function test_custom_user_retrieve_method()
    {
        config(['keycloak.user_provider_custom_retrieve_method' => 'custom_retrieve']);

        Auth::extend('keycloak', function ($app, $name, array $config) {
            return new KeycloakGuard(new CustomUserProvider(new BcryptHasher, User::class), $app->request);
        });

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertTrue(Auth::user()->customRetrieve);
    }

    public function test_throws_a_exception_with_invalid_iat()
    {
        $this->expectException(TokenException::class);

        $this->buildCustomToken([
            'iat' => time() + 30,   // time ahead in the future
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
    }

    public function test_works_with_leeway()
    {
        // Allows up to 60 seconds ahead in the  future
        config(['keycloak.leeway' => 60]);

        $this->buildCustomToken([
            'iat' => time() + 30, // time ahead in the future
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []],
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    public function test_authenticates_with_custom_input_key()
    {
        config(['keycloak.input_key' => 'api_token']);

        $this->json('GET', '/foo/secret?api_token='.$this->token);

        $this->assertEquals(Auth::id(), $this->user->id);

        $this->json('POST', '/foo/secret', ['api_token' => $this->token]);
    }

    public function test_authentication_prefers_input_api_token_over_with_custom_input_key()
    {
        config(['keycloak.input_key' => 'api_token']);

        $this->json('GET', '/foo/secret?api_token='.$this->token, ['Authorization' => 'Bearer '.$this->token]);

        $this->assertEquals(Auth::id(), $this->user->id);
    }

    public function test_acting_as_keycloak_user_trait()
    {
        $this->actingAsKeycloakUser($this->user);
        $this->json('GET', '/foo/secret');

        $this->assertEquals($this->user->username, Auth::user()->username);
        $token = Token::decode(request()->bearerToken(), config('keycloak.realm_public_key'), config('keycloak.leeway'), config('keycloak.token_encryption_algorithm'));
        $this->assertNotNull($token->iat);
        $this->assertNotNull($token->exp);
        $this->assertNotNull($token->iss);
        $this->assertNotNull($token->azp);
        $this->assertNotNull($token->aud);
    }

    public function test_acting_as_keycloak_user_trait_with_username()
    {
        $this->actingAsKeycloakUser($this->user->username);
        $this->json('GET', '/foo/secret');

        $this->assertEquals($this->user->username, Auth::user()->username);
        $token = Token::decode(request()->bearerToken(), config('keycloak.realm_public_key'), config('keycloak.leeway'), config('keycloak.token_encryption_algorithm'));
        $this->assertNotNull($token->iat);
        $this->assertNotNull($token->exp);
    }

    public function test_acting_as_keycloak_user_trait_with_custom_payload()
    {
        $this->do_acting_as_keycloak_user_trait_with_custom_payload('class');
        $this->do_acting_as_keycloak_user_trait_with_custom_payload('local');
    }

    public function do_acting_as_keycloak_user_trait_with_custom_payload(string $scope)
    {
        UserFactory::new()->create([
            'username' => 'test_username',
        ]);
        $payload = [
            'sub' => 'test_sub',
            'aud' => 'test_aud',
            'preferred_username' => 'test_username',
            'iat' => 12345,
            'exp' => 9999999999999,
        ];

        $arg = [];

        if ($scope === 'class') {
            $this->jwtPayload = $payload;
        } else {
            $this->jwtPayload['sub'] = 'should_be_overwritten';
            $arg = $payload;
        }

        $this->actingAsKeycloakUser(payload: $arg);
        $this->json('GET', '/foo/secret');

        $this->assertEquals('test_username', Auth::user()->username);
        $token = Token::decode(request()->bearerToken(), config('keycloak.realm_public_key'), config('keycloak.leeway'), config('keycloak.token_encryption_algorithm'));
        $this->assertEquals(12345, $token->iat);
        $this->assertEquals(9999999999999, $token->exp);
        $this->assertEquals('test_sub', $token->sub);
        $this->assertEquals('test_aud', $token->aud);
        $this->assertTrue(config('keycloak.load_user_from_database'));
    }

    public function test_acting_as_keycloak_user_trait_with_default_user()
    {
        config(['keycloak.load_user_from_database' => false]);
        $this->actingAsKeycloakUser();
        $this->json('GET', '/foo/secret');

        $this->assertTrue(Auth::hasUser());

        $this->assertFalse(Auth::guest());
    }

    public function test_it_decodes_token_with_the_configured_encryption_algorithm()
    {
        $this->prepareCredentials('ES256', [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);

        config([
            'keycloak.token_encryption_algorithm' => 'ES256',
            'keycloak.realm_public_key' => Token::plainPublicKey($this->publicKey),
        ]);

        $this->withKeycloakToken()->json('GET', '/foo/secret');
        $this->assertEquals($this->user->username, Auth::user()->username);
    }

    public function test_it_can_authenticate_from_proxy_user_info()
    {
        config(['keycloak.trust_proxy_userinfo' => true]);

        // with base64 encoding
        $this->withHeader('x-userinfo', base64_encode(json_encode([
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []],
        ])))->json('GET', '/foo/secret');

        $this->assertEquals($this->user->email, Auth::user()->email);

        // without base64 encoding
        $this->withHeader('x-userinfo', json_encode([
            'preferred_username' => 'johndoe',
            'resource_access' => ['myapp-backend' => []],
        ]))->json('GET', '/foo/secret');

        $this->assertEquals($this->user->email, Auth::user()->email);
    }

    public function test_it_can_get_public_key_from_server()
    {

        config(['keycloak.realm_public_key' => null]);
        config(['keycloak.keycloak_base_url' => 'https://keycloak.example.com']);
        config(['keycloak.keycloak_realm' => 'tencent-design']);
        config(['keycloak.ignore_resources_validation' => true]);
        config(['keycloak.load_user_from_database' => false]);
        config(['keycloak.leeway' => 100000000]); // to avoid expire time validation

        $response = '{
            "keys": [
                {
                "kid": "_cqQH2gok4ObvrRnLKPbZBGyY2o1XoUlvmfaug5tug8",
                "kty": "RSA",
                "alg": "RSA-OAEP",
                "use": "enc",
                "x5c": [
                    "MIIClzCCAX8CBgGVNnRp4zANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARzYWFzMB4XDTI1MDIyNDA1MzQxM1oXDTM1MDIyNDA1MzU1M1owDzENMAsGA1UEAwwEc2FhczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALA6I3PmKSwb6UvK6IYK6JBUZ/pVD6l7aypFHbXqE9NUUAu583poXCfe7PjdAyE529+fLD1antLFWmdIYCB5KgJyxmLAu6brHv2/XhJA5i0cNQuJeIXVlf/+/herfwIryRIDV6ie4hGZHfIkeLzja53Daj1+xCQhLWsqqtvvGRwWw1i/llAgtjCeGKv+N0S/rdLfQChVm4eTeRDHcgX57YjI3B7xpzYcTfeFdfFJXFVsPE+BWGrjzQoDMqsZaq3saRqvTCPD6iAvM2e28RbpQoAGIaWUW8U0vdcZmhcBcOrIfG/DMb5upw/1/Nk33Z8DsxMzvRE0iHb0ZyZCOY/axUECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAZ+iBNY32NbzTZvG+rIdnV0MyMqNnAu3mzQpQvGzh4YLpNmzALd4f70alvsff0TvnvtdBR4UxzAp4AL50MDeId0vdvusAu1wdhMGI3jKuBmTA11zHoKv5rUZqUdObUqQww2FDRworcWXqOXYTxBaumUN9D0mystypJ93TTHE5cd6GpQtbfSj+3gdDqAXcJnx+eP0+n084qUx2A0W9FzD7vsmoOcCdp5ZwgfyNa60MhBOWcZRpdrwkQQFzu6ssRUNfHiQmncIKGnVmoaX7jxJ1AZgW9kcKCmFvG4v19NWufDihqKNVfomOAgjsJw+5zdwj+AwZrFP+L4+75UtU/4vubw=="
                ],
                "x5t": "C_pitNekDkg2iRVJ1c8hcjYZ5MA",
                "x5t#S256": "QINLCxUo0a0n0w75VAKQ5lAX5ZpFHPTJci-lu_QEdLI",
                "n": "sDojc-YpLBvpS8rohgrokFRn-lUPqXtrKkUdteoT01RQC7nzemhcJ97s-N0DITnb358sPVqe0sVaZ0hgIHkqAnLGYsC7puse_b9eEkDmLRw1C4l4hdWV__7-F6t_AivJEgNXqJ7iEZkd8iR4vONrncNqPX7EJCEtayqq2-8ZHBbDWL-WUCC2MJ4Yq_43RL-t0t9AKFWbh5N5EMdyBfntiMjcHvGnNhxN94V18UlcVWw8T4FYauPNCgMyqxlqrexpGq9MI8PqIC8zZ7bxFulCgAYhpZRbxTS91xmaFwFw6sh8b8Mxvm6nD_X82TfdnwOzEzO9ETSIdvRnJkI5j9rFQQ",
                "e": "AQAB"
                },
                {
                "kid": "xbR4JTfmbvtPHPkkKhnBSowzS3GHQjiZ_gsUsgr4-Bc",
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "x5c": [
                    "MIIClzCCAX8CBgGVNnRn5TANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARzYWFzMB4XDTI1MDIyNDA1MzQxM1oXDTM1MDIyNDA1MzU1M1owDzENMAsGA1UEAwwEc2FhczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJcCuSJm1lxFuA7XQXUP09BuGrnvuQJttIkdZwSccwOJJQlIWmvImISlYm/xZI4r1clwNnH6n5gqssnN3YIi1m/G2jIlyFwuAAp6HNpDr2cu/3FmW1fQ3k8Qy7C9tGt9TzHhJHoelEkt5nK7rigOBKJEqd7WwIlzGjEoIqSD5w6ScdaOIXoEoGjbHcB+hW3wVpDuFZ9N8x1AZ31wZyLO5lJIuFODv0MZUQXoNOOxG5wnzlFWajsas70i+P0On7lypb7xRPDtAEcvUAaMPyTjXQLZIGT1ZM5DGDNdJ8QkNPl4z4ch74Qpkh7BQhPZER9A9scjw1v9NzSHVX4tPvgVO08CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAD3y6ybSIfAEDtig0bOiQFaFbndMQLYf761QabQ2I7bxTxmJb0AjpdEaM69+JDFhMmMvoevd9hS2CtR+tMaUv671vupdLflxUK3/ugvqAYIBCk/UWGrSmsJAy9rGIjqPPkSqOCPmiI8w9Dsqr8XYqexEmUfDJQmcCIsSbtBBd4aIWzZzjsxSK30RjC3be+VqEaU7Suj0zw5n1Eiax2fmbFqAqpZxuRbbiBxr0N/0G31KKCFD+MI3Ipt4v8ZnkzNOBTbIN5YHwEGc1HwiPwDDYsoS5z2K1YikXdBqZ3kgfLrGTOhJREQ27n7N5ZeXwpfjr/arrsFGn5wfgfxvYm0wZCQ=="
                ],
                "x5t": "HxWnrsU_VWyQ4U6x83wV-RgsEpo",
                "x5t#S256": "RBikIbGpXFHIx4COox-trrJdrH3Dw9UeMeSVgBq1I1w",
                "n": "lwK5ImbWXEW4DtdBdQ_T0G4aue-5Am20iR1nBJxzA4klCUhaa8iYhKVib_FkjivVyXA2cfqfmCqyyc3dgiLWb8baMiXIXC4ACnoc2kOvZy7_cWZbV9DeTxDLsL20a31PMeEkeh6USS3mcruuKA4EokSp3tbAiXMaMSgipIPnDpJx1o4hegSgaNsdwH6FbfBWkO4Vn03zHUBnfXBnIs7mUki4U4O_QxlRBeg047EbnCfOUVZqOxqzvSL4_Q6fuXKlvvFE8O0ARy9QBow_JONdAtkgZPVkzkMYM10nxCQ0-XjPhyHvhCmSHsFCE9kRH0D2xyPDW_03NIdVfi0--BU7Tw",
                "e": "AQAB"
                }
            ]
            }';
        
        // Prepare a mock handler for Guzzle
        $mock = new MockHandler([
            new Response(200, ['Content-Type' => 'application/json'], $response),
        ]);
        $client = new Client(['handler' => HandlerStack::create($mock)]);
        
        // Bind the mocked client into the service container
        $this->app->instance(Client::class, $client);

        $token = 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ4YlI0SlRmbWJ2dFBIUGtrS2huQlNvd3pTM0dIUWppWl9nc1VzZ3I0LUJjIn0.eyJleHAiOjE3NDQ4MTQyNDUsImlhdCI6MTc0MzUxODI0NSwianRpIjoiYjQ5ZjlmNDgtMjc2Mi00MDgwLWEwYjktZDNhMDZkOTNhMzM2IiwiaXNzIjoiaHR0cHM6Ly9kLnRlc3RzaXRlLndvYS5jb20vYXV0aC9yZWFsbXMvdGVuY2VudC1kZXNpZ24iLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiMTVmMzFlNjAtMWQ5Ny00ZGFiLWE4ZWEtNTYzNjVkNjYzNTVmIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoicmVzdGZ1bC1hcGkiLCJzaWQiOiI2N2YyNGU4NS0zMWI0LTRjYWQtYjY4NS01ZjMxN2FjOWE5ZWQiLCJhY3IiOiIxIiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtc2FhcyIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6InByb2ZpbGUgZW1haWwiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsIm5hbWUiOiJhZG1pbiBhZG1pbiIsInByZWZlcnJlZF91c2VybmFtZSI6ImFkbWluIiwiZ2l2ZW5fbmFtZSI6ImFkbWluIiwiZmFtaWx5X25hbWUiOiJhZG1pbiIsImVtYWlsIjoiYWRtaW5AYWRtaW4uY29tIn0.k0ADNI9IZjZYkDT4SW8VgVjxTTc-r-QRNKKu_W0znChpr4NwwnQB3YRc2wQy1rFeshWW0toyK51DEuQOYUgMUnwe0fj1VvT2E9i4wKcnkSqWNj6TLCkzVxVcjIL9zRHj9wiuT7Au3zt4BJvQCuaKihdvD548x3OB1EqAzx4towoiMKQaU-Enx_24R60lUEzrB66oKVTM-LUbs_PBt2E72jk5v9XnNMF0l5J3biVTh41Mg7a2Xl_0I1pic3RI4XMaweDrNactQAJ1QecUsYAD0m5ysQ8KBVKmLhw4zcNa3Ev75JU2oDGVz05Y30Xzw9pqtjXs_EFK5pEhI0am7tN1jA';

        $this->withToken($token)->json('GET', '/foo/secret');
        $this->assertEquals('admin', Auth::user()->username);
    }
}
