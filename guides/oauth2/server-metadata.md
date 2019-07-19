# Server metadata (RFC8414)

Asteroid implements OAuth 2.0 Authorization Server Metadata
([RFC8414](https://tools.ietf.org/html/rfc8414).

This RFC allows advertising metadata related to the OAuth2 server, and to be used in an
automated fashion by OAuth2 clients.

OAuth2 server metadata is made available on the `/.well-known/oauth-authorization-server`
and `/.well-known/oauth-authorization-server` URLs.

## Support

- [x] Advertises the following metadata:
  - `"issuer"`
  - `"grant_types_supported"`
  - `"scopes_supported"`
  - `"response_types_supported"`
  - `"authorization_endpoint"`
  - `"registration_endpoint"`
  - `"token_endpoint"`
  - `"token_endpoint_auth_methods_supported"`
  - `"revocation_endpoint"`
  - `"revocation_endpoint_auth_methods_supported"`
  - `"introspection_endpoint"`
  - `"introspect_endpoint_auth_methods_supported"`
  - `"code_challenge_methods_supported"`
  - `"jwks_uri"`
  - `"service_documentation"`
  - `"ui_locales_supported"`
  - `"op_policy_uri"`
  - `"op_tos_uri"`
  - `"device_authorization_endpoint"` (from [OAuth 2.0 Device Authorization Grant - section 4](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-4))
- [x] Signed metadata

## Published metadata

As per the RFC, metadata fields are advertised only when necessary. For instance, the
authorization endpoint will not be advertised if only the client credentials flow is enabled.

All metadata are automatically generated using the current configuration, except the following
field that can be configured manually in the configuration files:
- `"service_documentation"`
(see the `:oauth2_endpoint_metadata_service_documentation` configuration option)
- `"ui_locales_supported"`
(see the `:oauth2_endpoint_metadata_ui_locales_supported` configuration option)
- `"op_policy_uri"`
(see the `:oauth2_endpoint_metadata_op_policy_uri` configuration option)
- `"op_tos_uri"`
(see the `:oauth2_endpoint_metadata_op_tos_uri` configuration option)

Metadata is not cached, since reading configuration options is deemed fast enough on the
EVM to avoid the additional complexity of caching (including cache invalidation in case of
change of the configuration). As a consequence, changes to the configuration are immediatly
made available on this endpoint.

The result json can be modified using the `:oauth2_endpoint_metadata_before_send_resp_callback`
configuration option.

## Advertising scopes

Supported scopes are determined with scanning all scope configurations for all flows.

Note that it's possible to *not* advertise some scopes. See the related
[Managing scopes](managing-scopes.html) documentation.

## Endpoint URLs generation

URLs for the endpoints are generated automatically by Phoenix, and therefore use Phoenix's
configuration for host, scheme, port and path.

For instance, the default rendered metadata on development server will look like:

```json
{
   "authorization_endpoint":"http://localhost:4000/authorize",
   "code_challenge_methods_supported":[
      "S256"
   ],
   "grant_types_supported":[
      "authorization_code",
      "implicit",
      "password",
      "client_credentials",
      "refresh_token"
   ],
   "introspection_endpoint":"http://localhost:4000/api/oauth2/introspect",
   "introspection_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post"
   ],
   "issuer":"http://localhost:4000",
   "registration_endpoint":"http://localhost:4000/api/oauth2/register",
   "response_types_supported":[
      "code",
      "token"
   ],
   "revocation_endpoint":"http://localhost:4000/api/oauth2/revoke",
   "revocation_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post"
   ],
   "scopes_supported":[
      "api.access",
      "interbank_transfer",
      "read_account_information",
      "read_balance"
   ],
   "token_endpoint":"http://localhost:4000/api/oauth2/token",
   "token_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post",
      "none"
   ]
}
```
Changing Phoenix endpoint configuration adding the `:url` option like that:

```elixir
config :asteroid, AsteroidWeb.Endpoint,
  http: [port: 4000],
  url: [scheme: "https", host: "www.example.com", path: "/account/auth", port: 443],
  check_origin: false
  ]
```

will generate the following metadata:

```json
{
   "authorization_endpoint":"https://www.example.com/account/auth/authorize",
   "code_challenge_methods_supported":[
      "S256"
   ],
   "grant_types_supported":[
      "authorization_code",
      "implicit",
      "password",
      "client_credentials",
      "refresh_token"
   ],
   "introspection_endpoint":"https://www.example.com/account/auth/api/oauth2/introspect",
   "introspection_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post"
   ],
   "issuer":"https://www.example.com",
   "registration_endpoint":"https://www.example.com/account/auth/api/oauth2/register",
   "response_types_supported":[
      "code",
      "token"
   ],
   "revocation_endpoint":"https://www.example.com/account/auth/api/oauth2/revoke",
   "revocation_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post"
   ],
   "scopes_supported":[
      "api.access",
      "interbank_transfer",
      "read_account_information",
      "read_balance"
   ],
   "token_endpoint":"https://www.example.com/account/auth/api/oauth2/token",
   "token_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post",
      "none"
   ]
}
```

Beware, however, of changing these values in a live system, as existing tokens (such as JWTs)
will have their issuer invalid on Asteroid since it will have changed.

## Signed metadata

Some or all of the fields can be signed and published as a JWS in the `"signed_metadata"` field.
The related configuration otpions are:
- [`:oauth2_endpoint_metadata_signed_fields`](Asteroid.Config.html#module-oauth2_endpoint_metadata_signed_fields)
- [`:oauth2_endpoint_metadata_signing_alg`](Asteroid.Config.html#module-oauth2_endpoint_metadata_signing_alg)
- [`:oauth2_endpoint_metadata_signing_key`](Asteroid.Config.html#module-oauth2_endpoint_metadata_signing_key)

Using the following configuration:

```elixir
config :asteroid, :oauth2_endpoint_metadata_signed_fields,
  ["token_endpoint", "token_endpoint_auth_methods_supported", "scopes_supported"]

config :asteroid, :oauth2_endpoint_metadata_signing_key, "key_auto"

config :asteroid, :oauth2_endpoint_metadata_signing_alg, "PS384"
```

the `"signed_metadata"` will be published with the 3 configured fields (and the `"issuer"` field,
which is mandatory):

```json
{
   "authorization_endpoint":"http://localhost:4000/authorize",
   "code_challenge_methods_supported":[
      "S256"
   ],
   "device_authorization_endpoint":"http://localhost:4000/api/oauth2/device_authorization",
   "grant_types_supported":[
      "authorization_code",
      "implicit",
      "password",
      "client_credentials",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code"
   ],
   "introspection_endpoint":"http://localhost:4000/api/oauth2/introspect",
   "introspection_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post"
   ],
   "issuer":"http://localhost:4000",
   "jwks_uri":"http://localhost:4000/discovery/keys",
   "registration_endpoint":"http://localhost:4000/api/oauth2/register",
   "response_types_supported":[
      "code",
      "token"
   ],
   "revocation_endpoint":"http://localhost:4000/api/oauth2/revoke",
   "revocation_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post"
   ],
   "scopes_supported":[
      "api.access",
      "interbank_transfer",
      "read_account_information",
      "read_balance"
   ],
   "signed_metadata":"eyJhbGciOiJQUzM4NCJ9.eyJpc3N1ZXIiOiJodHRwOi8vbG9jYWxob3N0OjQwMDAiLCJzY29wZXNfc3VwcG9ydGVkIjpbImFwaS5hY2Nlc3MiLCJpbnRlcmJhbmtfdHJhbnNmZXIiLCJyZWFkX2FjY291bnRfaW5mb3JtYXRpb24iLCJyZWFkX2JhbGFuY2UiXSwidG9rZW5fZW5kcG9pbnQiOiJodHRwOi8vbG9jYWxob3N0OjQwMDAvYXBpL29hdXRoMi90b2tlbiIsInRva2VuX2VuZHBvaW50X2F1dGhfbWV0aG9kc19zdXBwb3J0ZWQiOlsiY2xpZW50X3NlY3JldF9iYXNpYyIsImNsaWVudF9zZWNyZXRfcG9zdCIsIm5vbmUiXX0.Q4TxdVGSs6r3U26XuFUJLitHDc2vRyFTn04JcmmIPG9pKYLJ26k2YcxTpidpemRvASoS8hKBTILle593q3regDW_3kMiicE4oxP1Cs8H-xSrNRhryleqTKD_nvhnA_Uo6hizGv1hb5Vs19b_NEDa4OcYphAITVXPPp9zf4-eillQuvB7dXCLMLNiBzHPzJu2w3PqgeGnIdEKEq3kOo7X5Za24AM8BfSBqRelDhgb53M8ZYLA3auxy-AjHGqXQ6rX5n3VpftPF-AtkNulcuFDHSfHYeCazsjDuTYHv_Av9vL5k1x9HObFxneoReRlVsQhJgkakUlcD3yNq9FsXp_KEA",
   "token_endpoint":"http://localhost:4000/api/oauth2/token",
   "token_endpoint_auth_methods_supported":[
      "client_secret_basic",
      "client_secret_post",
      "none"
   ]
}
```
