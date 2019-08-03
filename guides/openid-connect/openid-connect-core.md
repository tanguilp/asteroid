# OpenID Connect Core

Asteroid implements
[OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html).

## Support

Flows:
  - [x] authorization code flow
  - [x] implicit flow
  - [x] hybrid flow

Refresh tokens:
  - [x] refresh token can return new ID token (configurable)
  - [ ] `"offline_access"` scope

Response types:
  - [x] `"code"`
  - [x] `"id_token"`
  - [x] `"id_token token"`
  - [x] `"code id_token"`
  - [x] `"code token"`
  - [x] `"code id_token token"`

ID tokens:
  - [x] signed ID tokens
  - [x] encrypted ID tokens
  - [x] all standards attributes, including:
    - [x] `"at_hash"` attribute
    - [x] `"c_hash"` attribute
    - [x] `"nonce"` attribute
  - [x] customization of ID token contents (via a callback)

Claims:
  - [x] requesting claims using scope values
  - [ ] requesting claims using the "claims" request parameter
    - [ ] standard claims
    - [ ] essential claims
  - [ ] requesting the "acr" claim
  - [-] claim types:
    - [x] normal claims
    - [ ] aggregated claims
    - [ ] distributed claims

Userinfo endpoint:
  - [x] Bearer authentication, via:
    - [x] HTTP `"Authorization"` header
    - [x] form-enccoded body parameter
    - [x] URI query parameter
  - [x] plain claims returned
  - [x] signed claims returned
  - [x] encrypted claims returned
  - [x] encrypted and signed claims returned

Passing Request Parameters as JWTs:
  - comprehensive and conform support, see: [JWT Secured Authorization Request (JAR)](jar.html)

Subject identifier types:
  - [x] `"public"`
  - [ ] `"pairwise"`

Client authentication:
  - [x] `client_secret_basic` (via `APIacAuthBasic`)
  - [x] `client_secret_post` (via `APIacAuthClientSecretPost`)
  - [ ] `client_secret_jwt`
  - [ ] `private_key_jwt`

Self-Issued OpenID Provider:
  - [ ] Basic support

## ID tokens

Returned ID tokens are necessarily signed. The key name is configured with the
[`:oidc_id_token_signing_alg_callback`](Asteroid.Config.html#module-oidc_id_token_signing_alg_callback) configuration option.

They can also be encrypted. Refer to the following configuration options:
- [`:oidc_id_token_encryption_policy`](Asteroid.Config.html#module-oidc_id_token_encryption_policy)
- [`:oidc_id_token_encryption_alg_values_supported`](Asteroid.Config.html#module-oidc_id_token_encryption_alg_values_supported)
- [`:oidc_id_token_encryption_enc_values_supported`](Asteroid.Config.html#module-oidc_id_token_encryption_enc_values_supported)

The 2 latter configuration options are used to publish the
`"id_token_encryption_alg_values_supported"` and `"id_token_encryption_enc_values_supported"`
respectively. The `"id_token_signing_alg_values_supported"` discovery metadata uses the signing
algorithms of the following configuration options:
- [`:oidc_flow_authorization_code_id_token_signing_alg`](Asteroid.Config.html#module-oidc_flow_authorization_code_id_token_signing_alg)
- [`:oidc_flow_implicit_id_token_signing_alg`](Asteroid.Config.html#module-oidc_flow_implicit_id_token_signing_alg)
- [`:oidc_flow_hybrid_id_token_signing_alg`](Asteroid.Config.html#module-oidc_flow_hybrid_id_token_signing_alg)


ID tokens include the `"c_hash"` and `"at_hash"` values when returned from the authorization
endpoint directly. `"at_hash"` is returned from the token endpoint when exchanged against an
authorization code but not upon renewal). ID token may be returned when using a refresh token,
depending on the following configuration options:
- [`:oidc_flow_authorization_code_issue_id_token_refresh`](Asteroid.Config.html#module-oidc_flow_authorization_code_issue_id_token_refresh)
- [`:oidc_flow_hybrid_issue_id_token_refresh`](Asteroid.Config.html#module-oidc_flow_hybrid_issue_id_token_refresh)

## Userinfo endpoint

The userinfo endpoint can be reached on the `/api/oidc/userinfo` API.

The claims are returned depending on the requested claims (`"claims"` parameter) or scopes.
The following mapping shows the scope ↔ claims relationship:

```elixir
%{
  "profile" => [
    "name",
    "family_name",
    "given_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "updated_at"
  ],
  "email" => ["email", "email_verified"],
  "address" => ["address"],
  "phone" => ["phone_number", "phone_number_verified"]
}
```

The claims are directly retrieved from the subject associated to the access token used to request
this API.

The access token is verified by the `APIacAuthBearer` plug and already set up in the configuration
files:

```elixir
config :asteroid, :api_oidc_endpoint_userinfo_plugs,
  [
    {Corsica, [origins: "*"]},
    {APIacAuthBearer,
      realm: "Asteroid",
      bearer_validator: {Asteroid.OAuth2.APIacAuthBearer.Validator, []},
      bearer_extract_methods: [:header, :body],
      forward_bearer: true,
      error_response_verbosity: :normal
    }
  ]
```

By default, the access token is looked for in the `"Authorization"` header (`GET` requests) or
in the body (`POST` requests). Note that CORS is also enabled by default. Beware of changing that
configuration: it is recommended **not** adding other authentication plugs.

Note that this API does not requires from the access token to have the `"openid"` scope, since
an access token can be requested with fewer scopes than originated.

The response can be signed and/or encrypted. For signature, refer to the following configuration
options:
- [`:oidc_endpoint_userinfo_sign_response_policy`](Asteroid.Config.html#module-oidc_endpoint_userinfo_sign_response_policy)
- [`:oidc_endpoint_userinfo_signing_key`](Asteroid.Config.html#module-oidc_endpoint_userinfo_signing_key)
- [`:oidc_endpoint_userinfo_signing_alg`](Asteroid.Config.html#module-oidc_endpoint_userinfo_signing_alg)

Encryption is done with one of the valid key (for this usage) of the calling client (and are
retrieved using the `Asteroid.Client.get_jwks/1` function). Encryption is configured through:
- [`:oidc_endpoint_userinfo_encrypt_response_policy`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encrypt_response_policy)
- [`:oidc_endpoint_userinfo_encryption_alg_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encryption_alg_values_supported)
- [`:oidc_endpoint_userinfo_encryption_enc_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encryption_enc_values_supported)

Keys' configuration is published in the discovery data as soon as signing (resp. encryption) is
enabled with a policy different than `:disabled`. The following metadata is published:
- `"userinfo_signing_alg_values_supported"`: the algorithm of the
[`:oidc_endpoint_userinfo_signing_alg`](Asteroid.Config.html#module-oidc_endpoint_userinfo_signing_alg)
configuration option
- `"userinfo_encryption_alg_values_supported"`: the values of the
[`:oidc_endpoint_userinfo_encryption_alg_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encryption_alg_values_supported)
configuration option
- `"userinfo_encryption_enc_values_supported"`: the values of the
[`:oidc_endpoint_userinfo_encryption_enc_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encryption_enc_values_supported)
configuration option
