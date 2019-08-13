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
  - [x] `"offline_access"` scope

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
  - [x] requesting claims using the "claims" request parameter
  - [x] requesting the "acr" claim
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
  - [x] `"pairwise"`

Client authentication:
  - [x] `client_secret_basic` (via `APIacAuthBasic`)
  - [x] `client_secret_post` (via `APIacAuthClientSecretPost`)
  - [ ] `client_secret_jwt`
  - [ ] `private_key_jwt`

Initiating Login from a Third Party
  - [ ] Support

Self-Issued OpenID Provider:
  - [ ] Support

## ID tokens

Returned ID tokens are necessarily signed. They are signed with one of the stored keys matching
the `"id_token_signed_response_alg"` client attribute.

They can optionally be encrypted. Asteroid uses the `"id_token_encrypted_response_alg"` and
`"id_token_encrypted_response_enc"` client attributes to determine if the ID token should be
encrypted, and with which algorithms. In this case, Asteroid looks for a suitable key in the
client JWKs.

The following configuration options whitelists the acceptable algorithms:
- [`:oidc_id_token_signing_alg_values_supported`](Asteroid.Config.html#module-oidc_id_token_signing_alg_values_supported)
- [`:oidc_id_token_encryption_alg_values_supported`](Asteroid.Config.html#module-oidc_id_token_encryption_alg_values_supported)
- [`:oidc_id_token_encryption_enc_values_supported`](Asteroid.Config.html#module-oidc_id_token_encryption_enc_values_supported)

The values of these configuration options are used:
- to restrict client registration to whitelisted algorithms
- to advertise them on the `.well-known/*` discovery documents

It does not restrict a client's information somehow registered with other non-whitelisted values
to be used for ID token signing and encryption. If you change the whitelisted algorithms, you
might want to update the clients accordingly as well.

ID tokens include the `"c_hash"` and `"at_hash"` values when returned from the authorization
endpoint directly. `"at_hash"` is returned from the token endpoint when exchanged against an
authorization code but not upon renewal). ID token may be returned when using a refresh token,
depending on the following configuration options:
- [`:oidc_flow_authorization_code_issue_id_token_refresh`](Asteroid.Config.html#module-oidc_flow_authorization_code_issue_id_token_refresh)
- [`:oidc_flow_hybrid_issue_id_token_refresh`](Asteroid.Config.html#module-oidc_flow_hybrid_issue_id_token_refresh)

ID tokens also include the `"acr"`, `"amr"`, `"auth_time"` and `"nonce"` claims if available.

## Claims

The `claims` parameter is supported, in the sense that it is parsed and forwarded to the web
flow.

Since the specification stipulates that all claims (except `acr`), even those marked as
`"essential": true` are not really mandatory (an error should not be returned, even if a
condition is not met), Asteroid won't return an error handling this parameter (except for
`"acr"`).

Asteroid distinguishes 2 types of claims:
- Technical ID token claims:
  - `"iss"`,
  - `"sub"`,
  - `"aud"`,
  - `"exp"`,
  - `"iat"`,
  - `"auth_time"`,
  - `"nonce"`,
  - `"acr"`,
  - `"amr"`,
  - `"azp"`,
- subject claims: all claims not included in the list aforementioned

Subject claims are returned in the ID token or on the `/userinfo` endpoint, depending on the
`"claims"` parameter, from the subject. If the subject has no a specific claim, it is not
returned.

Technical claims are only returned in the ID Token.

## Requesting the `"acr"` Claim

The `"acr"` clain is a special case. When requesting on the `/authorize` endpoint, Asteroid
tries to determine the preferred acr for the current request. It does so by (in order):
- analyzing the `"claims"` parameter for a requested `"acr"`
- analyzing the `"acr_values"` parameter
- looking up at the `"default_acr_values"` of the client's

It then sets the `:preferred_acr` member of the request object
(`AsteroidWeb.AuthorizeController.Request`) accordingly.

It still up to the web flow to decide:
- which acr to use
- to reauthenticate or not depending on the `"max_age"` parameter

Back from the web flow and in the case the `"acr"` claim was requested as an essetnail claim,
Asteroid checks that the returned ACR does indeed satisfy the requirement. If not, an error is
returned.

Note: example of an `"claims"` parameter where the `"acr"` is requested as an essential claim:

```json
{
 "id_token":
  {
   "acr": {"essential": true, "values": ["2-factor", "3-factor"]}
  }
}
```

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

The response can be signed and/or encrypted. Asteroid uses the following OpenID Connect client
fields to determine if a response should be encrypted or signed:
- `"userinfo_signed_response_alg"`
- `"userinfo_encrypted_response_alg"`
- `"userinfo_encrypted_response_enc"`

Encrypting without signing is possible, using the signing `"none"` algorithm. It requires
activating the `"none"` algorithm. See
[ JWS "none" algorithm ](crypto-keys.html#jws-none-algorithm).

The acceptable signature and encryption algorithms are whitelisted using the following
configuration options:
- [`:oidc_endpoint_userinfo_signature_alg_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_signature_alg_values_supported)
- [`:oidc_endpoint_userinfo_encryption_alg_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encryption_alg_values_supported)
- [`:oidc_endpoint_userinfo_encryption_enc_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encryption_enc_values_supported)

The values of these configuration options are used:
- to restrict client registration to whitelisted algorithms
- to advertise them on the `.well-known/*` discovery documents

## Passing Request Parameters as JWTs

This is implemented through [JWT Secured Authorization Request (JAR)](jar.html).

## Subject identifier types

The `"pairwise"` subject identifier type is supported. Refer the following configuration options:
- [`:oidc_subject_identifier_callback`](Asteroid.Config.html#module-oidc_subject_identifier_callback)
- [`:oidc_subject_identifier_pairwise_salt`](Asteroid.Config.html#module-oidc_subject_identifier_pairwise_salt)

## Offline access

When using an OpenID Connect flow, issued refresh tokens are linked to the a authenticated
session.

When this authenticated session is destroyed, be it because the last authentication event has
expired or because the authenticated session was programmatically destroyed, Asteroid destroys
associated refresh tokens that *do not have* the `"offline_access"` scope.

In a nutshell, when an authenticated session is destroyed:
- a refresh tokens issued in an OpenID Connect flow:
  - is destroyed if it contains the `"openid"` scope
    - except if it also contains the `"offline_access"` scope
- other refresh tokens are left unchanged

Offline access is enabled by adding the `"offline_access"` scope in the relevant scope
configuration option, like any other scope.
