# Dynamic client registration (RFC7591)

Asteroid implements dynamic client registration
([RFC7591](https://tools.ietf.org/html/rfc7591).

This RFC allows dynamic creation of new OAuth2 clients on the authorization server. This can be
used:
- by an API manager to automate creation of clients from an API store (or more widely to
automate AS configuration in a standard manner)
- by mobile applications to create their "application accounts" on first use (however this
use-case is debatable since mobile applications cannot keep a secret, well, secret, and there
are other means)
- by IoT devices to register themselves on first use, thanks to a secret

## Support

Metadata:
  - [x] Client metadata fields
    - `"software_id"` and `"software_version"` are processed but not used in conjonction with
    software statements
  - [x] Issuing client secrets

Access control:
  - [ ] Software statement
  - [x] Initial access token
    - Actually any access token valid with the relevant scope
  - [x] Open registration


## Access policies

Access policy to the endpoint is determined by the
[`:oauth2_endpoint_register_authorization_policy`](Asteroid.Config.html#module-oauth2_endpoint_register_authorization_policy)
configuration option. See the associated documentation for further explanation.

Asteroid does support open registration. If you enable it, beware of the risks associated such
as DOS attacks from requester that could quickly create millions of new clients. One possible
countermeasure is to rate-limit this endpoint using the `APIacFilterThrottler` plug.

## Authentication

The only client authentication scheme required by the specification is the HTTP `Bearer` scheme,
to be used with an "initial access token" which is desribed as a long-lived access token.

Note that it contradicts the spirit of the OAuth2 model and the OAuth2
[OAuth 2.0 Threat Model and Security Considerations](https://tools.ietf.org/html/rfc6819#section-5.1.5.3)
specification. Unfortunately, RFC7591 do not provides with a rationale for such a design
choice.

Asteroid does support authentication using the HTTP `Bearer` scheme through the
`APIacAuthBearer` plug, which can be used with the `#FIXME` implementation of
`APIacAuthBearer.Validator`.

All other authentication methods are also supported. They are to be configured with the
[`:api_oauth2_endpoint_register_plugs`](Asteroid.Config.html#module-api_oauth2_endpoint_register_plugs)
configuration option.

In all authentication scenarios and when using the `:authorized_clients` policy, the calling
client must have been granted the `"asteroid.register"` scope to be allowed to create clients.
See the [clients' permission documentation](configuring-clients.html#asteroid-scopes) for further
information.

## Metadata fields

The `"client_id"` for new clients is derived by the
`Asteroid.OAuth2.Register.generate_client_id/1` function from the client's name. The client id
generation function can be modified by the
`:oauth2_endpoint_register_gen_client_id_callback` callback.

The `"client_id_issued_at"` and `"client_secret_expires_at"` are not issued when responding
because client secret expiration is not supported by Asteroid.

The `"software_statement"` field is not supported.

All other fields are supported.

## Defaults for metadata fields

Fields default to the default values specificied in the specification:
- `"token_endpoint_auth_method"` defaults to `"client_secret_basic"`
- `"grant_types"` defaults to `["authorization_code"]`
- `"response_types"` defaults to `["code"]`

These defaults can be configured at the client level with the following attributes (in which
case they take precedence):
- `"__asteroid_oauth2_endpoint_register_default_token_endpoint_auth_method"`
- `"__asteroid_oauth2_endpoint_register_default_grant_types"`
- `"__asteroid_oauth2_endpoint_register_default_response_types"`

See the `Asteroid.Client` module documentation for further information.

## Token endpoint authentication method

The enabled authentication method of the `/token` endpoint are determined by the
`:oauth2_endpoint_token_auth_methods_supported_callback` callback, which defaults to
`Asteroid.OAuth2.Endpoint.token_endpoint_auth_methods_supported/0` functions, which
basically reads the installed plugs on the endpoint to determine support.

## Saved client metadata for newly created clients

Newly created client's attributes are not exactly those returned to the requester in the
JSON response. The following subsections describe what's different.

### I18n fields

The internationalized fields such as `"client_name"` are preprocessed so as to make their use
simpler. A new map with the attribute name suffixed by `"_i18n"` is created and replace the
`"#"` annotated fields. For isntance the following request `"client_name"` fields:

```json
...
"client_name": "Example client number twenty one",
"client_name#fr": "Client d'exemple numéro un",
"client_name#ru": "Примерое приложение номер один",
...
```

will be returned as-is to the initiator of the request but will be saved in the client attribute
store as:

```elixir
...
"client_name" => "Example client number twenty one",
"client_name_i18n" => %{
  "fr" => "Client d'exemple numéro un",
  "ru" => "Примерое приложение номер один"
},
...
```

The following fields are internationalized:
- `"client_name"`
- `"client_uri"`
- `"logo_uri"`
- `"tos_uri"`
- `"policy_uri"`

### JWKs

Keys of a `"jwks"` are stored as a list of binary data in the client attribute repository. The
rationale is that:
- its complex structure may be hard to store in some stores, depending on the technology
- there is no need to have it stored in a structured way in a store, since it generally doesn't
make sense to search for cryptographic key values

Therefore the following keys:

```json
"jwks": {"keys": [
{
  "e": "AQAB",
  "n": "nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
  HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
  lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
  RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
  2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
  qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
  "kty": "RSA"},
{"kty": "EC",
  "crv": "P-256",
  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  "use": "enc",
  "kid": "1"}
]}
```

will be stored as:

```elixir
[
  binary_data: <<131, 116, 0, 0, 0, 6, 109, 0, 0, 0, 3, 99, 114, 118, 109, 0, 0,
    0, 5, 80, 45, 50, 53, 54, 109, 0, 0, 0, 3, 107, 105, 100, 109, 0, 0, 0, 1,
    49, 109, 0, 0, 0, 3, 107, 116, 121, 109, 0, 0, ...>>,
  binary_data: <<131, 116, 0, 0, 0, 3, 109, 0, 0, 0, 1, 101, 109, 0, 0, 0, 4,
    65, 81, 65, 66, 109, 0, 0, 0, 3, 107, 116, 121, 109, 0, 0, 0, 3, 82, 83, 65,
    109, 0, 0, 0, 1, 110, 109, 0, 0, 1, 121, ...>>
]
```

### Determining client type

When creating a new client, Asteroid requires to set its client type because public and
confidential clients are managed differently. The client type is either `"public"` or
`"confidential"` and is set under the `"client_type"` attribute of the client's attribute
repository as documented in the `Asteroid.Client` module.

The callback function to determine the client's type is configured by the
`:oauth2_endpoint_register_client_type_callback` configuration option and defaults to
`Asteroid.OAuth2.Register.client_type/1`.

### Issuing a client secret

A secret is automatically issued when the `"token_endpoint_auth_method"` is one of:
- `"client_secret_basic"`
- `"client_secret_post"`

The secret is generated by `Expwd` and stored as `t:Expwd.Hashed.Portable.t/0` string, such as
`"expwd:sha256:tN/TQmVIuEVwzAq25cocgomgoD09wxaZe0Gn2UYoOtA"`, to enable secure storage of the
secret.

### Client's creator

The client id of the client that created the new client is stored in the
`"__asteroid_created_by_client_id"` attribute. This only applies when an authenticated client
created it.
