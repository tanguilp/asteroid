# MTLS (RFC8705)

Asteroid implements parts of [RFC8705](https://tools.ietf.org/html/rfc8705).

## Support

- [x] 2. Mutual TLS for OAuth Client Authentication
  - [x] 2.1 PKI Mutual-TLS Method
  - [x] 2.2 Self-Signed Certificate Mutual-TLS Method
- [ ] 3. Mutual-TLS Client Certificate-Bound Access Tokens
- [x] 5. Metadata for Mutual-TLS Endpoint Aliases

## Native vs. remote TLS authentication termination

Depending on the deployment scenario, TLS termination may take place either directly on Asteroid
or upstream on a network authenticating reverse-proxy.

Asteroid uses the `:oauth2_mtls_start_endpoint` configuration to determine whether to start
and additional MTLS endpoint. When set to `:auto`, it uses the
`Asteroid.OAuth2.MTLS.in_use?/1` function with the `native: true` parameter.

These functions rely on the use of the `APIacAuthMTLS` plug in the configuration options. Refer
to its documentation for more information.

The additional endpoint consist in:
- the `AsteroidWeb.EndpointMTLSAliases` endpoint
- the `AsteroidWeb.RouterMTLSAliases` router

The endpoint can be configured like the default endpoint in configuration files. For instance:

```elixir
config :asteroid, AsteroidWeb.EndpointMTLSAliases,
  http: [port: 8443],
  url: [scheme: "https", host: "mtls.example.com", path: "/mtls", port: 10443]
```

Note that the router installs only the routes that are configured with an `APIacAuthMTLS` plug.
Routes can be shown using the `mix phx.routes` task:

```bash
$ mix phx.routes AsteroidWeb.RouterMTLSAliases
token_path  POST  /api/oauth2/token                      AsteroidWeb.API.OAuth2.TokenController :handle
```

## Advertising support

Alias for the endpoints using MTLS (which are those configured with an `APIacAuthMTLS` plug)
are advertised by default on `/.well-known/oauth-authorization-server` and
`/.well-known/openid-configuration`:

```json
{
...
"mtls_endpoint_aliases":{
	"token_endpoint":"https://mtls.example.com:10443/mtls/api/oauth2/token"
},
...
"token_endpoint_auth_methods_supported":[
	"client_secret_basic",
	"none",
	"tls_client_auth"
],
...
}
```

This can be turned off using the `:oauth2_mtls_advertise_aliases` configuration option.

## Client registration

Client registration supports registering `"tls_client_auth"` and `"self_signed_tls_client_auth"`
as an authentication method. In addition it supports registering the following attributes
(at most one per client) for use in conjunction with`"tls_client_auth"`:
- `"tls_client_auth_subject_dn"`
- `"tls_client_auth_san_dns"`
- `"tls_client_auth_san_uri"`
- `"tls_client_auth_san_ip"`
- `"tls_client_auth_san_email"`

## Callback functions

Asteroid provides with 2 callback functions for the `APIacAuthMTLS` plug:
- `Asteroid.OAuth2.MTLS.pki_mutual_tls_method/1`
- `Asteroid.OAuth2.MTLS.self_signed_mutual_tls_method/1`

Configuring the token endpoint for both methods would therefore require writing:

```elixir
config :asteroid, :api_oauth2_endpoint_token_plugs, [
  # some plugs
  {APIacAuthMTLS,
    allowed_methods: :both,
    pki_callback: &Asteroid.OAuth2.MTLS.pki_mutual_tls_method/1,
    selfsigned_callback: &Asteroid.OAuth2.MTLS.self_signed_mutual_tls_method/1,
    set_error_response: &APIacAuthMTLS.save_authentication_failure_response/3
  },
  # some other plugs
```
