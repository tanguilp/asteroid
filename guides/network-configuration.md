# Network configuration

## TLS

Use of TLS is mandatory for running OAuth2 servers. Asteroid, however, doesn't enforce it for the
sake of ease of development. However, with great power comes great responsibility.
TLS use is mandatory because of the tokens and user credentials transitting to and from the
Asteroid OAuth2 server. **Assess carefully** when using plain HTTP, even for development or test
environments (some real credentials could be entered by mistake by users).

To configure TLS, refer to the Phoenix documentation.

## Endpoints

Asteroid provides with one unique endpoint for both web and APIs. Support for
`mtls_endpoint_aliases` is considered for use of MTLS.

The endpoint is configured in the configuration file:

```elixir
config :asteroid, AsteroidWeb.Endpoint,
  http: [:inet6, port: System.get_env("PORT") || 443],
  url: [host: "example.com", port: 443]
```

Asteroid uses this configuration option to generate URLs, including on the
`/.well-known/oauth-authorization-server` endpoint.

These configuration options allow configuring Asteroid behing a reverse-proxy
since it generates URLs automatically based on that. However, note that `:url` information (as
described [here](https://hexdocs.pm/phoenix/Phoenix.Endpoint.html#module-runtime-configuration))
doesn't change the access url, scheme path and port of the Asteroid running instance, but only
URL generation.

## Well-known URI

According to the RFC and in case of having a path, the well-known path shall stay at the root
and the path appended at the end. In other words, having the path `/auth_service`, the well-known
URI shall be:

`www.example.come/.well-known/oauth-authorization-server/auth_service`

and **not**:


`www.example.come/auth_service/.well-known/oauth-authorization-server`

## CORS

Asteroid supports simple CORS requests simply by adding a CORS plug in the pipeline. Asteroid
imports the `Corsica` CORS library by default, but you are free to use another one. Example
with the revoke endpoint:

```elixir
config :asteroid, :api_oauth2_endpoint_revoke_plugs, [{Corsica, [origins: "*"]}]
```

Pre-flight requests are not supported.

Asteroid sets CORS plug by default for:
- `/api/oauth2/token`
- `/api/oauth2/revoke`

which are the 2 endpoints likely to be used by a javascript client.

Note that Corsica supports determining origin dynamically - it's therefore possible to return
only client's authorized origins as long as you have it registered upon client creation.

# Outbound request

Asteroid can perform outbound requests on any port, for instance:
- when retrieving JWKs
- when retrieving a request object
- when verifying a sector identifier URI against a list of redirect URIS
(`AsteroidWeb.RegisterController.verify_sector_identifier_uri/2`)
- etc.
