# Network configuration

## TLS

Use of TLS is mandatory for running OAuth2 servers. Asteroid, however, doesn't enforce it for the
sake of ease of development. However, with great power comes great responsibility.
TLS use is mandatory because of the tokens and user credentials transitting to and from the
Asteroid OAuth2 server. **Assess carefully** when using plain HTTP, even for development or test
environments (some real credentials could be entered by mistake by users).

To configure TLS, refer to the Phoenix documentation.

## Endpoints

Web and API endpoints run on different ports, as follows:
- `Asteroid.Endpoint`:
  - `/authorize`
  - `/device`
  - `/.well-known/oauth-authorization-server`
  - `/discover/keys`
- `Asteroid.EndpointAPI`:
  - `/api/oauth2/token`
  - `/api/oauth2/introspect`
  - `/api/oauth2/revoke`
  - `/api/oauth2/register`
  - `/api/oauth2/device_authorization`

Asteroid is designed this way so that:
- different policies between web and APIs can be applied at a higher level (reverse-proxy...)
- TLS mutual authentication can be used on API without interfering with the web flows, and
vice-versa
  - Indeed, when activating mutual TLS authentication, it may pop-up client certificate selection
  user interface in some browsers under certain circumstances. Thus, enabling eg. MTLS on the
  `/api/oauth2/token` API could have unwanted side effects on browsing experience during the web
  authentication process should the endpoints be on the same host and port

They are therefore configured separately in the configuration files:

```elixir
config :asteroid, AsteroidWeb.Endpoint,
  http: [:inet6, port: System.get_env("PORT") || 443],
  url: [host: "example.com", port: 443],
  cache_static_manifest: "priv/static/cache_manifest.json"

config :asteroid, AsteroidWeb.EndpointAPI,
  http: [:inet6, port: System.get_env("PORT_API") || 8443],
  url: [host: "example.com", port: 8443, scheme: "https"]
```

Asteroid uses these configuration options to generate URLs, including on the
`/.well-known/oauth-authorization-server` endpoint.

These configuration options allow configuring Asteroid behing a reverse-proxy
since it generates URLs automatically based on that. However, note that `:url` information (as
described [here](https://hexdocs.pm/phoenix/Phoenix.Endpoint.html#module-runtime-configuration))
doesn't change the access url, scheme path and port of the Asteroid running instance, but only
URL generation.

At startup the following lines appear in the shell:

```elixir
[info] Running AsteroidWeb.Endpoint with cowboy 2.6.3 at 0.0.0.0:4000 (http)
[info] Access AsteroidWeb.Endpoint at http://localhost:4000
[info] Running AsteroidWeb.EndpointAPI with cowboy 2.6.3 at 0.0.0.0:4001 (http)
[info] Access AsteroidWeb.EndpointAPI at http://localhost:4001
```

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
