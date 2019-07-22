# Asteroid

Authorization Server on sTEROIDs.

![Asteroid](assets/static/images/asteroid.svg)

Asteroid is an OAuth2 server designed for performance, extensibility and maintenability. It
benefits from the high performance of the Erlang Virtual Machine for servers.

## Protocol support

Asteroid supports the following specifications:
- The OAuth 2.0 Authorization Framework ([RFC6749](https://tools.ietf.org/html/rfc6749))
- OAuth 2.0 Token Introspection ([RFC7662](https://tools.ietf.org/html/rfc7662))
- OAuth 2.0 Token Revocation ([RFC7009](https://tools.ietf.org/html/rfc7009))
- Proof Key for Code Exchange by OAuth Public Clients ([RFC7636](https://tools.ietf.org/html/rfc7636))
- OAuth 2.0 Dynamic Client Registration Protocol ([RFC7591](https://tools.ietf.org/html/rfc7591))
- OAuth 2.0 Authorization Server Metadata ([RFC8414](https://tools.ietf.org/html/rfc8414))
- JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens ([draft-ietf-oauth-access-token-jwt-00](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-00))
- OAuth 2.0 Device Authorization Grant ([draft-ietf-oauth-device-flow-15](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15))

Asteroid strives to fully implement the specifications. For specifics about support, refer to
the documentation.

## Install from source

First,
[install Elixir](https://www.google.com/search?client=ubuntu&channel=fs&q=install+elixir&ie=utf-8&oe=utf-8). Then clone this repository and launch Asteroid:

```bash
git clone https://github.com/tanguilp/asteroid.git

cd asteroid/

mix deps.get

iex -S mix phx.server
```

## Documentation

You can build documentation using mix:

```bash
mix docs
```

The documentation is generated in the `doc/` folder.

It is also published [here](http://svground.fr/asteroid/doc/).

It contains information related to the use of the test application in the "Running the demo app"
section.
