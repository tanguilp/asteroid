# Asteroid

Authorization Server on sTEROIDs.

<img src="assets/static/images/asteroid.svg" alt="Asteroid" width="180px"/>


Asteroid is an OAuth2 server designed for performance, extensibility and maintenability. It
benefits from the high performances and reliability of the Erlang Virtual Machine.

## Protocol support

Asteroid supports the following specifications:
- OAuth2:
  - The OAuth 2.0 Authorization Framework ([RFC6749](https://tools.ietf.org/html/rfc6749))
  - The OAuth 2.0 Authorization Framework: Bearer Token Usage ([RFC6750](https://www.rfc-editor.org/rfc/rfc6750.html))
  with [`APIacAuthBearer`](https://github.com/tanguilp/apiac_auth_bearer)
  - OAuth 2.0 Token Introspection ([RFC7662](https://tools.ietf.org/html/rfc7662))
  - OAuth 2.0 Token Revocation ([RFC7009](https://tools.ietf.org/html/rfc7009))
  - Proof Key for Code Exchange by OAuth Public Clients ([RFC7636](https://tools.ietf.org/html/rfc7636))
  - OAuth 2.0 Dynamic Client Registration Protocol ([RFC7591](https://tools.ietf.org/html/rfc7591))
  - OAuth 2.0 Authorization Server Metadata ([RFC8414](https://tools.ietf.org/html/rfc8414))
  - OAuth 2.0 Device Authorization Grant ([RFC8628](https://www.rfc-editor.org/rfc/rfc8628.html))
  - JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens
  ([draft-ietf-oauth-access-token-jwt-00](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-00))
  - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens ([RFC8705](https://tools.ietf.org/html/rfc8705))
  with [`APIacAuthMTLS`](https://github.com/tanguilp/apiac_auth_mtls)
- OpenID Connect:
  - [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html)
  - [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html)
  - [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
  - [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
  - [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)

Asteroid strives to fully implement the specifications. For specifics about support, refer to
the documentation.

## Demo flows

The `demo_auth_workflow` branch implements two flows. Refer to the documentation for more
information.

### OAuth2 flow

[![OAuth2 demo flow](https://raw.githubusercontent.com/tanguilp/asteroid/master/guides/media/oauth2_flow_video_screenshot.png)](https://vimeo.com/356037657)

### OpenID Connect flow

[![OpenID Connect demo flow](https://raw.githubusercontent.com/tanguilp/asteroid/master/guides/media/oidc_flow_video_screenshot.png)](https://vimeo.com/356037941)

## Compatibility

**OTP22.1+**

Elixir 1.9

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
