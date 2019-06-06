# Terminology and conventions

## Terminology

### Flows

The term "flow" refers to the logical flows as documented in the
[RFC6749](https://tools.ietf.org/html/rfc6749) OAuth2 core specification.

The following flows are supported:
- authorization code flow
- implicit flow
- client credentials flow
- resource owner password credentials flow

They are documented in `t:Asteroid.OAuth2.flow/0`.

Note that the concept of flow is not per se doucmented in OAuth2 specifications, but Asteroid
uses it for convenience and because neither grant types nor response types concept do help
with segregating configuration for these flow. On the contrary, they can be overlapping: for
instance a refresh token grant type can be issued in 3 flows (authorization code, client
credentials and resource owner password credentials).

### Grant types

Grant types as documented in
[section 2 of RFC7591](https://tools.ietf.org/html/rfc7591#section-2).

The following grant types are supported:
- authorization code grant type
- implicit grant type
- client credentials grant type
- resource owner password credentials grant type
- refresh token grant type

They are documented in `t:Asteroid.OAuth2.grant_type/0`.

Note that because of the presence of the "implicit" grant type, that concept is not equivalent
of *something* being exchanged on the `"/token"` endpoint against an access token.

### Response types

Response types as documented in
[section 2 of RFC7591](https://tools.ietf.org/html/rfc7591#section-2).

The following response types are supported:
- code
- token

They are documented in `t:Asteroid.OAuth2.response_type/0`.

These are basically what you'll receive upon completion of the implicit flow.
