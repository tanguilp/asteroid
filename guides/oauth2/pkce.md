# Proof Key for Code Exchange (RFC7636)

Asteroid implements Proof Key for Code Exchange by OAuth Public Clients
[RFC7636](https://tools.ietf.org/html/rfc7636)

This specification mitigates the risk of authorization code interception on the client side,
making a malicious application having intercepted the authorization code unable to exchange it for
tokens on the `/api/oauth2/token` endpoint. This is especially useful for mobile applications
since a malicious application can, under certain circumstances, claim the redirect URI of the
legitimate application.

This protocol can only be used along the authorization code flow, by design.

## Support

[PKCE Code Challenge Methods](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#pkce-code-challenge-method):
- [x] `"plain"`
- [x] `"S256"`

## Policies

Three polciies are available:

- `:disabled`: PKCE support is disabled
- `:mandatory`: all requests using the authorization code flow must use PKCE
- `:optional`: use of PKCE is optional, except for clients marked as forced to use it
  - those clients have their `"__asteroid_oauth2_flow_authorization_code_mandatory_pkce_use"`
  attribute set to `true` (see `Asteroid.OAuth2.Client.must_use_pkce?/1`)

PKCE policy is configured by the
[`:oauth2_flow_authorization_code_pkce_policy`](Asteroid.Config.html#module-oauth2_flow_authorization_code_pkce_policy)
configuration option.

Other configuration options available are:
- [`:oauth2_flow_authorization_code_pkce_client_callback`](Asteroid.Config.html#module-oauth2_flow_authorization_code_pkce_client_callback)
- [`:oauth2_flow_authorization_code_pkce_allowed_methods`](Asteroid.Config.html#module-oauth2_flow_authorization_code_pkce_allowed_methods)
  - as stated by the specification: "The plain transformation is for compatibility with existing
    deployments and for constrained environments that can't use the S256 transformation.". You
    should probably keep it disabled.

