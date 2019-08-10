# Response mode

Asteroid parts of
[OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
and fully supports
[OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).

## Support

[OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html):
- [x] `"response_mode"` parameter
- [-] `"response_type"`: deprecated by OpenID Connect specification
  - [ ] `"none"` response type

[OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html):
- [x] `"form_post"` response mode

## Details

When requesting tokens on the authorization endpoint, the tokens can be returned either
in the URI fragment, the URI query parameters or as POST parameters.

This features is configured with the
[`:oauth2_response_mode_policy`](Asteroid.Config.html#module-oauth2_response_mode_policy)
configuration option, which can take 3 values:
- `:disabled`
- `:oidc_only`: the default value
- `:enabled`: enabled also for OAuth2 authorization and implicit flows

When set, the `"response_mode"` parameter must be one of: `"query"`, `"fragment"` or
`"form_post"`. Otherwise an error will be returned.
