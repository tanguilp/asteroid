# OpenID Connect Discovery 1.0

Asteroid implements parts of
[OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html).

OpenID Connect metadata is made available on the `/.well-known/oauth-authorization-server`
and `/.well-known/openid-configuration` URLs.

## Support

- Advertised metadata:
  - [x] `"issuer"`
  - [x] `"authorization_endpoint"`
  - [x] `"token_endpoint"`
  - [x] `"userinfo_endpoint"`
  - [x] `"jwks_uri"`
  - [x] `"registration_endpoint"`
  - [x] `"scopes_supported"`
  - [x] `"response_types_supported"`
  - [x] `"response_modes_supported"`
  - [x] `"grant_types_supported"`
  - [x] `"acr_values_supported"`
  - [x] `"subject_types_supported"`
  - [x] `"id_token_signing_alg_values_supported"`
  - [x] `"id_token_encryption_alg_values_supported"`
  - [x] `"id_token_encryption_enc_values_supported"`
  - [x] `"userinfo_signing_alg_values_supported"`
  - [x] `"userinfo_encryption_alg_values_supported"`
  - [x] `"userinfo_encryption_enc_values_supported"`
  - [ ] `"request_object_signing_alg_values_supported"`
  - [ ] `"request_object_encryption_alg_values_supported"`
  - [ ] `"request_object_encryption_enc_values_supported"`
  - [x] `"token_endpoint_auth_methods_supported"`
  - [ ] `"token_endpoint_auth_signing_alg_values_supported"`
  - [x] `"display_values_supported"`
  - [x] `"claim_types_supported"`
  - [ ] `"claims_supported"`
  - [x] `"service_documentation"`
  - [ ] `"claims_locales_supported"`
  - [ ] `"ui_locales_supported"`
  - [x] `"claims_parameter_supported"`
  - [x] `"request_parameter_supported"`
  - [x] `"request_uri_parameter_supported"`
  - [x] `"require_request_uri_registration"`
  - [x] `"op_policy_uri"`
  - [x] `"op_tos_uri"`
  - [x] `"device_authorization_endpoint"` (from [OAuth 2.0 Device Authorization Grant - section 4](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-4))

Deviations from the specification:
  - `/issuer1/.well-known/openid-configuration` syntax should not be supported as it violates
  RFC5785

## Configuration

The configuration of [Server metadata (RFC8414)](server-metadata.html) is applied.
