# OpenID Connect Dynamic Client Registration

Asteroid extends the OAuth2 dynamic client registration protocol and implements
[OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html)

## Support

Client metadata fields:
  - [x] `"redirect_uris"`
  - [x] `"response_types"`
  - [x] `"grant_types"`
  - [x] `"application_type"`
  - [x] `"contacts"`
  - [x] `"client_name"`
  - [x] `"logo_uri"`
  - [x] `"client_uri"`
  - [x] `"policy_uri"`
  - [x] `"tos_uri"`
  - [x] `"jwks_uri"`
  - [x] `"jwks"`
  - [x] `"sector_identifier_uri"`
  - [x] `"subject_type"`
  - [x] `"id_token_signed_response_alg"`
  - [x] `"id_token_encrypted_response_alg"`
  - [x] `"id_token_encrypted_response_enc"`
  - [x] `"userinfo_signed_response_alg"`
  - [x] `"userinfo_encrypted_response_alg"`
  - [x] `"userinfo_encrypted_response_enc"`
  - [x] `"request_object_signing_alg"`
  - [x] `"request_object_encryption_alg"`
  - [x] `"request_object_encryption_enc"`
  - [x] `"token_endpoint_auth_method"`
  - [ ] `"token_endpoint_auth_signing_alg"`
  - [x] `"default_max_age"`
  - [x] `"require_auth_time"`
  - [x] `"default_acr_values"`
  - [ ] `"initiate_login_uri"`
  - [ ] `"request_uris"`

Methods:
  - [x] `POST`
  - [ ] `GET`
