defmodule Asteroid.Client do
  use AttributeRepository.Resource, otp_app: :asteroid

  @moduledoc """
  `AttributeRepository.Resource` for clients

  Client refers to an OAuth2 client, that is a **application** (and not a machine). There are 2
  types of clients:
  - those who can keep a secret secret: *confidential clients* (such as a server). Usually there
  is one instance of this application running (even though it has several servers running), so in
  this case 1 client = 1 machine
  - those who can't: *public clients* (mobile applications, SPAs...). In this case there are
  multiple instances of the same client running, used by different subjects

  # FIXME: update with fields from Dynamic Registration

  ## Field naming
  The following fields have standardised meaning:
  - `"client_id"`: the client identifier (as in OAuth2) (`String.t()`)
  - `"client_secret"`: the client secret (`String.t()`)
  - `"client_type"`: `"public"` or `"confidential"`, depending on the client's type
  - `"grant_types"`: the list of grant types (`t:Asteroid.OAuth2.grant_type_str/0`) that the
  client is allowed to use
  - `"response_types"`: the list of response types (`t:Asteroid.OAuth2.response_type_str/0`) that
  the client is allowed to use
  - `"redirect_uris"`: the list of OAuth2 / OpenID Connect redirect URIs (`[String.t()]`)
  - `"scope"`: a list of OAuth2 scopes that the client can use when requesting tokens. Scopes
  starting with the string `"asteroid."` are special permissions used to access Asteroid
  endpoints. See also []()
  - `"token_endpoint_auth_method"`: a `t:Asteroid.Oauth2.Endpoint.auth_method_str/0`
  as specified in RFC7591
  - `"__asteroid_created_by_client_id"`: the `String.t()` client id of the client that has
  initially created this client using the `/register` endpoint (may not have a value if the
  client was created by another mean)
  - `"__asteroid_oauth2_flow_ropc_issue_refresh_token_init"`: a `boolean()` set to true if a
  refresh token is to be issued at the first request of the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_issue_refresh_token_refresh"`: a `boolean()` set to true if a
  refresh token is to be issued when refresh tokens in the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_refresh_token_lifetime"`: a `non_neg_integer()` set to the
  lifetime duration of a refresh token in the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_access_token_lifetime"`: a `non_neg_integer()` set to the
  lifetime duration of an access token in the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_access_token_serialization_format"`: the
  `t:Asteroid.Token.serialization_format_str/0` serialization format for the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_access_token_signing_key"`: the
  `t:Asteroid.Crypto.Key.name/0` signing key name for access tokens in the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_access_token_signing_alg"`: the
  `t:Asteroid.Crypto.Key.alg/0` signing algorithm for access tokens in the ROPC flow
  - `"__asteroid_oauth2_flow_client_credentials_issue_refresh_token_init"`: a `boolean()` set to
  `true` if a refresh token is to be issued at the first request of the client credentials flow
  - `"__asteroid_oauth2_flow_client_credentials_issue_refresh_token_refresh"`: a `boolean()` set
  to `true` if a refresh token is to be issued when refresh tokens in the client_credentials flow
  - `"__asteroid_oauth2_flow_client_credentials_refresh_token_lifetime"`: a `non_neg_integer()`
  set to the lifetime duration of a refresh token in the client credentials flow
  - `"__asteroid_oauth2_flow_client_credentials_access_token_lifetime"`: a `non_neg_integer()`
  set to the lifetime duration of an access token in the client credentials flow
  - `"__asteroid_oauth2_flow_client_credentials_access_token_serialization_format"`: the
  `t:Asteroid.Token.serialization_format_str/0` serialization format for the client credentials
  flow
  - `"__asteroid_oauth2_flow_client_credentials_access_token_signing_key"`: the
  `t:Asteroid.Crypto.Key.name/0` signing key name for access tokens in the client credentials flow
  - `"__asteroid_oauth2_flow_client_credentials_access_token_signing_alg"`: the
  `t:Asteroid.Crypto.Key.alg/0` signing algorithm for access tokens in the client credentials flow
  - `"__asteroid_oauth2_flow_authorization_code_authorization_code_lifetime"`: a
  `non_neg_integer()` set to the lifetime duration of an authorization in the code flow
  - `"__asteroid_oauth2_flow_authorization_code_issue_refresh_token_init"`: a `boolean()` set to
  true if a refresh token is to be issued in the authorization code flow when presenting the
  authorization code
  - `"__asteroid_oauth2_flow_authorization_code_issue_refresh_token_refresh"`: a `boolean()` set
  to true if a refresh token is to be issued when refreshing tokens in the authorization code flow
  - `"__asteroid_oauth2_flow_authorization_code_access_token_lifetime"`: a `non_neg_integer()`
  set to the lifetime duration of an access token in the authorization code flow
  - `"__asteroid_oauth2_flow_authorization_code_access_token_serialization_format"`: the
  `t:Asteroid.Token.serialization_format_str/0` serialization format for the authorization code
  flow
  - `"__asteroid_oauth2_flow_authorization_code_access_token_signing_key"`: the
  `t:Asteroid.Crypto.Key.name/0` signing key name for access tokens in the authorization code flow
  - `"__asteroid_oauth2_flow_authorization_code_access_token_signing_alg"`: the
  `t:Asteroid.Crypto.Key.alg/0` signing algorithm for access tokens in the authorization code flow
  - `"__asteroid_oauth2_flow_authorization_code_refresh_token_lifetime"`: a `non_neg_integer()`
  set to the lifetime duration of a refresh token in the authorization code flow
  - `"__asteroid_oauth2_flow_implicit_access_token_lifetime"`: a `non_neg_integer()`
  set to the lifetime duration of an access token in the implicit flow
  - `"__asteroid_oauth2_flow_implicit_access_token_serialization_format"`: the
  `t:Asteroid.Token.serialization_format_str/0` serialization format for the implicit flow
  - `"__asteroid_oauth2_flow_implicit_access_token_signing_alg"`: the
  `t:Asteroid.Crypto.Key.alg/0` signing algorithm for access tokens in the implicit flow
  - `"__asteroid_endpoint_introspect_claims_resp"`: the list of `String.t()` claims to be
  returned from the `"/introspect"` endpoint
  - `"__asteroid_oauth2_flow_authorization_code_mandatory_pkce_use"`: a `boolean()` indicating
  whether the client shall use PKCE or not (defaults to not being forced to use PKCE)
  - `"__asteroid_oauth2_endpoint_register_allowed_token_endpoint_auth_method"`: a list of
  `t:Asteroid.OAuth2.Endpoint.auth_method_str/0` that restricts the token endpoint auth methods
  that can be assigned to a new client created by this client. If absent or set to `nil`, all
  supported methods
  (#{Asteroid.Config.link_to_option(:oauth2_endpoint_token_auth_methods_supported_callback)})
  can be assigned to new clients
  - `"__asteroid_oauth2_endpoint_register_allowed_grant_types"`: a list of
  `t:Asteroid.OAuth2.grant_type_str/0` of grant types that can be assigned on newly created
  clients on the client registration endpoint. This is opt-in: when not set to a client,
  it will not be capable of creating new clients
  - `"__asteroid_oauth2_endpoint_register_allowed_response_types"`: a list of
  `t:Asteroid.OAuth2.response_type_str/0` of response types that can be assigned to newly created
  clients on the client registration endpoint. This is opt-in: when not set to a client,
  it will not be capable of creating new clients
  - `"__asteroid_oauth2_endpoint_register_allowed_scopes"`: a list of scopes that can be
  assigned to newly created clients on the client registration endpoint. If not set, defaults
  to the available scopes for the granted flows (determined from the grant types)
  - `"__asteroid_oauth2_endpoint_register_auto_scopes"`: a list of scopes that are automatically
  assigned to newly created clients, in addition to those requested. The existence of these
  automatically granted scopes are *not checked* against the configured scopes, which means
  that scopes that are not configured in the configuration files can be granted through this
  option
  - `"__asteroid_oauth2_endpoint_register_additional_metadata_fields"`: a list of strings
  for the additional metadata fields that will be saved upon client creation request
  - `"__asteroid_oauth2_endpoint_register_default_token_endpoint_auth_method"`: a
  `t:Asteroid.OAuth2.Endpoint.auth_method_str/0` that replaces the specification's default
  (`"client_secret_basic"`) for new clients created by this client
  - `"__asteroid_oauth2_endpoint_register_default_grant_types"`: a list of
  `t:Asteroid.OAuth2.grant_type_str/0` that replaces the specification's default
  (`["authorization_code"]`) for new clients created by this client
  - `"__asteroid_oauth2_endpoint_register_default_response_types"`: a list of
  `t:Asteroid.OAuth2.response_type_str/0` that replaces the specification's default
  (`["code"]`) for new clients created by this client
  - `"__asteroid_oauth2_flow_device_authorization_device_code_lifetime"`: a `non_neg_integer()`
  set to the lifetime duration of a device code in the device authorization flow
  - `"__asteroid_oauth2_flow_device_authorization_issue_refresh_token_init"`: a `boolean()` set
  to true if a refresh token is to be issued at the first request of the device authorization
  flow
  - `"__asteroid_oauth2_flow_device_authorization_issue_refresh_token_refresh"`: a `boolean()`
  set to true if a refresh token is to be issued when refresh tokens in the device authorization
  flow
  - `"__asteroid_oauth2_flow_device_authorization_refresh_token_lifetime"`: a `non_neg_integer()`
  set to the lifetime duration of a refresh token in the device authorization flow
  - `"__asteroid_oauth2_flow_device_authorization_access_token_lifetime"`: a `non_neg_integer()`
  set to the lifetime duration of an access token in the device authorization flow
  - `"__asteroid_oauth2_flow_device_authorization_access_token_serialization_format"`: the
  `t:Asteroid.Token.serialization_format_str/0` serialization format for the device authorization
  flow
  - `"__asteroid_oauth2_flow_device_authorization_access_token_signing_key"`: the
  `t:Asteroid.Crypto.Key.name/0` signing key name for access tokens in the device authorization
  flow
  - `"__asteroid_oauth2_flow_device_authorization_access_token_signing_alg"`: the
  `t:Asteroid.Crypto.Key.alg/0` signing algorithm for access tokens in the device authorization
  flow

  ## Configuration

  This modules uses the default configuration of `AttributeRepository.Resource` (see `config/1`).

  ## Security considerations

  - When using client secrets, make sure to 1) generate their secrets randomly and 2) store them
  in an appropriate manner. See the [expwd](https://github.com/tanguilp/expwd) library.
  - You **SHOULD NOT** issue client secrets to public clients
  [RFC6749 - 10.1.  Client Authentication](https://tools.ietf.org/html/rfc6749#section-10.1)
  """

  @doc """
  Returns the JWKs of a client

  Note that the `"jwks_uri"` field takes precedence over the `"jwks"` field. If `"jwks"` is
  somehow unreachable, it does **not** fallback to the `"jwks"` field.
  """

  @spec get_jwks(t()) :: [Asteroid.Crypto.Key.t()]

  def get_jwks(client) do
    client = fetch_attributes(client, ["jwks", "jwks_uri"])

    if client.attrs["jwks_uri"] do
      []
    else
      client.attrs["jwks"]["keys"] || []
    end
  end
end
