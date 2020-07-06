use Mix.Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :asteroid, AsteroidWeb.Endpoint,
  http: [port: 4000],
  server: false

# Print only warnings and errors during test
config :logger, level: :warn

# Configure your database
config :asteroid, Asteroid.Repo,
  username: "postgres",
  password: "postgres",
  database: "asteroid_test",
  hostname: "localhost",
  pool: Ecto.Adapters.SQL.Sandbox

config :mnesia,
  dir: 'Mnesia.#{node()}-#{Mix.env()}'

config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 4, cleanup_interval_ms: 60_000 * 10]}

# Configure your database
config :asteroid, Asteroid.Repo,
  username: "postgres",
  password: "postgres",
  database: "asteroid_dev",
  hostname: "localhost",
  pool_size: 10

######################################################################
######################################################################
################## Asteroid configuration ############################
######################################################################
######################################################################

config :asteroid, :object_store_access_token,
  module: Asteroid.ObjectStore.AccessToken.Mnesia,
  opts: [tab_def: [disc_copies: []]]

config :asteroid, :object_store_refresh_token,
  module: Asteroid.ObjectStore.RefreshToken.Mnesia,
  opts: [tab_def: [disc_copies: []]]

config :asteroid, :object_store_authorization_code,
  module: Asteroid.ObjectStore.AuthorizationCode.Mnesia

config :asteroid, :object_store_device_code, module: Asteroid.ObjectStore.DeviceCode.Mnesia

config :asteroid, :object_store_request_object,
  module: Asteroid.ObjectStore.GenericKV.Mnesia,
  opts: [table_name: :request_object]

config :asteroid, :attribute_repositories,
  subject: [
    module: AttributeRepositoryMnesia,
    run_opts: [instance: :subject],
    init_opts: [instance: :subject]
  ],
  client: [
    module: AttributeRepositoryMnesia,
    run_opts: [instance: :client],
    init_opts: [instance: :client]
  ],
  device: [
    module: AttributeRepositoryMnesia,
    run_opts: [instance: :device],
    init_opts: [instance: :device]
  ]

config :asteroid, :api_oauth2_endpoint_token_plugs, [
  {Corsica, [origins: "*"]},
  {APIacAuthBasic,
   realm: "always erroneous client password",
   callback: &Asteroid.Utils.always_nil/2,
   set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
   error_response_verbosity: :debug},
  {APIacAuthBasic,
   realm: "Asteroid",
   callback: &Asteroid.OAuth2.Client.get_client_secret/2,
   set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
   error_response_verbosity: :debug},
  {APIacAuthBearer,
   realm: "Asteroid",
   bearer_validator: {
     APIacAuthBearer.Validator.Identity,
     [response: {:error, :invalid_token}]
   },
   set_error_response: &APIacAuthBearer.save_authentication_failure_response/3,
   error_response_verbosity: :debug},
  {APIacAuthClientJWT,
  client_callback: &Asteroid.OIDC.AuthClientJWT.client_callback/1,
  jti_register: JTIRegister.ETS,
  server_metadata_callback: &Asteroid.OIDC.AuthClientJWT.server_metadata_callback/0,
  set_error_response: &APIacAuthClientJWT.save_authentication_failure_response/3
  }
]

config :asteroid, :api_oauth2_endpoint_introspect_plugs, [
  {APIacAuthBasic,
   realm: "always erroneous client password",
   callback: &Asteroid.Utils.always_nil/2,
   set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
   error_response_verbosity: :debug},
  {APIacAuthBasic,
   realm: "Asteroid",
   callback: &Asteroid.OAuth2.Client.get_client_secret/2,
   set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
   error_response_verbosity: :debug},
  {APIacAuthBearer,
   realm: "Asteroid",
   bearer_validator: {Asteroid.OAuth2.APIacAuthBearer.Validator, []},
   set_error_response: &APIacAuthBearer.save_authentication_failure_response/3,
   error_response_verbosity: :debug,
   required_scopes: ["asteroid.introspect"],
   forward_metadata: ["scope"]}
]

config :asteroid, :api_oauth2_endpoint_revoke_plugs, [
  {Corsica, [origins: "*"]},
  {APIacAuthBasic,
   realm: "always erroneous client password",
   callback: &Asteroid.Utils.always_nil/2,
   set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
   error_response_verbosity: :debug},
  {APIacAuthBasic,
   realm: "Asteroid",
   callback: &Asteroid.OAuth2.Client.get_client_secret/2,
   set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
   error_response_verbosity: :debug},
  {APIacAuthBearer,
   realm: "Asteroid",
   bearer_validator: {
     APIacAuthBearer.Validator.Identity,
     [response: {:error, :invalid_token}]
   },
   set_error_response: &APIacAuthBearer.save_authentication_failure_response/3,
   error_response_verbosity: :debug}
]

config :asteroid, :api_oauth2_endpoint_register_plugs, [
  {APIacAuthBasic,
   realm: "Asteroid",
   callback: &Asteroid.OAuth2.Client.get_client_secret/2,
   set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
   error_response_verbosity: :debug},
  {APIacAuthBearer,
   realm: "Asteroid",
   bearer_validator: {Asteroid.OAuth2.APIacAuthBearer.Validator, []},
   set_error_response: &APIacAuthBearer.save_authentication_failure_response/3,
   error_response_verbosity: :debug,
   required_scopes: ["asteroid.register"],
   forward_metadata: ["scope"]}
]

config :asteroid, :api_oauth2_endpoint_device_authorization_plugs, [
  {APIacAuthBasic,
   realm: "Asteroid",
   callback: &Asteroid.OAuth2.Client.get_client_secret/2,
   set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
   error_response_verbosity: :debug}
]

config :asteroid, :oauth2_grant_types_enabled, [
  :authorization_code,
  :implicit,
  :password,
  :client_credentials,
  :refresh_token,
  :"urn:ietf:params:oauth:grant-type:device_code"
]

config :asteroid, :api_oidc_plugs, []

config :asteroid, :api_oidc_endpoint_userinfo_plugs, [
  {Corsica, [origins: "*"]},
  {APIacAuthBearer,
   realm: "Asteroid",
   bearer_validator: {Asteroid.OAuth2.APIacAuthBearer.Validator, []},
   bearer_extract_methods: [:header, :body],
   forward_bearer: true,
   error_response_verbosity: :normal}
]

config :asteroid, :oauth2_response_types_enabled, [
  :code,
  :token,
  :id_token,
  :"id_token token",
  :"code id_token",
  :"code token",
  :"code id_token token"
]

config :asteroid, :oauth2_response_mode_policy, :oidc_only

config :asteroid, :api_error_response_verbosity, :debug

config :asteroid,
       :oauth2_flow_ropc_username_password_verify_callback,
       &Asteroid.Test.Callbacks.test_ropc_username_password_callback/3

config :asteroid, :oauth2_scope_callback, &Asteroid.OAuth2.Scope.grant_for_flow/2

config :asteroid,
       :oauth2_endpoint_token_grant_type_password_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_token_grant_type_password_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_token_grant_type_refresh_token_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_token_grant_type_refresh_token_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

# Endpoint: introspect

config :asteroid,
       :oauth2_endpoint_introspect_client_authorized,
       &Asteroid.OAuth2.Client.endpoint_introspect_authorized?/1

config :asteroid, :oauth2_endpoint_introspect_claims_resp, [
  "scope",
  "client_id",
  "username",
  "token_type",
  "exp",
  "iat",
  "nbf",
  "sub",
  "aud",
  "iss",
  "jti"
]

config :asteroid,
       :oauth2_endpoint_introspect_claims_resp_callback,
       &Asteroid.OAuth2.Introspect.endpoint_introspect_claims_resp/1

config :asteroid,
       :oauth2_endpoint_introspect_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_introspect_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

# Endpoint: revoke

config :asteroid,
       :oauth2_endpoint_revoke_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

# Flow: client credentials

config :asteroid, :oauth2_flow_client_credentials_issue_refresh_token_init, false

config :asteroid, :oauth2_flow_client_credentials_issue_refresh_token_refresh, false

config :asteroid, :oauth2_flow_client_credentials_access_token_lifetime, 60 * 10

config :asteroid,
       :oauth2_endpoint_token_grant_type_client_credentials_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_token_grant_type_client_credentials_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

# Refresh tokens

config :asteroid,
       :object_store_refresh_token_before_store_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_issue_refresh_token_callback,
       &Asteroid.Token.RefreshToken.issue_refresh_token?/1

config :asteroid, :oauth2_flow_ropc_issue_refresh_token_init, true

config :asteroid, :oauth2_flow_ropc_issue_refresh_token_refresh, false

config :asteroid, :oauth2_refresh_token_lifetime_callback, &Asteroid.Token.RefreshToken.lifetime/1

# 1 week
config :asteroid, :oauth2_flow_ropc_refresh_token_lifetime, 60 * 60 * 24 * 7

# access tokens

config :asteroid,
       :object_store_access_token_before_store_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid, :oauth2_access_token_lifetime_callback, &Asteroid.Token.AccessToken.lifetime/1

config :asteroid, :oauth2_flow_ropc_access_token_lifetime, 60 * 10

config :asteroid, :client_credentials_issue_refresh_token, false

config :asteroid, :client_credentials_scope_callback, &Asteroid.Utils.id_first_param/2

# authorization codes

config :asteroid,
       :object_store_authorization_code_before_store_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_authorization_code_lifetime_callback,
       &Asteroid.Token.AuthorizationCode.lifetime/1

config :asteroid, :oauth2_flow_authorization_code_authorization_code_lifetime, 60

config :asteroid,
       :oauth2_endpoint_authorize_before_send_redirect_uri_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_authorize_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid, :oauth2_flow_authorization_code_issue_refresh_token_init, true

config :asteroid, :oauth2_flow_authorization_code_issue_refresh_token_refresh, false

config :asteroid,
       :oauth2_flow_authorization_code_refresh_token_lifetime,
       # 1 week
       60 * 60 * 24 * 7

config :asteroid, :oauth2_flow_authorization_code_access_token_lifetime, 60 * 10

config :asteroid,
       :oauth2_endpoint_token_grant_type_authorization_code_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_token_grant_type_authorization_code_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid, :oauth2_pkce_policy, :optional

config :asteroid, :oauth2_pkce_allowed_methods, [:plain, :S256]

config :asteroid, :oauth2_pkce_must_use_callback, &Asteroid.OAuth2.Client.must_use_pkce?/1

# implicit flow

config :asteroid, :oauth2_flow_implicit_access_token_lifetime, 60 * 60

# client registration

config :asteroid,
       :oauth2_endpoint_register_authorization_callback,
       &Asteroid.OAuth2.Register.request_authorized?/2

config :asteroid, :oauth2_endpoint_register_authorization_policy, :authorized_clients

config :asteroid, :oauth2_endpoint_register_additional_metadata_field, ["test_field"]

config :asteroid,
       :oauth2_endpoint_register_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_register_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_register_client_before_save_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_register_gen_client_id_callback,
       &Asteroid.OAuth2.Register.generate_client_id/2

config :asteroid,
       :oauth2_endpoint_register_gen_client_resource_id_callback,
       &Asteroid.OAuth2.Register.generate_client_resource_id/2

config :asteroid,
       :oauth2_endpoint_register_client_type_callback,
       &Asteroid.OAuth2.Register.client_type/1

# endpoint token

config :asteroid,
       :oauth2_endpoint_token_auth_methods_supported_callback,
       &Asteroid.OAuth2.Endpoint.token_endpoint_auth_methods_supported/0

# scope configuration

config :asteroid, :scope_config,
  scopes: %{
    "scp1" => [],
    "scp2" => [],
    "scp3" => [],
    "scp4" => [],
    "scp5" => [],
    "scp6" => [],
    "openid" => []
  }

# OAuth2 metadata

config :asteroid, :oauth2_endpoint_metadata_before_send_resp_callback, &Asteroid.Utils.id/1

config :asteroid, :oauth2_endpoint_metadata_before_send_conn_callback, &Asteroid.Utils.id/1

# JWKs URI

config :asteroid, :oauth2_endpoint_discovery_keys_before_send_resp_callback, &Asteroid.Utils.id/1

config :asteroid, :oauth2_endpoint_discovery_keys_before_send_conn_callback, &Asteroid.Utils.id/1

# crypto

config :asteroid, :crypto_keys, %{
  "key_auto_sig" => {:auto_gen, [params: {:rsa, 1024}, use: :sig]},
  "key_auto_enc" => {:auto_gen, [params: {:rsa, 1024}, use: :enc]}
}

config :asteroid, :crypto_keys_cache, {Asteroid.Crypto.Key.Cache.ETS, []}

# JWS access tokens

config :asteroid,
       :oauth2_access_token_serialization_format_callback,
       &Asteroid.Token.AccessToken.serialization_format/1

config :asteroid,
       :oauth2_access_token_signing_key_callback,
       &Asteroid.Token.AccessToken.signing_key/1

config :asteroid,
       :oauth2_access_token_signing_alg_callback,
       &Asteroid.Token.AccessToken.signing_alg/1

config :asteroid, :oauth2_flow_ropc_access_token_serialization_format, :opaque

config :asteroid, :oauth2_flow_ropc_access_token_signing_key, "key_auto"

config :asteroid, :oauth2_flow_ropc_access_token_signing_alg, "RS384"
#
# device authorization flow

config :asteroid,
       :oauth2_endpoint_device_authorization_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_device_authorization_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :object_store_device_code_before_store_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid, :oauth2_flow_device_authorization_device_code_lifetime, 60 * 15

config :asteroid,
       :oauth2_flow_device_authorization_user_code_callback,
       &Asteroid.OAuth2.DeviceAuthorization.user_code/1

config :asteroid, :oauth2_flow_device_authorization_issue_refresh_token_init, true

config :asteroid, :oauth2_flow_device_authorization_issue_refresh_token_refresh, false

config :asteroid, :oauth2_flow_device_authorization_refresh_token_lifetime, 10 * 365 * 24 * 3600

config :asteroid, :oauth2_flow_device_authorization_access_token_lifetime, 60 * 10

config :asteroid,
       :oauth2_endpoint_token_grant_type_device_code_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_endpoint_token_grant_type_device_code_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oauth2_flow_device_authorization_rate_limiter,
       {Asteroid.OAuth2.DeviceAuthorization.RateLimiter.Hammer, []}

config :asteroid, :oauth2_flow_device_authorization_rate_limiter_interval, 5

config :asteroid, :web_authorization_callback, &Asteroid.WebFlow.web_authorization_callback/2

config :asteroid, :oidc_id_token_lifetime_callback, &Asteroid.Token.IDToken.lifetime/1

config :asteroid, :oidc_id_token_signing_key_callback, &Asteroid.Token.IDToken.signing_key/1

config :asteroid, :oidc_id_token_signing_alg_callback, &Asteroid.Token.IDToken.signing_alg/1

config :asteroid, :token_id_token_before_serialize_callback, &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oidc_issue_id_token_on_refresh_callback,
       &Asteroid.Token.IDToken.issue_id_token?/1

config :asteroid, :oidc_flow_authorization_code_authorization_code_lifetime, 60

config :asteroid,
       :oidc_endpoint_userinfo_before_send_resp_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :oidc_endpoint_userinfo_before_send_conn_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid, :oidc_id_token_encrypt_callback, &Asteroid.Token.IDToken.encrypt_token?/1

config :asteroid, :oidc_subject_identifier_callback, &Asteroid.OIDC.subject_identifier/2

config :asteroid,
       :oidc_subject_identifier_pairwise_salt,
       Base.encode64(:crypto.strong_rand_bytes(24))

config :asteroid, :object_store_authenticated_session,
  module: Asteroid.ObjectStore.AuthenticatedSession.Mnesia

config :asteroid, :object_store_authentication_event,
  module: Asteroid.ObjectStore.AuthenticationEvent.Mnesia

config :asteroid,
       :object_store_authenticated_session_before_store_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid,
       :object_store_authentication_event_before_store_callback,
       &Asteroid.Utils.id_first_param/2

config :asteroid, :oidc_acr_config,
  loa2: [
    callback: &Asteroid.Test.Callbacks.authorize_print_successful_request/2,
    auth_event_set: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
  ],
  loa1: [
    callback: &Asteroid.Test.Callbacks.authorize_print_successful_request/2,
    auth_event_set: [["password"], ["webauthn"], ["otp"]]
  ]
