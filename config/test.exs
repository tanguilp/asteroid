use Mix.Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :asteroid, AsteroidWeb.Endpoint,
  http: [port: 4002],
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
   dir: 'Mnesia.#{node()}-#{Mix.env}'

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

config :asteroid, :token_store_access_token, [
  module: Asteroid.TokenStore.AccessToken.Mnesia,
  opts: [tab_def: [disc_copies: []]]
]

config :asteroid, :token_store_refresh_token, [
  module: Asteroid.TokenStore.RefreshToken.Mnesia,
  opts: [tab_def: [disc_copies: []]]
]

config :asteroid, :token_store_authorization_code, [
  module: Asteroid.TokenStore.AuthorizationCode.Mnesia
]

config :asteroid, :attribute_repositories,
[
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
]

config :asteroid, :api_oauth2_plugs,
  [
    {APIacFilterIPWhitelist, [whitelist: ["127.0.0.1/32"], error_response_verbosity: :debug]}
  ]

config :asteroid, :api_oauth2_endpoint_token_plugs,
  [
    {APIacAuthBasic,
      realm: "always erroneous client password",
      callback: &Asteroid.Config.DefaultCallbacks.always_nil/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APIacAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APIacAuthBearer,
      realm: "Asteroid",
      bearer_validator:
        {
          APIacAuthBearer.Validator.Identity,
          [response: {:error, :invalid_token}]
        },
      set_error_response: &APIacAuthBearer.save_authentication_failure_response/3,
error_response_verbosity: :debug}
  ]

config :asteroid, :api_oauth2_endpoint_introspect_plugs,
  [
    {APIacAuthBasic,
      realm: "always erroneous client password",
      callback: &Asteroid.Config.DefaultCallbacks.always_nil/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APIacAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APIacAuthBearer,
      realm: "Asteroid",
      bearer_validator:
        {
          APIacAuthBearer.Validator.Identity,
          [response: {:error, :invalid_token}]
        },
      set_error_response: &APIacAuthBearer.save_authentication_failure_response/3,
error_response_verbosity: :debug}
  ]

config :asteroid, :api_oauth2_endpoint_revoke_plugs,
  [
    {APIacAuthBasic,
      realm: "always erroneous client password",
      callback: &Asteroid.Config.DefaultCallbacks.always_nil/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APIacAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APIacAuthBearer,
      realm: "Asteroid",
      bearer_validator:
        {
          APIacAuthBearer.Validator.Identity,
          [response: {:error, :invalid_token}]
        },
      set_error_response: &APIacAuthBearer.save_authentication_failure_response/3,
error_response_verbosity: :debug}
  ]

config :asteroid, :api_oauth2_endpoint_register_plugs,
  [
    {APIacAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
  ]

config :asteroid, :oauth2_grant_types_enabled, [
  :authorization_code, :implicit, :password, :client_credentials, :refresh_token
]

config :asteroid, :oauth2_response_types_enabled, [:code, :token]

config :asteroid, :api_error_response_verbosity, :debug

config :asteroid, :oauth2_ropc_username_password_verify_callback,
  &Asteroid.Config.DefaultCallbacks.test_ropc_username_password_callback/3

config :asteroid, :oauth2_flow_ropc_scope_config,
  %{
  }

config :asteroid, :oauth2_scope_callback,
  &Asteroid.OAuth2.Scope.grant_for_flow/2

config :asteroid, :oauth2_endpoint_token_grant_type_password_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_token_grant_type_password_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_token_grant_type_refresh_token_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_token_grant_type_refresh_token_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

# Endpoint: introspect

config :asteroid, :oauth2_endpoint_introspect_client_authorized,
  &Asteroid.OAuth2.Client.endpoint_introspect_authorized?/1

config :asteroid, :oauth2_endpoint_introspect_claims_resp,
  ["scope", "client_id", "username", "token_type", "exp", "iat", "nbf", "sub", "aud", "iss", "jti"]

config :asteroid, :oauth2_endpoint_introspect_claims_resp_callback,
  &Asteroid.OAuth2.Callback.endpoint_introspect_claims_resp/1

config :asteroid, :oauth2_endpoint_introspect_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_introspect_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

# Endpoint: revoke

config :asteroid, :oauth2_endpoint_revoke_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

# Flow: client credentials

config :asteroid, :oauth2_flow_client_credentials_scope_config,
  %{
  }

config :asteroid, :oauth2_flow_client_credentials_issue_refresh_token_init, false

config :asteroid, :oauth2_flow_client_credentials_issue_refresh_token_refresh, false

config :asteroid, :oauth2_flow_client_credentials_access_token_lifetime, 60 * 10

config :asteroid, :oauth2_endpoint_token_grant_type_client_credentials_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_token_grant_type_client_credentials_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

# Refresh tokens

config :asteroid, :token_store_refresh_token_before_store_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_issue_refresh_token_callback,
  &Asteroid.Token.RefreshToken.issue_refresh_token?/1

config :asteroid, :oauth2_flow_ropc_issue_refresh_token_init, true

config :asteroid, :oauth2_flow_ropc_issue_refresh_token_refresh, false

config :asteroid, :oauth2_refresh_token_lifetime_callback,
  &Asteroid.Token.RefreshToken.lifetime/1

config :asteroid, :oauth2_flow_ropc_refresh_token_lifetime, 60 * 60 * 24 * 7 # 1 week

# access tokens

config :asteroid, :token_store_access_token_before_store_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_access_token_lifetime_callback,
  &Asteroid.Token.AccessToken.lifetime/1

config :asteroid, :oauth2_flow_ropc_access_token_lifetime, 60 * 10

config :asteroid, :client_credentials_issue_refresh_token, false

config :asteroid, :client_credentials_scope_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

# authorization codes

config :asteroid, :token_store_authorization_code_before_store_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_authorization_code_lifetime_callback,
  &Asteroid.Token.AuthorizationCode.lifetime/1

config :asteroid, :oauth2_flow_authorization_code_authorization_code_lifetime, 60

config :asteroid, :oauth2_endpoint_authorize_response_type_code_before_send_redirect_uri_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_authorize_response_type_code_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_flow_authorization_code_issue_refresh_token_init, true

config :asteroid, :oauth2_flow_authorization_code_issue_refresh_token_refresh, false

config :asteroid, :oauth2_flow_authorization_code_refresh_token_lifetime,
  60 * 60 * 24 * 7 # 1 week

config :asteroid, :oauth2_flow_authorization_code_access_token_lifetime, 60 * 10

config :asteroid, :oauth2_endpoint_token_grant_type_authorization_code_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_token_grant_type_authorization_code_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_flow_authorization_code_pkce_policy, :optional

config :asteroid, :oauth2_flow_authorization_code_pkce_allowed_methods, [:plain, :S256]

config :asteroid, :oauth2_flow_authorization_code_pkce_client_callback,
  &Asteroid.OAuth2.Client.must_use_pkce?/1

# implicit flow

config :asteroid, :oauth2_flow_implicit_access_token_lifetime, 60 * 60

config :asteroid, :oauth2_endpoint_authorize_response_type_token_before_send_redirect_uri_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_authorize_response_type_token_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2
  #
# client registration

config :asteroid, :oauth2_endpoint_register_authorization_callback,
  &Asteroid.OAuth2.Register.request_authorized?/2

config :asteroid, :oauth2_endpoint_register_authorization_policy, :authorized_clients

config :asteroid, :oauth2_endpoint_register_additional_metadata_field, ["test_field"]

config :asteroid, :oauth2_endpoint_register_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_register_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_register_client_before_save_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :oauth2_endpoint_register_gen_client_id_callback,
  &Asteroid.OAuth2.Register.generate_client_id/1

# endpoint token

config :asteroid, :oauth2_endpoint_token_auth_methods_supported_callback,
  &Asteroid.OAuth2.Endpoint.token_endpoint_auth_methods_supported/0
