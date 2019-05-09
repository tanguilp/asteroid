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

config :asteroid, :attribute_repositories,
[
  subject: [
    module: AttributeRepositoryMnesia,
    run_opts: [instance: :subject]
  ],
  client: [
    module: AttributeRepositoryMnesia,
    run_opts: [instance: :client]
  ],
  device: [
    module: AttributeRepositoryMnesia,
    run_opts: [instance: :device]
  ]
]

config :asteroid, :api_oauth2_plugs,
  [
    {APIacFilterIPWhitelist, [whitelist: ["127.0.0.1/32"], error_response_verbosity: :debug]},
    {APIacAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug}
  ]

config :asteroid, :api_oauth2_endpoint_token_plugs,
  [
    {APIacFilterThrottler,
      key: &APIacFilterThrottler.Functions.throttle_by_ip_path/1,
      scale: 60_000,
      limit: 50,
      exec_cond: &Asteroid.Config.DefaultCallbacks.conn_not_authenticated?/1,
      error_response_verbosity: :debug},
    {APIacAuthBasic,
      realm: "always erroneous client password",
      callback: &Asteroid.Config.DefaultCallbacks.always_nil/2,
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
  ]

config :asteroid, :issuer_callback, &Asteroid.Config.DefaultCallbacks.issuer/1

config :asteroid, :api_error_response_verbosity, :debug

config :asteroid, :ropc_username_password_verify_callback,
  &Asteroid.Config.DefaultCallbacks.test_ropc_username_password_callback/3

config :asteroid, :issue_refresh_token_callback,
  &Asteroid.Config.DefaultCallbacks.issue_refresh_token_callback/1

config :asteroid, :ropc_issue_refresh_token, true

config :asteroid, :ropc_scope_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :refresh_token_lifetime_callback,
  &Asteroid.Config.DefaultCallbacks.refresh_token_lifetime_callback/1

config :asteroid, :refresh_token_lifetime_ropc, 60 * 60 * 24 * 7 # 1 week

config :asteroid, :access_token_lifetime_callback,
  &Asteroid.Config.DefaultCallbacks.access_token_lifetime_callback/1

config :asteroid, :access_token_lifetime_ropc, 60 * 10

config :asteroid, :ropc_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :ropc_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :ropc_issue_new_refresh_token, false

config :asteroid, :introspect_endpoint_authorized,
  &Asteroid.Config.DefaultCallbacks.introspect_endpoint_authorized?/1

config :asteroid, :introspect_resp_claims,
  fn _ctx -> [
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
  ] end

config :asteroid, :introspect_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :introspect_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :refresh_token_before_store_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :access_token_before_store_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

#FIXME: rename those callbacks
config :asteroid, :refresh_token_before_send_resp_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :refresh_token_before_send_conn_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2

config :asteroid, :client_credentials_issue_refresh_token, false

config :asteroid, :client_credentials_scope_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2
