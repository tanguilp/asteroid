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

config :asteroid, :store_access_token, [
  impl: Asteroid.AccessToken.Store.Mnesia,
  autostart: true,
  autostart: true,
  install_config: [
    disc_copies: [node()]
  ],
  run_config: [
    cleaning_interval: 60
  ]
]

config :asteroid, :store_refresh_token, [
  impl: Asteroid.RefreshToken.Store.Mnesia,
  autostart: true,
  autostart: true,
  install_config: [
    disc_copies: [node()]
  ],
  run_config: [
    cleaning_interval: 60 * 10
  ]
]


config :asteroid, :attribute_repositories,
[
  client: [
    impl: Asteroid.AttributeRepository.Impl.Mnesia,
    autoinstall: true,
    autostart: true,
    attribute_autoload: ["client_id", "client_type", "scope"],
    opts:
    [
      table: :client,
      mnesia_create_table:
      [
        disc_copies: [node()]
      ]
    ]
  ],
  subject: [
    impl: Asteroid.AttributeRepository.Impl.Mnesia,
    autoinstall: true,
    autostart: true,
    history: true,
    attribute_autoload: ["sub", "given_name", "family_name", "gender"],
    history: true,
    opts:
    [
      table: :subject,
      mnesia_create_table:
      [
        disc_copies: [node()]
      ]
    ]
  ]
]

config :asteroid, :plugs_oauth2_endpoint_token,
  [
    #{APISexFilterIPWhitelist, [whitelist: ["127.0.0.1/32"], error_response_verbosity: :debug]},
    {APISexAuthBasic,
      realm: "always erroneous client password",
      callback: &Asteroid.Config.DefaultCallbacks.always_nil/2,
      set_error_response: &APISexAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APISexAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APISexAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APISexAuthBearer,
      realm: "Asteroid",
      bearer_validator:
        {
          APISexAuthBearer.Validator.Identity,
          [response: {:error, :invalid_token}]
        },
      set_error_response: &APISexAuthBearer.save_authentication_failure_response/3,
      error_response_verbosity: :debug}
  ]

config :asteroid, :plugs_oauth2_endpoint_introspect,
  [
    {APISexAuthBasic,
      realm: "always erroneous client password",
      callback: &Asteroid.Config.DefaultCallbacks.always_nil/2,
      set_error_response: &APISexAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APISexAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APISexAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug},
    {APISexAuthBearer,
      realm: "Asteroid",
      bearer_validator:
        {
          APISexAuthBearer.Validator.Identity,
          [response: {:error, :invalid_token}]
        },
      set_error_response: &APISexAuthBearer.save_authentication_failure_response/3,
      error_response_verbosity: :debug}
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

config :asteroid, :ropc_issue_new_refresh_token, false

config :asteroid, :client_credentials_issue_refresh_token, false

config :asteroid, :client_credentials_scope_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2
