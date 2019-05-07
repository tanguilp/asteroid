use Mix.Config

# For development, we disable any cache and enable
# debugging and code reloading.
#
# The watchers configuration can be used to run external
# watchers to your application. For example, we use it
# with webpack to recompile .js and .css sources.
config :asteroid, AsteroidWeb.Endpoint,
  http: [port: 4000],
  debug_errors: true,
  code_reloader: true,
  check_origin: false,
  watchers: [
    node: [
      "node_modules/webpack/bin/webpack.js",
      "--mode",
      "development",
      "--watch-stdin",
      cd: Path.expand("../assets", __DIR__)
    ]
  ]

# ## SSL Support
#
# In order to use HTTPS in development, a self-signed
# certificate can be generated by running the following
# Mix task:
#
#     mix phx.gen.cert
#
# Note that this task requires Erlang/OTP 20 or later.
# Run `mix help phx.gen.cert` for more information.
#
# The `http:` config above can be replaced with:
#
#     https: [
#       port: 4001,
#       cipher_suite: :strong,
#       keyfile: "priv/cert/selfsigned_key.pem",
#       certfile: "priv/cert/selfsigned.pem"
#     ],
#
# If desired, both `http:` and `https:` keys can be
# configured to run both http and https servers on
# different ports.

# Watch static and templates for browser reloading.
config :asteroid, AsteroidWeb.Endpoint,
  live_reload: [
    patterns: [
      ~r{priv/static/.*(js|css|png|jpeg|jpg|gif|svg)$},
      ~r{priv/gettext/.*(po)$},
      ~r{lib/asteroid_web/views/.*(ex)$},
      ~r{lib/asteroid_web/templates/.*(eex)$}
    ]
  ]

# Do not include metadata nor timestamps in development logs
config :logger, :console, format: "[$level] $message\n"

# Set a higher stacktrace during development. Avoid configuring such
# in production as building large stacktraces may be expensive.
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime

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

config :asteroid, :token_store_access_token, [
  #module: Asteroid.TokenStore.AccessToken.Riak,
  #opts: [bucket_type: "ephemeral_token"]
  module: Asteroid.TokenStore.AccessToken.Mnesia
]

config :asteroid, :token_store_refresh_token, [
  #module: Asteroid.TokenStore.RefreshToken.Mnesia
  module: Asteroid.TokenStore.RefreshToken.Riak,
  opts: [bucket_type: "token"]
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
  subject: [
    module: AttributeRepositoryLdap,
    init_opts: [
      name: :slapd,
      max_overflow: 10,
      ldap_args: [hosts: ['localhost'], base: 'ou=people,dc=example,dc=org']
    ],
    run_opts: [instance: :slapd, base_dn: 'ou=people,dc=example,dc=org'],
    auto_install: false, # AttributeRepositoryLdap has no install callback implemented
    default_loaded_attributes: ["cn", "displayName", "givenName", "mail", "manager", "sn"]
  ],
  client: [
    module: AttributeRepositoryMnesia,
    init_opts: [mnesia_config: [disc_copies: [node()]]],
    run_opts: [instance: :client]
  ],
  device: [
    module: AttributeRepositoryRiak,
    run_opts: [instance: :device, bucket_type: "device"],
    auto_start: false
  ]
]

config :pooler,
  pools: [
    [
      name: :riak,
      group: :riak,
      max_count: 10,
      init_count: 5,
      start_mfa: {Riak.Connection, :start_link, ['127.0.0.1', 8087]}
    ]
  ]

config :asteroid, :plugs_oauth2_endpoint_token,
  [
    #{APIacFilterIPWhitelist, [whitelist: ["127.0.0.1/32"], error_response_verbosity: :debug]},
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
      error_response_verbosity: :debug},
    {APIacFilterThrottler,
      key: &APIacFilterThrottler.Functions.throttle_by_ip_path/1,
      scale: 60_000,
      limit: 50,
      exec_cond: &Asteroid.Config.DefaultCallbacks.conn_not_authenticated?/1,
      error_response_verbosity: :debug}
  ]

config :asteroid, :plugs_oauth2_endpoint_introspect,
  [
    {APIacAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
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
