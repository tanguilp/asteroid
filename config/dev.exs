use Mix.Config

# For development, we disable any cache and enable
# debugging and code reloading.
#
# The watchers configuration can be used to run external
# watchers to your application. For example, we use it
# with webpack to recompile .js and .css sources.
#
config :asteroid, AsteroidWeb.Endpoint,
  http: [port: 4000],
  # url: [scheme: "https", host: "www.example.com", path: "/account/auth", port: 443],
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

config :asteroid, AsteroidWeb.EndpointMTLSAliases,
  http: [port: 8443],
  url: [scheme: "https", host: "mtls.example.com", path: "/mtls", port: 10443],
  debug_errors: true,
  check_origin: false

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

config :asteroid, :jose_virtual_hsm_keys_config,  [
  {:auto_gen, {:rsa, 2048}},
  {:auto_gen, {:ec, "P-256"}}
]

# Do not include metadata nor timestamps in development logs
config :logger, :console, format: "[$level] $message\n"

# Set a higher stacktrace during development. Avoid configuring such
# in production as building large stacktraces may be expensive.
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime

config :mnesia,
  dir: 'Mnesia.#{node()}-#{Mix.env()}'

# Hammer is used for cache in some plugs (rate-limiting) and for the OAuth2 device flow

config :hammer,
  backend: {Hammer.Backend.ETS, [expiry_ms: 60_000 * 60 * 4, cleanup_interval_ms: 60_000 * 10]}
