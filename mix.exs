defmodule Asteroid.MixProject do
  use Mix.Project

  def project do
    [
      app: :asteroid,
      version: "0.1.0",
      elixir: "~> 1.5",
      elixirc_paths: elixirc_paths(Mix.env()),
      compilers: [:phoenix, :gettext] ++ Mix.compilers(),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(Mix.env()),
      docs: docs(),
      dialyzer: [plt_add_apps: [:mix]]
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      mod: {Asteroid.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:dev), do: ["lib", "custom"]
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(:prod), do: ["lib", "custom"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps(_) do
    [
      {:apiac, github: "tanguilp/apiac", tag: "0.3.0"},
      {:apiac_auth_basic, github: "tanguilp/apiac_auth_basic"},
      {:apiac_auth_bearer, github: "tanguilp/apiac_auth_bearer"},
      {:apiac_auth_client_secret_post, github: "tanguilp/apiac_auth_client_secret_post"},
      #{:apiac_auth_mtls, github: "tanguilp/apiac_auth_mtls"},
      {:apiac_filter_ip_blacklist, github: "tanguilp/apiac_filter_ip_blacklist"},
      {:apiac_filter_ip_whitelist, github: "tanguilp/apiac_filter_ip_whitelist"},
      {:apiac_filter_throttler, github: "tanguilp/apiac_filter_throttler"},
      {:oauth2_utils, github: "tanguilp/oauth2_utils", override: true},
      {:attribute_repository, github: "tanguilp/attribute_repository", override: true},
      # {:attribute_repository_ldap, github: "tanguilp/attribute_repository_ldap"},
      {:attribute_repository_mnesia, github: "tanguilp/attribute_repository_mnesia"},
      # {:attribute_repository_riak, github: "tanguilp/attribute_repository_riak"},
      {:corsica, "~> 1.0"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:gettext, "~> 0.11"},
      {:hammer, "~> 6.0"},
      {:httpoison, "~> 1.0", override: true},
      {:jason, "~> 1.0"},
      {:jose, "~> 1.9"},
      {:phoenix, "~> 1.4.0"},
      {:phoenix_html, "~> 2.11"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:plug_cowboy, "~> 2.0"},
      {:riak, github: "tanguilp/riak-elixir-client"},
      {:singleton, "~> 1.2.0"},
      {:wax, github: "tanguilp/wax", tag: "0.1.2"}
    ]
  end

  # Aliases are shortcuts or tasks specific to the current project.
  # For example, to create, migrate and run the seeds file at once:
  #
  #     $ mix ecto.setup
  #
  # See the documentation for `Mix` for more info on aliases.
  defp aliases do
    [
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      #test: ["ecto.create --quiet", "ecto.migrate", "test"]
    ]
  end

  defp docs() do
    [
      main: "getting-started",
      groups_for_modules: [
        "Resources": [Asteroid.Client, Asteroid.Subject, Asteroid.Device],
        "Tokens": [
          Asteroid.Token,
          Asteroid.Token.AccessToken,
          Asteroid.Token.RefreshToken,
          Asteroid.Token.AuthorizationCode],
        "Token stores": [
          Asteroid.TokenStore,
          Asteroid.TokenStore.AccessToken,
          Asteroid.TokenStore.AccessToken.Mnesia,
          Asteroid.TokenStore.AccessToken.Riak,
          Asteroid.TokenStore.RefreshToken,
          Asteroid.TokenStore.RefreshToken.Mnesia,
          Asteroid.TokenStore.RefreshToken.Riak
        ]
      ],
      extras: [
        "guides/getting-started.md",
        "guides/general-architecture.md",
        "guides/general-configuration.md",
        "guides/attribute-repositories.md",
        "guides/token-stores.md",
        "guides/protecting-apis.md",
        "guides/configuring-resources.md",
        "guides/crypto-keys.md",
        "guides/network-configuration.md",
        "guides/configuring-riak.md",
        "guides/customizing.md",
        "guides/running-demo-app.md",
        "guides/oauth2/terminology-conventions.md",
        "guides/oauth2/basic-configuration.md",
        "guides/oauth2/managing-scopes.md",
        "guides/oauth2/oauth2-core.md",
        "guides/oauth2/token-introspection.md",
        "guides/oauth2/token-revocation.md",
        "guides/oauth2/jwt-access-tokens.md",
        "guides/oauth2/pkce.md",
        "guides/oauth2/dynamic-client-registration.md",
        "guides/oauth2/device-flow.md",
        "guides/oauth2/server-metadata.md"
      ],
      groups_for_extras:
      [
        "OAuth2": [
          "guides/oauth2/terminology-conventions.md",
          "guides/oauth2/basic-configuration.md",
          "guides/oauth2/managing-scopes.md",
          "guides/oauth2/oauth2-core.md",
          "guides/oauth2/token-introspection.md",
          "guides/oauth2/token-revocation.md",
          "guides/oauth2/jwt-access-tokens.md",
          "guides/oauth2/pkce.md",
          "guides/oauth2/dynamic-client-registration.md",
          "guides/oauth2/device-flow.md",
          "guides/oauth2/server-metadata.md"
        ]
      ]
    ]
  end
end
