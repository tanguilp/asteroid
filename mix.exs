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
      docs: docs()
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
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps(_) do
    [
      {:apiac, github: "tanguilp/apiac", tag: "0.2.0"},
      {:apiac_auth_basic, github: "tanguilp/apiac_auth_basic", tag: "0.2.0"},
      {:apiac_auth_bearer, github: "tanguilp/apiac_auth_bearer", tag: "0.2.0"},
      {:apiac_auth_mtls, github: "tanguilp/apiac_auth_mtls", tag: "0.2.0"},
      {:apiac_filter_ip_blacklist, github: "tanguilp/apiac_filter_ip_blacklist", tag: "0.2.0"},
      {:apiac_filter_ip_whitelist, github: "tanguilp/apiac_filter_ip_whitelist", tag: "0.2.0"},
      {:apiac_filter_throttler, github: "tanguilp/apiac_filter_throttler", tag: "0.2.0"},
      {:oauth2_utils, github: "tanguilp/oauth2_utils", tag: "master"},
      {:attribute_repository_ldap, path: "../attribute_repository_ldap"},
      {:attribute_repository_mnesia, path: "../attribute_repository_mnesia"},
      {:attribute_repository_riak, path: "../attribute_repository_riak"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ecto_sql, "~> 3.0"},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:gettext, "~> 0.11"},
      {:jason, "~> 1.0"},
      {:phoenix, "~> 1.4.0"},
      {:phoenix_pubsub, "~> 1.1"},
      {:phoenix_ecto, "~> 4.0"},
      {:phoenix_html, "~> 2.11"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:plug_cowboy, "~> 2.0"},
      {:postgrex, ">= 0.0.0"},
      {:riak, github: "tanguilp/riak-elixir-client"},
      {:singleton, "~> 1.2.0"}
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
      test: ["test"]
    ]
  end

  defp docs() do
    [
      main: "getting-started",
      groups_for_modules: [
        "Basic resources": [Asteroid.Client, Asteroid.Subject, Asteroid.Device],
        "Tokens": [Asteroid.Token, Asteroid.Token.AccessToken, Asteroid.Token.RefreshToken],
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
        "guides/attribute-repositories.md",
        "guides/token-stores.md"
      ]
    ]
  end
end
