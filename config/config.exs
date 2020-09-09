# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
use Mix.Config

config :asteroid,
  ecto_repos: [Asteroid.Repo]

# Configures the endpoint
config :asteroid, AsteroidWeb.Endpoint,
  url: [host: "localhost"],
  secret_key_base: "2yJLxSza2m36oPseYvVwOZuGszU72qhncOIWgu83PtIGpYXDpILdc2tkHmEiEVYz",
  render_errors: [view: AsteroidWeb.ErrorView, accepts: ~w(html json)],
  pubsub_server: Asteroid.PubSub

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{Mix.env()}.exs"
