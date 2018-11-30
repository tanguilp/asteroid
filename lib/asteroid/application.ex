defmodule Asteroid.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  alias Asteroid.AttributeRepository, as: AttrRep
  alias Asteroid.Token

  def start(_type, _args) do
    # List all child processes to be supervised
    children = [
      # Start the Ecto repository
      #Asteroid.Repo,
      # Start the endpoint when the application starts
      AsteroidWeb.Endpoint
      # Starts a worker by calling: Asteroid.Worker.start_link(arg)
      # {Asteroid.Worker, arg},
    ]

    AttrRep.auto_install_from_config()
    AttrRep.auto_start_from_config()

    Token.auto_install_from_config()
    Token.auto_start_from_config()

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Asteroid.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  def config_change(changed, _new, removed) do
    AsteroidWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
