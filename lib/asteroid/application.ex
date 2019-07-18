defmodule Asteroid.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  alias Asteroid.AttributeRepository
  alias Asteroid.Client
  alias Asteroid.TokenStore
  alias Asteroid.Crypto

  def start(_type, _args) do
    # List all child processes to be supervised
    children = [
      # Start the Ecto repository
      #Asteroid.Repo,
      # Start the endpoint when the application starts
      AsteroidWeb.Endpoint,
      AsteroidWeb.EndpointAPI
      # Starts a worker by calling: Asteroid.Worker.start_link(arg)
      # {Asteroid.Worker, arg},
    ]

    with :ok <- AttributeRepository.auto_install_from_config(),
         :ok <- AttributeRepository.auto_start_from_config(),
         :ok <- TokenStore.auto_install_from_config(),
         :ok <- TokenStore.auto_start_from_config(),
         :ok <- Crypto.Key.load_from_config!()
    do
      # creating clients for the demo app
      create_clients()

      # See https://hexdocs.pm/elixir/Supervisor.html
      # for other strategies and supported options
      opts = [strategy: :one_for_one, name: Asteroid.Supervisor]
      Supervisor.start_link(children, opts)
    end
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  def config_change(changed, _new, removed) do
    AsteroidWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp create_clients() do
    Client.gen_new(id: "client1")
    |> Client.add("client_id", "client1")
    |> Client.add("client_name", "Le client")
    |> Client.add("client_type", "confidential")
    |> Client.add("client_secret", "clientpassword1")
    |> Client.add("grant_types", [
      "authorization_code",
      "password",
      "client_credentials",
      "refresh_token",
    ])
    |> Client.add("response_types", ["code"])
    |> Client.add("scope", [
      "read_balance",
      "read_account_information",
      "interbank_transfer",
      "asteroid.introspect"
    ])
    |> Client.add("redirect_uris", ["http://www.example.com/oauth2_redirect"])
    |> Client.store()
  end
end
