defmodule Asteroid.Application do
  @moduledoc false

  use Application

  import Asteroid.Utils

  alias Asteroid.AttributeRepository
  alias Asteroid.Client
  alias Asteroid.Subject
  alias Asteroid.ObjectStore
  alias Asteroid.Crypto

  def start(_type, _args) do
    children = [
      AsteroidWeb.Endpoint
    ]

    with :ok <- AttributeRepository.auto_install_from_config(),
         :ok <- AttributeRepository.auto_start_from_config(),
         :ok <- ObjectStore.auto_install_from_config(),
         :ok <- ObjectStore.auto_start_from_config(),
         :ok <- Crypto.Key.load_from_config!() do
      # creating clients and subjects for the demo app
      create_clients()
      create_subjects()

      if astrenv(:crypto_jws_none_alg_enabled, false) do
        JOSE.JWA.unsecured_signing(true)
      end

      opts = [strategy: :one_for_one, name: Asteroid.Supervisor]
      Supervisor.start_link(children, opts)
    end
  end

  def config_change(changed, _new, removed) do
    AsteroidWeb.Endpoint.config_change(changed, removed)
    :ok
  end

  defp create_clients() do
    Client.gen_new(id: "client1")
    |> Client.add("client_id", "client1")
    |> Client.add("client_name", "OAuth Tools")
    |> Client.add("client_type", "confidential")
    |> Client.add("client_secret", "clientpassword1")
    |> Client.add("grant_types", [
      "authorization_code",
      "implicit",
      "password",
      "client_credentials",
      "refresh_token"
    ])
    |> Client.add("response_types", [
      "code",
      "token",
      "id_token",
      "id_token token",
      "code id_token",
      "code token",
      "code id_token token"
    ])
    |> Client.add("scope", [
      "read_balance",
      "read_account_information",
      "interbank_transfer",
      "asteroid.introspect",
      "openid",
      "email",
      "profile",
      "address",
      "phone"
    ])
    |> Client.add("redirect_uris", [
      "https://oauth.tools/callback/code",
      "https://oauth.tools/callback/implicit",
      "https://oauth.tools/callback/hybrid",
      "http://localhost:4000/openid_connect_redirect_uri",
      "http://localhost:4000/openid_connect_redirect_uri?iss=https://repentant-brief-fishingcat.gigalixirapp.com"
    ])
    |> Client.store()

    Client.gen_new(id: "client2")
    |> Client.add("client_id", "client2")
    |> Client.add("client_type", "confidential")
    |> Client.add("client_secret", "clientpassword2")
    |> Client.add("grant_types", ["client_credentials"])
    |> Client.add("scope", [
      "read_balance",
      "read_account_information",
      "interbank_transfer",
      "asteroid.introspect"
    ])
    |> Client.add(
      "__asteroid_oauth2_flow_client_credentials_access_token_serialization_format",
      "jws"
    )
    |> Client.add(
      "__asteroid_oauth2_flow_client_credentials_access_token_signing_key",
      "key_auto"
    )
    |> Client.add(
      "__asteroid_oauth2_flow_client_credentials_access_token_signing_alg",
      "PS256"
    )
    |> Client.store()
  end

  def create_subjects() do
    Subject.gen_new(id: "user_demo")
    |> Subject.add("sub", "user_demo")
    |> Subject.add("password", "asteroidftw")
    |> Subject.store()
  end
end
