defmodule Asteroid.Application do
  @moduledoc false

  use Application

  import Asteroid.Utils

  alias Asteroid.{
    AttributeRepository,
    Crypto,
    OAuth2,
    ObjectStore
  }

  def start(_type, _args) do
    children = [
      AsteroidWeb.Endpoint
    ]
    |> maybe_add_mtls_aliases_endpoint()

    with :ok <- AttributeRepository.auto_install_from_config(),
         :ok <- AttributeRepository.auto_start_from_config(),
         :ok <- ObjectStore.auto_install_from_config(),
         :ok <- ObjectStore.auto_start_from_config(),
         :ok <- Crypto.Key.load_from_config!() do
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

  defp maybe_add_mtls_aliases_endpoint(children) do
    if OAuth2.MTLS.start_mtls_aliases_endpoint?() do
      [AsteroidWeb.EndpointMTLSAliases] ++ children
    else
      children
    end
  end
end
