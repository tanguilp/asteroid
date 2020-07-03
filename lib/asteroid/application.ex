defmodule Asteroid.Application do
  @moduledoc false

  use Application

  import Asteroid.Config, only: [opt: 1]

  alias Asteroid.{
    AttributeRepository,
    Config,
    OAuth2,
    OIDC,
    ObjectStore
  }

  def start(_type, _args) do
    {:ok, _conf} = Config.load_and_save()

    children = [
      AsteroidWeb.Endpoint,
      {JOSEVirtualHSM, keys: Config.opt(:jose_virtual_hsm_keys_config)},
    ]
    |> maybe_add_mtls_aliases_endpoint()

    if opt(:jose_virtual_hsm_crypto_fallback), do: JOSE.crypto_fallback(true)

    with :ok <- AttributeRepository.auto_install_from_config(),
         :ok <- AttributeRepository.auto_start_from_config(),
         :ok <- ObjectStore.auto_install_from_config(),
         :ok <- ObjectStore.auto_start_from_config()
    do
      opts = [strategy: :one_for_one, name: Asteroid.Supervisor]
      {:ok, pid} = Supervisor.start_link(children, opts)

      with :ok <- OIDC.verify_config() do
        {:ok, pid}
      end
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
