defmodule Asteroid.Application do
  @moduledoc false

  use Application

  import Asteroid.Config, only: [opt: 1]

  alias Asteroid.{
    AttributeRepository,
    Config,
    OAuth2,
    ObjectStore
  }

  def start(_type, _args) do
    {:ok, _conf} = Config.load_and_save()

    children = [
      AsteroidWeb.Endpoint,
      {JOSEVirtualHSM, keys_config: Config.opt(:jose_virtual_hsm_keys_config)},
    ]
    |> maybe_add_mtls_aliases_endpoint()

    #FIXME: remove
    JOSE.crypto_fallback(true)

    with :ok <- AttributeRepository.auto_install_from_config(),
         :ok <- AttributeRepository.auto_start_from_config(),
         :ok <- ObjectStore.auto_install_from_config(),
         :ok <- ObjectStore.auto_start_from_config()
    do
      if opt(:crypto_jws_none_alg_enabled) do
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
