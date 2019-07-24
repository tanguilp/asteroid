defmodule Asteroid.TokenStore do
  @token_store_conf_keys [
    :token_store_access_token,
    :token_store_refresh_token,
    :token_store_authorization_code,
    :token_store_device_code,
    :token_store_request_object
  ]

  import Asteroid.Utils

  require Logger

  @spec auto_install_from_config() :: :ok | {:error, any()}

  def auto_install_from_config() do
    token_store_conf_entries()
    |> do_auto_install_from_config()
  end

  @spec do_auto_install_from_config([Keyword.t()]) :: :ok | {:error, any()}

  defp do_auto_install_from_config([token_store_opts | t]) do
    if token_store_opts[:auto_install] != false do
      Logger.info("#{__MODULE__}: configuring token store `#{token_store_opts[:module]}`")

      case token_store_opts[:module].install(token_store_opts[:opts]) do
        :ok ->
          do_auto_install_from_config(t)

        {:error, _} = error ->
          error
      end
    else
      do_auto_install_from_config(t)
    end
  end

  defp do_auto_install_from_config([]) do
    :ok
  end

  @spec auto_start_from_config() :: :ok | {:error, any()}

  def auto_start_from_config() do
    token_store_conf_entries()
    |> do_auto_start_from_config()
  end

  @spec do_auto_start_from_config([Keyword.t()]) :: :ok | {:error, any()}

  defp do_auto_start_from_config([token_store_opts | t]) do
    if token_store_opts[:auto_start] != false do
      Logger.info("#{__MODULE__}: starting token store `#{token_store_opts[:module]}`")

      impl = token_store_opts[:module]

      if function_exported?(impl, :start_link, 1) do
        case impl.start_link(token_store_opts[:opts] || []) do
          {:ok, _pid} ->
            do_auto_start_from_config(t)

          {:error, _} = error ->
            error
        end
      else
        case impl.start(token_store_opts[:opts] || []) do
          :ok ->
            do_auto_start_from_config(t)

          {:error, _} = error ->
            error
        end
      end
    else
      do_auto_start_from_config(t)
    end
  end

  defp do_auto_start_from_config([]) do
    :ok
  end

  @spec token_store_conf_entries() :: [Keyword.t()]

  defp token_store_conf_entries() do
    Enum.reduce(
      @token_store_conf_keys,
      [],
      fn
        key, acc ->
          case astrenv(key) do
            opts when is_list(opts) ->
              acc ++ [opts]

            nil ->
              acc
          end
      end
    )
  end
end
