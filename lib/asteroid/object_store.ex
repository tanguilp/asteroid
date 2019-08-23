defmodule Asteroid.ObjectStore do
  @object_store_conf_keys [
    :object_store_access_token,
    :object_store_refresh_token,
    :object_store_authorization_code,
    :object_store_device_code,
    :object_store_request_object,
    :object_store_authenticated_session,
    :object_store_authentication_event
  ]

  import Asteroid.Utils

  require Logger

  @spec auto_install_from_config() :: :ok | {:error, any()}

  def auto_install_from_config() do
    object_store_conf_entries()
    |> do_auto_install_from_config()
  end

  @spec do_auto_install_from_config([Keyword.t()]) :: :ok | {:error, any()}

  defp do_auto_install_from_config([object_store_opts | t]) do
    if object_store_opts[:auto_install] != false do
      Logger.info("#{__MODULE__}: configuring token store `#{object_store_opts[:module]}`")

      case object_store_opts[:module].install(object_store_opts[:opts]) do
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
    object_store_conf_entries()
    |> do_auto_start_from_config()
  end

  @spec do_auto_start_from_config([Keyword.t()]) :: :ok | {:error, any()}

  defp do_auto_start_from_config([object_store_opts | t]) do
    if object_store_opts[:auto_start] != false do
      Logger.info("#{__MODULE__}: starting token store `#{object_store_opts[:module]}`")

      impl = object_store_opts[:module]

      if function_exported?(impl, :start_link, 1) do
        case impl.start_link(object_store_opts[:opts] || []) do
          {:ok, _pid} ->
            do_auto_start_from_config(t)

          {:error, _} = error ->
            error
        end
      else
        case impl.start(object_store_opts[:opts] || []) do
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

  @spec object_store_conf_entries() :: [Keyword.t()]

  defp object_store_conf_entries() do
    Enum.reduce(
      @object_store_conf_keys,
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
