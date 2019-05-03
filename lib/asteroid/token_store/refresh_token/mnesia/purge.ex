defmodule Asteroid.TokenStore.RefreshToken.Mnesia.Purge do
  @moduledoc false

  use GenServer
  require Logger
  import Asteroid.Utils

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts)
  end

  def init(opts) do
    if opts[:purge_interval] != :no_purge do
      Process.send_after(self(), :purge, opts[:purge_interval] * 1000)
    end

    {:ok, opts}
  end

  def handle_info(:purge, opts) do
    purge(opts)

    Process.send_after(self(), :purge, opts[:purge_interval] * 1000)

    {:noreply, opts}
  end

  defp purge(opts) do
    Logger.info("#{__MODULE__}: starting refresh token purge process on #{node()}")

    table_name = opts[:table_name] || :asteroid_refresh_token

    matchspec = [
      {
        {:_, :"$1", :_, :_, :_, %{"exp" => :"$2"}},
        [{:<, :"$2", :os.system_time(:second)}],
        [:"$1"]
      }
    ]

    access_token_store_config = {
      astrenv(:token_store_access_token)[:module],
      astrenv(:token_store_access_token)[:opts] || []
    }

    for refresh_token_id <- :mnesia.dirty_select(table_name, matchspec) do
      Asteroid.TokenStore.RefreshToken.Mnesia.delete(refresh_token_id,
                                                     opts,
                                                     access_token_store_config)
    end
  end
end
