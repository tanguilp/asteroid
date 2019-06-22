defmodule Asteroid.TokenStore.DeviceCode.Mnesia.Purge do
  @moduledoc false

  use GenServer
  require Logger

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
    Logger.info("#{__MODULE__}: starting device code purge process on #{node()}")

    table_name = opts[:table_name] || :asteroid_device_code

    matchspec = [
      {
        {:_, :"$1", :_, %{"exp" => :"$2"}},
        [{:<, :"$2", :os.system_time(:second)}],
        [:"$1"]
      }
    ]

    for device_code_id <- :mnesia.dirty_select(table_name, matchspec) do
      Asteroid.TokenStore.DeviceCode.Mnesia.delete(device_code_id, opts)
    end
  end
end
