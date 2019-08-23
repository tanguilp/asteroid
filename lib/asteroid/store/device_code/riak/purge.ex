defmodule Asteroid.Store.DeviceCode.Riak.Purge do
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

    request = "exp_int_register:[0 TO #{:os.system_time(:second)}]"

    case Asteroid.Store.DeviceCode.Riak.search(request, opts) do
      {:ok, device_code_ids} ->
        for device_code_id <- device_code_ids do
          # this causes Riak connection exhaustion, to investigate further
          # Task.start(Asteroid.Store.DeviceCode.Riak, :delete, [device_code_id, opts])
          Asteroid.Token.DeviceCode.delete(device_code_id)
        end

        :ok

      {:error, _} = error ->
        Logger.warn(
          "#{__MODULE__}: purge process on #{node()} failed with error #{inspect(error)}"
        )
    end
  end
end
