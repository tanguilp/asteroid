defmodule Asteroid.TokenStore.AuthorizationCode.Riak.Purge do
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
    Logger.info("#{__MODULE__}: starting authorization code purge process on #{node()}")

    request = "exp_int_register:[0 TO #{:os.system_time(:second)}]"

    case Asteroid.TokenStore.AuthorizationCode.Riak.search(request, opts) do
      {:ok, authorization_code_ids} ->
        for authorization_code_id <- authorization_code_ids do
          Task.start(Asteroid.TokenStore.AuthorizationCode.Riak,
                     :delete,
                     [authorization_code_id, opts])
        end

        :ok

      {:error, _} = error ->
        Logger.warn(
          "#{__MODULE__}: purge process on #{node()} failed with error #{inspect(error)}"
        )
    end
  end
end
