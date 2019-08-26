defmodule Asteroid.ObjectStore.AuthenticationEvent.Riak.Purge do
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
    Logger.info("#{__MODULE__}: starting authentication event purge process on #{node()}")

    request = "exp_int_register:[0 TO #{:os.system_time(:second)}]"

    case Asteroid.ObjectStore.AuthenticationEvent.Riak.search(request, opts) do
      {:ok, authentication_event_ids} ->
        for authentication_event_id <- authentication_event_ids do
          # this causes Riak connection exhaustion, to investigate further
          # Task.start(Asteroid.ObjectStore.AuthenticationEvent.Riak, :delete, [authentication_event_id, opts])
          Asteroid.OIDC.AuthenticationEvent.delete(authentication_event_id)
        end

        :ok

      {:error, _} = error ->
        Logger.warn(
          "#{__MODULE__}: purge process on #{node()} failed with error #{inspect(error)}"
        )
    end
  end
end
