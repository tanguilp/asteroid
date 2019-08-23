defmodule Asteroid.Store.AuthorizationCode.Mnesia.Purge do
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
    Logger.info("#{__MODULE__}: starting authorization code purge process on #{node()}")

    table_name = opts[:table_name] || :asteroid_authorization_code

    matchspec = [
      {
        {:_, :"$1", %{"exp" => :"$2"}},
        [{:<, :"$2", :os.system_time(:second)}],
        [:"$1"]
      }
    ]

    for authorization_code_id <- :mnesia.dirty_select(table_name, matchspec) do
      Asteroid.Token.AuthorizationCode.delete(authorization_code_id)
    end
  end
end
