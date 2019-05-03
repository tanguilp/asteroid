defmodule Asteroid.RefreshToken.Store.Mnesia do
  @behaviour Asteroid.RefreshToken.Store
  alias Asteroid.Token.RefreshToken
  import Asteroid.Utils
  require Logger

  @impl Asteroid.RefreshToken.Store
  def install() do
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    default_config = [
      attributes: [:id, :claims]
    ]

    # user configuration overrides the default config
    config =
      default_config
      |> Keyword.merge(astrenv(:store_refresh_token, [])[:install_config])

    case :mnesia.create_table(:refresh_token, config) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: installed succesfully")
        :ok

      {_, reason} = error ->
        Logger.warn("#{__MODULE__}: install failed, reason: #{inspect error}")
        {:error, reason}
    end
  end

  @impl Asteroid.RefreshToken.Store
  def start() do
    :mnesia.start()
    Logger.info("#{__MODULE__}: started")

    cleaning_interval = astrenv(:store_refresh_token)[:run_config][:cleaning_interval]

    Singleton.start_child(Asteroid.RefreshToken.Store.Mnesia.Cleaner, cleaning_interval,
      __MODULE__)
  end

  @impl Asteroid.RefreshToken.Store
  def stop() do
    :mnesia.stop()

    :ok
  end

  @impl Asteroid.RefreshToken.Store
  def get(id) do
    Logger.debug("#{__MODULE__}: get refresh token `#{id}`")
    case :mnesia.transaction(fn -> :mnesia.read(:refresh_token, id) end) do
      {:atomic, [{:refresh_token, ^id, claims}]} ->
        {:ok,
          %RefreshToken{
            id: id,
            data: claims
          }
        }

      error ->
        {:error, error}
    end
  end

  @impl Asteroid.RefreshToken.Store
  def put(refresh_token) do
    Logger.debug("#{__MODULE__}: put refresh token `#{inspect refresh_token}`")
    :mnesia.transaction(fn ->
      :mnesia.write({:refresh_token, refresh_token.id, refresh_token.data})
    end)

    refresh_token
  end

  @impl Asteroid.RefreshToken.Store
  def delete(id) do
    Logger.debug("#{__MODULE__}: delete refresh token `#{id}`")
    {:atomic, :ok} = :mnesia.transaction(fn -> :mnesia.delete({:refresh_token, id}) end)
  end

  defmodule Cleaner do
    use GenServer
    require Logger

    def start_link do
      GenServer.start_link(__MODULE__, %{})
    end

    def init(interval) do
      interval = interval * 1000

      Process.send_after(self(), :clean, interval)

      {:ok, interval}
    end

    def handle_info(:clean, interval) do
      clean_cache()

      Process.send_after(self(), :clean, interval)

      {:noreply, interval}
    end

    defp clean_cache() do
      Logger.info"#{__MODULE__}: starting cleaning process on #{node()}"

      # :ets.fun2ms(fn {_, at, _, %{:exp => exp}} when exp <= timestamp -> at end)
      matchspec = [{{:_, :"$1", %{exp: :"$2"}}, [{:"=<", :"$2", now()}], [:"$1"]}]

      for refresh_token_id <- :mnesia.dirty_select(:refresh_token, matchspec) do
        Asteroid.RefreshToken.Store.Mnesia.delete(refresh_token_id)
      end
    end

  end
end
