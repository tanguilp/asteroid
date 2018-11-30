defmodule Asteroid.AccessToken.Store.Mnesia do
  @behaviour Asteroid.AccessToken.Store
  alias Asteroid.Token.AccessToken
  import Asteroid.Utils
  require Logger

  @impl Asteroid.AccessToken.Store
  def install() do
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    default_config = [
      attributes: [:id, :refresh_token_id, :claims],
      index: [:store_access_token]
    ]

    # user configuration overrides the default config
    config =
      default_config
      |> Keyword.merge(astrenv(:store_access_token, [])[:install_config])

    case :mnesia.create_table(:access_token, config) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: installed succesfully")
        :ok

      {_, reason}  = error ->
        Logger.warn("#{__MODULE__}: install failed, reason: #{inspect error}")
        {:error, reason}
    end
  end

  @impl Asteroid.AccessToken.Store
  def start() do
    :mnesia.start()
    Logger.info("#{__MODULE__}: started")

    cleaning_interval = astrenv(:store_access_token)[:run_config][:cleaning_interval]
    
    Singleton.start_child(Asteroid.AccessToken.Store.Mnesia.Cleaner, cleaning_interval,
      __MODULE__)
  end

  @impl Asteroid.AccessToken.Store
  def stop() do
    :mnesia.stop()
    Logger.info("#{__MODULE__}: stopped")

    :ok
  end

  @impl Asteroid.AccessToken.Store
  def get(id) do
    Logger.debug("#{__MODULE__}: get access token `#{id}`")
    
    case :mnesia.transaction(fn -> :mnesia.read(:access_token, id) end) do
      {:atomic, [{:access_token, ^id, refresh_token_id, claims}]} ->
        {:ok,
          %AccessToken{
            id: id,
            refresh_token_id: refresh_token_id,
            claims: claims
          }
        }

      error ->
        {:error, error}
    end
  end

  @impl Asteroid.AccessToken.Store
  def put(access_token) do
    Logger.debug("#{__MODULE__}: put access token `#{inspect access_token}`")
    :mnesia.transaction(fn ->
      :mnesia.write({:access_token,
        access_token.id,
        access_token.refresh_token_id,
        access_token.claims})
    end)

    access_token
  end

  @impl Asteroid.AccessToken.Store
  def delete(id) do
    Logger.debug("#{__MODULE__}: delete access token `#{id}`")
    {:atomic, :ok} = :mnesia.transaction(fn -> :mnesia.delete({:access_token, id}) end)
  end

  @impl Asteroid.AccessToken.Store
  def delete_access_tokens_of_refresh_token(refresh_token_id) do
    Logger.debug("#{__MODULE__}: deletion of access token for refresh token `#{refresh_token_id}`")
    access_tokens = :mnesia.dirty_index_read(:access_token, refresh_token_id, :refresh_token_id)

    for {:access_token, id, _refresh_token_id, _claims} <- access_tokens do
      delete(id)
    end
  end

  defmodule Cleaner do
    use GenServer
    require Logger

    def start_link do
      GenServer.start_link(__MODULE__, %{})
    end

    def init(interval) do
      Process.send_after(self(), :clean, interval * 1000)
      {:ok, interval}
    end

    def handle_info(:clean, interval) do
      clean_cache()
      Process.send_after(self(), :clean, interval * 1000)
      {:noreply, interval}
    end

    defp clean_cache() do
      Logger.info"#{__MODULE__}: starting cleaning process on #{node()}"

      # :ets.fun2ms(fn {_, at, _, %{:exp => exp}} when exp <= timestamp -> at end)
      matchspec = [{{:_, :"$1", :_, %{exp: :"$2"}}, [{:"=<", :"$2", now()}], [:"$1"]}]

      for access_token_id <- :mnesia.dirty_select(:access_token, matchspec) do
        Asteroid.AccessToken.Store.Mnesia.delete(access_token_id)
      end
    end

  end
end
