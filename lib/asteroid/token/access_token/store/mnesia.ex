defmodule Asteroid.AccessToken.Store.Mnesia do
  @behaviour Asteroid.AccessToken.Store
  alias Asteroid.Token.AccessToken
  import Asteroid.Utils

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
        :ok

      {_, error} ->
        {:error, error}
    end
  end

  @impl Asteroid.AccessToken.Store
  def start() do
    :mnesia.start()
  end

  @impl Asteroid.AccessToken.Store
  def stop() do
    :mnesia.stop()

    :ok
  end

  @impl Asteroid.AccessToken.Store
  def get(id) do
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
    {:atomic, :ok} = :mnesia.transaction(fn -> :mnesia.delete({:access_token, id}) end)
  end

  @impl Asteroid.AccessToken.Store
  def delete_access_tokens_of_refresh_token(refresh_token_id) do
    access_tokens = :mnesia.dirty_index_read(:access_token, refresh_token_id, :refresh_token_id)

    for {:access_token, id, _refresh_token_id, _claims} <- access_tokens do
      delete(id)
    end
  end
end
