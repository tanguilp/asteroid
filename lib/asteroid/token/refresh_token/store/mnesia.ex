defmodule Asteroid.RefreshToken.Store.Mnesia do
  @behaviour Asteroid.RefreshToken.Store
  alias Asteroid.Token.RefreshToken
  import Asteroid.Utils

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
        :ok

      {_, error} ->
        {:error, error}
    end
  end

  @impl Asteroid.RefreshToken.Store
  def start() do
    :mnesia.start()
  end

  @impl Asteroid.RefreshToken.Store
  def stop() do
    :mnesia.stop()

    :ok
  end

  @impl Asteroid.RefreshToken.Store
  def get(id) do
    case :mnesia.transaction(fn -> :mnesia.read(:refresh_token, id) end) do
      {:atomic, [{:refresh_token, ^id, claims}]} ->
        {:ok,
          %RefreshToken{
            id: id,
            claims: claims
          }
        }

      error ->
        {:error, error}
    end
  end

  @impl Asteroid.RefreshToken.Store
  def put(refresh_token) do
    :mnesia.transaction(fn ->
      :mnesia.write({:refresh_token, refresh_token.id, refresh_token.claims})
    end)

    refresh_token
  end

  @impl Asteroid.RefreshToken.Store
  def delete(id) do
    {:atomic, :ok} = :mnesia.transaction(fn -> :mnesia.delete({:refresh_token, id}) end)
  end
end
