defmodule Asteroid.Store.RefreshToken.Mnesia do
  @behaviour Asteroid.Store.RefreshToken
  alias Asteroid.Token.RefreshToken

  @impl Asteroid.Store.RefreshToken
  def install() do
    :mnesia.create_table(:refresh_token, [
      attributes: [:id, :claims]
    ])
  end

  @impl Asteroid.Store.RefreshToken
  def get(id) do
    {:atomic, [{:refresh_token, ^id, claims}]} =
      :mnesia.transaction(fn -> :mnesia.read(:refresh_token, id) end)

    %RefreshToken{
      id: id,
      claims: claims
    }
  end

  @impl Asteroid.Store.RefreshToken
  def put(refresh_token, %Asteroid.Context{}) do
    :mnesia.transaction(fn ->
      :mnesia.write({:refresh_token, refresh_token.id, refresh_token.claims})
    end)

    refresh_token
  end

  @impl Asteroid.Store.RefreshToken
  def delete(id) do
    {:atomic, :ok} = :mnesia.transaction(fn -> :mnesia.delete({:refresh_token, id}) end)
  end
end
