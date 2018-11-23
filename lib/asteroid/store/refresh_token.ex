defmodule Asteroid.Store.RefreshToken do
  @moduledoc """
  """

  @callback install() :: :ok

  @callback get(Asteroid.Token.RefreshToken.id()) :: Asteroid.Token.RefreshToken.t()

  @callback put(Asteroid.Token.RefreshToken.t()) :: Asteroid.Token.RefreshToken.t()

  @callback delete(Asteroid.Token.RefreshToken.id()) :: :ok
end
