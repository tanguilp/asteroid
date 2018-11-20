defmodule Asteroid.Store.AccessToken do
  @moduledoc """
  """

  @callback install() :: :ok

  @callback get(Asteroid.Token.AccessToken.id()) :: Asteroid.Token.AccessToken.t()

  @callback put(Asteroid.Token.AccessToken.t()) :: :ok

  @callback delete(Asteroid.Token.AccessToken.id()) :: :ok
end
