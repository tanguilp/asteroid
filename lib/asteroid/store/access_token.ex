defmodule Asteroid.Store.AccessToken do
  @moduledoc """
  """

  @callback install() :: :ok

  @callback get(Asteroid.Token.AccessToken.id()) :: {:ok, Asteroid.Token.AccessToken.t()} |
    {:error, any()}

  @callback put(Asteroid.Token.AccessToken.t()) :: :ok

  @callback delete(Asteroid.Token.AccessToken.id()) :: :ok
end
