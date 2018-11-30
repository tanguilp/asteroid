defmodule Asteroid.RefreshToken.Store do
  @moduledoc """
  """

  @callback install() :: :ok

  @callback start() :: :ok | {:error, any()}

  @callback stop() :: :ok | {:error, any()}

  @callback get(Asteroid.Token.RefreshToken.id()) :: {:ok, Asteroid.Token.RefreshToken.t()} |
    {:error, any()}

  @callback put(Asteroid.Token.RefreshToken.t()) :: Asteroid.Token.RefreshToken.t()

  @callback delete(Asteroid.Token.RefreshToken.id()) :: :ok
end
