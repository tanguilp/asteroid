defmodule Asteroid.AccessToken.Store do
  @moduledoc """
  """

  @callback install() :: :ok | {:error, any()}

  @callback start() :: :ok | {:error, any()}

  @callback stop() :: :ok | {:error, any()}

  @callback get(Asteroid.Token.AccessToken.id()) :: {:ok, Asteroid.Token.AccessToken.t()} |
    {:error, any()}

  @callback put(Asteroid.Token.AccessToken.t()) :: :ok | {:error, any()}

  @callback delete(Asteroid.Token.AccessToken.id()) :: :ok | {:error, any()}

  @callback delete_access_tokens_of_refresh_token(Asteroid.Token.RefreshToken.id()) ::
    :ok | {:error, any()}
end
