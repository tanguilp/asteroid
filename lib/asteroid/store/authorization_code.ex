defmodule Asteroid.Store.AuthorizationCode do
  @moduledoc """
  Behaviour for authorization code store
  """

  @type opts :: Keyword.t()

  @doc """
  Installs the authorization code store
  """

  @callback install(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the authorization code store (non supervised)
  """

  @callback start(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the authorization code store (supervised)
  """

  @callback start_link(opts()) :: Supervisor.on_start()

  @doc """
  Returns an authorization code from its id

  Returns `{:ok, %Asteroid.Token.AuthorizationCode{}}` if the authorization code exists
  and `{:ok, nil}` otherwise.
  """

  @callback get(Asteroid.Token.AuthorizationCode.id(), opts()) ::
  {:ok, Asteroid.Token.AuthorizationCode.t() | nil}
  | {:error, any()}

  @doc """
  Stores an authorization code 

  If the authorization code already exists, all of its data should be erased.
  """

  @callback put(Asteroid.Token.AuthorizationCode.t(), opts()) :: :ok | {:error, any()}

  @doc """
  Removes an authorization code
  """

  @callback delete(Asteroid.Token.AuthorizationCode.id(), opts()) :: :ok | {:error, any()}

  @optional_callbacks start: 1,
                      start_link: 1
end
