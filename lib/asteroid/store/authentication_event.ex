defmodule Asteroid.Store.AuthenticationEvent do
  @moduledoc """
  Behaviour for authentication event store
  """

  @type opts :: Keyword.t()

  @doc """
  Installs the authentication event store
  """

  @callback install(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the authentication event store (non supervised)
  """

  @callback start(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the authentication event store (supervised)
  """

  @callback start_link(opts()) :: Supervisor.on_start()

  @doc """
  Returns an authentication event from its id

  Returns `{:ok, %Asteroid.OIDC.AuthenticationEvent{}}` if the authentication event exists
  and `{:ok, nil}` otherwise.
  """

  @callback get(Asteroid.OIDC.AuthenticationEvent.id(), opts()) ::
  {:ok, Asteroid.OIDC.AuthenticationEvent.t() | nil}
  | {:error, any()}

  @doc """
  Returns all the *authentication event ids* of a subject
  """

  @callback get_from_authenticated_session_id(Asteroid.Subject.id(), opts()) ::
  {:ok, [Asteroid.OIDC.AuthenticationEvent.id()]} | {:error, any()}

  @doc """
  Stores an authentication event

  If the authentication event already exists, all of its data should be erased.
  """

  @callback put(Asteroid.OIDC.AuthenticationEvent.t(), opts()) :: :ok | {:error, any()}

  @doc """
  Removes an authentication event
  """

  @callback delete(Asteroid.OIDC.AuthenticationEvent.id(), opts()) :: :ok | {:error, any()}

  @optional_callbacks start: 1,
                      start_link: 1
end
