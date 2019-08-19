defmodule Asteroid.Store.AuthenticatedSession do
  @moduledoc """
  Behaviour for authenticated session store
  """

  @type opts :: Keyword.t()

  @doc """
  Installs the authenticated session store
  """

  @callback install(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the authenticated session store (non supervised)
  """

  @callback start(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the authenticated session store (supervised)
  """

  @callback start_link(opts()) :: Supervisor.on_start()

  @doc """
  Returns an authenticated session from its id

  Returns `{:ok, %Asteroid.OIDC.AuthenticatedSession{}}` if the authenticated session exists
  and `{:ok, nil}` otherwise.
  """

  @callback get(Asteroid.OIDC.AuthenticatedSession.id(), opts()) ::
  {:ok, Asteroid.OIDC.AuthenticatedSession.t() | nil}
  | {:error, any()}

  @doc """
  Returns all the *authenticated session ids* of a subject
  """

  @callback get_from_subject_id(Asteroid.Subject.id(), opts()) ::
  {:ok, [Asteroid.OIDC.AuthenticatedSession.id()]} | {:error, any()}

  @doc """
  Stores an authenticated session

  If the authenticated session already exists, all of its data should be erased.
  """

  @callback put(Asteroid.OIDC.AuthenticatedSession.t(), opts()) :: :ok | {:error, any()}

  @doc """
  Removes an authenticated session
  """

  @callback delete(Asteroid.OIDC.AuthenticatedSession.id(), opts()) :: :ok | {:error, any()}

  @optional_callbacks start: 1,
                      start_link: 1
end
