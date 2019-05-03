defmodule Asteroid.TokenStore.RefreshToken do
  @moduledoc """
  Behaviour for refresh token store
  """

  @type opts :: Keyword.t()

  @doc """
  Installs the refresh token store
  """

  @callback install(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the refresh token store (non supervised)
  """

  @callback start(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the refresh token store (supervised)
  """

  @callback start_link(opts()) :: Supervisor.on_start()

  @doc """
  Returns an refresh token from its id

  Returns `{:ok, %Asteroid.Token.RefreshToken{}}` if the refresh token exists and `{:ok, nil}`
  otherwise.
  """

  @callback get(Asteroid.Token.RefreshToken.id(), opts()) ::
  {:ok, Asteroid.Token.RefreshToken.t() | nil}
  | {:error, any()}

  @doc """
  Returns all the *refresh token ids* of a subject
  """

  @callback get_from_subject_id(Asteroid.Subject.id(), opts()) ::
  {:ok, [Asteroid.RefreshToken.id()]} | {:error, any()}

  @doc """
  Returns all the *refresh token ids* of a client
  """

  @callback get_from_client_id(Asteroid.Client.id(), opts()) ::
  {:ok, [Asteroid.RefreshToken.id()]} | {:error, any()}

  @doc """
  Returns all the *refresh token ids* of a device
  """

  @callback get_from_device_id(Asteroid.Device.id(), opts()) ::
  {:ok, [Asteroid.RefreshToken.id()]} | {:error, any()}

  @doc """
  Stores an refresh token

  If the refresh token already exists, all of its data should be erased.
  """

  @callback put(Asteroid.Token.RefreshToken.t(), opts()) :: :ok | {:error, any()}

  @doc """
  Removes an refresh token

  The third argument is a 2-tuple composed of:
  1. A module that implements the `Asteroid.TokenStore.AccessToken` behaviour
  2. Options for this module

  Implementation of this callback shall call the
  `c:Asteroid.TokenStore.AccessToken.delete_from_refresh_token_id/2` callback so as to delete
  the access tokens associated with the deleted refresh token.
  """

  @callback delete(Asteroid.Token.RefreshToken.id(),
                   opts(),
                   {module(), Asteroid.TokenStore.AccessToken.opts()}) ::
  :ok | {:error, any()}

  @optional_callbacks start: 1,
                      start_link: 1,
                      get_from_subject_id: 2,
                      get_from_client_id: 2,
                      get_from_device_id: 2
end
