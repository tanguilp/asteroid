defmodule Asteroid.ObjectStore.AccessToken do
  @moduledoc """
  Behaviour for access token store
  """

  @type opts :: Keyword.t()

  @doc """
  Installs the access token store
  """

  @callback install(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the access token store (non supervised)
  """

  @callback start(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the access token store (supervised)
  """

  @callback start_link(opts()) :: Supervisor.on_start()

  @doc """
  Returns an access token from its id

  Returns `{:ok, %Asteroid.Token.AccessToken{}}` if the access token exists and `{:ok, nil}`
  otherwise.
  """

  @callback get(Asteroid.Token.AccessToken.id(), opts()) ::
              {:ok, Asteroid.Token.AccessToken.t() | nil}
              | {:error, any()}

  @doc """
  Returns all the *access token ids* from a refresh token id
  """

  @callback get_from_refresh_token_id(Asteroid.Token.RefreshToken.id(), opts()) ::
              {:ok, [Asteroid.Token.AccessToken.id()]} | {:error, any()}

  @doc """
  Returns all the *access token ids* of a subject
  """

  @callback get_from_subject_id(Asteroid.Subject.id(), opts()) ::
              {:ok, [Asteroid.Token.AccessToken.id()]} | {:error, any()}

  @doc """
  Returns all the *access token ids* of a client
  """

  @callback get_from_client_id(Asteroid.Client.id(), opts()) ::
              {:ok, [Asteroid.Token.AccessToken.id()]} | {:error, any()}

  @doc """
  Returns all the *access token ids* of a device
  """

  @callback get_from_device_id(Asteroid.Device.id(), opts()) ::
              {:ok, [Asteroid.Token.AccessToken.id()]} | {:error, any()}

  @doc """
  Stores an access token

  If the access token already exists, all of its data should be erased.
  """

  @callback put(Asteroid.Token.AccessToken.t(), opts()) :: :ok | {:error, any()}

  @doc """
  Removes an access token
  """

  @callback delete(Asteroid.Token.AccessToken.id(), opts()) :: :ok | {:error, any()}

  @optional_callbacks start: 1,
                      start_link: 1,
                      get_from_subject_id: 2,
                      get_from_client_id: 2,
                      get_from_device_id: 2
end
