defmodule Asteroid.TokenStore.DeviceCode do
  @moduledoc """
  Behaviour for device code store
  """

  @type opts :: Keyword.t()

  @doc """
  Installs the device code store
  """

  @callback install(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the device code store (non supervised)
  """

  @callback start(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the device code store (supervised)
  """

  @callback start_link(opts()) :: Supervisor.on_start()

  @doc """
  Returns an device code from its id

  Returns `{:ok, %Asteroid.Token.DeviceCode{}}` if the device code exists and `{:ok, nil}`
  otherwise.
  """

  @callback get(Asteroid.OAuth2.DeviceAuthorization.device_code(), opts()) ::
  {:ok, Asteroid.Token.DeviceCode.t() | nil}
  | {:error, any()}

  @doc """
  Returns the *device code id* from a user code
  """

  @callback get_from_user_code(Asteroid.OAuth2.DeviceAuthorization.user_code(), opts()) ::
  {:ok, Asteroid.Token.DeviceCode.t()} | {:error, any()}

  @doc """
  Stores an device code

  If the device code already exists, all of its data will be erased.
  """

  @callback put(Asteroid.Token.DeviceCode.t(), opts()) :: :ok | {:error, any()}

  @doc """
  Removes an device code
  """

  @callback delete(Asteroid.OAuth2.DeviceAuthorization.device_code(), opts()) ::
  :ok
  | {:error, any()}

  @optional_callbacks start: 1,
                      start_link: 1
end
