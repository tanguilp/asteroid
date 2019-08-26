defmodule Asteroid.ObjectStore.GenericKV do
  @moduledoc """
  Behaviour for access token store
  """

  @type opts :: Keyword.t()

  @typedoc """
  Key of the object

  The key can be of any type. Implementation should carefully deal with non-string values.
  """

  @type key :: any()

  @type value :: any()

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
  Returns an object from its id
  """

  @callback get(key(), opts()) ::
              {:ok, value() | nil}
              | {:error, any()}

  @doc """
  Stores an object

  If the object already exists, all of its data should be erased.

  If the object is a map, that contains the `"exp"` key, it can be used be the implementation
  to purge the object after that unix timestamp.
  """

  @callback put(key(), value(), opts()) :: :ok | {:error, any()}

  @doc """
  Removes an object
  """

  @callback delete(key(), opts()) :: :ok | {:error, any()}

  @optional_callbacks start: 1,
                      start_link: 1
end
