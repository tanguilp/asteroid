defmodule Asteroid.Crypto.Key.Cache do
  @moduledoc """
  JWK cache behaviour specification
  """

  defmodule NotFoundError do
    @moduledoc """
    Error returned when the key can not be found in the JWK cache
    """

    defexception []

    @impl true

    def message(_), do: "Key not found in JWK cache"
  end

  alias Asteroid.Crypto

  @type opts :: Keyword.t()

  @doc """
  Starts the JWK cache (non-supervised)

  Does the intiialization work if necessary.
  """

  @callback start(opts()) :: :ok | {:error, any()}

  @doc """
  Starts the JWK cache (supervised)

  Does the intiialization work if necessary.
  """

  @callback start_link(opts()) :: Supervisor.on_start()

  @doc """
  Returns a key from the cache
  """

  @callback get(Crypto.Key.name(), opts()) :: {:ok, %JOSE.JWK{}} | {:error, Exception.t()}

  @doc """
  Stores a key in the cache
  """

  @callback put(Crypto.Key.name(), %JOSE.JWK{}, opts()) :: :ok | {:error, Exception.t()}

  @doc """
  Deletes a key from the cache
  """

  @callback delete(Crypto.Key.name(), opts()) :: :ok | {:error, Exception.t()}

  @doc """
  Returns all keys
  """

  @callback get_all(opts()) :: {:ok, [{Crypto.Key.name(), %JOSE.JWK{}}]} | {:error, Exception.t()}

  @optional_callbacks start: 1,
                      start_link: 1
end
