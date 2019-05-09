defmodule Asteroid.Utils do
  @doc """
  Returns the current UNIX timestamp
  """
  @spec now() :: non_neg_integer()
  def now(), do: System.system_time(:second)

  @doc """
  Returns a secure random base 64 string of `size` bytes of randomness
  """
  @spec secure_random_b64(non_neg_integer()) :: String.t()
  def secure_random_b64(bytes \\ 32) do
    :crypto.strong_rand_bytes(bytes)
    |> Base.url_encode64(padding: false)
  end

  @spec astrenv(atom()) :: any()
  def astrenv(key) do
    Application.get_env(:asteroid, key)
  end

  @spec astrenv(atom(), any()) :: any()
  def astrenv(key, default) do
    case Application.get_env(:asteroid, key) do
      nil ->
        default

      val ->
        val
    end
  end

  @spec put_if_not_nil(map(), Map.key(), Map.value()) :: map()

  def put_if_not_nil(map, _, nil), do: map
  def put_if_not_nil(map, key, value), do: Map.put(map, key, value)
end
