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

  @doc """
  Returns the configuration option value

  In tests, checks first the process dictionnary for the value and fallbacks to the standard
  configuration, so that one can set configuration at the testing process level using:

  ```elixir
  Process.put(:configuration_option, value)
  ```
  """
  @spec astrenv(atom()) :: any()

  if Mix.env() == :test do
    def astrenv(key, default_value \\ nil) do
      case Process.get(key) do
        nil ->
          Application.get_env(:asteroid, key, default_value)

        value ->
          value
      end
    end
  else
    def astrenv(key, default_value \\ nil) do
      Application.get_env(:asteroid, key, default_value)
    end
  end

  @spec put_if_not_nil(map(), Map.key(), Map.value()) :: map()

  def put_if_not_nil(map, _, nil), do: map
  def put_if_not_nil(map, key, value), do: Map.put(map, key, value)
end
