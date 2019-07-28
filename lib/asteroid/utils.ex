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

  In tests, checks first the process dictionary for the value and fall backs to the standard
  configuration, so that one can set configuration at the testing process level using:

  ```elixir
  Process.put(:configuration_option, value)
  ```
  """
  @spec astrenv(atom()) :: any()

  if Mix.env() == :test do
    def astrenv(key, default_value \\ nil) do
      if key in Keyword.keys(Process.get()) do
        Process.get(key)
      else
        Application.get_env(:asteroid, key, default_value)
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

  @spec put_if_not_empty_string(map(), Map.key(), String.t()) :: map()

  def put_if_not_empty_string(map, _, ""), do: map
  def put_if_not_empty_string(map, key, value), do: Map.put(map, key, value)

  @spec put_if_not_empty(map(), Map.key(), [any()]) :: map()

  def put_if_not_empty(map, _, []), do: map
  def put_if_not_empty(map, key, list), do: Map.put(map, key, list)

  @doc """
  Returns the parameter unchanged
  """

  @spec id(any()) :: any()

  def id(param), do: param

  @doc """
  Returns the first parameter unchanged
  """

  @spec id_first_param(any(), any()) :: any()

  def id_first_param(param, _), do: param

  @doc """
  Always returns nil
  """

  @spec always_nil(any(), any()) :: nil

  def always_nil(_, _ \\ nil), do: nil

  @spec conn_not_authenticated?(Plug.Conn.t()) :: boolean()

  def conn_not_authenticated?(conn), do: not APIac.authenticated?(conn)

  @doc """
  Returns `true` if a list of headers contains, `false` otherwise

  ## Example

  ```elixir
  iex> headers
  [
    {"Date", "Sun, 28 Jul 2019 21:07:14 GMT"},
    {"Content-Type", "text/html;charset=utf-8"},
    {"Transfer-Encoding", "chunked"},
    {"Server", "Apache"},
    {"X-Powered-By", "PHP/5.6"},
    {"Vary", "Accept-Encoding"},
    {"Set-Cookie", "SERVERID100401=1520152|XT4Oh|XT4Oh; path=/"},
    {"Cache-control", "private"},
    {"X-IPLB-Instance", "28305"}
  ]
  iex> Asteroid.Utils.headers_contain_content_type?(headers, "text", "html")                      
  true
  iex> Asteroid.Utils.headers_contain_content_type?(headers, "application", "xml")
  false
  ```
  """

  @spec headers_contain_content_type?(list(), String.t(), String.t()) :: boolean()

  def headers_contain_content_type?(headers, type, subtype) do
    case Enum.find_value(
      headers,
      fn
        {header, value} ->
          if String.downcase(header) == "content-type" do
            value
          else
            false
          end
      end
    ) do
      nil ->
        false

      media_type ->
        case ContentType.content_type(media_type) do
          {:ok, ^type, ^subtype, _} ->
            true

          _ ->
            false
        end
    end
  end
end
