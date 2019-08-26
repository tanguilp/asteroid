defmodule Asteroid.OAuth2.DeviceAuthorization do
  @moduledoc """
  Types and convenience functions to work with the device flow
  """

  import Asteroid.Utils

  defmodule ExpiredTokenError do
    @moduledoc """
    Error returned when a device code has expired
    """

    defexception []

    @type t :: %__MODULE__{}

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "The device code has expired"

        :normal ->
          "The device code has expired"

        :minimal ->
          ""
      end
    end
  end

  defmodule AuthorizationPendingError do
    @moduledoc """
    Error returned when a device code is valid but has not been granted access yet by the user
    """

    defexception []

    @type t :: %__MODULE__{}

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "The device code authorization is pending"

        :normal ->
          "The device code authorization is pending"

        :minimal ->
          ""
      end
    end
  end

  defmodule RateLimitedError do
    @moduledoc """
    Error returned when requests with a device code become rate-limited

    The `:retry_after` option is in seconds.
    """

    defexception [:retry_after]

    @type t :: %__MODULE__{
            retry_after: non_neg_integer()
          }

    def message(%{retry_after: retry_after}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          if is_integer(retry_after) do
            "Too many requests (retry after #{to_string(retry_after)} seconds)"
          else
            "Too many requests"
          end

        :normal ->
          "Too many requests"

        :minimal ->
          ""
      end
    end
  end

  alias Asteroid.Context

  @type user_code :: String.t()

  @type device_code :: String.t()

  @doc """
  8-character user code generation fucntion

  This function returns the characters of the follwoing alphabet:
  "ABCDEFGHIJKLMNPQRSTUVWXYZ2345678" with an entropy of 32^8
  """

  @spec user_code(Context.t()) :: String.t()

  def user_code(_) do
    :crypto.strong_rand_bytes(5)
    |> Base.encode32(padding: false)
    |> String.replace("O", "8")
  end

  @doc """
  Returns `:ok` if the device code is not rate-limited,
  `{:error, %Asteroid.OAuth2.DeviceAuthorization.RateLimitedError{}}` otherwise.
  """

  @spec rate_limited?(device_code) :: :ok | {:error, RateLimitedError.t()}

  def rate_limited?(device_code) do
    case astrenv(:oauth2_flow_device_authorization_rate_limiter) do
      {module, opts} ->
        case module.check(device_code, opts) do
          :ok ->
            :ok

          {:rate_limited, nil} ->
            {:error, RateLimitedError.exception([])}

          {:rate_limited, retry_after} ->
            {:error, RateLimitedError.exception(retry_after: retry_after)}
        end

      nil ->
        :ok
    end
  end
end
