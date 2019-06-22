defmodule Asteroid.OAuth2.DeviceAuthorization.RateLimiter do
  @moduledoc """
  Behaviour for rate limiters in the device authorization flow
  """

  alias Asteroid.OAuth2.DeviceAuthorization

  @type opts :: Keyword.t()

  @doc """
  Returns `:ok` if the given device code is not rate limited, `{:error, retry_after}` otherwise

  The retry after variable is a non negative number expressed in seconds, or `nil` if the
  backend has no capability to give that number.
  """

  @callback check(DeviceAuthorization.device_code(), opts()) ::
  :ok
  | {:rate_limited, non_neg_integer()}
  | {:rate_limited, nil}
end
