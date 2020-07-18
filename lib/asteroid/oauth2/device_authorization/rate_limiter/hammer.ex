defmodule Asteroid.OAuth2.DeviceAuthorization.RateLimiter.Hammer do
  import Asteroid.Config, only: [opt: 1]

  @behaviour Asteroid.OAuth2.DeviceAuthorization.RateLimiter

  @impl true

  def check(device_code_param, _opts) do
    interval = opt(:oauth2_flow_device_authorization_rate_limiter_interval)

    case Hammer.check_rate(device_code_param, interval * 1000, 1) do
      {:allow, _} ->
        :ok

      _ ->
        {:ok, {_count, _count_remaining, ms_to_next_bucket, _created_at, _updated_at}} =
          Hammer.inspect_bucket(device_code_param, interval * 1000, 1)

        {:rate_limited, div(ms_to_next_bucket, 1000) + 1}
    end
  end
end
