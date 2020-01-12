defmodule AsteroidWeb.EndpointMTLSAliases do
  @moduledoc false

  use Phoenix.Endpoint, otp_app: :asteroid

  # Code reloading can be explicitly enabled under the
  # :code_reloader configuration of your endpoint.
  if code_reloading? do
    socket "/phoenix/live_reload/socket", Phoenix.LiveReloader.Socket
    plug Phoenix.LiveReloader
    plug Phoenix.CodeReloader
  end

  plug Plug.RequestId
  plug Plug.Logger
  plug Plug.MethodOverride
  plug Plug.Head

  plug AsteroidWeb.RouterMTLSAliases
end
