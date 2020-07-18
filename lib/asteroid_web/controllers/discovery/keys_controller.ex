defmodule AsteroidWeb.Discovery.KeysController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Config, only: [opt: 1]

  alias Asteroid.Crypto

  def handle(conn, _params) do
    conn
    |> opt(:oauth2_endpoint_discovery_keys_before_send_conn_callback).()
    |> json(opt(:oauth2_endpoint_discovery_keys_before_send_resp_callback).(
      %{"keys" => Crypto.JOSE.public_keys()}
    ))
  end
end
