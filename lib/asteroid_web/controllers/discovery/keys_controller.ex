defmodule AsteroidWeb.Discovery.KeysController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias Asteroid.Crypto

  def handle(conn, _params) do
    key_list =
      Enum.reduce(
        Crypto.Key.get_all_public(),
        [],
        fn
          jwk_public, acc ->
            case JOSE.JWK.to_public_map(jwk_public) do
              # JOSE returns the private secret for oct keys, hence this match
              {%{kty: :jose_jwk_kty_oct}, _jwk} ->
                acc

              {_key_type, jwk_public_map} ->
                acc ++ [Map.delete(jwk_public_map, "advertise")]
            end
        end
      )
      |> put_keys()
      |> astrenv(:oauth2_endpoint_discovery_keys_before_send_resp_callback).()

    conn
    |> astrenv(:oauth2_endpoint_discovery_keys_before_send_conn_callback).()
    |> json(key_list)
  end

  @spec put_keys([map()]) :: map()

  defp put_keys(key_list) do
    %{"keys" => key_list}
  end
end
