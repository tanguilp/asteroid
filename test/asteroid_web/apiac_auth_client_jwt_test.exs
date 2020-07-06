defmodule AsteroidWeb.APIacAuthClientJWTTest do
  use AsteroidWeb.ConnCase, async: true

  alias Asteroid.{Client, OAuth2}
  alias AsteroidWeb.Router.Helpers, as: Routes

  @client_id_mac "client_apiac_auth_client_jwt_mac"
  @client_id_ec "client_apiac_auth_client_jwt_ec"

  setup_all do
    Client.gen_new(id: @client_id_mac)
    |> Client.add("client_id", @client_id_mac)
    |> Client.add("client_type", "confidential")
    |> Client.add("grant_types", ["password"])
    |> Client.add("jwks", %{"keys" => [
      JOSE.JWK.generate_key({:oct, 32}) |> JOSE.JWK.to_map() |> elem(1)
    ]})
    |> Client.add("token_endpoint_auth_method", "client_secret_jwt")
    |> Client.add("token_endpoint_auth_signing_alg", "HS256")
    |> Client.store()

    Client.gen_new(id: @client_id_ec)
    |> Client.add("client_id", @client_id_ec)
    |> Client.add("client_type", "confidential")
    |> Client.add("grant_types", ["password"])
    |> Client.add("jwks", %{"keys" => [
      JOSE.JWK.generate_key({:ec, "P-256"}) |> JOSE.JWK.to_map() |> elem(1)
    ]})
    |> Client.add("token_endpoint_auth_method", "private_key_jwt")
    |> Client.add("token_endpoint_auth_signing_alg", "ES256")
    |> Client.store()
  end

  test "assertion with invalid signature is rejected", %{conn: conn} do
    Process.put(:oidc_endpoint_token_auth_signing_alg_values_supported, ["HS256"])

    invalid_assertion =
      @client_id_mac
      |> client_assertion()
      |> Kernel.<>("z")

    req_body = %{
      "grant_type" => "password",
      "username" => "user_does_not_exist",
      "password" => "asteroidftw",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion" => invalid_assertion
    }

    response =
      conn
      |> post(Routes.token_path(conn, :handle), req_body)
      |> json_response(401)

    assert response["error"] == "invalid_client"
  end

  test "JWT client authentication (MAC: client_secret_jwt)", %{conn: conn} do
    Process.put(:oidc_endpoint_token_auth_signing_alg_values_supported, ["HS256"])

    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion" => client_assertion(@client_id_mac)
    }

    conn
    |> post(Routes.token_path(conn, :handle), req_body)
    |> json_response(200)
  end

  test "JWT client authentication (EC: private_key_jwt)", %{conn: conn} do
    Process.put(:oidc_endpoint_token_auth_signing_alg_values_supported, ["ES256"])

    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      "client_assertion" => client_assertion(@client_id_ec)
    }

    conn
    |> post(Routes.token_path(conn, :handle), req_body)
    |> json_response(200)
  end

  defp client_assertion(client_id) do
    {:ok, client} = Client.load(client_id)
    jwk_priv = client.attrs["jwks"] |> Map.get("keys") |> List.first()

    %{
      iss: client_id,
      sub: client_id,
      aud: OAuth2.Metadata.get()["token_endpoint"],
      jti: :crypto.strong_rand_bytes(20) |> Base.encode64(),
      exp: now() + 30,
      iat: now()
    }
    |> JOSEUtils.JWS.sign!(jwk_priv, client.attrs["token_endpoint_auth_signing_alg"])
  end

  def now(), do: System.system_time(:second)
end
