defmodule AsteroidWeb.API.OAuth2.DeviceAuthorizationControllerTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias AsteroidWeb.Router.Helpers, as: Routes
  alias Asteroid.Token.DeviceCode

  # error cases

  test "no credentials for confidential client", %{conn: conn} do
    req = %{}

    conn =
      conn
      |> post(Routes.device_authorization_path(conn, :handle), req)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
             ~s(Basic realm="Asteroid")

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  test "invalid basic credentials for confidential client", %{conn: conn} do
    req_body = %{}

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "invalid"))
      |> post(Routes.device_authorization_path(conn, :handle), req_body)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
             ~s(Basic realm="Asteroid")

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  test "unknown public client", %{conn: conn} do
    req = %{"client_id" => "unkown_public_client"}

    conn =
      conn
      |> post(Routes.device_authorization_path(conn, :handle), req)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
             ~s(Basic realm="Asteroid")

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  test "malformed public client", %{conn: conn} do
    req = %{"client_id" => "unkown⌿public_client"}

    response =
      conn
      |> post(Routes.device_authorization_path(conn, :handle), req)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "malformed scope parameter", %{conn: conn} do
    req = %{
      "client_id" => "client_public_1",
      "scope" => "scp1 scp2 scpů"
    }

    response =
      conn
      |> post(Routes.device_authorization_path(conn, :handle), req)
      |> json_response(400)

    assert response["error"] == "invalid_scope"
  end

  test "unauthorized grant type", %{conn: conn} do
    req = %{"client_id" => "client_confidential_2"}

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(Routes.device_authorization_path(conn, :handle), req)
      |> json_response(400)

    assert response["error"] == "unauthorized_client"
  end

  test "unauthorized scope", %{conn: conn} do
    req = %{
      "client_id" => "client_public_1",
      "scope" => "scp1 scp2 scp9"
    }

    response =
      conn
      |> post(Routes.device_authorization_path(conn, :handle), req)
      |> json_response(400)

    assert response["error"] == "invalid_scope"
  end

  # success cases

  test "successful request confidential client without scopes", %{conn: conn} do
    req = %{}

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.device_authorization_path(conn, :handle), req)
      |> json_response(200)

    assert is_binary(response["device_code"])
    assert is_binary(response["user_code"])
    assert is_binary(response["verification_uri"])
    assert is_binary(response["verification_uri_complete"])
    assert is_integer(response["expires_in"])

    assert response["interval"] ==
             astrenv(:oauth2_flow_device_authorization_rate_limiter_interval)

    {:ok, device_code} = DeviceCode.get(response["device_code"])

    assert device_code.user_code == response["user_code"]
    assert device_code.data["clid"] == "client_confidential_1"
    assert device_code.data["sjid"] == nil
    assert device_code.data["requested_scopes"] == []
    assert device_code.data["granted_scopes"] == nil
    assert device_code.data["status"] == "authorization_pending"
  end

  test "successful request confidential client with scopes", %{conn: conn} do
    req = %{"scope" => "scp1 scp2 scp5 scp6"}

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.device_authorization_path(conn, :handle), req)
      |> json_response(200)

    assert is_binary(response["device_code"])
    assert is_binary(response["user_code"])
    assert is_binary(response["verification_uri"])
    assert is_binary(response["verification_uri_complete"])
    assert is_integer(response["expires_in"])

    assert response["interval"] ==
             astrenv(:oauth2_flow_device_authorization_rate_limiter_interval)

    # there is not such an attribute returned
    assert response["scope"] == nil

    {:ok, device_code} = DeviceCode.get(response["device_code"])

    assert device_code.user_code == response["user_code"]
    assert device_code.data["clid"] == "client_confidential_1"
    assert device_code.data["sjid"] == nil
    assert device_code.data["granted_scopes"] == nil

    assert Scope.Set.equal?(
             Scope.Set.new(device_code.data["requested_scopes"]),
             Scope.Set.new(["scp1", "scp2", "scp6", "scp5"])
           )

    assert device_code.data["status"] == "authorization_pending"
  end

  test "successful request public client with scopes", %{conn: conn} do
    req = %{
      "scope" => "scp1 scp3 scp5",
      "client_id" => "client_public_1"
    }

    response =
      conn
      |> post(Routes.device_authorization_path(conn, :handle), req)
      |> json_response(200)

    assert is_binary(response["device_code"])
    assert is_binary(response["user_code"])
    assert is_binary(response["verification_uri"])
    assert is_binary(response["verification_uri_complete"])
    assert is_integer(response["expires_in"])

    assert response["interval"] ==
             astrenv(:oauth2_flow_device_authorization_rate_limiter_interval)

    # there is not such an attribute returned
    assert response["scope"] == nil

    {:ok, device_code} = DeviceCode.get(response["device_code"])

    assert device_code.user_code == response["user_code"]
    assert device_code.data["clid"] == "client_public_1"
    assert device_code.data["sjid"] == nil
    assert device_code.data["granted_scopes"] == nil

    assert Scope.Set.equal?(
             Scope.Set.new(device_code.data["requested_scopes"]),
             Scope.Set.new(["scp1", "scp3", "scp5"])
           )

    assert device_code.data["status"] == "authorization_pending"
  end

  defp basic_auth_header(client, secret) do
    "Basic " <> Base.encode64(client <> ":" <> secret)
  end
end
