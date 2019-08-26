defmodule AsteroidWeb.DeviceControllerTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.OAuth2
  alias Asteroid.Token.DeviceCode

  test "Authorization denied - access denied with no user code", %{conn: conn} do
    authz_request = %AsteroidWeb.DeviceController.Request{params: %{}}

    conn =
      conn
      |> bypass_through(AsteroidWeb.Router, [:browser])
      |> get("/device")
      |> AsteroidWeb.DeviceController.authorization_denied(%{
        authz_request: authz_request,
        user_code: nil,
        error: OAuth2.AccessDeniedError.exception(reason: "abc def")
      })

    assert html_response(conn, 200) =~ "Pairing denied"
  end

  test "Authorization denied - access denied with user code", %{conn: conn} do
    authz_request = %AsteroidWeb.DeviceController.Request{params: %{}}

    DeviceCode.gen_new(user_code: "ABCDEFGH1")
    |> DeviceCode.store(%{})

    conn =
      conn
      |> bypass_through(AsteroidWeb.Router, [:browser])
      |> get("/device")
      |> AsteroidWeb.DeviceController.authorization_denied(%{
        authz_request: authz_request,
        user_code: "ABCDEFGH1",
        error: OAuth2.AccessDeniedError.exception(reason: "abc def")
      })

    assert html_response(conn, 200) =~ "Pairing denied"

    assert {:ok, %DeviceCode{data: %{"status" => "denied"}}} =
             DeviceCode.get_from_user_code("ABCDEFGH1")
  end

  test "Authorization denied - server error", %{conn: conn} do
    authz_request = %AsteroidWeb.DeviceController.Request{params: %{}}

    conn =
      conn
      |> bypass_through(AsteroidWeb.Router, [:browser])
      |> get("/device")
      |> AsteroidWeb.DeviceController.authorization_denied(%{
        authz_request: authz_request,
        user_code: nil,
        error: OAuth2.ServerError.exception(reason: "abc def")
      })

    assert html_response(conn, 400) =~ "Pairing error"
  end

  test "Authorization granted", %{conn: conn} do
    authz_request = %AsteroidWeb.DeviceController.Request{params: %{}}

    DeviceCode.gen_new(user_code: "ABCDEFGH2")
    |> DeviceCode.put_value("exp", now() + 1000)
    |> DeviceCode.put_value("clid", "client_confidential_1")
    |> DeviceCode.store(%{})

    conn =
      conn
      |> bypass_through(AsteroidWeb.Router, [:browser])
      |> get("/device")
      |> AsteroidWeb.DeviceController.authorization_granted(%{
        authz_request: authz_request,
        user_code: "ABCDEFGH2",
        sjid: "user_1",
        granted_scopes: Scope.Set.new([])
      })

    assert html_response(conn, 200) =~ "Pairing successful"

    assert {:ok, %DeviceCode{data: %{"status" => "granted"}}} =
             DeviceCode.get_from_user_code("ABCDEFGH2")
  end
end
