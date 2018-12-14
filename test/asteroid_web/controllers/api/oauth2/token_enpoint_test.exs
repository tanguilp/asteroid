defmodule AsteroidWeb.API.OAuth2.TokenEndpointTest do
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias OAuth2Utils.Scope
  use AsteroidWeb.ConnCase

  ##########################################################################
  # General tests
  ##########################################################################

  test "no grant_type", %{conn: conn} do
    response =
      conn
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle))
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "invalid content-type", %{conn: conn} do
    response =
      conn
      |> put_req_header("content-type", "plain/text")
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), "Some plain text")
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "invalid grant_type", %{conn: conn} do
    response =
      conn
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle),
                                                             %{"grant_type" => "unknown"})
      |> json_response(400)

    assert response["error"] == "unsupported_grant_type"
  end

  test "no credentials for confidential client", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw"
    }

    conn = post(conn, AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="always erroneous client password")

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="Asteroid")

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Bearer realm="Asteroid")

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  # next 2 tests testing that:
  #
  # If the
  # client attempted to authenticate via the "Authorization"
  # request header field, the authorization server MUST
  # respond with an HTTP 401 (Unauthorized) status code and
  # include the "WWW-Authenticate" response header field
  # matching the authentication scheme used by the client.
  #
  # from https://tools.ietf.org/html/rfc6749#section-5.2
  test "invalid basic credentials for confidential client", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("invalid_client", "secret"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm=)

    refute Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Bearer )

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  test "invalid bearer credentials for confidential client", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw"
    }

    conn =
      conn
      |> put_req_header("authorization", "Bearer weeoqxymrzmuixrtgq")
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    refute Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm=)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Bearer )

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  test "public client with credentials does not authenticate", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "client_id" => "client_public_2"
    }

    conn = post(conn, AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="always erroneous client password")

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="Asteroid")

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Bearer realm="Asteroid")

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  test "grant type not authorized for client", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "unauthorized_client"
  end

  test "Malformed scope", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "scope" => "scp1   scp5"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_scope"
  end

  ##########################################################################
  # ROPC tests
  ##########################################################################

  test "ropc missing parameter", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "password" => "asteroidftw"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "invalid username & password", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_does_not_exist",
      "password" => "asteroidftw"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "valid username", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, _} = AccessToken.get(response["access_token"])
    assert {:ok, _} = RefreshToken.get(response["refresh_token"])
    assert response["scope"] == nil
  end

  test "valid username and scopes", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp5", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "scope" => Enum.join(req_scope, " ")
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    assert refresh_token.claims["scope"] == req_scope
    assert access_token.claims["scope"] == req_scope
    assert refresh_token.claims["sub"] == req_body["username"]
    assert access_token.claims["sub"] == req_body["username"]
    assert refresh_token.claims["client_id"] == "client_confidential_1"
    assert access_token.claims["client_id"] == "client_confidential_1"
    assert response["scope"] == nil
  end

  test "valid username and invalid scopes", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp7", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "scope" => Enum.join(req_scope, " ")
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_scope"
  end

  test "additional scope added by callback", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp5", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "scope" => Enum.join(req_scope, " ")
    }

    ropc_scope_callback_origin = Application.get_env(:asteroid, :ropc_scope_callback)
    Application.put_env(:asteroid, :ropc_scope_callback,
                        &Asteroid.CallbackTest.add_scp99_scope/2)

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    Application.put_env(:asteroid, :ropc_scope_callback, ropc_scope_callback_origin)

    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    refute refresh_token.claims["scope"] == req_scope
    refute access_token.claims["scope"] == req_scope
    assert refresh_token.claims["sub"] == req_body["username"]
    assert access_token.claims["sub"] == req_body["username"]
    assert refresh_token.claims["client_id"] == "client_confidential_1"
    assert access_token.claims["client_id"] == "client_confidential_1"
    assert Scope.Set.from_scope_param!(response["scope"]) == MapSet.put(req_scope, "scp99")
  end

  ##########################################################################
  # Helper functions
  ##########################################################################

  defp basic_auth_header(client, secret) do
    "Basic " <> Base.encode64(client <> ":" <> secret)
  end

end
