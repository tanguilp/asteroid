defmodule AsteroidWeb.API.OAuth2.TokenEndpointTest do
  import Asteroid.Utils
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
    assert_raise Plug.Parsers.UnsupportedMediaTypeError, fn ->
      conn
      |> put_req_header("content-type", "plain/text")
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), "Some plain text")
      |> json_response(400)
    end

    #FIXME: check json returned value
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

  test "public client with invalid client_id", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "client_id" => "nю-client"
    }

    response =
      conn
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
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

  test "ropc invalid username param", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "not\nweel-formed username",
      "password" => "asteroidftw"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "ropc invalid password param", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "aster\roidftw"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "ropc invalid username & password", %{conn: conn} do
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

  test "ropc valid username", %{conn: conn} do
    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, _} = AccessToken.get(response["access_token"])
    assert {:ok, _} = RefreshToken.get(response["refresh_token"])
    assert response["scope"] == nil
  end

  test "ropc valid username and scopes", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp5", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "scope" => Enum.join(req_scope, " ")
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
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

  test "ropc valid username and invalid scopes", %{conn: conn} do
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

  test "ropc additional scope added by callback", %{conn: conn} do
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

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    Application.put_env(:asteroid, :ropc_scope_callback, ropc_scope_callback_origin)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
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
  # Client Credentials tests
  ##########################################################################

  test "client credentials public client with no credentials: authentication is mandatory", %{conn: conn} do
    req_body = %{
      "grant_type" => "client_credentials"
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

  test "client credentials valid client authentication, token issued", %{conn: conn} do
    req_body = %{
      "grant_type" => "client_credentials"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.claims["sub"] == nil
    assert access_token.claims["client_id"] == "client_confidential_1"
    assert response["scope"] == nil
    assert response["refresh_token"] == nil
  end

  test "client credentials valid client authentication, token issued (incl. refresh token)", %{conn: conn} do
    req_body = %{
      "grant_type" => "client_credentials"
    }

    Application.put_env(:asteroid, :client_credentials_issue_refresh_token, true)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    Application.put_env(:asteroid, :client_credentials_issue_refresh_token, false)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    assert refresh_token.claims["sub"] == nil
    assert access_token.claims["sub"] == nil
    assert refresh_token.claims["client_id"] == "client_confidential_1"
    assert access_token.claims["client_id"] == "client_confidential_1"
    assert response["scope"] == nil
  end

  test "client credentials valid client authentication, token issued with scopes", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp5", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "client_credentials",
      "scope" => Enum.join(req_scope, " ")
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.claims["sub"] == nil
    assert access_token.claims["client_id"] == "client_confidential_1"
    assert response["scope"] == nil
    assert response["refresh_token"] == nil
    assert access_token.claims["scope"] == req_scope
    assert response["scope"] == nil
  end

  test "client credentials additional scope added by callback", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp5", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "client_credentials",
      "scope" => Enum.join(req_scope, " ")
    }

    client_credentials_scope_callback_origin =
      Application.get_env(:asteroid, :client_credentials_scope_callback)
    Application.put_env(:asteroid, :client_credentials_scope_callback,
                        &Asteroid.CallbackTest.add_scp99_scope/2)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    Application.put_env(:asteroid, :client_credentials_scope_callback,
                        client_credentials_scope_callback_origin)

    response= json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    refute access_token.claims["scope"] == req_scope
    assert access_token.claims["sub"] == nil
    assert access_token.claims["client_id"] == "client_confidential_1"
    assert Scope.Set.from_scope_param!(response["scope"]) == MapSet.put(req_scope, "scp99")
  end

  test "client credentials valid client authentication, invalid scope", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp7", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "client_credentials",
      "scope" => Enum.join(req_scope, " ")
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_scope"
  end

  ##########################################################################
  # Refresh token grant types
  ##########################################################################

  test "refresh token public client with credentials: authentication is mandatory", %{conn: conn} do
    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => "xfedwgfzqyrtgmqkeiw"
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

  test "refresh token missing refresh_token parameter", %{conn: conn} do
    req_body = %{
      "grant_type" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "refresh token invalid refresh token param", %{conn: conn} do
    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => "exghzerytshwчервьeyhewavgrw"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "refresh token valid request confidential client", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("sub", "user_1")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.claims["client_id"] == "client_confidential_1"
    assert access_token.claims["sub"] == "user_1"
  end

  test "refresh token valid request public client", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("client_id", "client_public_1")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    conn =
      conn
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.claims["client_id"] == "client_public_1"
  end

  test "refresh token valid request, issuance of new refresh token", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("sub", "user_1")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp4", "scp1"]))
      |> RefreshToken.store(%Asteroid.Context{request: %{:flow => :ropc}})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    Application.put_env(:asteroid, :ropc_issue_new_refresh_token, true)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    Application.put_env(:asteroid, :ropc_issue_new_refresh_token, true)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    refute refresh_token.id == RefreshToken.get(response["refresh_token"])
    assert {:ok, newly_issued_refresh_token} = RefreshToken.get(response["refresh_token"])
    assert {:error, _} = RefreshToken.get(refresh_token.id)
    assert newly_issued_refresh_token.claims["client_id"] == refresh_token.claims["xyz"]
    assert newly_issued_refresh_token.claims["sub"] == refresh_token.claims["xyz"]
    assert newly_issued_refresh_token.claims["iss"] == refresh_token.claims["xyz"]
    assert newly_issued_refresh_token.claims["scope"] == refresh_token.claims["xyz"]
  end

  test "refresh token issued to different client_id", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("client_id", "client_confidential_99")
      |> RefreshToken.put_claim("sub", "user_1")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "nonexistent refresh token", %{conn: conn} do
    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => "rsxzmigjuwx7m9ct2zew45y72o"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "invalid refresh token", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("client_id", "client_confidential_99")
      |> RefreshToken.put_claim("sub", "user_1")
      |> RefreshToken.put_claim("exp", now() - 42)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "refresh token valid request, check scopes of access token", %{conn: conn} do
    scopes = Enum.reduce(1..129, MapSet.new(), fn n, mapset -> MapSet.put(mapset, "scp#{n}") end)

    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.put_claim("scope", scopes)
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id,
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert OAuth2Utils.Scope.Set.from_scope_param!(access_token.claims["scope"]) == scopes
  end
  test "refresh token valid request subset of scope", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp4", "scp1", "scp6"]))
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id,
      "scope" => "scp1 scp4"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert Plug.Conn.get_resp_header(conn, "cache-control") == "no-store"
    assert Plug.Conn.get_resp_header(conn, "pragma", "no-cache")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.claims["client_id"] == "client_confidential_1"
    assert response["scope"] in ["scp1 scp4", "scp4 scp1"]
    assert access_token.claims["scope"] == MapSet.new(["scp1", "scp4"])
  end

  test "refresh token invalid request, scope not included in refresh token", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp4", "scp1", "scp6"]))
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id,
      "scope" => "scp1 scp4 scp2"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_scope"
  end
  ##########################################################################
  # Helper functions
  ##########################################################################

  defp basic_auth_header(client, secret) do
    "Basic " <> Base.encode64(client <> ":" <> secret)
  end

end
