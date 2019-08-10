defmodule AsteroidWeb.API.OAuth2.TokenEndpointTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Utils

  alias AsteroidWeb.Router.Helpers, as: Routes
  alias Asteroid.Token.{RefreshToken, AccessToken, AuthorizationCode, DeviceCode}
  alias OAuth2Utils.Scope
  alias Asteroid.OAuth2
  alias Asteroid.Crypto

  ##########################################################################
  # General tests
  ##########################################################################

  test "no grant_type", %{conn: conn} do
    response =
      conn
      |> post(Routes.token_endpoint_path(conn, :handle))
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "invalid content-type", %{conn: conn} do
    assert_raise Plug.Parsers.UnsupportedMediaTypeError, fn ->
      conn
      |> put_req_header("content-type", "plain/text")
      |> post(Routes.token_endpoint_path(conn, :handle), "Some plain text")
      |> json_response(400)
    end
  end

  test "invalid grant_type", %{conn: conn} do
    response =
      conn
      |> post(Routes.token_endpoint_path(conn, :handle),
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

    conn = post(conn, Routes.token_endpoint_path(conn, :handle), req_body)

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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

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

    conn = post(conn, Routes.token_endpoint_path(conn, :handle), req_body)

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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    assert MapSet.equal?(MapSet.new(refresh_token.data["scope"]), req_scope)
    assert MapSet.equal?(MapSet.new(access_token.data["scope"]), req_scope)
    assert refresh_token.data["sub"] == req_body["username"]
    assert access_token.data["sub"] == req_body["username"]
    assert refresh_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["client_id"] == "client_confidential_1"
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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

    f = fn
      scopes, _ctx ->
        Scope.Set.put(scopes, "scp99")
    end

    Process.put(:oauth2_scope_callback, f)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    assert Scope.Set.equal?(Scope.Set.new(refresh_token.data["scope"]),
                            Scope.Set.put(req_scope, "scp99"))
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.put(req_scope, "scp99"))
    assert refresh_token.data["sub"] == req_body["username"]
    assert access_token.data["sub"] == req_body["username"]
    assert refresh_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["client_id"] == "client_confidential_1"
    assert Scope.Set.equal?(Scope.Set.from_scope_param!(response["scope"]),
                            Scope.Set.put(req_scope, "scp99"))
  end

  test "ropc access and refresh token lifetime limited by scope config", %{conn: conn} do
    req_scope = MapSet.new(["scp1", "scp2", "scp3", "scp4"])

    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw",
      "scope" => Enum.join(req_scope, " ")
    }

    Process.put(:oauth2_flow_ropc_scope_config, [
      scopes: %{
        "scp1" => [],
        "scp2" => [],
        "scp3" => [],
        "scp4" => [max_refresh_token_lifetime: 1000, max_access_token_lifetime: 30]
      }])

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)
    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert response["expires_in"] >= 29
    assert response["expires_in"] <= 31
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    assert Scope.Set.equal?(Scope.Set.new(refresh_token.data["scope"]),
                            Scope.Set.new(req_scope))
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.new(req_scope))
    assert refresh_token.data["exp"] >= now() + 999
    assert refresh_token.data["exp"] <= now() + 1001
    assert access_token.data["exp"] >= now() + 29
    assert access_token.data["exp"] <= now() + 31
  end

  test "ropc valid username, JWS access token", %{conn: conn} do
    Process.put(:oauth2_flow_ropc_access_token_serialization_format, :jws)
    Process.put(:oauth2_flow_ropc_access_token_signing_key, "key_auto_sig")
    Process.put(:oauth2_flow_ropc_access_token_signing_alg, "RS384")

    req_body = %{
      "grant_type" => "password",
      "username" => "user_1",
      "password" => "asteroidftw"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, _} = RefreshToken.get(response["refresh_token"])
    assert response["scope"] == nil

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, _, _} = JOSE.JWS.verify_strict(jwk, ["RS384"], response["access_token"])
  end

  ##########################################################################
  # Client Credentials tests
  ##########################################################################

  test "client credentials public client with no credentials: authentication is mandatory", %{conn: conn} do
    req_body = %{
      "grant_type" => "client_credentials"
    }

    conn = post(conn, Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 401)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="always erroneous client password")
    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="Asteroid")
    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Bearer realm="Asteroid")
    assert response["error"] == "invalid_client"
  end

  test "client credentials confidential client with invalid credentials: authentication is mandatory", %{conn: conn} do
    req_body = %{
      "grant_type" => "client_credentials"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "invalid"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 401)

    # here we should only have one value in this header because the authentication failed, we
    # are not in the case there is NO authentication attempt
    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="Asteroid")
    assert response["error"] == "invalid_client"
  end

  test "client credentials valid confidential client authentication, token issued", %{conn: conn} do
    req_body = %{
      "grant_type" => "client_credentials"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.data["sub"] == nil
    assert access_token.data["client_id"] == "client_confidential_1"
    assert response["scope"] == nil
    assert response["refresh_token"] == nil
  end

  test "client credentials valid client authentication, token issued (incl. refresh token)", %{conn: conn} do
    req_body = %{
      "grant_type" => "client_credentials"
    }

    Process.put(:oauth2_flow_client_credentials_issue_refresh_token_init, true)
    Process.put(:oauth2_flow_client_credentials_refresh_token_lifetime, 60 * 60)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    assert refresh_token.data["sub"] == nil
    assert access_token.data["sub"] == nil
    assert refresh_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["client_id"] == "client_confidential_1"
    assert response["scope"] == nil
  end

  test "client credentials valid client authentication, access token issued with scopes", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp5", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "client_credentials",
      "scope" => Enum.join(req_scope, " ")
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.data["sub"] == nil
    assert access_token.data["client_id"] == "client_confidential_1"
    assert response["scope"] == nil
    assert response["refresh_token"] == nil
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]), req_scope)
    assert response["scope"] == nil
  end

  test "client credentials additional scope added by callback", %{conn: conn} do
    req_scope = MapSet.new(["scp3", "scp5", "scp6", "scp1"])

    req_body = %{
      "grant_type" => "client_credentials",
      "scope" => Enum.join(req_scope, " ")
    }

    f = fn
      scopes, _ctx ->
        Scope.Set.put(scopes, "scp99")
    end

    Process.put(:oauth2_scope_callback, f)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.data["scope"] != nil
    assert access_token.data["sub"] == nil
    assert access_token.data["client_id"] == "client_confidential_1"
    assert Scope.Set.equal?(Scope.Set.from_scope_param!(response["scope"]),
                            Scope.Set.put(req_scope, "scp99"))
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_scope"
  end

  test "client credentials access and refresh token lifetime limited by scope config", %{conn: conn} do
    req_scope = MapSet.new(["scp1", "scp2", "scp3", "scp4"])

    req_body = %{
      "grant_type" => "client_credentials",
      "scope" => Enum.join(req_scope, " ")
    }

    Process.put(:oauth2_flow_client_credentials_scope_config, [
      scopes: %{
        "scp1" => [],
        "scp2" => [],
        "scp3" => [],
        "scp4" => [max_refresh_token_lifetime: 1000, max_access_token_lifetime: 30]
      }])
    Process.put(:oauth2_flow_client_credentials_issue_refresh_token_init, true)
    Process.put(:oauth2_flow_client_credentials_refresh_token_lifetime, 60_000)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert response["expires_in"] >= 29
    assert response["expires_in"] <= 31
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    assert Scope.Set.equal?(Scope.Set.new(refresh_token.data["scope"]),
                            Scope.Set.new(req_scope))
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.new(req_scope))
    assert refresh_token.data["exp"] >= now() + 999
    assert refresh_token.data["exp"] <= now() + 1001
    assert access_token.data["exp"] >= now() + 29
    assert access_token.data["exp"] <= now() + 31
  end

  test "client credentials valid confidential client authentication, JWS token issued", %{conn: conn} do
    Process.put(:oauth2_flow_client_credentials_access_token_serialization_format, :jws)
    Process.put(:oauth2_flow_client_credentials_access_token_signing_key, "key_auto_sig")
    Process.put(:oauth2_flow_client_credentials_access_token_signing_alg, "RS384")

    req_body = %{
      "grant_type" => "client_credentials"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert response["scope"] == nil
    assert response["refresh_token"] == nil

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, access_token_str, _} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], response["access_token"])

    access_token_data = Jason.decode!(access_token_str)

    assert access_token_data["sub"] == nil
    assert access_token_data["client_id"] == "client_confidential_1"
  end
  ##########################################################################
  # Refresh token grant types
  ##########################################################################

  test "refresh token public client with credentials: authentication is mandatory", %{conn: conn} do
    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => "xfedwgfzqyrtgmqkeiw"
    }

    conn = post(conn, Routes.token_endpoint_path(conn, :handle), req_body)

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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "refresh token valid request confidential client", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("sub", "user_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> RefreshToken.store(%{flow: :ropc})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["sub"] == "user_1"
  end

  #FIXME: start here
  test "refresh token valid request public client", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_public_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> RefreshToken.store(%{flow: :ropc})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id,
      "client_id" => "client_public_1"
    }

    conn =
      conn
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.data["client_id"] == "client_public_1"
  end

  test "refresh token valid request, issuance of new refresh token", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("sub", "user_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", ["scp3", "scp4", "scp1"])
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "ropc")
      |> RefreshToken.store(%{:flow => :ropc})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    Process.put(:oauth2_flow_ropc_issue_refresh_token_refresh, true)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    refute refresh_token.id == RefreshToken.get(response["refresh_token"])
    assert {:ok, newly_issued_refresh_token} = RefreshToken.get(response["refresh_token"])
    assert {:error, _} = RefreshToken.get(refresh_token.id)
    assert newly_issued_refresh_token.data["client_id"] == refresh_token.data["client_id"]
    assert newly_issued_refresh_token.data["sub"] == refresh_token.data["sub"]
    assert newly_issued_refresh_token.data["iss"] == refresh_token.data["iss"]
    assert Scope.Set.equal?(
      Scope.Set.new(newly_issued_refresh_token.data["scope"]),
      Scope.Set.new(refresh_token.data["scope"]))
  end

  test "refresh token valid request, access and refresh token lifetime limited by scope config",
    %{conn: conn}
  do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("sub", "user_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", ["scp3", "scp4", "scp1"])
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "ropc")
      |> RefreshToken.store(%{:flow => :ropc})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    Process.put(:oauth2_flow_ropc_scope_config, [
      scopes: %{
        "scp1" => [],
        "scp2" => [],
        "scp3" => [],
        "scp4" => [max_refresh_token_lifetime: 1000, max_access_token_lifetime: 30]
      }])
    Process.put(:oauth2_flow_ropc_issue_refresh_token_refresh, true)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert response["expires_in"] >= 29
    assert response["expires_in"] <= 31
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, newly_issued_refresh_token} = RefreshToken.get(response["refresh_token"])
    assert Scope.Set.equal?(
      Scope.Set.new(newly_issued_refresh_token.data["scope"]),
      Scope.Set.new(refresh_token.data["scope"]))
    assert newly_issued_refresh_token.data["exp"] >= now() + 999
    assert newly_issued_refresh_token.data["exp"] <= now() + 1001
    assert access_token.data["exp"] >= now() + 29
    assert access_token.data["exp"] <= now() + 31
  end

  test "refresh token issued to different client_id", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_99")
      |> RefreshToken.put_value("sub", "user_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> RefreshToken.store(%{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
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
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "invalid refresh token", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_99")
      |> RefreshToken.put_value("sub", "user_1")
      |> RefreshToken.put_value("exp", now() - 42)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.store(%{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "refresh token valid request, check scopes of access token", %{conn: conn} do
    scopes = Enum.reduce(1..129, MapSet.new(), fn n, mapset -> MapSet.put(mapset, "scp#{n}") end)

    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", scopes)
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "ropc")
      |> RefreshToken.store(%{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id,
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]), scopes)
  end

  test "refresh token valid request subset of scope", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", ["scp3", "scp4", "scp1", "scp6"])
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "ropc")
      |> RefreshToken.store(%{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id,
      "scope" => "scp1 scp4"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert access_token.data["client_id"] == "client_confidential_1"
    assert response["scope"] == nil
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.new(["scp1", "scp4"]))
  end

  test "refresh token invalid request, scope not included in refresh token", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", ["scp3", "scp4", "scp1", "scp6"])
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "ropc")
      |> RefreshToken.store(%{})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id,
      "scope" => "scp1 scp4 scp2"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_scope"
  end

  test "refresh token valid request confidential client, JWS access token", %{conn: conn} do
    Process.put(:oauth2_flow_ropc_access_token_serialization_format, :jws)
    Process.put(:oauth2_flow_ropc_access_token_signing_key, "key_auto_sig")
    Process.put(:oauth2_flow_ropc_access_token_signing_alg, "RS384")

    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("sub", "user_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "ropc")
      |> RefreshToken.store(%{flow: :ropc})

    req_body = %{
      "grant_type" => "refresh_token",
      "refresh_token" => refresh_token.id
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)

    response = json_response(conn, 200)

    assert "no-store" in Plug.Conn.get_resp_header(conn, "cache-control")
    assert "no-cache" in Plug.Conn.get_resp_header(conn, "pragma")
    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, access_token_str, _} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], response["access_token"])

    access_token_data = Jason.decode!(access_token_str)

    assert access_token_data["client_id"] == "client_confidential_1"
    assert access_token_data["sub"] == "user_1"
  end

  ##########################################################################
  # Authorization code grant types
  ##########################################################################

  test "grant type code not enabled", %{conn: conn} do
    req_body = %{
      "grant_type" => "authorization_code",
      "code" => "eigzjewochgwortuxwh",
      "redirect_uri" => "https://www.example.com"
    }

    Process.put(:oauth2_grant_types_enabled, [:password, :client_credentials, :refresh_token])

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "unsupported_grant_type"
  end

  test "grant type code public client doesn't provide the client_id parameter", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_public_1")
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(401)

    assert response["error"] == "invalid_client"
  end

  test "grant type code missing code parameter", %{conn: conn} do
    req_body = %{
      "grant_type" => "authorization_code",
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "grant type code missing redirect_uri parameter", %{conn: conn} do
    req_body = %{
      "grant_type" => "authorization_code",
      "code" => "eigzjewochgwortuxwh"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "grant type code confidential client uses a code issued to another client", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_2")
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "grant type code confidential client uses a code issued to the request's client_id", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_2")
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com",
      "client_id" => "client_confidential_2"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "grant type code public client uses a code issued to the erroneous request's client_id", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_public_2")
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com",
      "client_id" => "client_public_1"
    }

    response =
      conn
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "grant type code confidential client uses an expired code", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("exp", now() - 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "grant type code confidential client uses an nonexistent code", %{conn: conn} do
    req_body = %{
      "grant_type" => "authorization_code",
      "code" => "eigzjewochgwortuxwh",
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "grant type code confidential client uses different redirect URIs", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://example.org/auth/web/"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "grant type code confidential client is not authorized to use this grant type", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_2")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "unauthorized_client"
  end

  test "grant type code success with refresh token without scopes", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    # lets sleep a bit so that we can check that iat and exp of released access and refresh
    # tokens are not the same as the ones of the authorization code, which would mean they
    # are copied while they shouldn't
    :timer.sleep(1500)

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])

    assert access_token.refresh_token_id == refresh_token.id

    assert access_token.data["client_id"] == code.data["client_id"]
    assert access_token.data["sub"] == code.data["sub"]
    assert access_token.data["issuer"] == code.data["issuer"]

    refute access_token.data["iat"] == code.data["iat"]
    refute access_token.data["exp"] == code.data["exp"]

    assert refresh_token.data["client_id"] == code.data["client_id"]
    assert refresh_token.data["sub"] == code.data["sub"]
    assert refresh_token.data["__asteroid_oauth2_initial_flow"] ==
      code.data["__asteroid_oauth2_initial_flow"]
    assert refresh_token.data["issuer"] == code.data["issuer"]

    refute refresh_token.data["iat"] == code.data["iat"]
    refute refresh_token.data["exp"] == code.data["exp"]
  end

  test "grant type code success with refresh token with scopes", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("requested_scopes", Scope.Set.new(["scp1", "scp2", "scp5"]))
      |> AuthorizationCode.put_value("granted_scopes", Scope.Set.new(["scp1", "scp2", "scp5"]))
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    # lets sleep a bit so that we can check that iat and exp of released access and refresh
    # tokens are not the same as the ones of the authorization code, which would mean they
    # are copied while they shouldn't
    :timer.sleep(1500)

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert response["scope"] == nil
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])

    assert access_token.refresh_token_id == refresh_token.id

    assert access_token.data["client_id"] == code.data["client_id"]
    assert access_token.data["sub"] == code.data["sub"]
    assert access_token.data["issuer"] == code.data["issuer"]
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.new(code.data["granted_scopes"]))

    refute access_token.data["iat"] == code.data["iat"]
    refute access_token.data["exp"] == code.data["exp"]

    assert refresh_token.data["client_id"] == code.data["client_id"]
    assert refresh_token.data["sub"] == code.data["sub"]
    assert refresh_token.data["__asteroid_oauth2_initial_flow"] ==
      code.data["__asteroid_oauth2_initial_flow"]
    assert refresh_token.data["issuer"] == code.data["issuer"]
    assert Scope.Set.equal?(Scope.Set.new(refresh_token.data["scope"]),
                            Scope.Set.new(code.data["granted_scopes"]))

    refute refresh_token.data["iat"] == code.data["iat"]
    refute refresh_token.data["exp"] == code.data["exp"]
  end

  test "grant type code success with refresh token with granted and requested scope different",
  %{conn: conn}
  do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("requested_scopes", Scope.Set.new(["scp1", "scp2", "scp5"]))
      |> AuthorizationCode.put_value("granted_scopes", Scope.Set.new(["scp1", "scp5"]))
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert Scope.Set.equal?(Scope.Set.new(response["scope"]),
                            Scope.Set.new(code.data["granted_scopes"]))

    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])

    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.new(code.data["granted_scopes"]))

    assert Scope.Set.equal?(Scope.Set.new(refresh_token.data["scope"]),
                            Scope.Set.new(code.data["granted_scopes"]))
  end

  test "grant type code success with access and refresh token lifetime limited by scope config", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("requested_scopes",
                                     Scope.Set.new(["scp1", "scp2", "scp3", "scp4"]))
      |> AuthorizationCode.put_value("granted_scopes",
                                    Scope.Set.new(["scp1", "scp2", "scp3", "scp4"]))
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    # lets sleep a bit so that we can check that iat and exp of released access and refresh
    # tokens are not the same as the ones of the authorization code, which would mean they
    # are copied while they shouldn't
    :timer.sleep(1500)

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    Process.put(:oauth2_flow_authorization_code_scope_config, [
      scopes: %{
        "scp1" => [],
        "scp2" => [],
        "scp3" => [],
        "scp4" => [max_refresh_token_lifetime: 1000, max_access_token_lifetime: 30]
      }])

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert response["expires_in"] >= 29
    assert response["expires_in"] <= 31
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])
    assert refresh_token.data["exp"] >= now() + 999
    assert refresh_token.data["exp"] <= now() + 1001
    assert access_token.data["exp"] >= now() + 29
    assert access_token.data["exp"] <= now() + 31
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.new(code.data["granted_scopes"]))
    assert Scope.Set.equal?(Scope.Set.new(refresh_token.data["scope"]),
                            Scope.Set.new(code.data["granted_scopes"]))
  end

  test "grant type code success without refresh token without scopes", %{conn: conn} do
    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    # lets sleep a bit so that we can check that iat and exp of released access and refresh
    # tokens are not the same as the ones of the authorization code, which would mean they
    # are copied while they shouldn't
    :timer.sleep(1500)

    Process.put(:oauth2_flow_authorization_code_issue_refresh_token_init, false)

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, access_token} = AccessToken.get(response["access_token"])
    assert response["refresh_token"] == nil

    assert access_token.refresh_token_id == nil

    assert access_token.data["client_id"] == code.data["client_id"]
    assert access_token.data["sub"] == code.data["sub"]
    assert access_token.data["issuer"] == code.data["issuer"]

    refute access_token.data["iat"] == code.data["iat"]
    refute access_token.data["exp"] == code.data["exp"]
  end

  test "grant type code success with refresh token without scopes, with JWS access token", %{conn: conn} do
    Process.put(:oauth2_flow_authorization_code_access_token_serialization_format, :jws)
    Process.put(:oauth2_flow_authorization_code_access_token_signing_key, "key_auto_sig")
    Process.put(:oauth2_flow_authorization_code_access_token_signing_alg, "RS512")

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    # lets sleep a bit so that we can check that iat and exp of released access and refresh
    # tokens are not the same as the ones of the authorization code, which would mean they
    # are copied while they shouldn't
    :timer.sleep(1500)

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, access_token_str, _} =
      JOSE.JWS.verify_strict(jwk, ["RS512"], response["access_token"])

    access_token_data = Jason.decode!(access_token_str)

    assert {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])

    assert access_token_data["client_id"] == code.data["client_id"]
    assert access_token_data["sub"] == code.data["sub"]
    assert access_token_data["issuer"] == code.data["issuer"]

    refute access_token_data["iat"] == code.data["iat"]
    refute access_token_data["exp"] == code.data["exp"]

    assert refresh_token.data["client_id"] == code.data["client_id"]
    assert refresh_token.data["sub"] == code.data["sub"]
    assert refresh_token.data["__asteroid_oauth2_initial_flow"] ==
      code.data["__asteroid_oauth2_initial_flow"]
    assert refresh_token.data["issuer"] == code.data["issuer"]

    refute refresh_token.data["iat"] == code.data["iat"]
    refute refresh_token.data["exp"] == code.data["exp"]
  end

  test "PKCE - grant type code success with plain code challenge method", %{conn: conn} do
    code_verifier = String.duplicate("r", 50)

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge", code_verifier)
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge_method", "plain")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com",
      "code_verifier" => code_verifier
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, _} = AccessToken.get(response["access_token"])
    assert {:ok, _} = RefreshToken.get(response["refresh_token"])
  end

  test "PKCE - grant type code success with S256 code challenge method", %{conn: conn} do
    code_verifier = String.duplicate("r", 50)
    code_challenge = Base.url_encode64(:crypto.hash(:sha256, code_verifier), padding: false)

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge", code_challenge)
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge_method", "S256")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com",
      "code_verifier" => code_verifier
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response["token_type"] == "bearer"
    assert is_integer(response["expires_in"])
    assert {:ok, _} = AccessToken.get(response["access_token"])
    assert {:ok, _} = RefreshToken.get(response["refresh_token"])
  end

  test "PKCE - grant type code failure with invalid code verifier", %{conn: conn} do
    code_verifier = String.duplicate("r", 50)
    code_challenge = Base.url_encode64(:crypto.hash(:sha256, code_verifier), padding: false)
    code_verifier = code_verifier <> "_invalid"

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge", code_challenge)
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge_method", "S256")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com",
      "code_verifier" => code_verifier
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "PKCE - grant type code failure with absent code verifier", %{conn: conn} do
    code_verifier = String.duplicate("r", 50)
    code_challenge = Base.url_encode64(:crypto.hash(:sha256, code_verifier), padding: false)

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "code")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge", code_challenge)
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge_method", "S256")
      |> AuthorizationCode.put_value("issuer", OAuth2.issuer())
      |> AuthorizationCode.store()

    req_body = %{
      "grant_type" => "authorization_code",
      "code" => AuthorizationCode.serialize(code),
      "redirect_uri" => "https://www.example.com"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  ##########################################################################
  # Device code grant type
  ##########################################################################

  test "Device flow: missing device_code parameter", %{conn: conn} do
    req_body = %{"grant_type" => "urn:ietf:params:oauth:grant-type:device_code"}

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "Device flow: invalid device code", %{conn: conn} do
    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => "non_existant_code"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "Device flow: deactivated grant type", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI1")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", [])
      |> DeviceCode.put_value("granted_scopes", [])
      |> DeviceCode.put_value("status", "granted")
      |> DeviceCode.store(%{})

    Process.put(:oauth2_grant_types_enabled, [])

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "unsupported_grant_type"
  end

  test "Device flow: client unauthorized to use device flow", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI2")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", [])
      |> DeviceCode.put_value("granted_scopes", [])
      |> DeviceCode.put_value("status", "granted")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "unauthorized_client"
  end

  test "Device flow: device code issued to another client", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI3")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_2")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", [])
      |> DeviceCode.put_value("granted_scopes", [])
      |> DeviceCode.put_value("status", "granted")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_grant"
  end

  test "Device flow: authorization is pending", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI4")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", [])
      |> DeviceCode.put_value("granted_scopes", [])
      |> DeviceCode.put_value("status", "authorization_pending")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "authorization_pending"
  end

  test "Device flow: access was denied by the user", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI5")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", [])
      |> DeviceCode.put_value("granted_scopes", [])
      |> DeviceCode.put_value("status", "denied")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "access_denied"
  end

  test "Device flow: device code is expired", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI6")
      |> DeviceCode.put_value("exp", now() - 3)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", [])
      |> DeviceCode.put_value("granted_scopes", [])
      |> DeviceCode.put_value("status", "authorization_pending")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "expired_token"
  end

  test "Device flow: rate limited", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI7")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", [])
      |> DeviceCode.put_value("granted_scopes", [])
      |> DeviceCode.put_value("status", "authorization_pending")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    [_, _, _, _, _, response] =
      for _ <- 1..6 do
        conn
        |> put_req_header("authorization",
                          basic_auth_header("client_confidential_1", "password1"))
        |> post(Routes.token_endpoint_path(conn, :handle), req_body)
        |> json_response(400)
      end

    assert response["error"] == "slow_down"
  end

  test "Device flow: success, no scopes", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI8")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", [])
      |> DeviceCode.put_value("granted_scopes", [])
      |> DeviceCode.put_value("status", "granted")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert is_binary(response["refresh_token"])
    assert is_binary(response["access_token"])
    assert is_integer(response["expires_in"])
    assert response["token_type"] == "bearer"
    assert response["scope"] == nil
    assert {:error, _} = DeviceCode.get(device_code.id)

    {:ok, access_token} = AccessToken.get(response["access_token"])
    {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])

    assert refresh_token.data["client_id"] == "client_confidential_1"
    assert refresh_token.data["sub"] == "user_1"
    assert refresh_token.data["scope"] == []
    assert access_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["sub"] == "user_1"
    assert access_token.data["scope"] == []
    assert access_token.refresh_token_id == refresh_token.id
  end

  test "Device flow: success with scopes (same as requested)", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI9")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", ["scp1", "scp4", "scp5"])
      |> DeviceCode.put_value("granted_scopes", ["scp1", "scp4", "scp5"])
      |> DeviceCode.put_value("status", "granted")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert is_binary(response["refresh_token"])
    assert is_binary(response["access_token"])
    assert is_integer(response["expires_in"])
    assert response["token_type"] == "bearer"
    assert response["scope"] == nil
    assert {:error, _} = DeviceCode.get(device_code.id)

    {:ok, access_token} = AccessToken.get(response["access_token"])
    {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])

    assert refresh_token.data["client_id"] == "client_confidential_1"
    assert refresh_token.data["sub"] == "user_1"
    assert Scope.Set.equal?(Scope.Set.new(refresh_token.data["scope"]),
                            Scope.Set.new(device_code.data["granted_scopes"]))
    assert access_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["sub"] == "user_1"
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.new(device_code.data["granted_scopes"]))
    assert access_token.refresh_token_id == refresh_token.id
  end

  test "Device flow: success with scopes (different as requested)", %{conn: conn} do
    {:ok, device_code} =
      DeviceCode.gen_new(user_code: "ABCDEFGHI10")
      |> DeviceCode.put_value("exp", now() + 1000)
      |> DeviceCode.put_value("clid", "client_confidential_1")
      |> DeviceCode.put_value("sjid", "user_1")
      |> DeviceCode.put_value("requested_scopes", ["scp1", "scp4", "scp5"])
      |> DeviceCode.put_value("granted_scopes", ["scp1", "scp4"])
      |> DeviceCode.put_value("status", "granted")
      |> DeviceCode.store(%{})

    req_body = %{
      "grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
      "device_code" => device_code.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.token_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert is_binary(response["refresh_token"])
    assert is_binary(response["access_token"])
    assert is_integer(response["expires_in"])
    assert response["token_type"] == "bearer"
    assert Enum.sort(Scope.Set.from_scope_param!(response["scope"])) ==
      Enum.sort(device_code.data["granted_scopes"])
    assert {:error, _} = DeviceCode.get(device_code.id)

    {:ok, access_token} = AccessToken.get(response["access_token"])
    {:ok, refresh_token} = RefreshToken.get(response["refresh_token"])

    assert refresh_token.data["client_id"] == "client_confidential_1"
    assert refresh_token.data["sub"] == "user_1"
    assert Scope.Set.equal?(Scope.Set.new(refresh_token.data["scope"]),
                            Scope.Set.new(device_code.data["granted_scopes"]))
    assert access_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["sub"] == "user_1"
    assert Scope.Set.equal?(Scope.Set.new(access_token.data["scope"]),
                            Scope.Set.new(device_code.data["granted_scopes"]))
    assert access_token.refresh_token_id == refresh_token.id
  end

  ##########################################################################
  # Helper functions
  ##########################################################################

  defp basic_auth_header(client, secret) do
    "Basic " <> Base.encode64(client <> ":" <> secret)
  end

end
