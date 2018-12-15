defmodule AsteroidWeb.API.OAuth2.IntrospectEndpointTest do
  import Asteroid.Utils
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias OAuth2Utils.Scope
  use AsteroidWeb.ConnCase

  ##########################################################################
  # General tests
  ##########################################################################

  test "invalid content-type", %{conn: conn} do
    response =
      conn
      |> put_req_header("content-type", "plain/text")
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), "Some plain text")
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "missing token parameter", %{conn: conn} do
    req_body = %{
      "other" => "parameter"
    }

    response =
      conn
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "invalid token parameter", %{conn: conn} do
    req_body = %{
      "token" => "asdexøeughwz5827zm27mz78w"
    }

    response =
      conn
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "invalid token_type_hint parameter", %{conn: conn} do
    req_body = %{
      "token" => "asd7zm27mz78w",
      "token_type_hint" => "unknown"
    }

    response =
      conn
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "no credentials for confidential client", %{conn: conn} do
    req_body = %{
      "other" => "parameter"
    }

    conn = post(conn, AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)

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
      "token" => "dsxfuewxmogi"
    }

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("invalid_client", "secret"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm=)

    refute Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Bearer )

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  test "public client with no credentials forbidden", %{conn: conn} do
    req_body = %{
      "token" => "onetokenewxoqziurmfaiy"
    }

    conn = post(conn, AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle),
                                                                          req_body)

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="always erroneous client password")

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="Asteroid")

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Bearer realm="Asteroid")

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
  end

  ##########################################################################
  # Endpoint test - access tokens
  ##########################################################################

  test "existing access token, no token_type_hint param", %{conn: conn} do
    access_token =
      AccessToken.new()
      |> AccessToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> AccessToken.put_claim("client_id", "client_confidential_1")
      |> AccessToken.put_claim("token_type", "strange_type")
      |> AccessToken.put_claim("exp", now() + 3600)
      |> AccessToken.put_claim("iat", now())
      |> AccessToken.put_claim("iss", "https://example.net")
      |> AccessToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => access_token.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(access_token.claims, "active", true)
  end

  test "existing access token, correct token_type_hint param", %{conn: conn} do
    access_token =
      AccessToken.new()
      |> AccessToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> AccessToken.put_claim("client_id", "client_confidential_1")
      |> AccessToken.put_claim("token_type", "strange_type")
      |> AccessToken.put_claim("exp", now() + 3600)
      |> AccessToken.put_claim("iat", now())
      |> AccessToken.put_claim("iss", "https://example.net")
      |> AccessToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "access_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(access_token.claims, "active", true)
  end

  test "existing access token, incorrect token_type_hint param", %{conn: conn} do
    access_token =
      AccessToken.new()
      |> AccessToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> AccessToken.put_claim("client_id", "client_confidential_1")
      |> AccessToken.put_claim("token_type", "strange_type")
      |> AccessToken.put_claim("exp", now() + 3600)
      |> AccessToken.put_claim("iat", now())
      |> AccessToken.put_claim("iss", "https://example.net")
      |> AccessToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(access_token.claims, "active", true)
  end

  test "existing access token, but expired", %{conn: conn} do
    access_token =
      AccessToken.new()
      |> AccessToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> AccessToken.put_claim("client_id", "client_confidential_1")
      |> AccessToken.put_claim("token_type", "strange_type")
      |> AccessToken.put_claim("exp", now() - 3600)
      |> AccessToken.put_claim("iat", now())
      |> AccessToken.put_claim("iss", "https://example.net")
      |> AccessToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == %{"active" => false}
  end

  test "existing access token, but not valid yet", %{conn: conn} do
    access_token =
      AccessToken.new()
      |> AccessToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> AccessToken.put_claim("client_id", "client_confidential_1")
      |> AccessToken.put_claim("token_type", "strange_type")
      |> AccessToken.put_claim("exp", now() + 3600)
      |> AccessToken.put_claim("iat", now())
      |> AccessToken.put_claim("nbf", now() + 1000)
      |> AccessToken.put_claim("iss", "https://example.net")
      |> AccessToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == %{"active" => false}
  end

  test "revoked access token", %{conn: conn} do
    access_token =
      AccessToken.new()
      |> AccessToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> AccessToken.put_claim("client_id", "client_confidential_1")
      |> AccessToken.put_claim("token_type", "strange_type")
      |> AccessToken.put_claim("exp", now() + 3600)
      |> AccessToken.put_claim("iat", now())
      |> AccessToken.put_claim("status", "revoked")
      |> AccessToken.put_claim("iss", "https://example.net")
      |> AccessToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == %{"active" => false}
  end

  test "access token with audiences, client is one of them", %{conn: conn} do
    access_token =
      AccessToken.new()
      |> AccessToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> AccessToken.put_claim("client_id", "client_confidential_1")
      |> AccessToken.put_claim("token_type", "strange_type")
      |> AccessToken.put_claim("exp", now() + 3600)
      |> AccessToken.put_claim("iat", now())
      |> AccessToken.put_claim("status", "revoked")
      |> AccessToken.put_claim("iss", "https://example.net")
      |> AccessToken.put_claim("aud", ["https://client1.api", "https://client2.api"])
      |> AccessToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(access_token, "active", true)
  end

  test "access token with audience which is not client", %{conn: conn} do
    access_token =
      AccessToken.new()
      |> AccessToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> AccessToken.put_claim("client_id", "client_confidential_1")
      |> AccessToken.put_claim("token_type", "strange_type")
      |> AccessToken.put_claim("exp", now() + 3600)
      |> AccessToken.put_claim("iat", now())
      |> AccessToken.put_claim("status", "revoked")
      |> AccessToken.put_claim("iss", "https://example.net")
      |> AccessToken.put_claim("aud", "https://client2.api")
      |> AccessToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == %{"active" => false}
  end

  ##########################################################################
  # Endpoint test - refresh tokens
  ##########################################################################

  test "existing refresh token, no token_type_hint param", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("token_type", "strange_type")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => refresh_token.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(refresh_token.claims, "active", true)
  end

  test "existing refresh token, correct token_type_hint param", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("token_type", "strange_type")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(refresh_token.claims, "active", true)
  end

  test "existing refresh token, incorrect token_type_hint param", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("token_type", "strange_type")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "access_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(refresh_token.claims, "active", true)
  end

  test "existing refresh token, but expired", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("token_type", "strange_type")
      |> RefreshToken.put_claim("exp", now() - 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == %{"active" => false}
  end

  test "existing refresh token, but not valid yet", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("token_type", "strange_type")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("nbf", now() + 1000)
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == %{"active" => false}
  end

  test "revoked refresh token", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("token_type", "strange_type")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("status", "revoked")
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == %{"active" => false}
  end

  test "refresh token with audiences, client is one of them", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("token_type", "strange_type")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("status", "revoked")
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.put_claim("aud", ["https://client1.api", "https://client2.api"])
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(refresh_token, "active", true)
  end

  test "refresh token with audience which is not client", %{conn: conn} do
    refresh_token =
      RefreshToken.new()
      |> RefreshToken.put_claim("scope", MapSet.new(["scp3", "scp9", "scp1"]))
      |> RefreshToken.put_claim("client_id", "client_confidential_1")
      |> RefreshToken.put_claim("token_type", "strange_type")
      |> RefreshToken.put_claim("exp", now() + 3600)
      |> RefreshToken.put_claim("iat", now())
      |> RefreshToken.put_claim("status", "revoked")
      |> RefreshToken.put_claim("iss", "https://example.net")
      |> RefreshToken.put_claim("aud", "https://client2.api")
      |> RefreshToken.store(%Asteroid.Context{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == %{"active" => false}
  end

  ##########################################################################
  # Helper functions
  ##########################################################################

  defp basic_auth_header(client, secret) do
    "Basic " <> Base.encode64(client <> ":" <> secret)
  end

end
