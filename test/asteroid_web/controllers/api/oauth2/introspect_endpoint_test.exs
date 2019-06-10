defmodule AsteroidWeb.API.OAuth2.IntrospectEndpointTest do
  import Asteroid.Utils
  alias Asteroid.Token.{RefreshToken, AccessToken}

  use AsteroidWeb.ConnCase, async: true

  ##########################################################################
  # General tests
  ##########################################################################

  test "invalid content-type", %{conn: conn} do
    assert_raise Plug.Parsers.UnsupportedMediaTypeError, fn ->
      conn
      |> put_req_header("content-type", "plain/text")
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), "Some plain text")
      |> json_response(400)
    end
  end

  test "missing token parameter", %{conn: conn} do
    req_body = %{
      "other" => "parameter"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
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
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
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
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_request"
  end

  test "no credentials for confidential client", %{conn: conn} do
    req_body = %{
      "token" => "egxeghqearfza"
    }
    conn =
      post(conn, AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)

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
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("token_type", "strange_type")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.put_value("iss", "https://example.net")
      |> AccessToken.store(%{})

    req_body = %{
      "token" => access_token.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(access_token.data, "active", true)
  end

  test "existing access token, correct token_type_hint param", %{conn: conn} do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("token_type", "strange_type")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.put_value("iss", "https://example.net")
      |> AccessToken.store(%{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "access_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(access_token.data, "active", true)
  end

  test "existing access token, incorrect token_type_hint param", %{conn: conn} do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("token_type", "strange_type")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.put_value("iss", "https://example.net")
      |> AccessToken.store(%{})

    req_body = %{
      "token" => access_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(access_token.data, "active", true)
  end

  test "existing access token, but expired", %{conn: conn} do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("token_type", "strange_type")
      |> AccessToken.put_value("exp", now() - 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.put_value("iss", "https://example.net")
      |> AccessToken.store(%{})

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
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("token_type", "strange_type")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.put_value("nbf", now() + 1000)
      |> AccessToken.put_value("iss", "https://example.net")
      |> AccessToken.store(%{})

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
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("token_type", "strange_type")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.put_value("status", "revoked")
      |> AccessToken.put_value("iss", "https://example.net")
      |> AccessToken.store(%{})

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
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("token_type", "strange_type")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.store(%{})

    req_body = %{
      "token" => refresh_token.id
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(refresh_token.data, "active", true)
  end

  test "existing refresh token, correct token_type_hint param", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("token_type", "strange_type")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.store(%{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "refresh_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(refresh_token.data, "active", true)
  end

  test "existing refresh token, incorrect token_type_hint param", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("token_type", "strange_type")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.store(%{})

    req_body = %{
      "token" => refresh_token.id,
      "token_type_hint" => "access_token"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), req_body)
      |> json_response(200)

    assert response == Map.put(refresh_token.data, "active", true)
  end

  test "existing refresh token, but expired", %{conn: conn} do
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("token_type", "strange_type")
      |> RefreshToken.put_value("exp", now() - 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.store(%{})

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
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("token_type", "strange_type")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("nbf", now() + 1000)
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.store(%{})

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
    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("scope", ["scp3", "scp9", "scp1"])
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("token_type", "strange_type")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("status", "revoked")
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.store(%{})

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
