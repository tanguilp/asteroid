defmodule AsteroidWeb.AuthorizeControllerTest do
  use AsteroidWeb.ConnCase

  alias Asteroid.Client
  alias OAuth2Utils.Scope

  ##########################
  # Invalid requests
  ##########################

  test "Missing response_type parameter with valid client_id & redirect_uri", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_request"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "Missing response_type and no client_id & redirect_uri", %{conn: conn} do
    params = %{
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "Missing parameter"
  end

  test "Missing redirect uri", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "Missing parameter"
  end

  test "Malformed redirect uri", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1",
      "redirect_uri" => "wxthwermgkzawu"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "Malformed redirect_uri"
  end

  test "Redirect uri not registered for client", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://example.br"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "Unregistered redirect_uri"
  end

  test "client_id is missing", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "redirect_uri" => "https://example.br"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "Missing parameter"
  end

  test "client_id is invalid", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "invalid_cłiend_id",
      "redirect_uri" => "https://example.br"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "Invalid client_id"
  end

  test "response_type not enabled", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com"
    }

    Process.put(:oauth2_response_types_enabled, [])

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "unsupported_response_type"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "Unauthorized response_type for client", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_2",
      "redirect_uri" => "https://www.example.com"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "unauthorized_client"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "Malformed scope param", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "scope" => "scp1 s¢p2 scp3"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_scope"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "Unauthorized scope param", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "scope" => "scp1 scp2 scp3 scp99"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "access_denied"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  ##########################
  # Authorization denied
  ##########################

  test "Authorization denied - access denied with no state", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :code,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_denied(
      conn,
      authz_request,
      %{reason: :access_denied, description: "abc def"})

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "access_denied", "error_description" => "abc def"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)

    refute URI.decode_query(URI.parse(redirected_to(conn)).query)["state"]
  end

  test "Authorization denied - access denied with state", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :code,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_denied(
      conn,
      authz_request,
      %{reason: :access_denied, description: "abc def"})

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{
      "error" => "access_denied",
      "error_description" => "abc def",
      "state" => "sxgjwzedrgdfchexgim"} = URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "Authorization denied - server error with no state", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :code,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_denied(
      conn,
      authz_request,
      %{reason: :server_error, description: "abc def"})

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "server_error", "error_description" => "abc def"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "Authorization denied - temporarily unavailable with no state", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :code,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_denied(
      conn,
      authz_request,
      %{reason: :temporarily_unavailable, description: "abc def"})

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "temporarily_unavailable", "error_description" => "abc def"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  ##########################
  # Authorization granted (code)
  ##########################

  test "Authorization granted (code) - access granted with state", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :code,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      authz_request,
      %{sub: "user_1"})

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"code" => _, "state" => "sxgjwzedrgdfchexgim"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)

    %{"code" => az_code} = URI.decode_query(URI.parse(redirected_to(conn)).query)

    {:ok, authorization_code} = Asteroid.Token.AuthorizationCode.get(az_code)

    assert authorization_code.data["client_id"] == "client_confidential_1"
    assert authorization_code.data["sub"] == "user_1"
  end

  test "Authorization granted (code) - access granted without state", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :code,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      authz_request,
      %{sub: "user_1"})

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"code" => az_code} = URI.decode_query(URI.parse(redirected_to(conn)).query)
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["state"] == nil

    {:ok, authorization_code} = Asteroid.Token.AuthorizationCode.get(az_code)

    assert authorization_code.data["client_id"] == "client_confidential_1"
    assert authorization_code.data["sub"] == "user_1"
  end

  ##########################
  # Authorization granted (implicit)
  ##########################

  test "Authorization granted (implicit) - access granted with state", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :token,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      authz_request,
      %{sub: "user_1", granted_scopes: MapSet.new()})

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "access_token" => access_token,
      "token_type" => "bearer",
      "expires_in" => _,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {:ok, access_token} = Asteroid.Token.AccessToken.get(access_token)

    assert access_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["sub"] == "user_1"
  end

  test "Authorization granted (implicit) - access granted without state", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :token,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      authz_request,
      %{sub: "user_1", granted_scopes: MapSet.new()})

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "access_token" => access_token,
      "token_type" => "bearer",
      "expires_in" => _,
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    assert URI.decode_query(URI.parse(redirected_to(conn)).fragment)["state"] == nil

    {:ok, access_token} = Asteroid.Token.AccessToken.get(access_token)

    assert access_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["sub"] == "user_1"
  end

  test "Authorization granted (implicit) - access granted with differing scopes", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :token,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: Scope.Set.new(["scp1", "scp2", "scp3", "scp4"]),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      authz_request,
      %{sub: "user_1", granted_scopes: Scope.Set.new(["scp2", "scp4", "scp3"])})

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "access_token" => access_token,
      "token_type" => "bearer",
      "expires_in" => _,
      "scope" => granted_scopes,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    assert Scope.Set.equal?(Scope.Set.from_scope_param!(granted_scopes),
                            Scope.Set.new(["scp2", "scp4", "scp3"]))

    {:ok, access_token} = Asteroid.Token.AccessToken.get(access_token)

    assert access_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["sub"] == "user_1"
  end
end
