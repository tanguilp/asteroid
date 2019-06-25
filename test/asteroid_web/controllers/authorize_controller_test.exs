defmodule AsteroidWeb.AuthorizeControllerTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
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

    assert html_response(conn, 400) =~ "missing parameter"
  end

  test "Missing redirect uri", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "missing parameter"
  end

  test "Malformed redirect uri", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1",
      "redirect_uri" => "wxthwermgkzawu"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "Malformed parameter"
    assert html_response(conn, 400) =~ "redirect_uri"
  end

  test "Redirect uri not registered for client", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://example.br"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "unregistered"
    assert html_response(conn, 400) =~ "redirect_uri"
  end

  test "client_id is missing", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "redirect_uri" => "https://example.br"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "missing parameter"
  end

  test "client_id is malformed", %{conn: conn} do
    params = %{
      "response_type" => "code",
      "client_id" => "invalid_cłiend_id",
      "redirect_uri" => "https://example.br"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert html_response(conn, 400) =~ "Malformed parameter"
    assert html_response(conn, 400) =~ "client_id"
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
    assert %{"error" => "invalid_scope"} =
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
      OAuth2.AccessDeniedError.exception(reason: "abc def"))

    assert redirected_to(conn) =~ "https://www.example.com"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error"] == "access_denied"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error_description"] =~ "abc def"

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
      OAuth2.AccessDeniedError.exception(reason: "abc def"))

    assert redirected_to(conn) =~ "https://www.example.com"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error"] == "access_denied"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error_description"] =~ "abc def"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["state"] == "sxgjwzedrgdfchexgim"
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
      OAuth2.ServerError.exception(reason: "abc def"))

    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error"] == "server_error"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error_description"] =~ "abc def"
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
      OAuth2.TemporarilyUnavailableError.exception(reason: "abc def"))

    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error"] == "temporarily_unavailable"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error_description"] =~ "abc def"
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
      %{sub: "user_1", granted_scopes: Scope.Set.new()})

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
      %{sub: "user_1", granted_scopes: Scope.Set.new()})

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

  test "Authorization granted (implicit) - access granted with capped access token lifetime", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :token,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: Scope.Set.new(["scp1", "scp2", "scp3", "scp4"]),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    Process.put(:oauth2_flow_implicit_scope_config, [
      scopes: %{
        "scp1" => [],
        "scp2" => [],
        "scp3" => [],
        "scp4" => [max_refresh_token_lifetime: 1000, max_access_token_lifetime: 30]
      }])

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      authz_request,
      %{sub: "user_1", granted_scopes: Scope.Set.new(["scp2", "scp4", "scp3", "scp1"])})

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "access_token" => access_token,
      "token_type" => "bearer",
      "expires_in" => expires_in,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {:ok, access_token} = Asteroid.Token.AccessToken.get(access_token)

    assert (expires_in |> Integer.parse() |> elem(0)) >= 29
    assert (expires_in |> Integer.parse() |> elem(0)) <= 31
    assert access_token.data["client_id"] == "client_confidential_1"
    assert access_token.data["sub"] == "user_1"
    assert access_token.data["exp"] >= now() + 29
    assert access_token.data["exp"] <= now() + 31
  end

  test "Authorization granted (implicit) - access granted with JWS access token", %{conn: conn} do
    Process.put(:oauth2_flow_implicit_access_token_serialization_format, :jws)
    Process.put(:oauth2_flow_implicit_access_token_signing_key, "key_auto")
    Process.put(:oauth2_flow_implicit_access_token_signing_alg, "RS384")

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

    jws_at = URI.decode_query(URI.parse(redirected_to(conn)).fragment)["access_token"]

    {:ok, jwk} = Crypto.Key.get("key_auto")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, access_token_str, _} = JOSE.JWS.verify_strict(jwk, ["RS384"], jws_at)

    access_token_data = Jason.decode!(access_token_str)

    assert access_token_data["client_id"] == "client_confidential_1"
    assert access_token_data["sub"] == "user_1"
  end

  ##########################
  # PKCE
  ##########################

  test "PKCE - error: mandatory set globally but not used", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code"
    }

    Process.put(:oauth2_flow_authorization_code_pkce_policy, :mandatory)

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_request"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "PKCE - error: client doesn't use PKCE but must", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_3",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_request"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "PKCE - error: code challenge too short", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "code_challenge" => "too_short",
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_request"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "PKCE - error: code challenge too long", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "code_challenge" => String.duplicate("x", 129)
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_request"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "PKCE - error: code challenge contains an invalid character", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "code_challenge" => String.duplicate("x", 50) <> "ṽxxxxx"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_request"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "PKCE - error: code challenge method is unsupported", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "code_challenge" => String.duplicate("x", 50),
      "code_challenge_method" => "unknown"
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_request"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "PKCE - error: code challenge method is not enabled", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "code_challenge" => String.duplicate("x", 50),
      "code_challenge_method" => "plain"
    }

    Process.put(:oauth2_flow_authorization_code_pkce_allowed_methods, [:S256])

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"error" => "invalid_request"} =
      URI.decode_query(URI.parse(redirected_to(conn)).query)
  end

  test "PKCE - succes request", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "code_challenge" => String.duplicate("x", 50),
      "code_challenge_method" => "S256"
    }

    Process.put(:oauth2_flow_authorization_code_web_authorization_callback,
                fn conn, request ->
                  request_map =
                    Map.from_struct(%{request |
                      client: Map.from_struct(request.client),
                      requested_scopes: Scope.Set.to_list(request.requested_scopes)
                    })

                  conn
                  |> put_status(200)
                  |> Phoenix.Controller.json(request_map)
                end
    )

    response =
      conn
      |> get("/authorize?#{URI.encode_query(params)}")
      |> json_response(200)

    assert response["pkce_code_challenge"] == String.duplicate("x", 50)
    assert response["pkce_code_challenge_method"] == "S256"
  end

  test "PKCE (code) - access granted", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        response_type: :code,
        client: Client.load("client_confidential_1") |> elem(1),
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        pkce_code_challenge: String.duplicate("x", 50),
        pkce_code_challenge_method: :S256,
        params: %{}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      authz_request,
      %{sub: "user_1", granted_scopes: Scope.Set.new()})

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"code" => az_code} = URI.decode_query(URI.parse(redirected_to(conn)).query)

    {:ok, authorization_code} = Asteroid.Token.AuthorizationCode.get(az_code)

    assert authorization_code.data["client_id"] == "client_confidential_1"
    assert authorization_code.data["sub"] == "user_1"
    assert authorization_code.data["__asteroid_oauth2_pkce_code_challenge"] ==
      String.duplicate("x", 50)
    assert authorization_code.data["__asteroid_oauth2_pkce_code_challenge_method"] == "S256"
  end
end
