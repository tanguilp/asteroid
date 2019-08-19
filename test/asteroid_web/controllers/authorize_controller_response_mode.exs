defmodule AsteroidWeb.AuthorizeControllerTest do
  use AsteroidWeb.ConnCase, async: true

  alias Asteroid.Subject

  # initial request on /authorize

  test "Error case - invalid response mode OIDC", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "response_mode" => "invalid response mode",
      "scope" => "openid"
    }

    Process.put(:oauth2_response_mode_policy, :oidc_only)

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error"] == "invalid_request"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error_description"]
      =~ "invalid parameter"
  end

  test "Error case - invalid response mode OAuth2", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "response_mode" => "invalid response mode"
    }

    Process.put(:oauth2_response_mode_policy, :enabled)

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error"] == "invalid_request"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error_description"]
      =~ "invalid parameter"
  end

  test "Success case - no param default response mode OAuth2 flow code", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code"
    }

    Process.put(:oauth2_response_mode_policy, :enabled)
    Process.put(:oauth2_flow_authorization_code_web_authorization_callback,
                &Asteroid.Test.Callbacks.authorize_print_successful_request/2)

    response =
      conn
      |> get("/authorize?#{URI.encode_query(params)}")
      |> json_response(200)

    assert response["response_mode"] == "query"
  end

  test "Success case - no param default response mode OAuth2 flow implicit", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "token"
    }

    Process.put(:oauth2_response_mode_policy, :enabled)
    Process.put(:oauth2_flow_implicit_web_authorization_callback,
                &Asteroid.Test.Callbacks.authorize_print_successful_request/2)

    response =
      conn
      |> get("/authorize?#{URI.encode_query(params)}")
      |> json_response(200)

    assert response["response_mode"] == "fragment"
  end

  test "Success case - no param default response mode OIDC flow code", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "scope" => "openid"
    }

    Process.put(:oauth2_response_mode_policy, :enabled)
    Process.put(:oidc_flow_authorization_code_web_authorization_callback,
                &Asteroid.Test.Callbacks.authorize_print_successful_request/2)

    response =
      conn
      |> get("/authorize?#{URI.encode_query(params)}")
      |> json_response(200)

    assert response["response_mode"] == "query"
  end

  test "Success case - no param default response mode OIDC flow implicit", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "id_token token",
      "nonce" => "sxgjwzedrgdfchexgim",
      "scope" => "openid"
    }

    Process.put(:oauth2_response_mode_policy, :enabled)
    Process.put(:oidc_flow_implicit_web_authorization_callback,
                &Asteroid.Test.Callbacks.authorize_print_successful_request/2)

    response =
      conn
      |> get("/authorize?#{URI.encode_query(params)}")
      |> json_response(200)

    assert response["response_mode"] == "fragment"
  end

  test "Success case - no param default response mode OIDC flow hybrid", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code id_token token",
      "scope" => "openid"
    }

    Process.put(:oauth2_response_mode_policy, :enabled)
    Process.put(:oidc_flow_hybrid_web_authorization_callback,
                &Asteroid.Test.Callbacks.authorize_print_successful_request/2)

    response =
      conn
      |> get("/authorize?#{URI.encode_query(params)}")
      |> json_response(200)

    assert response["response_mode"] == "fragment"
  end

  # returning from an authorization process

  test "Success case - access granted query response mode OIDC hybrid flow", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_hybrid_access_token_lifetime, 43)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_hybrid,
        response_type: :"code id_token token",
        response_mode: :query,
        client_id: "client_confidential_1",
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(["scp1", "scp2", "scp3"]),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: MapSet.new(["scp3"]),
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["code"] != nil
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["access_token"] != nil
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["token_type"] == "Bearer"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["expires_in"] == "43"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["id_token"] != nil
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["scope"] == "scp3"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["state"] == "sxgjwzedrgdfchexgim"

    assert URI.parse(redirected_to(conn)).fragment == nil
  end

  test "Success case - access granted fragment response mode OAuth2 azcode flow", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :authorization_code,
        response_type: :code,
        response_mode: :fragment,
        client_id: "client_confidential_1",
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: MapSet.new(),
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert URI.decode_query(URI.parse(redirected_to(conn)).fragment)["code"] != nil
    assert URI.decode_query(URI.parse(redirected_to(conn)).fragment)["state"] == "sxgjwzedrgdfchexgim"

    assert URI.parse(redirected_to(conn)).query == nil
  end

  test "Success case - access granted form_post response mode OIDC hybrid flow", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_hybrid_access_token_lifetime, 43)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_hybrid,
        response_type: :"code id_token token",
        response_mode: :form_post,
        client_id: "client_confidential_1",
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(["scp1", "scp2", "scp3"]),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn =
      conn
      |> bypass_through(AsteroidWeb.Router, [:browser])
      #|> Plug.Conn.put_private(:plug_skip_csrf_protection, true)
      |> get("/authorize")
      |> AsteroidWeb.AuthorizeController.authorization_granted(
        %{
          authz_request: authz_request,
          subject: Subject.load("user_1") |> elem(1),
          granted_scopes: MapSet.new(["scp3"]),
        })

    assert html_response(conn, 200) =~ ~s(name="code")
    assert html_response(conn, 200) =~ ~s(name="access_token")
    assert html_response(conn, 200) =~ ~s(name="token_type")
    assert html_response(conn, 200) =~ ~s(name="expires_in")
    assert html_response(conn, 200) =~ ~s(name="id_token")
    assert html_response(conn, 200) =~ ~s(name="scope")
    assert html_response(conn, 200) =~ ~s(name="state")
  end
end
