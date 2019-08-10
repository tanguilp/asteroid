defmodule AsteroidWeb.AuthorizeControllerOIDCTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias Asteroid.Subject
  alias OAuth2Utils.Scope

  setup_all do
      rsa_enc_alg_all =
        JOSE.JWK.generate_key({:rsa, 1024})
        |> Crypto.Key.set_key_use(:enc)

      Client.gen_new(id: "client_oidc_azcode_sig")
      |> Client.add("client_id", "client_oidc_azcode_sig")
      |> Client.add("client_secret", "password1")
      |> Client.add("client_type", "confidential")
      |> Client.add("grant_types", ["authorization_code", "refresh_token"])
      |> Client.add("redirect_uris", ["https://www.example.com"])
      |> Client.add("id_token_signed_response_alg", "RS384")
      |> Client.add("jwks",
                    [rsa_enc_alg_all |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1)])
      |> Client.store()

      Client.gen_new(id: "client_oidc_azcode_enc")
      |> Client.add("client_id", "client_oidc_azcode_enc")
      |> Client.add("client_secret", "password1")
      |> Client.add("client_type", "confidential")
      |> Client.add("grant_types", ["authorization_code"])
      |> Client.add("redirect_uris", ["https://www.example.com"])
      |> Client.add("id_token_signed_response_alg", "RS384")
      |> Client.add("id_token_encrypted_response_alg", "RSA1_5")
      |> Client.add("id_token_encrypted_response_enc", "A128GCM")
      |> Client.add("jwks",
                    [rsa_enc_alg_all |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1)])
      |> Client.store()

      Client.gen_new(id: "client_oidc_pairwise")
      |> Client.add("client_id", "client_oidc_pairwise")
      |> Client.add("client_secret", "password1")
      |> Client.add("client_type", "confidential")
      |> Client.add("grant_types", ["authorization_code"])
      |> Client.add("redirect_uris", ["https://www.example.com"])
      |> Client.add("id_token_signed_response_alg", "RS384")
      |> Client.add("subject_type", "pairwise")
      |> Client.add("sector_identifier_uri", "https://example.com/sector")
      |> Client.store()

    %{rsa_enc_alg_all: rsa_enc_alg_all}
  end

  # invalid request to /authorize

  test "Error - implicit - missing nonce", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "id_token",
      "scope" => "openid",
    }

    conn = get(conn, "/authorize?#{URI.encode_query(params)}")

    assert redirected_to(conn) =~ "https://www.example.com"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error"] == "invalid_request"
    assert URI.decode_query(URI.parse(redirected_to(conn)).query)["error_description"] =~
      "missing parameter"
  end

  # valid request to /authorize

  test "Success - az code - simple request", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "code",
      "scope" => "openid"
    }

    Process.put(:oidc_flow_authorization_code_web_authorization_callback,
                fn conn, request ->
                  request_map =
                    Map.from_struct(%{request |
                      client_id: request.client_id,
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

    assert response["flow"] == "oidc_authorization_code"
    assert response["redirect_uri"] == params["redirect_uri"]
    assert response["client_id"] == params["client_id"]
    assert response["response_type"] == params["response_type"]
    assert Scope.Set.equal?(Scope.Set.new(response["requested_scopes"]),
                            Scope.Set.new(params["scope"]))
  end

  test "Success - implicit - simple request", %{conn: conn} do
    params = %{
      "client_id" => "client_confidential_1",
      "redirect_uri" => "https://www.example.com",
      "response_type" => "id_token",
      "scope" => "openid",
      "nonce" => "some_nonce_dfeasjgfndyxcrgfds"
    }

    Process.put(:oidc_flow_implicit_web_authorization_callback,
                fn conn, request ->
                  request_map =
                    Map.from_struct(%{request |
                      client_id: request.client_id,
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

    assert response["flow"] == "oidc_implicit"
    assert response["redirect_uri"] == params["redirect_uri"]
    assert response["client_id"] == params["client_id"]
    assert response["response_type"] == params["response_type"]
    assert Scope.Set.equal?(Scope.Set.new(response["requested_scopes"]),
                            Scope.Set.new(params["scope"]))
  end

  # request back from workflow

  test "Success - az code - az code returned", %{conn: conn} do
    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_authorization_code,
        response_type: :code,
        response_mode: :query,
        client_id: "client_oidc_azcode_sig",
        redirect_uri: "https://www.example.com",
        requested_scopes: MapSet.new(),
        params: %{}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: Scope.Set.new()
      })

    assert redirected_to(conn) =~ "https://www.example.com"
    assert %{"code" => az_code} = URI.decode_query(URI.parse(redirected_to(conn)).query)

    {:ok, authorization_code} = Asteroid.Token.AuthorizationCode.get(az_code)

    assert authorization_code.data["client_id"] == "client_oidc_azcode_sig"
    assert authorization_code.data["sub"] == "user_1"
  end

  test "Success - implicit - id_token returned", %{conn: conn} do
    Process.put(:oidc_flow_implicit_id_token_lifetime, 60)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_implicit,
        response_type: :id_token,
        response_mode: :fragment,
        client_id: "client_oidc_azcode_sig",
        redirect_uri: "https://www.example.com",
        nonce: "some_nonce_dfeasjgfndyxcrgfds",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: Scope.Set.new()
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "id_token" => id_token_jws,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, _} = JOSE.JWS.verify_strict(jwk, ["RS384"], id_token_jws)

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_oidc_azcode_sig"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == authz_request.nonce
    assert id_token_data["sub"] == "user_1"
  end

  test "Success - implicit - encrypted id_token returned",
  %{conn: conn, rsa_enc_alg_all: rsa_enc_alg_all}
  do
    Process.put(:oidc_flow_implicit_id_token_lifetime, 60)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_implicit,
        response_type: :id_token,
        response_mode: :fragment,
        client_id: "client_oidc_azcode_enc",
        redirect_uri: "https://www.example.com",
        nonce: "some_nonce_dfeasjgfndyxcrgfds",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: Scope.Set.new()
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "id_token" => id_token_jwe,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {id_token_jws, _jwe} = JOSE.JWE.block_decrypt(rsa_enc_alg_all, id_token_jwe)

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, _} = JOSE.JWS.verify_strict(jwk, ["RS384"], id_token_jws)

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_oidc_azcode_enc"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == authz_request.nonce
    assert id_token_data["sub"] == "user_1"
  end

  test "Success - implicit - id_token & token returned", %{conn: conn} do
    Process.put(:oidc_flow_implicit_access_token_lifetime, 30)
    Process.put(:oidc_flow_implicit_id_token_lifetime, 60)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_implicit,
        response_type: :"id_token token",
        response_mode: :fragment,
        client_id: "client_oidc_azcode_sig",
        redirect_uri: "https://www.example.com",
        nonce: "some_nonce_dfeasjgfndyxcrgfds",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: Scope.Set.new()
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "id_token" => id_token_jws,
      "access_token" => access_token_param,
      "token_type" => "bearer",
      "expires_in" => expires_in,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {:ok, access_token} = Asteroid.Token.AccessToken.get(access_token_param)

    assert (expires_in |> Integer.parse() |> elem(0)) >= 29
    assert (expires_in |> Integer.parse() |> elem(0)) <= 31
    assert access_token.data["client_id"] == "client_oidc_azcode_sig"
    assert access_token.data["sub"] == "user_1"
    assert access_token.data["exp"] >= now() + 29
    assert access_token.data["exp"] <= now() + 31

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], id_token_jws)

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_oidc_azcode_sig"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == authz_request.nonce
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["at_hash"] == TestOIDCHelpers.token_hash(digest, access_token_param)
  end

  test "Success - hybrid - code & id_token & token returned", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_access_token_lifetime, 30)
    Process.put(:oidc_flow_hybrid_authorization_code_lifetime, 30)
    Process.put(:oidc_flow_hybrid_id_token_lifetime, 60)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_hybrid,
        response_type: :"code id_token token",
        response_mode: :fragment,
        client_id: "client_oidc_azcode_sig",
        redirect_uri: "https://www.example.com",
        nonce: "some_nonce_dfeasjgfndyxcrgfds",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: Scope.Set.new()
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "code" => az_code,
      "id_token" => id_token_jws,
      "access_token" => access_token_param,
      "token_type" => "bearer",
      "expires_in" => expires_in,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {:ok, authorization_code} = Asteroid.Token.AuthorizationCode.get(az_code)

    assert authorization_code.data["client_id"] == "client_oidc_azcode_sig"
    assert authorization_code.data["sub"] == "user_1"
    assert authorization_code.data["exp"] >= now() + 29
    assert authorization_code.data["exp"] <= now() + 31

    {:ok, access_token} = Asteroid.Token.AccessToken.get(access_token_param)

    assert (expires_in |> Integer.parse() |> elem(0)) >= 29
    assert (expires_in |> Integer.parse() |> elem(0)) <= 31
    assert access_token.data["client_id"] == "client_oidc_azcode_sig"
    assert access_token.data["sub"] == "user_1"
    assert access_token.data["exp"] >= now() + 29
    assert access_token.data["exp"] <= now() + 31

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], id_token_jws)

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_oidc_azcode_sig"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == authz_request.nonce
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["at_hash"] == TestOIDCHelpers.token_hash(digest, access_token_param)
    assert id_token_data["c_hash"] == TestOIDCHelpers.token_hash(digest, az_code)
  end

  test "Success - hybrid - code & id_token returned", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_authorization_code_lifetime, 30)
    Process.put(:oidc_flow_hybrid_id_token_lifetime, 60)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_hybrid,
        response_type: :"code id_token",
        response_mode: :fragment,
        client_id: "client_oidc_azcode_sig",
        redirect_uri: "https://www.example.com",
        nonce: "some_nonce_dfeasjgfndyxcrgfds",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: Scope.Set.new()
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "code" => az_code,
      "id_token" => id_token_jws,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {:ok, authorization_code} = Asteroid.Token.AuthorizationCode.get(az_code)

    assert authorization_code.data["client_id"] == "client_oidc_azcode_sig"
    assert authorization_code.data["sub"] == "user_1"
    assert authorization_code.data["exp"] >= now() + 29
    assert authorization_code.data["exp"] <= now() + 31

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], id_token_jws)

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_oidc_azcode_sig"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == authz_request.nonce
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["c_hash"] == TestOIDCHelpers.token_hash(digest, az_code)
  end

  test "Success - hybrid - code & token returned", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_access_token_lifetime, 30)
    Process.put(:oidc_flow_hybrid_authorization_code_lifetime, 30)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_hybrid,
        response_type: :"code token",
        response_mode: :fragment,
        client_id: "client_oidc_azcode_sig",
        redirect_uri: "https://www.example.com",
        nonce: "some_nonce_dfeasjgfndyxcrgfds",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: Scope.Set.new()
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "code" => az_code,
      "access_token" => access_token_param,
      "token_type" => "bearer",
      "expires_in" => expires_in,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {:ok, authorization_code} = Asteroid.Token.AuthorizationCode.get(az_code)

    assert authorization_code.data["client_id"] == "client_oidc_azcode_sig"
    assert authorization_code.data["sub"] == "user_1"
    assert authorization_code.data["exp"] >= now() + 29
    assert authorization_code.data["exp"] <= now() + 31

    {:ok, access_token} = Asteroid.Token.AccessToken.get(access_token_param)

    assert (expires_in |> Integer.parse() |> elem(0)) >= 29
    assert (expires_in |> Integer.parse() |> elem(0)) <= 31
    assert access_token.data["client_id"] == "client_oidc_azcode_sig"
    assert access_token.data["sub"] == "user_1"
    assert access_token.data["exp"] >= now() + 29
    assert access_token.data["exp"] <= now() + 31
  end

  test "Success - implicit - id_token returned with pairwise sub", %{conn: conn} do
    Process.put(:oidc_flow_implicit_id_token_lifetime, 60)

    authz_request =
      %AsteroidWeb.AuthorizeController.Request{
        flow: :oidc_implicit,
        response_type: :id_token,
        response_mode: :fragment,
        client_id: "client_oidc_pairwise",
        redirect_uri: "https://www.example.com",
        nonce: "some_nonce_dfeasjgfndyxcrgfds",
        requested_scopes: MapSet.new(),
        params: %{"state" => "sxgjwzedrgdfchexgim"}
      }

    conn = AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: authz_request,
        subject: Subject.load("user_1") |> elem(1),
        granted_scopes: Scope.Set.new()
      })

    assert redirected_to(conn) =~ "https://www.example.com"

    assert %{
      "id_token" => id_token_jws,
      "state" => "sxgjwzedrgdfchexgim"
    } = URI.decode_query(URI.parse(redirected_to(conn)).fragment)

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, _} = JOSE.JWS.verify_strict(jwk, ["RS384"], id_token_jws)

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_oidc_pairwise"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == authz_request.nonce
    assert id_token_data["sub"] != "user_1"
  end
end
