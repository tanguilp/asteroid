defmodule AsteroidWeb.API.OAuth2.TokenEndpointOIDCTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Utils

  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias Asteroid.Token.{AuthorizationCode, RefreshToken}
  alias OAuth2Utils.Scope

  test "grant type code flow code success with no refresh token", %{conn: conn} do
    Process.put(:oidc_flow_authorization_code_issue_refresh_token_init, false)
    Process.put(:oidc_flow_authorization_code_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_authorization_code_id_token_signing_alg, "RS384")

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("requested_scopes", Scope.Set.new(["openid"]))
      |> AuthorizationCode.put_value("granted_scopes", Scope.Set.new(["openid"]))
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "oidc_authorization_code")
      |> AuthorizationCode.put_value("__asteroid_oidc_nonce", "xkgjuf9eswmgwszorixq")
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

    assert response["token_type"] == "bearer"
    assert response["access_token"] != nil
    assert response["refresh_token"] == nil
    assert is_integer(response["expires_in"])

    {:ok, jwk} = Crypto.Key.get("key_auto")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], response["id_token"])

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_confidential_1"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == "xkgjuf9eswmgwszorixq"
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["at_hash"] ==
      TestOIDCHelpers.token_hash(digest, response["access_token"])
  end

  test "grant type code flow code success with refresh token", %{conn: conn} do
    Process.put(:oidc_flow_authorization_code_issue_refresh_token_init, true)
    Process.put(:oidc_flow_authorization_code_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_authorization_code_id_token_signing_alg, "RS384")

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("requested_scopes", Scope.Set.new(["openid"]))
      |> AuthorizationCode.put_value("granted_scopes", Scope.Set.new(["openid"]))
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "oidc_authorization_code")
      |> AuthorizationCode.put_value("__asteroid_oidc_nonce", "xkgjuf9eswmgwszorixq")
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

    assert response["token_type"] == "bearer"
    assert response["access_token"] != nil
    assert response["refresh_token"] != nil
    assert is_integer(response["expires_in"])

    {:ok, jwk} = Crypto.Key.get("key_auto")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], response["id_token"])

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_confidential_1"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == "xkgjuf9eswmgwszorixq"
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["at_hash"] ==
      TestOIDCHelpers.token_hash(digest, response["access_token"])
  end

  test "grant type code flow hybrid success with no refresh token", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_issue_refresh_token_init, false)
    Process.put(:oidc_flow_hybrid_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_hybrid_id_token_signing_alg, "RS384")

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("requested_scopes", Scope.Set.new(["openid"]))
      |> AuthorizationCode.put_value("granted_scopes", Scope.Set.new(["openid"]))
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "oidc_hybrid")
      |> AuthorizationCode.put_value("__asteroid_oidc_nonce", "xkgjuf9eswmgwszorixq")
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

    assert response["token_type"] == "bearer"
    assert response["access_token"] != nil
    assert response["refresh_token"] == nil
    assert is_integer(response["expires_in"])

    {:ok, jwk} = Crypto.Key.get("key_auto")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], response["id_token"])

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_confidential_1"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == "xkgjuf9eswmgwszorixq"
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["at_hash"] == nil
  end

  test "grant type code flow hybrid success with refresh token", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_issue_refresh_token_init, true)
    Process.put(:oidc_flow_hybrid_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_hybrid_id_token_signing_alg, "RS384")

    {:ok, code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("client_id", "client_confidential_1")
      |> AuthorizationCode.put_value("sub", "user_1")
      |> AuthorizationCode.put_value("requested_scopes", Scope.Set.new(["openid"]))
      |> AuthorizationCode.put_value("granted_scopes", Scope.Set.new(["openid"]))
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp", now() + 5)
      |> AuthorizationCode.put_value("redirect_uri", "https://www.example.com")
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "oidc_hybrid")
      |> AuthorizationCode.put_value("__asteroid_oidc_nonce", "xkgjuf9eswmgwszorixq")
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

    assert response["token_type"] == "bearer"
    assert response["access_token"] != nil
    assert response["refresh_token"] != nil
    assert is_integer(response["expires_in"])

    {:ok, jwk} = Crypto.Key.get("key_auto")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], response["id_token"])

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_confidential_1"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == "xkgjuf9eswmgwszorixq"
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["at_hash"] == nil
  end

  test "grant type refresh token flow az code success with no new ID token", %{conn: conn} do
    Process.put(:oidc_flow_authorization_code_issue_id_token_refresh, false)
    Process.put(:oidc_flow_authorization_code_issue_refresh_token_refresh, false)
    Process.put(:oidc_flow_authorization_code_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_authorization_code_id_token_signing_alg, "RS384")

    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", Scope.Set.new(["openid"]))
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "oidc_authorization_code")
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

    assert response["token_type"] == "bearer"
    assert response["access_token"] != nil
    assert response["refresh_token"] == nil
    assert response["id_token"] == nil
    assert is_integer(response["expires_in"])
  end

  test "grant type refresh token flow az code success with new ID token", %{conn: conn} do
    Process.put(:oidc_flow_authorization_code_issue_id_token_refresh, true)
    Process.put(:oidc_flow_authorization_code_issue_refresh_token_refresh, false)
    Process.put(:oidc_flow_authorization_code_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_authorization_code_id_token_signing_alg, "RS384")

    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("sub", "user_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", Scope.Set.new(["openid"]))
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "oidc_authorization_code")
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

    assert response["token_type"] == "bearer"
    assert response["access_token"] != nil
    assert response["refresh_token"] == nil
    assert response["id_token"] != nil
    assert is_integer(response["expires_in"])

    {:ok, jwk} = Crypto.Key.get("key_auto")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], response["id_token"])

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_confidential_1"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == nil
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["at_hash"] == nil
  end

  test "grant type refresh token flow hybrid success with no new ID token", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_issue_id_token_refresh, false)
    Process.put(:oidc_flow_hybrid_issue_refresh_token_refresh, false)
    Process.put(:oidc_flow_hybrid_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_hybrid_id_token_signing_alg, "RS384")

    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", Scope.Set.new(["openid"]))
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "oidc_hybrid")
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

    assert response["token_type"] == "bearer"
    assert response["access_token"] != nil
    assert response["refresh_token"] == nil
    assert response["id_token"] == nil
    assert is_integer(response["expires_in"])
  end

  test "grant type refresh token flow hybrid success with new ID token", %{conn: conn} do
    Process.put(:oidc_flow_hybrid_issue_id_token_refresh, true)
    Process.put(:oidc_flow_hybrid_issue_refresh_token_refresh, false)
    Process.put(:oidc_flow_hybrid_id_token_signing_key, "key_auto")
    Process.put(:oidc_flow_hybrid_id_token_signing_alg, "RS384")

    {:ok, refresh_token} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("client_id", "client_confidential_1")
      |> RefreshToken.put_value("sub", "user_1")
      |> RefreshToken.put_value("exp", now() + 3600)
      |> RefreshToken.put_value("iat", now())
      |> RefreshToken.put_value("iss", "https://example.net")
      |> RefreshToken.put_value("scope", Scope.Set.new(["openid"]))
      |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "oidc_hybrid")
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

    assert response["token_type"] == "bearer"
    assert response["access_token"] != nil
    assert response["refresh_token"] == nil
    assert response["id_token"] != nil
    assert is_integer(response["expires_in"])

    {:ok, jwk} = Crypto.Key.get("key_auto")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, id_token_str, %JOSE.JWS{alg: {_alg, digest}}} =
      JOSE.JWS.verify_strict(jwk, ["RS384"], response["id_token"])

    id_token_data = Jason.decode!(id_token_str)

    assert id_token_data["aud"] == "client_confidential_1"
    assert id_token_data["iss"] == OAuth2.issuer()
    assert id_token_data["nonce"] == nil
    assert id_token_data["sub"] == "user_1"
    assert id_token_data["at_hash"] == nil
  end

  ##########################################################################
  # Helper functions
  ##########################################################################

  defp basic_auth_header(client, secret) do
    "Basic " <> Base.encode64(client <> ":" <> secret)
  end
end
