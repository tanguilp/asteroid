defmodule AsteroidWeb.WellKnown.OauthAuthorizationServerControllerTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Utils

  alias AsteroidWeb.Router.Helpers, as: Routes
  alias AsteroidWeb.Endpoint
  alias AsteroidWeb.Endpoint
  alias Asteroid.OAuth2
  alias OAuth2Utils.Scope

  test "verifiy all fields", %{conn: conn} do
    response =
      conn
      |> get(Routes.oauth_authorization_server_endpoint_path(conn, :handle))
      |> json_response(200)

    assert response["issuer"] == OAuth2.issuer()
    assert response["authorization_endpoint"] == Routes.authorize_url(Endpoint, :pre_authorize)
    assert response["token_endpoint"] == Routes.token_endpoint_url(Endpoint, :handle)
    assert response["jwks_uri"] == Routes.keys_endpoint_url(Endpoint, :handle)
    assert response["registration_endpoint"] ==
      Routes.register_endpoint_url(Endpoint, :handle)
    assert Enum.sort(response["scopes_supported"]) ==
      Scope.Set.new()
      |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:ropc))
      |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:client_credentials))
      |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:authorization_code))
      |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:implicit))
      |> Scope.Set.to_list()
      |> Enum.sort()
    assert Enum.sort(response["response_types_supported"]) ==
      astrenv(:oauth2_response_types_enabled)
      |> Enum.map(&to_string/1)
      |> Enum.sort()
    assert Enum.sort(response["grant_types_supported"]) ==
      astrenv(:oauth2_grant_types_enabled)
      |> Enum.map(&to_string/1)
      |> Enum.sort()
    assert Enum.sort(response["token_endpoint_auth_methods_supported"]) ==
      OAuth2.Endpoint.token_endpoint_auth_methods_supported()
      |> Enum.map(&to_string/1)
      |> Enum.sort()
    assert response["service_documentation"] == nil
    assert response["ui_locales_supported"] == nil
    assert response["op_policy_uri"] == nil
    assert response["op_tos_uri"] == nil
    assert response["revocation_endpoint"] == Routes.revoke_endpoint_url(Endpoint, :handle)
    assert Enum.sort(response["revocation_endpoint_auth_methods_supported"]) ==
      OAuth2.Endpoint.revoke_endpoint_auth_methods_supported()
      |> Enum.map(&to_string/1)
      |> Enum.sort()
    assert response["introspection_endpoint"] ==
      Routes.introspect_endpoint_url(Endpoint, :handle)
    assert Enum.sort(response["introspection_endpoint_auth_methods_supported"]) ==
      OAuth2.Endpoint.introspect_endpoint_auth_methods_supported()
      |> Enum.map(&to_string/1)
      |> Enum.sort()
    assert Enum.sort(response["code_challenge_methods_supported"]) ==
      astrenv(:oauth2_pkce_allowed_methods)
      |> Enum.map(&to_string/1)
      |> Enum.sort()
  end

  test "authorization endpoint not needed", %{conn: conn} do
    Process.put(:oauth2_grant_types_enabled, [:client_credentials, :password])

    response =
      conn
      |> get(Routes.oauth_authorization_server_endpoint_path(conn, :handle))
      |> json_response(200)

    assert response["authorization_endpoint"] == nil
  end

  test "token endpoint not needed", %{conn: conn} do
    Process.put(:oauth2_grant_types_enabled, [:implicit])

    response =
      conn
      |> get(Routes.oauth_authorization_server_endpoint_path(conn, :handle))
      |> json_response(200)

    assert response["token_endpoint"] == nil
  end

  test "scope not advertised", %{conn: conn} do
    Process.put(:oauth2_scope_config, scopes: %{"scp6" => [advertise: false]})

    response =
      conn
      |> get(Routes.oauth_authorization_server_endpoint_path(conn, :handle))
      |> json_response(200)

    assert Enum.sort(response["scopes_supported"]) ==
      Scope.Set.new()
      |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:ropc))
      |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:client_credentials))
      |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:authorization_code))
      |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:implicit))
      |> Scope.Set.to_list()
      |> Kernel.--(["scp6"])
      |> Enum.sort()
  end

  test "non automatic fields can be set", %{conn: conn} do
    Process.put(:oauth2_endpoint_metadata_service_documentation, "aaa")
    Process.put(:oauth2_endpoint_metadata_ui_locales_supported, "bbb")
    Process.put(:oauth2_endpoint_metadata_op_policy_uri, "ccc")
    Process.put(:oauth2_endpoint_metadata_op_tos_uri, "ddd")

    response =
      conn
      |> get(Routes.oauth_authorization_server_endpoint_path(conn, :handle))
      |> json_response(200)

    assert response["service_documentation"] == "aaa"
    assert response["ui_locales_supported"] == "bbb"
    assert response["op_policy_uri"] == "ccc"
    assert response["op_tos_uri"] == "ddd"
  end

  test "PKCE methods not set if disabled", %{conn: conn} do
    Process.put(:oauth2_pkce_policy, :disabled)

    response =
      conn
      |> get(Routes.oauth_authorization_server_endpoint_path(conn, :handle))
      |> json_response(200)

    assert response["code_challenge_methods_supported"] == nil
  end

  test "jwks_uri not set if disabled", %{conn: conn} do
    Process.put(:crypto_keys, nil)

    response =
      conn
      |> get(Routes.oauth_authorization_server_endpoint_path(conn, :handle))
      |> json_response(200)

    assert response["jwks_uri"] == nil
  end

  test "signed_metadata published with issuer and correct signature", %{conn: conn} do
    Process.put(:oauth2_endpoint_metadata_signed_fields,
      ["token_endpoint", "token_endpoint_auth_methods_supported", "scopes_supported"])
    Process.put(:oauth2_endpoint_metadata_signing_key, "key_auto")
    Process.put(:oauth2_endpoint_metadata_signing_alg, "PS512")

    response =
      conn
      |> get(Routes.oauth_authorization_server_endpoint_path(conn, :handle))
      |> json_response(200)

    {:ok, jwk} = Asteroid.Crypto.Key.get("key_auto")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, signed_metadata_str, _} =
      JOSE.JWS.verify_strict(jwk, ["PS512"], response["signed_metadata"])

    signed_metadata = Jason.decode!(signed_metadata_str)

    assert signed_metadata["issuer"] == OAuth2.issuer()
  end
end
