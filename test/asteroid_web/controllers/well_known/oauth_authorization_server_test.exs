defmodule AsteroidWeb.WellKnown.OauthAuthorizationServerControllerTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Config, only: [opt: 1]

  alias AsteroidWeb.Router.Helpers, as: Routes
  alias AsteroidWeb.Endpoint
  alias AsteroidWeb.Endpoint
  alias Asteroid.{Crypto, OAuth2}
  alias OAuth2Utils.Scope

  test "verifiy all fields", %{conn: conn} do
    response =
      conn
      |> get(Routes.oauth_authorization_server_path(conn, :handle))
      |> json_response(200)

    assert response["issuer"] == OAuth2.issuer()
    assert response["authorization_endpoint"] == Routes.authorize_url(Endpoint, :pre_authorize)
    assert response["token_endpoint"] == Routes.token_url(Endpoint, :handle)
    assert response["jwks_uri"] == Routes.keys_url(Endpoint, :handle)

    assert response["registration_endpoint"] ==
             Routes.register_url(Endpoint, :handle)

    assert Enum.sort(response["scopes_supported"]) ==
             Scope.Set.new()
             |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:ropc))
             |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:client_credentials))
             |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:authorization_code))
             |> Scope.Set.union(OAuth2.Scope.scopes_for_flow(:implicit))
             |> Scope.Set.to_list()
             |> Enum.sort()

    assert Enum.sort(response["response_types_supported"]) ==
             opt(:oauth2_response_types_enabled)
             |> Enum.map(&to_string/1)
             |> Enum.sort()

    assert Enum.sort(response["grant_types_supported"]) ==
             opt(:oauth2_grant_types_enabled)
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
    assert response["revocation_endpoint"] == Routes.revoke_url(Endpoint, :handle)

    assert Enum.sort(response["revocation_endpoint_auth_methods_supported"]) ==
             OAuth2.Endpoint.revoke_endpoint_auth_methods_supported()
             |> Enum.map(&to_string/1)
             |> Enum.sort()

    assert response["introspection_endpoint"] == Routes.introspect_url(Endpoint, :handle)

    assert Enum.sort(response["introspection_endpoint_auth_methods_supported"]) ==
             OAuth2.Endpoint.introspect_endpoint_auth_methods_supported()
             |> Enum.map(&to_string/1)
             |> Enum.sort()

    assert Enum.sort(response["code_challenge_methods_supported"]) ==
             opt(:oauth2_pkce_allowed_methods)
             |> Enum.map(&to_string/1)
             |> Enum.sort()
  end

  test "authorization endpoint not needed", %{conn: conn} do
    Process.put(:oauth2_grant_types_enabled, [:client_credentials, :password])

    response =
      conn
      |> get(Routes.oauth_authorization_server_path(conn, :handle))
      |> json_response(200)

    assert response["authorization_endpoint"] == nil
  end

  test "token endpoint not needed", %{conn: conn} do
    Process.put(:oauth2_grant_types_enabled, [:implicit])

    response =
      conn
      |> get(Routes.oauth_authorization_server_path(conn, :handle))
      |> json_response(200)

    assert response["token_endpoint"] == nil
  end

  test "scope not advertised", %{conn: conn} do
    Process.put(:oauth2_scope_config, scopes: %{"scp6" => [advertise: false]})

    response =
      conn
      |> get(Routes.oauth_authorization_server_path(conn, :handle))
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
      |> get(Routes.oauth_authorization_server_path(conn, :handle))
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
      |> get(Routes.oauth_authorization_server_path(conn, :handle))
      |> json_response(200)

    assert response["code_challenge_methods_supported"] == nil
  end

  test "signed_metadata published with issuer and correct signature", %{conn: conn} do
    Process.put(
      :oauth2_endpoint_metadata_signed_fields,
      ["token_endpoint", "token_endpoint_auth_methods_supported", "scopes_supported"]
    )

    response =
      conn
      |> get(Routes.oauth_authorization_server_path(conn, :handle))
      |> json_response(200)

    assert {:ok, {signed_metadata_str, _jwk}} = JOSEUtils.JWS.verify(
      response["signed_metadata"], Crypto.JOSE.public_keys(), sig_algs_supported()
    )

    signed_metadata = Jason.decode!(signed_metadata_str)

    assert signed_metadata["issuer"] == OAuth2.issuer()
  end

  defp sig_algs_supported do
    Asteroid.Crypto.JOSE.public_keys()
    |> Enum.flat_map(fn jwk -> JOSEUtils.JWK.sig_algs_supported(jwk) end)
  end
end
