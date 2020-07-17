defmodule AsteroidWeb.WellKnown.OauthAuthorizationServerController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Config, only: [opt: 1]
  import Asteroid.Utils

  alias Asteroid.OAuth2
  alias Asteroid.OIDC
  alias AsteroidWeb.Router.Helpers, as: Routes
  alias AsteroidWeb.RouterMTLSAliases.Helpers, as: RoutesMTLS

  def handle(conn, _params) do
    metadata =
      %{}
      |> Map.put("issuer", OAuth2.issuer())
      |> maybe_put_authorization_endpoint()
      |> maybe_put_token_endpoint()
      |> put_registration_endpoint()
      |> put_scopes_supported()
      |> put_response_types_supported()
      |> put_grant_types_supported()
      |> put_token_endpoint_auth_method_supported()
      |> put_jwks_uri()
      |> put_revocation_endpoint()
      |> put_revocation_endpoint_auth_method_supported()
      |> put_introspection_endpoint()
      |> put_introspection_endpoint_auth_method_supported()
      |> put_device_authorization_endpoint()
      |> put_code_challenge_methods_supported()
      |> put_if_not_nil(
        "service_documentation",
        opt(:oauth2_endpoint_metadata_service_documentation)
      )
      |> put_if_not_nil(
        "ui_locales_supported",
        opt(:oauth2_endpoint_metadata_ui_locales_supported)
      )
      |> put_if_not_nil(
        "op_policy_uri",
        opt(:oauth2_endpoint_metadata_op_policy_uri)
      )
      |> put_if_not_nil(
        "op_tos_uri",
        opt(:oauth2_endpoint_metadata_op_tos_uri)
      )
      |> put_jar_enabled()
      |> put_jar_metadata_values()
      |> put_oidc_metadata()
      |> put_mtls_endpoint_aliases()
      |> opt(:oauth2_endpoint_metadata_before_send_resp_callback).()
      |> sign_metadata()

    conn
    |> opt(:oauth2_endpoint_metadata_before_send_conn_callback).()
    |> json(metadata)
  end

  @spec maybe_put_authorization_endpoint(map()) :: map()

  defp maybe_put_authorization_endpoint(metadata) do
    if Enum.any?(
         opt(:oauth2_grant_types_enabled),
         fn grant_type -> OAuth2Utils.uses_authorization_endpoint?(to_string(grant_type)) end
       ) do
      Map.put(
        metadata,
        "authorization_endpoint",
        Routes.authorize_url(AsteroidWeb.Endpoint, :pre_authorize)
      )
    else
      metadata
    end
  end

  @spec maybe_put_token_endpoint(map()) :: map()

  defp maybe_put_token_endpoint(metadata) do
    case opt(:oauth2_grant_types_enabled) do
      [:implicit] ->
        metadata

      _ ->
        Map.put(
          metadata,
          "token_endpoint",
          Routes.token_url(AsteroidWeb.Endpoint, :handle)
        )
    end
  end

  @spec put_registration_endpoint(map()) :: map()

  defp put_registration_endpoint(metadata) do
    Map.put(
      metadata,
      "registration_endpoint",
      Routes.register_url(AsteroidWeb.Endpoint, :handle)
    )
  end

  @spec put_scopes_supported(map()) :: map()

  defp put_scopes_supported(metadata) do
    grant_types_enabled = opt(:oauth2_grant_types_enabled)

    scopes =
      if :password in grant_types_enabled do
        OAuth2.Scope.configuration_for_flow(:ropc)[:scopes]
      else
        %{}
      end

    scopes =
      if :client_credentials in grant_types_enabled do
        Map.merge(scopes, OAuth2.Scope.configuration_for_flow(:client_credentials)[:scopes])
      else
        scopes
      end

    scopes =
      if :authorization_code in grant_types_enabled do
        Map.merge(scopes, OAuth2.Scope.configuration_for_flow(:authorization_code)[:scopes])
      else
        scopes
      end

    scopes =
      if :implicit in grant_types_enabled do
        Map.merge(scopes, OAuth2.Scope.configuration_for_flow(:authorization_code)[:scopes])
      else
        scopes
      end

    advertised_scopes =
      Enum.reduce(
        scopes,
        [],
        fn
          {scope, scope_opts}, acc ->
            if scope_opts[:advertise] == false do
              acc
            else
              acc ++ [scope]
            end
        end
      )

    case advertised_scopes do
      [_ | _] ->
        Map.put(metadata, "scopes_supported", advertised_scopes)

      [] ->
        metadata
    end
  end

  @spec put_response_types_supported(map()) :: map()

  defp put_response_types_supported(metadata) do
    case opt(:oauth2_response_types_enabled) do
      [] ->
        metadata

      response_types when is_list(response_types) ->
        Map.put(metadata, "response_types_supported", Enum.map(response_types, &to_string/1))
    end
  end

  @spec put_grant_types_supported(map()) :: map()

  defp put_grant_types_supported(metadata) do
    case opt(:oauth2_grant_types_enabled) do
      [] ->
        metadata

      grant_types when is_list(grant_types) ->
        Map.put(metadata, "grant_types_supported", Enum.map(grant_types, &to_string/1))
    end
  end

  @spec put_token_endpoint_auth_method_supported(map()) :: map()

  defp put_token_endpoint_auth_method_supported(metadata) do
    token_endpoint_auth_methods_supported =
      OAuth2.Endpoint.token_endpoint_auth_methods_supported()
      |> Enum.map(&to_string/1)

    case token_endpoint_auth_methods_supported do
      [] ->
        metadata

      methods when is_list(methods) ->
        Map.put(metadata, "token_endpoint_auth_methods_supported", methods)
    end
  end

  @spec put_jwks_uri(map()) :: map()

  defp put_jwks_uri(metadata) do
    if opt(:crypto_keys) do
      Map.put(
        metadata,
        "jwks_uri",
        Routes.keys_url(AsteroidWeb.Endpoint, :handle)
      )
    else
      metadata
    end
  end

  @spec put_revocation_endpoint(map()) :: map()

  defp put_revocation_endpoint(metadata) do
    Map.put(
      metadata,
      "revocation_endpoint",
      Routes.revoke_url(AsteroidWeb.Endpoint, :handle)
    )
  end

  @spec put_revocation_endpoint_auth_method_supported(map()) :: map()

  defp put_revocation_endpoint_auth_method_supported(metadata) do
    revoke_endpoint_auth_methods_supported =
      OAuth2.Endpoint.revoke_endpoint_auth_methods_supported()
      |> Enum.map(&to_string/1)

    case revoke_endpoint_auth_methods_supported do
      [] ->
        metadata

      methods when is_list(methods) ->
        Map.put(metadata, "revocation_endpoint_auth_methods_supported", methods)
    end
  end

  @spec put_introspection_endpoint(map()) :: map()

  defp put_introspection_endpoint(metadata) do
    Map.put(
      metadata,
      "introspection_endpoint",
      Routes.introspect_url(AsteroidWeb.Endpoint, :handle)
    )
  end

  @spec put_introspection_endpoint_auth_method_supported(map()) :: map()

  defp put_introspection_endpoint_auth_method_supported(metadata) do
    introspect_endpoint_auth_methods_supported =
      OAuth2.Endpoint.introspect_endpoint_auth_methods_supported()
      |> Enum.map(&to_string/1)

    case introspect_endpoint_auth_methods_supported do
      [] ->
        metadata

      methods when is_list(methods) ->
        Map.put(metadata, "introspection_endpoint_auth_methods_supported", methods)
    end
  end

  @spec put_device_authorization_endpoint(map()) :: map()

  defp put_device_authorization_endpoint(metadata) do
    if :"urn:ietf:params:oauth:grant-type:device_code" in opt(:oauth2_grant_types_enabled) do
      Map.put(
        metadata,
        "device_authorization_endpoint",
        Routes.device_authorization_url(AsteroidWeb.Endpoint, :handle)
      )
    else
      metadata
    end
  end

  @spec put_code_challenge_methods_supported(map()) :: map()

  defp put_code_challenge_methods_supported(metadata) do
    case opt(:oauth2_pkce_policy) do
      :disabled ->
        metadata

      _ ->
        methods =
          opt(:oauth2_pkce_allowed_methods)
          |> Enum.map(&to_string/1)

        Map.put(metadata, "code_challenge_methods_supported", methods)
    end
  end

  @spec put_jar_enabled(map()) :: map()

  defp put_jar_enabled(metadata) do
    case opt(:oauth2_jar_enabled) do
      :disabled ->
        Map.put(metadata, "request_parameter_supported", false)

      :request_only ->
        Map.put(metadata, "request_parameter_supported", true)

      :request_uri_only ->
        Map.put(metadata, "request_uri_parameter_supported", true)

      :enabled ->
        metadata
        |> Map.put("request_parameter_supported", true)
        |> Map.put("request_uri_parameter_supported", true)
    end
  end

  @spec put_jar_metadata_values(map()) :: map()

  defp put_jar_metadata_values(metadata) do
    case opt(:oauth2_jar_enabled) do
      :disabled ->
        metadata

      _ ->
        metadata
        |> put_if_not_empty(
          "request_object_encryption_alg_values_supported",
          opt(:oauth2_jar_request_object_encryption_alg_values_supported)
        )
        |> put_if_not_empty(
          "request_object_encryption_enc_values_supported",
          opt(:oauth2_jar_request_object_encryption_enc_values_supported)
        )
        |> put_if_not_empty(
          "request_object_signing_alg_values_supported",
          opt(:oauth2_jar_request_object_signing_alg_values_supported)
        )
    end
  end

  @spec put_oidc_metadata(map()) :: map()

  defp put_oidc_metadata(metadata) do
    if OIDC.enabled?() do
      sig_alg = opt(:oidc_endpoint_userinfo_signature_alg_values_supported)
      enc_alg = opt(:oidc_endpoint_userinfo_encryption_alg_values_supported)
      enc_enc = opt(:oidc_endpoint_userinfo_encryption_enc_values_supported)

      #FIXME: force the presence of a RSA key?
      id_token_sig_alg =
        ["RS256" | opt(:oidc_id_token_signing_alg_values_supported)]
        |> Enum.uniq()

      id_token_enc_alg = opt(:oidc_id_token_encryption_alg_values_supported)
      id_token_enc_enc = opt(:oidc_id_token_encryption_enc_values_supported)

      acr_values = Enum.map(opt(:oidc_acr_config), fn {k, _} -> Atom.to_string(k) end)

      response_modes_supported =
        if opt(:oauth2_response_mode_policy) == :disabled do
          ["query", "fragment"]
        else
          ["query", "fragment", "form_post"]
        end

      metadata
      |> Map.put("claims_parameter_supported", true)
      |> Map.put("request_parameter_supported", true)
      |> Map.put("request_uri_parameter_supported", true)
      |> Map.put("subject_types_supported", ["public", "pairwise"])
      |> Map.put("userinfo_endpoint", Routes.userinfo_url(AsteroidWeb.Endpoint, :show))
      |> Map.put("response_modes_supported", response_modes_supported)
      |> put_if_not_empty("id_token_signing_alg_values_supported", id_token_sig_alg)
      |> put_if_not_empty("id_token_encryption_alg_values_supported", id_token_enc_alg)
      |> put_if_not_empty("id_token_encryption_enc_values_supported", id_token_enc_enc)
      |> put_if_not_empty("userinfo_signing_alg_values_supported", sig_alg)
      |> put_if_not_empty("userinfo_encryption_alg_values_supported", enc_alg)
      |> put_if_not_empty("userinfo_encryption_enc_values_supported", enc_enc)
      |> put_if_not_empty("acr_values_supported", acr_values)
      |> put_if_not_empty("claims_supported", opt(:oidc_claims_supported))
      |> put_if_not_empty(
        "display_values_supported",
        opt(:oidc_endpoint_metadata_display_values_supported)
      )
    else
      metadata
    end
  end

  @spec put_mtls_endpoint_aliases(map()) :: map()
  defp put_mtls_endpoint_aliases(metadata) do
    if opt(:oauth2_mtls_advertise_aliases) and OAuth2.MTLS.in_use?() do
      helpers = %{
        token_url: "token_endpoint",
        introspect_url: "introspection_endpoint",
        revoke_url: "revocation_endpoint",
        register_url: "registration_endpoint",
        device_authorization_url: "device_authorization_endpoint"
      }

      aliases =
        Enum.reduce(
          helpers,
          %{},
          fn {helper, endpoint}, acc ->
            if Kernel.function_exported?(RoutesMTLS, helper, 2) do
              Map.put(
                acc,
                endpoint,
                apply(RoutesMTLS, helper, [AsteroidWeb.EndpointMTLSAliases, :handle])
              )
            else
              acc
            end
          end
        )

      Map.put(metadata, "mtls_endpoint_aliases", aliases)
    else
      metadata
    end
  end

  @spec sign_metadata(map()) :: map()

  defp sign_metadata(metadata) do
    case opt(:oauth2_endpoint_metadata_signed_fields) do
      :disabled ->
        metadata

      :all ->
        Map.put(metadata, "signed_metadata", signed_statement(metadata))

      fields when is_list(fields) ->
        fields_to_be_signed = Map.take(metadata, fields ++ ["issuer"])

        Map.put(metadata, "signed_metadata", signed_statement(fields_to_be_signed))
    end
  end

  @spec signed_statement(map()) :: String.t()

  defp signed_statement(to_be_signed) do
    signing_key = opt(:oauth2_endpoint_metadata_signing_key)
    signing_alg = opt(:oauth2_endpoint_metadata_signing_alg)

    {:ok, jwk} = Asteroid.Crypto.Key.get(signing_key)

    if signing_alg do
      jws = JOSE.JWS.from_map(%{"alg" => signing_alg})

      JOSE.JWT.sign(jwk, jws, to_be_signed)
      |> JOSE.JWS.compact()
      |> elem(1)
    else
      JOSE.JWT.sign(jwk, to_be_signed)
      |> JOSE.JWS.compact()
      |> elem(1)
    end
  end
end
