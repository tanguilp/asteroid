defmodule AsteroidWeb.API.OAuth2.RegisterEndpoint do
  @moduledoc false

  defmodule InvalidClientMetadataField do
    @moduledoc """
    Error returned when client metadata is invalid
    """

    defexception [:field, :reason]

    @impl true

    def message(%{field: field, reason: reason}) do
      "Invalid field `#{field}` (reason: #{reason})"
    end
  end

  defmodule UnauthorizedRequestedScopes do
    @moduledoc """
    Error returned when returning scopes are not allowed according to the policy (either the
    client's configuration or the scopes existing in the configuration options).
    """

    defexception [:scopes]

    @impl true

    def message (%{scopes: scopes}) do
      "The following requested scope are not allowed under the current policy: " <>
      Enum.join(scopes, " ")
    end
  end

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.Client
  alias Asteroid.OAuth2

  def handle(conn, input_metadata) do
    with {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- OAuth2.Register.client_authorized?(conn, client)
    do
      ctx =
        %{}
        |> Map.put(:endpoint, :register)
        |> Map.put(:client, client)

      processed_metadata =
        %{}
        |> process_grant_types(client, input_metadata)
        |> process_response_types(client, input_metadata)
        |> process_redirect_uris(input_metadata)
        |> process_token_endpoint_auth_method(client, input_metadata)
        |> process_i18n_field(input_metadata, "client_name")
        |> process_i18n_field(input_metadata, "client_uri")
        |> process_i18n_field(input_metadata, "logo_uri")
        |> process_i18n_field(input_metadata, "tos_uri")
        |> process_i18n_field(input_metadata, "policy_uri")
        |> process_scope(client, input_metadata)
        |> process_contacts(input_metadata)
        |> process_jwks_uri(input_metadata)
        |> process_jwks(input_metadata)
        |> process_software_id(input_metadata)
        |> process_software_version(input_metadata)
        |> process_additional_metadata_fields(client, input_metadata)

      client_id = gen_new_client_id(processed_metadata)

      maybe_client_secret_and_hash =
        if "client_secret_basic" in processed_metadata["token_endpoint_auth_method"] or
          "client_secret_post" in processed_metadata["token_endpoint_auth_method"]
        do
          Expwd.Hashed.gen()
        else
          nil
        end

      client =
        Enum.reduce(
          processed_metadata,
          Client.gen_new(id: client_id),
          fn
            {k, v}, acc ->
              Client.add(acc, k, v)
          end
        )

      client =
        if maybe_client_secret_and_hash do
          hashed_client_str =
            maybe_client_secret_and_hash
            |> elem(1)
            |> Expwd.Hashed.Portable.to_portable()

          Client.add(client, "client_secret", hashed_client_str)
        else
          client
        end

      :ok = Client.store(client)

      processed_metadata =
        if maybe_client_secret_and_hash do
          {client_secret, _client_secret_hashed} = maybe_client_secret_and_hash

          Map.put(processed_metadata, "client_secret", client_secret)
        else
          processed_metadata
        end

      processed_metadata =
        astrenv(:oauth2_endpoint_register_client_before_send_resp_callback).(processed_metadata)

      conn
      |> put_status(200)
      |> astrenv(:oauth2_endpoint_register_client_before_send_conn_callback).(ctx)
      |> json(processed_metadata)
    else
      {:error, %Asteroid.OAuth2.Client.AuthenticationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, %Asteroid.OAuth2.Register.UnauthorizedClientError{} = error} ->
        OAuth2.Request.error_response(conn, error)

      {:error, :missing_redirect_uri} ->
        error_resp(conn, error: :invalid_client_metadata,
                   error_description: "Missing mandatory redirect URIs for these grant types")
    end
  rescue
    e in OAuth2.RedirectUri.MalformedError ->
      error_resp(conn, error: :invalid_redirect_uri, error_description: Exception.message(e))

    e in OAuth2.Endpoint.UnsupportedAuthMethod ->
      error_resp(conn, error: :invalid_client_metadata, error_description: Exception.message(e))

    e in __MODULE__.InvalidClientMetadataField ->
      error_resp(conn, error: :invalid_client_metadata, error_description: Exception.message(e))

    e in Scope.Set.InvalidScopeParam ->
      error_resp(conn, error: :invalid_client_metadata, error_description: Exception.message(e))
  end

  @spec process_grant_types(map(), Client.t(), map()) :: map()

  defp process_grant_types(
    processed_metadata,
    client,
    %{"grant_types" => requested_grant_types}) when is_list(requested_grant_types)
  do
    conf_attr = "__asteroid_oauth2_endpoint_register_allowed_grant_types"

    client = Client.fetch_attributes(client, [conf_attr])

    enabled_grant_types =
      astrenv(:oauth2_grant_types_enabled)
      |> Enum.map(&to_string/1)

    allowed_grant_types =
      MapSet.intersection(
        MapSet.new(client.data[conf_attr] || []),
        MapSet.new(enabled_grant_types)
      )

    if MapSet.subset?(MapSet.new(requested_grant_types), allowed_grant_types) do
      Map.put(processed_metadata, "grant_types", requested_grant_types)
    else
      raise __MODULE__.InvalidClientMetadataField,
        field: "grant_types",
        reason: "None of the grant types could be granted as a result of applying the server policy"
    end
  end

  defp process_grant_types(_, _, %{"grant_types" => _}) do
    raise __MODULE__.InvalidClientMetadataField,
      field: "grant_types",
      reason: "Invalid type for the `grant_types` field (should be a list)"
  end

  defp process_grant_types(processed_metadata, _, _) do
    Map.put(processed_metadata, "grant_types", ["authorization_code"])
  end

  @spec process_response_types(map(), Client.t(), map()) :: map()

  defp process_response_types(
    processed_metadata,
    client,
    %{"response_types" => requested_response_types}) when is_list(requested_response_types)
  do
    conf_attr = "__asteroid_oauth2_endpoint_register_allowed_response_types"

    client = Client.fetch_attributes(client, [conf_attr])

    enabled_response_types =
      astrenv(:oauth2_response_types_enabled)
      |> Enum.map(&to_string/1)

    allowed_response_types =
      MapSet.intersection(
        MapSet.new(client.data[conf_attr] || []),
        MapSet.new(enabled_response_types)
      )

    if MapSet.subset?(MapSet.new(requested_response_types), allowed_response_types) do
      case {
          "authorization_code" in processed_metadata and "code" not in requested_response_types,
          "implicit" in processed_metadata and "token" not in requested_response_types
        } do
        {true, _} ->
          raise __MODULE__.InvalidClientMetadataField,
            field: "response_types",
            reason: "Response type `code` must be registered along with the grant type `authorization_code`"

        {_, true} ->
          raise __MODULE__.InvalidClientMetadataField,
            field: "response_types",
            reason: "Response type `token` must be registered along with the grant type `implicit`"

        _ ->
          Map.put(processed_metadata, "response_types", requested_response_types)
      end
    else
      raise __MODULE__.InvalidClientMetadataField,
        field: "response_types",
        reason: "None of the response types could be granted as a result of applying the server policy"
    end
  end

  defp process_response_types(_, _, %{"response_types" => _}) do
    raise __MODULE__.InvalidClientMetadataField,
      field: "response_types",
      reason: "Invalid type for the `response_types` field (should be a list)"
  end

  defp process_response_types(processed_metadata, _, _) do
    Map.put(processed_metadata, "response_types", ["code"])
  end

  @spec process_redirect_uris(map(), map()) :: map()

  defp process_redirect_uris(processed_metadata, input_metadata) do
    case input_metadata["redirect_uris"] do
      [_ | _] = redirect_uris ->
        Enum.each(
          redirect_uris,
          fn
            redirect_uri ->
              case OAuth2.RedirectUri.valid?(redirect_uri) do
                :ok ->
                  :ok

                {:error, e} ->
                  raise e
              end
          end
        )

        Map.put(processed_metadata, "redirect_uris", redirect_uris)

      _ ->
        if Enum.any?(
          processed_metadata["grant_types"],
          fn
            grant_type ->
              OAuth2Utils.uses_authorization_endpoint?(grant_type)
          end
        ) do
          {:error, :missing_redirect_uri}
        else
          processed_metadata
        end
    end
  end

  defp error_resp(conn, error_status \\ 400, error_data) do
    conn
    |> put_status(error_status)
    |> json(Enum.into(error_data, %{}))
  end

  @spec process_token_endpoint_auth_method(map(), Client.t(), map()) :: map()

  defp process_token_endpoint_auth_method(
    processed_metadata,
    client,
    %{"token_endpoint_auth_method" => token_endpoint_auth_method})
  do
    auth_meth_client = "__asteroid_oauth2_endpoint_register_allowed_token_endpoint_auth_methods"

    client = Client.fetch_attributes(client, [auth_meth_client])

    auth_method_allowed_str =
      case client.data[auth_meth_client] do
        nil ->
          astrenv(:oauth2_endpoint_token_auth_methods_supported_callback).f()
          |> Enum.map(&to_string/1)

        l when is_list(l) ->
          MapSet.intersection(
            l,
            astrenv(:oauth2_endpoint_token_auth_methods_supported_callback).f()
            |> Enum.map(&to_string/1)
          )
          |> MapSet.to_list()
      end

    if token_endpoint_auth_method in auth_method_allowed_str do
      Map.put(processed_metadata, "token_endpoint_auth_method", token_endpoint_auth_method)
    else
      raise OAuth2.Endpoint.UnsupportedAuthMethod,
        endpoint: :token,
        auth_method: token_endpoint_auth_method
    end
  end

  defp process_token_endpoint_auth_method(processed_metadata, _, _) do
    Map.put(processed_metadata, "token_endpoint_auth_method", "client_secret_basic")
  end

  @spec process_scope(map(), Client.t(), map()) :: map()

  defp process_scope(processed_metadata, client, %{"scope" => scope_param}) do
    attr_allowed_scope = "__asteroid_oauth2_endpoint_register_allowed_scopes"
    attr_auto_scope = "__asteroid_oauth2_endpoint_register_auto_scopes"

    client = Client.fetch_attributes(client, [attr_allowed_scope, attr_auto_scope])

    client_auto_scopes = Scope.Set.new(client.attrs[attr_auto_scope] || [])

    requested_scopes = Scope.Set.from_scope_param!(scope_param)

    if client.attrs[attr_allowed_scope] do
      client_allowed_scopes = Scope.Set.new(client.attrs[attr_allowed_scope] || [])

      if Scope.Set.subset?(requested_scopes, client_allowed_scopes) do
        result_scopes = Scope.Set.union(requested_scopes, client_auto_scopes)

        Map.put(processed_metadata, "scope", Scope.Set.to_list(result_scopes))
      else
        raise UnauthorizedRequestedScopes,
          scope: Scope.Set.difference(requested_scopes, client_allowed_scopes)
      end
    else
      # let's compute all the available scopes for the flo9ws associated to the accepted
      # grant types
      allowed_scopes_for_flows =
        Enum.reduce(
          processed_metadata["grant_types"],
          MapSet.new(),
          fn
            grant_type_str, acc ->
              grant_type = OAuth2.to_grant_type!(grant_type_str)

              case OAuth2.grant_type_to_flow(grant_type) do
                flow when is_atom(flow) ->
                  Scope.Set.union(acc, OAuth2.Scope.scopes_for_flow(flow))

                nil ->
                  acc
              end
          end
        )

      if Scope.Set.subset?(requested_scopes, allowed_scopes_for_flows) do
        result_scopes = Scope.Set.union(requested_scopes, client_auto_scopes)

        Map.put(processed_metadata, "scope", Scope.Set.to_list(result_scopes))
      else
        raise UnauthorizedRequestedScopes,
          scope: Scope.Set.difference(requested_scopes, allowed_scopes_for_flows)
      end
    end
  end

  defp process_scope(processed_metadata, client, _input_metadata) do
    attr_auto_scope = "__asteroid_oauth2_endpoint_register_auto_scopes"

    client = Client.fetch_attributes(client, [attr_auto_scope])

    if client.attrs[attr_auto_scope] do
      Map.put(processed_metadata, "scope", client.attrs[attr_auto_scope])
    else
      processed_metadata
    end
  end

  @spec process_contacts(map(), map()) :: map()

  defp process_contacts(processed_metadata, %{"contacts" => contacts}) do
    case contacts do
      l when is_list(l) ->
        Enum.each(
          l,
          fn
            contact when is_binary(contact) ->
              :ok

            _ ->
              raise __MODULE__.InvalidClientMetadataField,
                field: "contacts",
                reason: "one of the list value is not a string"
          end
        )

        Map.put(processed_metadata, "contacts", contacts)

      _ ->
        raise __MODULE__.InvalidClientMetadataField,
          field: "contacts",
          reason: "not a list"
    end
  end

  defp process_contacts(processed_metadata, _input_metadata) do
    processed_metadata
  end

  @spec process_jwks_uri(map(), map()) :: map()

  defp process_jwks_uri(processed_metadata, %{"jwks_uri" => jwks_uri}) do
    case URI.parse(jwks_uri) do
      # we force it to be an HTTPS URL because the spec is unclear about it and to avoid
      # schemes such as file:///
      %URI{scheme: "https"} ->
        Map.put(processed_metadata, "jwks_uri", jwks_uri)

      _ ->
        raise __MODULE__.InvalidClientMetadataField,
          field: "jwks_uri",
          reason: "must be an https:// URL"
    end
  end

  defp process_jwks_uri(processed_metadata, _input_metadata) do
    processed_metadata
  end

  @spec process_jwks(map(), map()) :: map()

  defp process_jwks(%{"jwks_uri" => _}, %{"jwks" => _}) do
    raise __MODULE__.InvalidClientMetadataField,
      field: "jwks",
      reason: "`jwks_uri` and `jwks` fields cannot be present at the same time"
  end

  defp process_jwks(processed_metadata, %{"jwks" => jwks}) do
    case jwks["keys"] do
      key_list when is_list(key_list) ->
        Enum.each(
          key_list,
          fn
            %{"kty" => _} ->
              :ok

            key ->
              raise __MODULE__.InvalidClientMetadataField,
                field: "jwks",
                reason: "invalid key `#{inspect(key)}`, must be a map and contain `kty`"
          end
        )

        Map.put(processed_metadata, "jwks", key_list)

      _ ->
      raise __MODULE__.InvalidClientMetadataField,
        field: "jwks",
        reason: "jwks must have a `keys` key containing a list of keys"
    end
  end

  defp process_jwks(processed_metadata, _input_metadata) do
    processed_metadata
  end

  @spec process_software_id(map(), map()) :: map()

  defp process_software_id(processed_metadata, %{"software_id" => software_id}) do
    if is_binary(software_id) do
      Map.put(processed_metadata, "software_id", software_id)
    else
      raise __MODULE__.InvalidClientMetadataField,
        field: "software_id",
        reason: "must be a string"
    end
  end

  defp process_software_id(processed_metadata, _) do
    processed_metadata
  end

  @spec process_software_version(map(), map()) :: map()

  defp process_software_version(processed_metadata, %{"software_version" => software_version}) do
    if is_binary(software_version) do
      Map.put(processed_metadata, "software_version", software_version)
    else
      raise __MODULE__.InvalidClientMetadataField,
        field: "software_version",
        reason: "must be a string"
    end
  end

  defp process_software_version(processed_metadata, _) do
    processed_metadata
  end

  @spec process_additional_metadata_fields(map(), Client.t(), map()) :: map()

  defp process_additional_metadata_fields(processed_metadata, client, input_metadata) do
    add_met = "__asteroid_oauth2_endpoint_register_additional_metadata_fields"

    client = Client.fetch_attributes(client, [add_met])

    Enum.reduce(
      client.attrs[add_met] ||
        astrenv(:oauth2_endpoint_register_client_additional_metadata_field, []),
      processed_metadata,
      fn
        additional_field, acc ->
          put_if_not_nil(acc, additional_field, input_metadata[additional_field])
      end
    )
  end

  @spec gen_new_client_id(map()) :: String.t()

  defp gen_new_client_id(%{"client_name" => client_name}) do
    client_name_sanitized =
      client_name
      |> String.replace(~r/[^\x20-\x7E]/, "")
      |> String.replace(" ", "_")

    gen_new_client_id_from_client_name(client_name_sanitized, 0)
  end

  defp gen_new_client_id(_) do
    secure_random_b64(20)
  end

  @spec gen_new_client_id_from_client_name(String.t(), non_neg_integer()) :: String.t()

  defp gen_new_client_id_from_client_name(_client_name, n) when n >= 10_000 do
    secure_random_b64(20)
  end

  defp gen_new_client_id_from_client_name(client_name, n) do
    client_name =
      case n do
        0 ->
          client_name

        _ ->
          client_name <> "_" <> Integer.to_string(n)
      end

    case Client.load(client_name, attributes: []) do
      {:ok, _} ->
        client_name

      {:error, _} ->
        gen_new_client_id_from_client_name(client_name, n + 1)
    end
  end

  @spec process_i18n_field(map(), map(), String.t()) :: map()

  defp process_i18n_field(processed_metadata, input_metadata, field_name) do
    Enum.reduce(
      input_metadata,
      processed_metadata,
      fn
        {key, value}, acc ->
          if key == field_name or String.starts_with?(key, field_name <> "#") do
            Map.put(acc, key, value)
          else
            acc
          end
      end
    )
  end
end
