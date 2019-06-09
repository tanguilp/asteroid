defmodule AsteroidWeb.API.OAuth2.RegisterEndpoint do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.Client
  alias Asteroid.OAuth2

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
      "The following requested scopes are not allowed under the current policy: " <>
      Enum.join(scopes, " ")
    end
  end

  defmodule MissingRedirectURIError do
    @moduledoc """
    Error raised when the redirect uri is missing and grant types require at least one.
    """

    defexception []

    @impl true

    def message(_) do
      "Missing redirect URI, mandatory in regards of the request grant types"
    end
  end

  def handle(conn, input_metadata) do
    maybe_authenticated_client =
      case OAuth2.Client.get_authenticated_client(conn) do
        {:ok, client} ->
          client

        {:error, _} ->
          nil
      end

    case OAuth2.Register.request_authorized?(conn, maybe_authenticated_client) do
      :ok ->
        :ok

      {:error, e} ->
        raise e
    end

    ctx =
      %{}
      |> Map.put(:endpoint, :register)
      |> put_if_not_nil(:client, maybe_authenticated_client)

    processed_metadata =
      %{}
      |> process_grant_types(maybe_authenticated_client, input_metadata)
      |> process_response_types(maybe_authenticated_client, input_metadata)
      |> check_grant_response_type_consistency()
      |> process_redirect_uris(input_metadata)
      |> process_token_endpoint_auth_method(maybe_authenticated_client, input_metadata)
      |> process_i18n_field(input_metadata, "client_name")
      |> process_i18n_field(input_metadata, "client_uri")
      |> process_i18n_field(input_metadata, "logo_uri")
      |> process_i18n_field(input_metadata, "tos_uri")
      |> process_i18n_field(input_metadata, "policy_uri")
      |> process_scope(maybe_authenticated_client, input_metadata)
      |> process_contacts(input_metadata)
      |> process_jwks_uri(input_metadata)
      |> process_jwks(input_metadata)
      |> process_software_id(input_metadata)
      |> process_software_version(input_metadata)
      |> process_additional_metadata_fields(maybe_authenticated_client, input_metadata)

    maybe_client_secret_and_hash =
      if processed_metadata["token_endpoint_auth_method"] == "client_secret_basic" or
         processed_metadata["token_endpoint_auth_method"] == "client_secret_post"
      do
        Expwd.Hashed.gen()
      else
        nil
      end

    client_id = astrenv(:oauth2_endpoint_register_gen_client_id_callback).(processed_metadata)

    new_client =
      Enum.reduce(
        processed_metadata,
        Client.gen_new(id: client_id),
        fn
          {k, v}, acc ->
            Client.add(acc, k, v)
        end
      )
      |> Client.add("client_id", client_id)
      |> set_client_type()

    new_client =
      if maybe_client_secret_and_hash do
        hashed_client_str =
          maybe_client_secret_and_hash
          |> elem(1)
          |> Expwd.Hashed.Portable.to_portable()

        Client.add(new_client, "client_secret", hashed_client_str)
      else
        new_client
      end

    :ok =
      new_client
      |> jwks_to_binary()
      |> astrenv(:oauth2_endpoint_register_client_before_save_callback).(ctx)
      |> Client.store()

    processed_metadata =
      if maybe_client_secret_and_hash do
        {client_secret, _client_secret_hashed} = maybe_client_secret_and_hash

        Map.put(processed_metadata, "client_secret", client_secret)
      else
        processed_metadata
      end
      |> Map.put("client_id", client_id)
      |> astrenv(:oauth2_endpoint_register_before_send_resp_callback).(ctx)

    conn
    |> put_status(201)
    |> astrenv(:oauth2_endpoint_register_before_send_conn_callback).(ctx)
    |> json(processed_metadata)
  rescue
    e in Asteroid.OAuth2.Client.AuthenticationError ->
      OAuth2.Client.error_response(conn, e)

    e in Asteroid.OAuth2.Register.UnauthorizedRequestError ->
      OAuth2.Register.error_response(conn, e)

    e in OAuth2.RedirectUri.MalformedError ->
      error_resp(conn, error: :invalid_redirect_uri, error_description: Exception.message(e))

    e in InvalidClientMetadataField ->
      error_resp(conn, error: :invalid_client_metadata, error_description: Exception.message(e))

    e in MissingRedirectURIError ->
      error_resp(conn, error: :invalid_client_metadata, error_description: Exception.message(e))

    e in UnauthorizedRequestedScopes ->
      error_resp(conn, error: :invalid_client_metadata, error_description: Exception.message(e))

    e in Scope.Set.InvalidScopeParam ->
      error_resp(conn, error: :invalid_client_metadata, error_description: Exception.message(e))

    e in OAuth2.Endpoint.UnsupportedAuthMethod ->
      error_resp(conn, error: :invalid_client_metadata, error_description: Exception.message(e))
  end

  @spec process_grant_types(map(), Client.t() | nil, map()) :: map()

  defp process_grant_types(
    processed_metadata,
    nil,
    %{"grant_types" => requested_grant_types}) when is_list(requested_grant_types)
  do
    enabled_grant_types =
      astrenv(:oauth2_grant_types_enabled)
      |> Enum.map(&to_string/1)
      |> MapSet.new()

    if MapSet.subset?(MapSet.new(requested_grant_types), enabled_grant_types) do
      Map.put(processed_metadata, "grant_types", requested_grant_types)
    else
      raise InvalidClientMetadataField,
        field: "grant_types",
        reason: "one of the grant types could be granted as a result of applying the server policy"
    end
  end

  defp process_grant_types(
    processed_metadata,
    authenticated_client,
    %{"grant_types" => requested_grant_types}) when is_list(requested_grant_types)
  do
    conf_attr = "__asteroid_oauth2_endpoint_register_allowed_grant_types"

    client = Client.fetch_attributes(authenticated_client, [conf_attr])

    enabled_grant_types =
      astrenv(:oauth2_grant_types_enabled)
      |> Enum.map(&to_string/1)

    allowed_grant_types =
      MapSet.intersection(
        MapSet.new(client.attrs[conf_attr] || enabled_grant_types),
        MapSet.new(enabled_grant_types)
      )

    if MapSet.subset?(MapSet.new(requested_grant_types), allowed_grant_types) do
      Map.put(processed_metadata, "grant_types", requested_grant_types)
    else
      raise InvalidClientMetadataField,
        field: "grant_types",
        reason: "one of the grant types could be granted as a result of applying the server policy"
    end
  end

  defp process_grant_types(_, _, %{"grant_types" => _}) do
    raise InvalidClientMetadataField,
      field: "grant_types",
      reason: "should be a list of strings"
  end

  defp process_grant_types(processed_metadata, _, _) do
    Map.put(processed_metadata, "grant_types", ["authorization_code"])
  end

  @spec process_response_types(map(), Client.t() | nil, map()) :: map()

  defp process_response_types(
    processed_metadata,
    nil,
    %{"response_types" => requested_response_types}) when is_list(requested_response_types)
  do
    enabled_response_types =
      astrenv(:oauth2_response_types_enabled)
      |> Enum.map(&to_string/1)
      |> MapSet.new()

    if MapSet.subset?(MapSet.new(requested_response_types), enabled_response_types) do
      Map.put(processed_metadata, "response_types", requested_response_types)
    else
      raise InvalidClientMetadataField,
        field: "response_types",
        reason: "one of the response types could be granted as a result of applying the server policy"
    end
  end

  defp process_response_types(
    processed_metadata,
    authenticated_client,
    %{"response_types" => requested_response_types}) when is_list(requested_response_types)
  do
    conf_attr = "__asteroid_oauth2_endpoint_register_allowed_response_types"

    client = Client.fetch_attributes(authenticated_client, [conf_attr])

    enabled_response_types =
      astrenv(:oauth2_response_types_enabled)
      |> Enum.map(&to_string/1)

    allowed_response_types =
      MapSet.intersection(
        MapSet.new(client.attrs[conf_attr] || enabled_response_types),
        MapSet.new(enabled_response_types)
      )

    if MapSet.subset?(MapSet.new(requested_response_types), allowed_response_types) do
          Map.put(processed_metadata, "response_types", requested_response_types)
    else
      raise InvalidClientMetadataField,
        field: "response_types",
        reason: "one of the response types could be granted as a result of applying the server policy"
    end
  end

  defp process_response_types(_, _, %{"response_types" => _}) do
    raise InvalidClientMetadataField,
      field: "response_types",
      reason: "should be a list of strings"
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
          raise MissingRedirectURIError
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

  @spec process_token_endpoint_auth_method(map(), Client.t() | nil, map()) :: map()

  defp process_token_endpoint_auth_method(
    processed_metadata,
    nil,
    %{"token_endpoint_auth_method" => token_endpoint_auth_method})
      when is_binary(token_endpoint_auth_method)
  do
    auth_method_allowed_str =
      astrenv(:oauth2_endpoint_token_auth_methods_supported_callback).f()
      |> Enum.map(&to_string/1)

    if token_endpoint_auth_method in auth_method_allowed_str do
      Map.put(processed_metadata, "token_endpoint_auth_method", token_endpoint_auth_method)
    else
      raise OAuth2.Endpoint.UnsupportedAuthMethod,
        endpoint: :token,
        auth_method: token_endpoint_auth_method
    end
  end

  defp process_token_endpoint_auth_method(
    processed_metadata,
    authenticated_client,
    %{"token_endpoint_auth_method" => token_endpoint_auth_method})
      when is_binary(token_endpoint_auth_method)
  do
    auth_meth_client = "__asteroid_oauth2_endpoint_register_allowed_token_endpoint_auth_methods"

    client = Client.fetch_attributes(authenticated_client, [auth_meth_client])

    token_endpoint_auth_methods_supported =
      astrenv(:oauth2_endpoint_token_auth_methods_supported_callback).()

    auth_method_allowed_str =
      case client.attrs[auth_meth_client] do
        nil ->
          Enum.map(token_endpoint_auth_methods_supported, &to_string/1)

        l when is_list(l) ->
          MapSet.intersection(
            MapSet.new(l),
            token_endpoint_auth_methods_supported |> Enum.map(&to_string/1) |> MapSet.new()
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

  defp process_token_endpoint_auth_method(
    _processed_metadata,
    _authenticated_client,
    %{"token_endpoint_auth_method" => _})
  do
    raise InvalidClientMetadataField,
      field: "token_endpoint_auth_method",
      reason: "should be a list of strings"
  end

  defp process_token_endpoint_auth_method(processed_metadata, _, _) do
    Map.put(processed_metadata, "token_endpoint_auth_method", "client_secret_basic")
  end

  @spec process_scope(map(), Client.t() | nil, map()) :: map()

  defp process_scope(
    processed_metadata,
    nil,
    %{"scope" => scope_param}) when is_binary(scope_param)
  do
    requested_scopes = Scope.Set.from_scope_param!(scope_param)

    # let's compute all the available scopes for the flows associated to the accepted
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
      Map.put(processed_metadata, "scope", Scope.Set.to_scope_param(requested_scopes))
    else
      raise UnauthorizedRequestedScopes,
        scopes: Scope.Set.difference(requested_scopes, allowed_scopes_for_flows)
    end
  end

  defp process_scope(
    processed_metadata,
    authorized_client,
    %{"scope" => scope_param}) when is_binary(scope_param)
  do
    attr_allowed_scope = "__asteroid_oauth2_endpoint_register_allowed_scopes"
    attr_auto_scope = "__asteroid_oauth2_endpoint_register_auto_scopes"

    client = Client.fetch_attributes(authorized_client, [attr_allowed_scope, attr_auto_scope])

    client_auto_scopes = Scope.Set.new(client.attrs[attr_auto_scope] || [])

    requested_scopes = Scope.Set.from_scope_param!(scope_param)

    if client.attrs[attr_allowed_scope] do
      client_allowed_scopes = Scope.Set.new(client.attrs[attr_allowed_scope] || [])

      if Scope.Set.subset?(requested_scopes, client_allowed_scopes) do
        result_scopes = Scope.Set.union(requested_scopes, client_auto_scopes)

        Map.put(processed_metadata, "scope", Scope.Set.to_scope_param(result_scopes))
      else
        raise UnauthorizedRequestedScopes,
          scopes: Scope.Set.difference(requested_scopes, client_allowed_scopes)
      end
    else
      # let's compute all the available scopes for the flows associated to the accepted
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

        Map.put(processed_metadata, "scope", Scope.Set.to_scope_param(result_scopes))
      else
        raise UnauthorizedRequestedScopes,
          scopes: Scope.Set.difference(requested_scopes, allowed_scopes_for_flows)
      end
    end
  end

  defp process_scope(_processed_metadata, _client, %{"scope" => _}) do
    raise InvalidClientMetadataField,
      field: "scope",
      reason: "should be a string"
  end

  defp process_scope(processed_metadata, nil, _input_metadata) do
    #FIXME: allow default scopes here?

    processed_metadata
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
              raise InvalidClientMetadataField,
                field: "contacts",
                reason: "one of the list value is not a string"
          end
        )

        Map.put(processed_metadata, "contacts", contacts)

      _ ->
        raise InvalidClientMetadataField,
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
        raise InvalidClientMetadataField,
          field: "jwks_uri",
          reason: "must be an https:// URL"
    end
  end

  defp process_jwks_uri(processed_metadata, _input_metadata) do
    processed_metadata
  end

  @spec process_jwks(map(), map()) :: map()

  defp process_jwks(%{"jwks_uri" => _}, %{"jwks" => _}) do
    raise InvalidClientMetadataField,
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
              raise InvalidClientMetadataField,
                field: "jwks",
                reason: "invalid key `#{inspect(key)}`, must be a map and contain `kty`"
          end
        )

        Map.put(processed_metadata, "jwks", key_list)

      _ ->
      raise InvalidClientMetadataField,
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
      raise InvalidClientMetadataField,
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
      raise InvalidClientMetadataField,
        field: "software_version",
        reason: "must be a string"
    end
  end

  defp process_software_version(processed_metadata, _) do
    processed_metadata
  end

  @spec process_additional_metadata_fields(map(), Client.t() | nil, map()) :: map()

  defp process_additional_metadata_fields(processed_metadata, nil, input_metadata) do
    Enum.reduce(
      astrenv(:oauth2_endpoint_register_additional_metadata_field, []),
      processed_metadata,
      fn
        additional_field, acc ->
          put_if_not_nil(acc, additional_field, input_metadata[additional_field])
      end
    )
  end

  defp process_additional_metadata_fields(processed_metadata, authorized_client, input_metadata) do
    add_met = "__asteroid_oauth2_endpoint_register_additional_metadata_fields"

    client = Client.fetch_attributes(authorized_client, [add_met])

    Enum.reduce(
      client.attrs[add_met] ||
        astrenv(:oauth2_endpoint_register_additional_metadata_field, []),
      processed_metadata,
      fn
        additional_field, acc ->
          put_if_not_nil(acc, additional_field, input_metadata[additional_field])
      end
    )
  end

  @spec set_client_type(Client.t()) :: Client.t()

  defp set_client_type(client) do
    if client.attrs["token_endpoint_auth_method"] == "none" do
      Client.add(client, "client_type", "public")
    else
      Client.add(client, "client_type", "confidential")
    end
  end

  @spec check_grant_response_type_consistency(map()) :: map()

  defp check_grant_response_type_consistency(processed_metadata) do
    case OAuth2.Register.grant_response_types_consistent?(
      processed_metadata["grant_types"],
      processed_metadata["response_types"])
    do
      :ok ->
        processed_metadata

      {:error, {:grant_type, error_str}} ->
        raise InvalidClientMetadataField, field: "grant_types", reason: error_str

      {:error, {:response_type, error_str}} ->
        raise InvalidClientMetadataField, field: "response_types", reason: error_str
    end
  end

  @spec jwks_to_binary(Client.t()) :: Client.t()

  defp jwks_to_binary(%Client{:attrs => %{"jwks" => jwks}} = client) do
    jwks_binary = for jwk <- jwks, do: {:binary_data, :erlang.term_to_binary(jwk)}

    client
    |> Client.remove("jwks")
    |> Client.add("jwks", jwks_binary)
  end

  defp jwks_to_binary(client) do
    client
  end

  @spec process_i18n_field(map(), map(), String.t()) :: map()

  defp process_i18n_field(processed_metadata, input_metadata, field_name) do
    Enum.reduce(
      input_metadata,
      processed_metadata,
      fn
        {key, value}, acc ->
          cond do
            field_name == key ->
              Map.put(acc, key, value)

            # for instance `client_name#fr`
            String.starts_with?(key, field_name <> "#") ->
              field_name_i18n = field_name <> "_i18n"

              [^field_name, i18n_key] = String.split(key, "#")

              case acc[field_name_i18n] do
                nil ->
                  Map.put(acc, field_name_i18n, %{i18n_key => value})

                _ -> # key already exsists
                  put_in(acc, [field_name_i18n, i18n_key], value)
              end

            true ->
              acc
          end
      end
    )
  end
end
