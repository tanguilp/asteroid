defmodule AsteroidWeb.API.OAuth2.RegisterController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.Client
  alias Asteroid.OAuth2

  defmodule InvalidClientMetadataFieldError do
    @moduledoc """
    Error returned when client metadata is invalid
    """

    defexception [:field, :reason]

    @impl true

    def message(%{field: field, reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          case field do
            "token_endpoint_auth_method" ->
              "Invalid field `#{field}` (reason: #{reason}, supported methods:)" <>
              "#{inspect astrenv(:oauth2_endpoint_token_auth_methods_supported_callback).()})"

            _ ->
              "Invalid field `#{field}` (reason: #{reason})"
          end

        :normal ->
          "Invalid field `#{field}`"

        :minimal ->
          ""
      end
    end
  end

  defmodule UnauthorizedRequestedScopesError do
    @moduledoc """
    Error returned when returning scopes are not allowed according to the policy (either the
    client's configuration or the scopes existing in the configuration options).
    """

    defexception [:scopes]

    @impl true

    def message (%{scopes: scopes}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "The following requested scopes are not allowed under the current policy: " <>
          Enum.join(scopes, " ")

        :normal ->
          "The requested scopes are not allowed under the current policy"

        :minimal ->
          ""
      end
    end
  end

  defmodule InvalidRedirectURIError do
    @moduledoc """
    Error raised when the one or more redirect URIs are invalid
    """

    defexception [:redirect_uri]

    @type t :: %__MODULE__{
      redirect_uri: String.t()
    }

    @impl true

    def message(%{redirect_uri: redirect_uri}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Invalid redirect URI `#{redirect_uri}`"

        :normal ->
          "Invalid redirect URI `#{redirect_uri}`"

        :minimal ->
          ""
      end
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
      |> Map.put(:conn, conn)
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
      |> process_oidc_application_type(input_metadata)
      |> process_oidc_sector_identifier_uri(input_metadata)
      |> process_oidc_subject_type(input_metadata)
      |> process_oidc_id_token_signed_response_alg(input_metadata)
      |> process_oidc_id_token_encrypted_response_alg(input_metadata)
      |> process_oidc_id_token_encrypted_response_enc(input_metadata)
      |> process_oidc_userinfo_signed_response_alg(input_metadata)
      |> process_oidc_userinfo_encrypted_response_alg(input_metadata)
      |> process_oidc_userinfo_encrypted_response_enc(input_metadata)
      |> process_oidc_request_object_signed_response_alg(input_metadata)
      |> process_oidc_request_object_encrypted_response_alg(input_metadata)
      |> process_oidc_request_object_encrypted_response_enc(input_metadata)
      |> process_oidc_default_max_age(input_metadata)
      |> process_oidc_require_auth_time(input_metadata)
      |> process_oidc_default_acr_values(input_metadata)
      |> process_additional_metadata_fields(maybe_authenticated_client, input_metadata)
      |> set_client_id(ctx)

    maybe_client_secret_and_hash =
      if processed_metadata["token_endpoint_auth_method"] == "client_secret_basic" or
         processed_metadata["token_endpoint_auth_method"] == "client_secret_post"
      do
        Expwd.Hashed.gen()
      end

    client_resource_id =
      astrenv(:oauth2_endpoint_register_gen_client_resource_id_callback).(processed_metadata, ctx)

    new_client =
      Enum.reduce(
        processed_metadata,
        Client.gen_new(id: client_resource_id),
        fn
          {k, v}, acc ->
            Client.add(acc, k, v)
        end
      )
      |> set_new_client_type()
      |> set_client_created_by(maybe_authenticated_client)

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
      |> astrenv(:oauth2_endpoint_register_before_send_resp_callback).(ctx)

    conn
    |> put_status(201)
    |> astrenv(:oauth2_endpoint_register_before_send_conn_callback).(ctx)
    |> json(processed_metadata)
  rescue
    e in [
      Asteroid.OAuth2.Client.AuthenticationError,
      Asteroid.OAuth2.Client.AuthorizationError,
      InvalidClientMetadataFieldError,
      InvalidRedirectURIError,
      UnauthorizedRequestedScopesError
    ] ->
      AsteroidWeb.Error.respond_api(conn, e)

    _ in Scope.Set.InvalidScopeParam ->
      AsteroidWeb.Error.respond_api(conn, InvalidClientMetadataFieldError.exception(
        field: "scope",
        reason: "malformed scope param"
      ))
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
      raise InvalidClientMetadataFieldError,
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
      raise InvalidClientMetadataFieldError,
        field: "grant_types",
        reason: "one of the grant types could be granted as a result of applying the server policy"
    end
  end

  defp process_grant_types(_, _, %{"grant_types" => _}) do
    raise InvalidClientMetadataFieldError,
      field: "grant_types",
      reason: "should be a list of strings"
  end

  defp process_grant_types(processed_metadata, nil, _) do
    Map.put(processed_metadata, "grant_types", ["authorization_code"])
  end

  defp process_grant_types(processed_metadata, authenticated_client, _) do
    attr = "__asteroid_oauth2_endpoint_register_default_grant_types"

    client = Client.fetch_attributes(authenticated_client, [attr])

    case client.attrs[attr] do
      l when is_list(l) ->
        Map.put(processed_metadata, "grant_types", l)

      nil ->
        Map.put(processed_metadata, "grant_types", ["authorization_code"])
    end
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
      raise InvalidClientMetadataFieldError,
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
      raise InvalidClientMetadataFieldError,
        field: "response_types",
        reason: "one of the response types could be granted as a result of applying the server policy"
    end
  end

  defp process_response_types(_, _, %{"response_types" => _}) do
    raise InvalidClientMetadataFieldError,
      field: "response_types",
      reason: "should be a list of strings"
  end

  defp process_response_types(processed_metadata, nil, _) do
    Map.put(processed_metadata, "response_types", ["code"])
  end

  defp process_response_types(processed_metadata, authenticated_client, _) do
    attr = "__asteroid_oauth2_endpoint_register_default_response_types"

    client = Client.fetch_attributes(authenticated_client, [attr])

    case client.attrs[attr] do
      l when is_list(l) ->
        Map.put(processed_metadata, "response_types", l)

      nil ->
        Map.put(processed_metadata, "response_types", ["code"])
    end
  end

  @spec process_redirect_uris(map(), map()) :: map()

  defp process_redirect_uris(processed_metadata, input_metadata) do
    case input_metadata["redirect_uris"] do
      [_ | _] = redirect_uris ->
        Enum.each(
          redirect_uris,
          fn
            redirect_uri ->
              unless OAuth2.RedirectUri.valid?(redirect_uri) do
                  raise InvalidRedirectURIError, redirect_uri: redirect_uri
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
          raise InvalidClientMetadataFieldError,
            field: "redirect_uris",
            reason: "field is mandatory in regards to the requested grant types"
        else
          processed_metadata
        end
    end
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
      raise InvalidClientMetadataFieldError,
        field: "token_endpoint_auth_method",
        reason: "The client authentication method `#{token_endpoint_auth_method}` is unsupported"
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
      raise InvalidClientMetadataFieldError,
        field: "token_endpoint_auth_method",
        reason: "The client authentication method `#{token_endpoint_auth_method}` is unsupported"
    end
  end

  defp process_token_endpoint_auth_method(
    _processed_metadata,
    _authenticated_client,
    %{"token_endpoint_auth_method" => _})
  do
    raise InvalidClientMetadataFieldError,
      field: "token_endpoint_auth_method",
      reason: "should be a list of strings"
  end

  defp process_token_endpoint_auth_method(processed_metadata, nil, _) do
    Map.put(processed_metadata, "token_endpoint_auth_method", "client_secret_basic")
  end

  defp process_token_endpoint_auth_method(processed_metadata, authenticated_client, _) do
    attr = "__asteroid_oauth2_endpoint_register_default_token_endpoint_auth_method"

    client = Client.fetch_attributes(authenticated_client, [attr])

    case client.attrs[attr] do
      auth_method when is_binary(auth_method) ->
        Map.put(processed_metadata, "token_endpoint_auth_method", auth_method)

      nil ->
        Map.put(processed_metadata, "token_endpoint_auth_method", "client_secret_basic")
    end
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
              nil ->
                acc

              flow when is_atom(flow) ->
                Scope.Set.union(acc, OAuth2.Scope.scopes_for_flow(flow))
            end
        end
      )

    if Scope.Set.subset?(requested_scopes, allowed_scopes_for_flows) do
      Map.put(processed_metadata, "scope", Scope.Set.to_scope_param(requested_scopes))
    else
      raise UnauthorizedRequestedScopesError,
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
        raise UnauthorizedRequestedScopesError,
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
                nil ->
                  acc

                flow when is_atom(flow) ->
                  Scope.Set.union(acc, OAuth2.Scope.scopes_for_flow(flow))
              end
          end
        )

      if Scope.Set.subset?(requested_scopes, allowed_scopes_for_flows) do
        result_scopes = Scope.Set.union(requested_scopes, client_auto_scopes)

        Map.put(processed_metadata, "scope", Scope.Set.to_scope_param(result_scopes))
      else
        raise UnauthorizedRequestedScopesError,
          scopes: Scope.Set.difference(requested_scopes, allowed_scopes_for_flows)
      end
    end
  end

  defp process_scope(_processed_metadata, _client, %{"scope" => _}) do
    raise InvalidClientMetadataFieldError,
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
              raise InvalidClientMetadataFieldError,
                field: "contacts",
                reason: "one of the list value is not a string"
          end
        )

        Map.put(processed_metadata, "contacts", contacts)

      _ ->
        raise InvalidClientMetadataFieldError,
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
        raise InvalidClientMetadataFieldError,
          field: "jwks_uri",
          reason: "must be an https:// URL"
    end
  end

  defp process_jwks_uri(processed_metadata, _input_metadata) do
    processed_metadata
  end

  @spec process_jwks(map(), map()) :: map()

  defp process_jwks(%{"jwks_uri" => _}, %{"jwks" => _}) do
    raise InvalidClientMetadataFieldError,
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
              raise InvalidClientMetadataFieldError,
                field: "jwks",
                reason: "invalid key `#{inspect(key)}`, must be a map and contain `kty`"
          end
        )

        Map.put(processed_metadata, "jwks", key_list)

      _ ->
      raise InvalidClientMetadataFieldError,
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
      raise InvalidClientMetadataFieldError,
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
      raise InvalidClientMetadataFieldError,
        field: "software_version",
        reason: "must be a string"
    end
  end

  defp process_software_version(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_application_type(map(), map()) :: map()

  defp process_oidc_application_type(processed_metadata, %{"application_type" => app_type})
    when app_type in ["native", "web"]
  do
    Map.put(processed_metadata, "application_type", app_type)
  end

  defp process_oidc_application_type(_processed_metadata, %{"application_type" => _}) do
    raise InvalidClientMetadataFieldError,
      field: "application_type",
      reason: "must be `web` or `native`"
  end

  defp process_oidc_application_type(processed_metadata, _) do
    Map.put(processed_metadata, "application_type", "web")
  end

  @doc """
  Verifies that the content of the document stored at a sector identifier URI is valid against
  a list of redirect URIs
  """

  @spec verify_sector_identifier_uri(String.t(), [OAuth2.RedirectUri.t(), ...]) ::
  :ok
  | {:error, %InvalidClientMetadataFieldError{}}

  def verify_sector_identifier_uri(sector_identifier_uri, redirect_uris) do
    case URI.parse(sector_identifier_uri) do
      %URI{scheme: "https"} ->
        case HTTPoison.get(sector_identifier_uri, [], []) do
          {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
            case Jason.decode(body) do
              {:ok, loaded_redirect_uris} when is_list(loaded_redirect_uris) ->
                if Enum.all?(redirect_uris, &(&1 in loaded_redirect_uris)) do
                  :ok
                else
                  {:error, InvalidClientMetadataFieldError.exception([
                    field: "sector_identifier_uri",
                    reason: "sector identifier URI redirect URIs not all included in" <>
                      "request redirect URIs"])}
                end

              {:error, _e} ->
                {:error, InvalidClientMetadataFieldError.exception([
                  field: "sector_identifier_uri",
                  reason: "invalid JSON content at sector identifier URI, must be a JSON list"])}
            end

          {:ok, %HTTPoison.Response{status_code: st_code}} ->
            {:error, InvalidClientMetadataFieldError.exception([
              field: "sector_identifier_uri",
              reason: "requesting the sector identifier URI resulted in HTTP code #{st_code}"])}

          {:error, e} ->
            {:error, InvalidClientMetadataFieldError.exception([
              field: "sector_identifier_uri",
              reason: "HTTP error: " <> Exception.message(e)])}
        end

      _ ->
        {:error, InvalidClientMetadataFieldError.exception([
          field: "sector_identifier_uri",
          reason: "scheme must be `https`"])}
    end
  end

  @spec process_oidc_sector_identifier_uri(map(), map()) :: map()

  defp process_oidc_sector_identifier_uri(processed_metadata,
                                     %{"sector_identifier_uri" => sector_identifier_uri})
  do
    case verify_sector_identifier_uri(sector_identifier_uri,
                                      processed_metadata["redirect_uris"])
    do
      :ok ->
        Map.put(processed_metadata, "sector_identifier_uri", sector_identifier_uri)

      {:error, e} ->
        raise e
    end
  end

  defp process_oidc_sector_identifier_uri(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_subject_type(map(), map()) :: map()

  defp process_oidc_subject_type(processed_metadata, %{"subject_type" => "pairwise"}) do
    redir_hosts =
      Enum.reduce(
        processed_metadata,
        MapSet.new(),
        fn redirect_uri, acc -> MapSet.put(acc, URI.parse(redirect_uri).host) end)

    if MapSet.size(redir_hosts) > 1 and processed_metadata["sector_identifier_uri"] == nil do
      raise InvalidClientMetadataFieldError,
        field: "pairwise",
        reason: "`sector_identifier_uri` is mandatory when registering more than one " <>
                "host within redirect URIs"
    else
        Map.put(processed_metadata, "subject_type", "pairwise")
    end
  end

  defp process_oidc_subject_type(processed_metadata, %{"subject_type" => "public"}) do
    Map.put(processed_metadata, "subject_type", "public")
  end

  defp process_oidc_subject_type(_processed_metadata, %{"subject_type" => _}) do
    raise InvalidClientMetadataFieldError,
      field: "subject_type",
      reason: "invalid subject type, must be `pairwise` or `public`"
  end

  defp process_oidc_subject_type(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_id_token_signed_response_alg(map(), map()) :: map()

  defp process_oidc_id_token_signed_response_alg(
    processed_metadata,
    %{"id_token_signed_response_alg" => id_token_signed_response_alg}
  ) do
    if id_token_signed_response_alg in astrenv(:oidc_id_token_supported_signing_algs, []) do
      Map.put(processed_metadata, "id_token_signed_response_alg", id_token_signed_response_alg)
    else
      raise InvalidClientMetadataFieldError,
        field: "id_token_signed_response_alg",
        reason: "value provided not in supported signing algs"
    end
  end

  defp process_oidc_id_token_signed_response_alg(processed_metadata, _) do
    Map.put(processed_metadata, "id_token_signed_response_alg", "RS256")
  end

  @spec process_oidc_id_token_encrypted_response_alg(map(), map()) :: map()

  defp process_oidc_id_token_encrypted_response_alg(
    processed_metadata,
    %{"id_token_encrypted_response_alg" => id_token_encrypted_response_alg}
  ) do
    if id_token_encrypted_response_alg in astrenv(:oidc_id_token_supported_encryption_algs, []) do
      Map.put(processed_metadata,
              "id_token_encrypted_response_alg",
              id_token_encrypted_response_alg)
    else
      raise InvalidClientMetadataFieldError,
        field: "id_token_encrypted_response_alg",
        reason: "value provided not in supported encryption algs"
    end
  end

  defp process_oidc_id_token_encrypted_response_alg(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_id_token_encrypted_response_enc(map(), map()) :: map()

  defp process_oidc_id_token_encrypted_response_enc(
    processed_metadata,
    %{"id_token_encrypted_response_enc" => id_token_encrypted_response_enc,
      "id_token_encrypted_response_alg" => _}
  ) do
    if id_token_encrypted_response_enc in astrenv(:oidc_id_token_supported_encryption_encs, []) do
      Map.put(processed_metadata,
              "id_token_encrypted_response_enc",
              id_token_encrypted_response_enc)
    else
      raise InvalidClientMetadataFieldError,
        field: "id_token_encrypted_response_enc",
        reason: "value provided not in supported encryption encs"
    end
  end

  defp process_oidc_id_token_encrypted_response_enc(
    _,
    %{"id_token_encrypted_response_enc" => _}
    ) do
    raise InvalidClientMetadataFieldError,
      field: "id_token_encrypted_response_enc",
      reason: "`id_token_encrypted_response_alg` must be registered along with this field"
  end

  defp process_oidc_id_token_encrypted_response_enc(
    processed_metadata,
      %{"id_token_encrypted_response_alg" => _}
  ) do
    Map.put(processed_metadata, "id_token_encrypted_response_enc", "A128CBC-HS256")
  end

  defp process_oidc_id_token_encrypted_response_enc(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_userinfo_signed_response_alg(map(), map()) :: map()

  defp process_oidc_userinfo_signed_response_alg(
    processed_metadata,
    %{"userinfo_signed_response_alg" => userinfo_signed_response_alg}
  ) do
    if userinfo_signed_response_alg in astrenv(:oidc_userinfo_supported_signing_algs, []) do
      Map.put(processed_metadata, "userinfo_signed_response_alg", userinfo_signed_response_alg)
    else
      raise InvalidClientMetadataFieldError,
        field: "userinfo_signed_response_alg",
        reason: "value provided not in supported signing algs"
    end
  end

  defp process_oidc_userinfo_signed_response_alg(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_userinfo_encrypted_response_alg(map(), map()) :: map()

  defp process_oidc_userinfo_encrypted_response_alg(
    processed_metadata,
    %{"userinfo_encrypted_response_alg" => userinfo_encrypted_response_alg}
  ) do
    if userinfo_encrypted_response_alg in astrenv(:oidc_userinfo_supported_encryption_algs, []) do
      Map.put(processed_metadata,
              "userinfo_encrypted_response_alg",
              userinfo_encrypted_response_alg)
    else
      raise InvalidClientMetadataFieldError,
        field: "userinfo_encrypted_response_alg",
        reason: "value provided not in supported encryption algs"
    end
  end

  defp process_oidc_userinfo_encrypted_response_alg(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_userinfo_encrypted_response_enc(map(), map()) :: map()

  defp process_oidc_userinfo_encrypted_response_enc(
    processed_metadata,
    %{"userinfo_encrypted_response_enc" => userinfo_encrypted_response_enc,
      "userinfo_encrypted_response_alg" => _}
  ) do
    if userinfo_encrypted_response_enc in astrenv(:oidc_userinfo_supported_encryption_encs, []) do
      Map.put(processed_metadata,
              "userinfo_encrypted_response_enc",
              userinfo_encrypted_response_enc)
    else
      raise InvalidClientMetadataFieldError,
        field: "userinfo_encrypted_response_enc",
        reason: "value provided not in supported encryption encs"
    end
  end

  defp process_oidc_userinfo_encrypted_response_enc(
    _processed_metadata,
    %{"userinfo_encrypted_response_enc" => _}
  ) do
    raise InvalidClientMetadataFieldError,
      field: "userinfo_encrypted_response_enc",
      reason: "`userinfo_encrypted_response_alg` must be registered along with this field"
  end

  defp process_oidc_userinfo_encrypted_response_enc(
    processed_metadata,
    %{"userinfo_encrypted_response_alg" => _}
  ) do
    Map.put(processed_metadata, "userinfo_encrypted_response_enc", "A128CBC-HS256")
  end

  defp process_oidc_userinfo_encrypted_response_enc(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_request_object_signed_response_alg(map(), map()) :: map()

  defp process_oidc_request_object_signed_response_alg(
    processed_metadata,
    %{"request_object_signed_response_alg" => request_object_signed_response_alg}
  ) do
    if request_object_signed_response_alg in
      astrenv(:oidc_request_object_supported_signing_algs, [])
    do
      Map.put(processed_metadata,
              "request_object_signed_response_alg",
              request_object_signed_response_alg)
    else
      raise InvalidClientMetadataFieldError,
        field: "request_object_signed_response_alg",
        reason: "value provided not in supported signing algs"
    end
  end

  defp process_oidc_request_object_signed_response_alg(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_request_object_encrypted_response_alg(map(), map()) :: map()

  defp process_oidc_request_object_encrypted_response_alg(
    processed_metadata,
    %{"request_object_encrypted_response_alg" => request_object_encrypted_response_alg}
  ) do
    if request_object_encrypted_response_alg in astrenv(:oidc_request_object_supported_encryption_algs, []) do
      Map.put(processed_metadata,
              "request_object_encrypted_response_alg",
              request_object_encrypted_response_alg)
    else
      raise InvalidClientMetadataFieldError,
        field: "request_object_encrypted_response_alg",
        reason: "value provided not in supported encryption algs"
    end
  end

  defp process_oidc_request_object_encrypted_response_alg(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_request_object_encrypted_response_enc(map(), map()) :: map()

  defp process_oidc_request_object_encrypted_response_enc(
    processed_metadata,
    %{"request_object_encrypted_response_enc" => request_object_encrypted_response_enc,
      "request_object_encrypted_response_alg" => _}
  ) do
    if request_object_encrypted_response_enc in
      astrenv(:oidc_request_object_supported_encryption_encs, [])
    do
      Map.put(processed_metadata,
              "request_object_encrypted_response_enc",
              request_object_encrypted_response_enc)
    else
      raise InvalidClientMetadataFieldError,
        field: "request_object_encrypted_response_enc",
        reason: "value provided not in supported encryption encs"
    end
  end

  defp process_oidc_request_object_encrypted_response_enc(
    _processed_metadata,
    %{"request_object_encrypted_response_enc" => _request_object_encrypted_response_enc}
  ) do
    raise InvalidClientMetadataFieldError,
      field: "request_object_encrypted_response_enc",
      reason: "`request_object_encrypted_response_alg` must be registered along with this field"
  end

  defp process_oidc_request_object_encrypted_response_enc(
    processed_metadata,
    %{"request_object_encrypted_response_alg" => _}
  ) do
    Map.put(processed_metadata, "request_object_encrypted_response_enc", "A128CBC-HS256")
  end

  defp process_oidc_request_object_encrypted_response_enc(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_default_max_age(map(), map()) :: map()

  defp process_oidc_default_max_age(processed_metadata, %{"default_max_age" => default_max_age})
    when is_integer(default_max_age)
  do
    Map.put(processed_metadata, "default_max_age", default_max_age)
  end

  defp process_oidc_default_max_age(_processed_metadata, %{"default_max_age" => _}) do
    raise InvalidClientMetadataFieldError,
      field: "default_max_age",
      reason: "must be an integer"
  end

  defp process_oidc_default_max_age(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_require_auth_time(map(), map()) :: map()

  defp process_oidc_require_auth_time(
    processed_metadata, %{"require_auth_time" => require_auth_time})
    when is_boolean(require_auth_time)
  do
    Map.put(processed_metadata, "require_auth_time", require_auth_time)
  end

  defp process_oidc_require_auth_time(_processed_metadata, %{"require_auth_time" => _}) do
    raise InvalidClientMetadataFieldError,
      field: "require_auth_time",
      reason: "must be a boolean"
  end

  defp process_oidc_require_auth_time(processed_metadata, _) do
    processed_metadata
  end

  @spec process_oidc_default_acr_values(map(), map()) :: map()

  defp process_oidc_default_acr_values(
    processed_metadata, %{"default_acr_values" => default_acr_values})
    when is_list(default_acr_values)
  do
    acr_values_supported =
      Enum.map(astrenv(:oidc_acr_config, []), fn {k, _} -> Atom.to_string(k) end)

    if Enum.all?(default_acr_values, &(&1 in acr_values_supported)) do
      Map.put(processed_metadata, "default_acr_values", default_acr_values)
    else
      raise InvalidClientMetadataFieldError,
        field: "default_acr_values",
        reason: "one request acr value not in supported acr values"
    end
  end

  defp process_oidc_default_acr_values(_processed_metadata, %{"default_acr_values" => _}) do
    raise InvalidClientMetadataFieldError,
      field: "default_acr_values",
      reason: "must be a list of ACRs"
  end

  defp process_oidc_default_acr_values(processed_metadata, _) do
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

  @spec set_client_id(map(), Asteroid.Context.t()) :: map()

  defp set_client_id(processed_metadata, ctx) do
    client_id =
      astrenv(:oauth2_endpoint_register_gen_client_id_callback).(processed_metadata, ctx)

    Map.put(processed_metadata, "client_id", client_id)
  end

  @spec set_new_client_type(Client.t()) :: Client.t()

  defp set_new_client_type(client) do
    case astrenv(:oauth2_endpoint_register_client_type_callback).(client) do
      :public ->
        Client.add(client, "client_type", "public")

      :confidential ->
        Client.add(client, "client_type", "private")
    end
  end

  @spec set_client_created_by(Client.t(), Client.t() | nil) :: Client.t()

  defp set_client_created_by(new_client, nil) do
    new_client
  end

  defp set_client_created_by(new_client, client) do
    client = Client.fetch_attributes(client, ["client_id"])

    Client.add(new_client, "__asteroid_created_by_client_id", client.attrs["client_id"])
  end

  @spec check_grant_response_type_consistency(map()) :: map()

  defp check_grant_response_type_consistency(processed_metadata) do
    case OAuth2.Register.grant_response_types_consistent?(
      processed_metadata["grant_types"],
      processed_metadata["response_types"])
    do
      :ok ->
        processed_metadata

      {:error, error_str} ->
        raise InvalidClientMetadataFieldError, field: "response_types", reason: error_str
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
