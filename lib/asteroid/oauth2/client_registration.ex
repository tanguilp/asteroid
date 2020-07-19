defmodule Asteroid.OAuth2.ClientRegistration do
  @moduledoc """
  Convenience functions related to client registration
  """

  import Asteroid.Config, only: [opt: 1]
  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.OAuth2
  alias Asteroid.Token.IDToken
  alias OAuth2Utils.Scope

  @type result :: {:ok, Client.metadata()} | {:error, Exception.t()}

  @tls_supported_param_values [
    "tls_client_auth_subject_dn",
    "tls_client_auth_san_dns",
    "tls_client_auth_san_uri",
    "tls_client_auth_san_ip",
    "tls_client_auth_san_email"
  ]

  @response_type_grant_type_mapping %{
    "code" => ["authorization_code"],
    "token" => ["implicit"],
    "id_token" => ["implicit"],
    "token id_token" => ["implicit"],
    "code id_token" => ["authorization_code", "implicit"],
    "code token" => ["authorization_code", "implicit"],
    "code id_token token" => ["authorization_code", "implicit"]
  }
  @auth_methods_requiring_password ["client_secret_basic", "client_secret_post"]

  defmodule InvalidClientMetadataFieldError do
    @moduledoc """
    Error returned when client metadata is invalid
    """

    defexception [:field, :reason]

    @impl true

    def message(%{field: field, reason: reason}) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          case field do
            "token_endpoint_auth_method" ->
              "Invalid field `#{field}` (reason: #{reason}, supported methods:)" <>
                "#{inspect(opt(:oauth2_endpoint_token_auth_methods_supported_callback).())})"

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

    def message(%{scopes: scopes}) do
      case opt(:api_error_response_verbosity) do
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
      case opt(:api_error_response_verbosity) do
        :debug ->
          "Invalid redirect URI `#{redirect_uri}`"

        :normal ->
          "Invalid redirect URI `#{redirect_uri}`"

        :minimal ->
          ""
      end
    end
  end

  @doc """
  Registers a new client

  The following paragraphs describe the registration rules.

  ## Grant and response types

  Compatibility of grant types vis-a-vis response types are checked with the
  `check_grant_response_type_consistent/2` function.

  By default, the `"authorization_code"` and `"refresh_token"` grant types and `"code"`
  response type are granted.

  ## Client secret

  A client secret is granted if the token endpoint authentication method is either
  `"client_secret_basic"` or `"client_secret_post"`.

  It is returned as is in the response (so that it can be used by the client) but is stored
  in a hashed format in the attribute repository.

  ## Internationalized fields

  The `"client_name"`, `"client_uri"`, `"logo_uri"`, `"tos_uri"` and `"policy_uri"` fields
  can be internationalized. Asteroid deconstructs the i18n fields and store them in the
  `"<FIELD>_i18n"` where `<FIELD>` is the field name, keys are language code and the value the
  extracted i18n value.

  For instance, i18n client name would be stored as follow in the `"client_name_i18n"`:

      %{
        "en" => "My application",
        "fr" => "Mon application",
        "ru" => "Моё приложение"
      }

  ## Subject type

  Subject types are handled by Asteroid and following OpenID Connect specification, the redirect
  URIs are checked against the `"sector_identifier_uri"` document if different hosts are
  present in the set of redirect URIs.

  In case of problem with such a validation, one can easily add a Tesla logging middleware
  using the #{Asteroid.Config.link_to_option(:tesla_middlewares_client_registration)} option.
  """
  @spec register(Client.metadata(), Client.t() | nil) :: result()
  def register(req_metadata, maybe_client) do
    metadata = %{}

    with {:ok, metadata} <- handle_grant_types(metadata, req_metadata, maybe_client),
         {:ok, metadata} <- handle_response_types(metadata, req_metadata, maybe_client),
         %{"grant_types" => grant_types, "response_types" => response_types} = metadata,
         :ok <- check_grant_response_type_consistent(grant_types, response_types),
         {:ok, metadata} <- handle_redirect_uris(metadata, req_metadata),
         {:ok, metadata} <-
           handle_token_endpoint_auth_method(metadata, req_metadata, maybe_client),
         {:ok, metadata} <- handle_mtls_pki_method_parameter(metadata, req_metadata),
         {:ok, metadata} <- handle_scope(metadata, req_metadata, maybe_client),
         {:ok, metadata} <- handle_jwks_uri(metadata, req_metadata),
         {:ok, metadata} <- handle_jwks(metadata, req_metadata),
         {:ok, metadata} <- handle_software_id(metadata, req_metadata),
         {:ok, metadata} <- handle_software_version(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_application_type(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_sector_identifier_uri(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_subject_type(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_id_token_signed_response_alg(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_id_token_encrypted_response_alg(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_id_token_encrypted_response_enc(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_userinfo_signed_response_alg(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_userinfo_encrypted_response_alg(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_userinfo_encrypted_response_enc(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_jar_signing_response_alg(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_jar_encryption_response_alg(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_jar_encryption_response_enc(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_default_max_age(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_require_auth_time(metadata, req_metadata),
         {:ok, metadata} <- handle_oidc_default_acr_values(metadata, req_metadata),
         {:ok, metadata} <- handle_contacts(metadata, req_metadata),
         {:ok, metadata} <- handle_i18n_field("client_name", metadata, req_metadata),
         {:ok, metadata} <- handle_i18n_field("client_uri", metadata, req_metadata),
         {:ok, metadata} <- handle_i18n_field("logo_uri", metadata, req_metadata),
         {:ok, metadata} <- handle_i18n_field("tos_uri", metadata, req_metadata),
         {:ok, metadata} <- handle_i18n_field("policy_uri", metadata, req_metadata),
         {:ok, metadata} <- handle_additional_fields(metadata, req_metadata, maybe_client),
         {:ok, metadata} <- handle_client_id(metadata, req_metadata, maybe_client) do

      client_resource_id = opt(:oauth2_endpoint_register_gen_client_resource_id_callback).(
        metadata,
        req_metadata,
        maybe_client
      )

      {maybe_secret, maybe_hash} =
        if metadata["token_endpoint_auth_method"] in @auth_methods_requiring_password do
          {secret, expwd_hashed} = Expwd.Hashed.gen()

          {secret, Expwd.Hashed.Portable.to_portable(expwd_hashed)}
        else
          {nil, nil}
        end

      metadata =
        if maybe_secret, do: Map.put(metadata, "client_secret", maybe_secret), else: metadata

      Enum.reduce(metadata, Client.gen_new(id: client_resource_id), fn {field, value}, acc ->
        Client.add(acc, field, value)
      end)
      |> set_new_client_type()
      |> set_client_created_by(maybe_client)
      |> set_client_secret(maybe_hash)
      |> opt(:oauth2_endpoint_register_client_before_save_callback).(
        metadata, req_metadata, maybe_client
      )
      |> Client.store()
      |> case do
        :ok ->
          {:ok, metadata}

        {:error, _} = error ->
          error
      end
    end
  rescue
    _ in Scope.Set.InvalidScopeParam ->
      {:error, %InvalidClientMetadataFieldError{
        field: "scope", reason: "malformed scope param"}
      }
  end

  @doc """
  Returns `:ok` if the grant types and the responses types are consistent,
  `{:error, %InvalidClientMetadataFieldError{}}` otherwise.

  The error response's string contains a human-readable explanation of the reason it is not
  consistent.

  The following table is used for consistency check:


  | grant_types value includes:                   | response_types      |
  |-----------------------------------------------|---------------------|
  | authorization_code                            | code                |
  | implicit                                      | token               |
  | implicit                                      | id_token            |
  | implicit                                      | token id_token      |
  | authorization_code, implicit                  | code id_token       |
  | authorization_code, implicit                  | code token          |
  | authorization_code, implicit                  | code id_token token |
  | password                                      | (none)              |
  | client_credentials                            | (none)              |
  | refresh_token                                 | (none)              |
  | urn:ietf:params:oauth:grant-type:jwt-bearer   | (none)              |
  | urn:ietf:params:oauth:grant-type:saml2-bearer | (none)              |

  """

  @spec check_grant_response_type_consistent(
          [OAuth2.grant_type_str()],
          [OAuth2.response_type_str()]
        ) :: :ok | {:error, Exception.t()}
  def check_grant_response_type_consistent(grant_types, response_types) do
    Enum.reduce_while(
      response_types,
      :ok,
      fn
        response_type, _acc ->
          mandatory_grant_types = @response_type_grant_type_mapping[response_type]

          if Enum.all?(mandatory_grant_types, &(&1 in grant_types)) do
            {:cont, :ok}
          else
            {:halt,
              {:error, %InvalidClientMetadataFieldError{
                field: "response_types",
                reason: "response_type `#{response_type}` have missing mandatory grant type"
              }}
            }
          end
      end
    )
  end

  @doc """
  Generates a new id for the client attribute repository

  This function simply returns the client id passed in the processed metadata
  """
  @spec generate_client_resource_id(
    Client.metadata(),
    Client.metadata(),
    Client.t() | nil
  ) :: AttributeRepository.resource_id()
  def generate_client_resource_id(%{"client_id" => client_id}, _, _), do: client_id

  @doc """
  Generates a new OAuth2 client id

  It takes into parameter the map of the parsed and controlled client metadata ready to be
  returned to the initiating client.

  This function generates a new `client_id` given the following rules:
  - If the map value of `"client_name"` is a string:
    - Strips the parameters from invalid characters (not in the range \x20-\x7E)
    - Lowercase this string
    - Replace spaces by underscores
    - If the resulting string is not the empty string:
      - Returns it if no client as already the same `client_id`
      - Otherwise, append `"_1"`, `"_2"`, `"_3"`, `"_4"`... to `"_99"` until there's no client
      with that `client_id` already in the base
      - If all these client exists, returns a 20 bytes random string
    - Otherwise returns a 20 bytes random string
  - Otherwise returns a 20 bytes random string
  """

  @spec generate_client_id(Client.metadata(), Client.metadata(), Client.t() | nil) :: String.t()
  def generate_client_id(
    _metadata = %{"client_name" => client_name},
    _req_metadata,
    _maybe_client
  ) when is_binary(client_name) do
    client_name_sanitized =
      client_name
      |> String.replace(~r/[^\x20-\x7E]/, "")
      |> String.downcase(:ascii)
      |> String.replace(" ", "_")

    gen_new_client_id_from_client_name(client_name_sanitized, 0)
  end

  def generate_client_id(_, _req_metadata, _maybe_client) do
    secure_random_b64(20)
  end

  @spec gen_new_client_id_from_client_name(String.t(), non_neg_integer()) :: String.t()
  defp gen_new_client_id_from_client_name(_client_name, n) when n >= 100 do
    secure_random_b64(20)
  end

  # client is only composed of special chars - no interest to use client name here

  defp gen_new_client_id_from_client_name("", _) do
    secure_random_b64(20)
  end

  defp gen_new_client_id_from_client_name(client_name, n) do
    client_name_suffixed =
      case n do
        0 ->
          client_name

        _ ->
          client_name <> "_" <> Integer.to_string(n)
      end

    case Client.load_from_unique_attribute("client_id", client_name_suffixed, attributes: []) do
      {:error, %AttributeRepository.Read.NotFoundError{}} ->
        # the client doesn't exist
        client_name_suffixed

      {:ok, _} ->
        gen_new_client_id_from_client_name(client_name, n + 1)
    end
  end

  @doc """
  Returns the computed client's type

  Returns `:public` if the client `"token_endpoint_auth_method"` is set to `"none"`,
  `:confidential` otherwise.
  """

  @spec client_type(Client.t()) :: OAuth2.Client.type()

  def client_type(client) do
    client = Client.fetch_attributes(client, ["token_endpoint_auth_method"])

    if client.attrs["token_endpoint_auth_method"] == "none" do
      :public
    else
      :confidential
    end
  end

  @doc """
  Verifies that the content of the document stored at a sector identifier URI is valid against
  a list of redirect URIs
  """
  @spec verify_redirect_uris_against_sector_identifier_uri(
    String.t(), [OAuth2.RedirectUri.t(), ...]
  ) :: :ok | {:error, Exception.t()}
  def verify_redirect_uris_against_sector_identifier_uri(
    sector_identifier_uri, redirect_uris
  ) do
    with %URI{scheme: "https"} <- URI.parse(sector_identifier_uri),
         client = Tesla.client(tesla_middlewares()),
         {:ok, %Tesla.Env{status: 200, body: body}} <- Tesla.get(client, sector_identifier_uri),
         true <- is_list(body) do
      if Enum.all?(redirect_uris, &(&1 in body)) do
        :ok
      else
        missing = Enum.find(redirect_uris, &(&1 in body))

        {:error, %InvalidClientMetadataFieldError{
           field: "sector_identifier_uri",
           reason: "`#{missing}` redirect URI not included in list of retrieved redirect URIs"
         }}
      end
    else
      %URI{} ->
        {:error, %InvalidClientMetadataFieldError{
           field: "sector_identifier_uri",
           reason: "scheme must be `https`"
        }}

      {:ok, %Tesla.Env{status: status}} ->
        {:error, %InvalidClientMetadataFieldError{
           field: "sector_identifier_uri",
           reason: "requesting the sector identifier URI resulted in HTTP code #{status}"
         }}

      false ->
        {:error, %InvalidClientMetadataFieldError{
           field: "sector_identifier_uri",
           reason: "invalid JSON content at sector identifier URI: must be a list"
         }}

      {:error, error} ->
        {:error, %InvalidClientMetadataFieldError{
           field: "sector_identifier_uri",
           reason: "requesting the sector identifier URI resulted in error #{inspect(error)}"
         }}
    end
  end

  @spec handle_grant_types(Client.metadata(), Client.metadata(), Client.t() | nil) :: result()
  defp handle_grant_types(metadata, %{"grant_types" => requested_grant_types}, nil)
    when is_list(requested_grant_types) do
    enabled_grant_types =
      opt(:oauth2_grant_types_enabled)
      |> Enum.map(&to_string/1)
      |> MapSet.new()

    if MapSet.subset?(MapSet.new(requested_grant_types), enabled_grant_types) do
      {:ok, Map.put(metadata, "grant_types", requested_grant_types)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "grant_types",
        reason:
          "one of the grant types could be granted as a result of applying the server policy"
      }}
    end
  end

  defp handle_grant_types(
         metadata,
         %{"grant_types" => requested_grant_types},
         %Client{} = authenticated_client
       ) when is_list(requested_grant_types) do
    conf_attr = "__asteroid_oauth2_endpoint_register_allowed_grant_types"

    client = Client.fetch_attributes(authenticated_client, [conf_attr])

    enabled_grant_types =
      opt(:oauth2_grant_types_enabled)
      |> Enum.map(&to_string/1)

    allowed_grant_types =
      MapSet.intersection(
        MapSet.new(client.attrs[conf_attr] || enabled_grant_types),
        MapSet.new(enabled_grant_types)
      )

    if MapSet.subset?(MapSet.new(requested_grant_types), allowed_grant_types) do
      {:ok, Map.put(metadata, "grant_types", requested_grant_types)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "grant_types",
        reason:
        "one of the grant types could be granted as a result of applying the server policy"
      }}
    end
  end

  defp handle_grant_types(_, %{"grant_types" => _}, _) do
    {:error, %InvalidClientMetadataFieldError{
      field: "grant_types",
      reason: "should be a list of strings"
    }}
  end

  defp handle_grant_types(metadata, _, nil) do
    {:ok, Map.put(metadata, "grant_types", ["authorization_code", "refresh_token"])}
  end

  defp handle_grant_types(metadata, _, %Client{} = authenticated_client) do
    attr = "__asteroid_oauth2_endpoint_register_default_grant_types"

    client = Client.fetch_attributes(authenticated_client, [attr])

    case client.attrs[attr] do
      l when is_list(l) ->
        {:ok, Map.put(metadata, "grant_types", l)}

      nil ->
        {:ok, Map.put(metadata, "grant_types", ["authorization_code"])}
    end
  end

  @spec handle_response_types(
    Client.metadata(),
    Client.metadata(),
    Client.t() | nil
  ) :: result()
  defp handle_response_types(
         metadata,
         %{"response_types" => requested_response_types},
         nil
       ) when is_list(requested_response_types) do
    enabled_response_types =
      opt(:oauth2_response_types_enabled)
      |> Enum.map(&to_string/1)
      |> MapSet.new()

    if MapSet.subset?(MapSet.new(requested_response_types), enabled_response_types) do
      {:ok, Map.put(metadata, "response_types", requested_response_types)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "response_types",
        reason:
          "one of the response types could be granted as a result of applying the server policy"
      }}
    end
  end

  defp handle_response_types(
         metadata,
         %{"response_types" => requested_response_types},
         %Client{} = authenticated_client
       ) when is_list(requested_response_types) do
    conf_attr = "__asteroid_oauth2_endpoint_register_allowed_response_types"

    client = Client.fetch_attributes(authenticated_client, [conf_attr])

    enabled_response_types =
      opt(:oauth2_response_types_enabled)
      |> Enum.map(&to_string/1)

    allowed_response_types =
      MapSet.intersection(
        MapSet.new(client.attrs[conf_attr] || enabled_response_types),
        MapSet.new(enabled_response_types)
      )

    if MapSet.subset?(MapSet.new(requested_response_types), allowed_response_types) do
      {:ok, Map.put(metadata, "response_types", requested_response_types)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "response_types",
        reason:
          "one of the response types could be granted as a result of applying the server policy"
      }}
    end
  end

  defp handle_response_types(_, %{"response_types" => _}, _) do
    {:error, %InvalidClientMetadataFieldError{
      field: "response_types",
      reason: "should be a list of strings"
    }}
  end

  defp handle_response_types(metadata, _, nil) do
    {:ok, Map.put(metadata, "response_types", ["code"])}
  end

  defp handle_response_types(metadata, _, %Client{} = authenticated_client) do
    attr = "__asteroid_oauth2_endpoint_register_default_response_types"

    client = Client.fetch_attributes(authenticated_client, [attr])

    case client.attrs[attr] do
      l when is_list(l) ->
        {:ok, Map.put(metadata, "response_types", l)}

      nil ->
        {:ok, Map.put(metadata, "response_types", ["code"])}
    end
  end

  @spec handle_redirect_uris(Client.metadata(), Client.metadata()) :: result()
  defp handle_redirect_uris(metadata, req_metadata) do
    case req_metadata["redirect_uris"] do
      [_ | _] = redirect_uris ->
        if Enum.all?(redirect_uris, &OAuth2.RedirectUri.valid?/1) do
          {:ok, Map.put(metadata, "redirect_uris", redirect_uris)}
        else
          {:error, %InvalidRedirectURIError{redirect_uri:
            Enum.find(redirect_uris, fn
              redirect_uri -> OAuth2.RedirectUri.valid?(redirect_uri) == false
            end)}}
        end

      _ ->
        unless Enum.any?(metadata["grant_types"], &OAuth2Utils.uses_authorization_endpoint?/1) do
          {:ok, metadata}
        else
          {:error, %InvalidClientMetadataFieldError{
            field: "redirect_uris",
            reason: "field is mandatory in regards to the requested grant types"
          }}
        end
    end
  end

  @spec handle_token_endpoint_auth_method(
    Client.metadata(),
    Client.metadata(),
    Client.t() | nil
  ) :: result()
  defp handle_token_endpoint_auth_method(
         metadata,
         %{"token_endpoint_auth_method" => token_endpoint_auth_method},
         nil
       ) when is_binary(token_endpoint_auth_method) do
    auth_method_allowed_str =
      opt(:oauth2_endpoint_token_auth_methods_supported_callback).f()
      |> Enum.map(&to_string/1)

    if token_endpoint_auth_method in auth_method_allowed_str do
      {:ok, Map.put(metadata, "token_endpoint_auth_method", token_endpoint_auth_method)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "token_endpoint_auth_method",
        reason: "The client authentication method `#{token_endpoint_auth_method}` is unsupported"
      }}
    end
  end

  defp handle_token_endpoint_auth_method(
         metadata,
         %{"token_endpoint_auth_method" => token_endpoint_auth_method},
         %Client{} = authenticated_client
       ) when is_binary(token_endpoint_auth_method) do
    auth_meth_client = "__asteroid_oauth2_endpoint_register_allowed_token_endpoint_auth_methods"

    client = Client.fetch_attributes(authenticated_client, [auth_meth_client])

    token_endpoint_auth_methods_supported =
      opt(:oauth2_endpoint_token_auth_methods_supported_callback).()

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
      {:ok, Map.put(metadata, "token_endpoint_auth_method", token_endpoint_auth_method)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "token_endpoint_auth_method",
        reason: "The client authentication method `#{token_endpoint_auth_method}` is unsupported"
      }}
    end
  end

  defp handle_token_endpoint_auth_method(
         _processed_metadata,
         %{"token_endpoint_auth_method" => _},
         _authenticated_client
       ) do
    {:error, %InvalidClientMetadataFieldError{
      field: "token_endpoint_auth_method",
      reason: "should be a list of strings"
    }}
  end

  defp handle_token_endpoint_auth_method(metadata, _, nil) do
    {:ok, Map.put(metadata, "token_endpoint_auth_method", "client_secret_basic")}
  end

  defp handle_token_endpoint_auth_method(metadata, _, %Client{} = authenticated_client) do
    attr = "__asteroid_oauth2_endpoint_register_default_token_endpoint_auth_method"

    client = Client.fetch_attributes(authenticated_client, [attr])

    case client.attrs[attr] do
      auth_method when is_binary(auth_method) ->
        {:ok, Map.put(metadata, "token_endpoint_auth_method", auth_method)}

      nil ->
        {:ok, Map.put(metadata, "token_endpoint_auth_method", "client_secret_basic")}
    end
  end

  @spec handle_mtls_pki_method_parameter(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_mtls_pki_method_parameter(
    metadata,
    %{"token_endpoint_auth_method" => "tls_client_auth"} = input_metadata)
  do
    tls_param = Map.take(input_metadata, @tls_supported_param_values)

    case Enum.count(tls_param) do
      0 ->
        {:error, %InvalidClientMetadataFieldError{
          field: "token_endpoint_auth_method",
          reason: "Missing one param of: `#{inspect(@tls_supported_param_values)}`"
        }}

      1 ->
        {:ok, Map.merge(metadata, tls_param)}

      n ->
        {:error, %InvalidClientMetadataFieldError{
          field: "token_endpoint_auth_method",
          reason: "Maximum one param of: `#{inspect(@tls_supported_param_values)}` allowed, #{n} given"
        }}
    end
  end

  defp handle_mtls_pki_method_parameter(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_scope(
    Client.metadata(),
    Client.metadata(),
    Client.t() | nil
  ) :: result()
  defp handle_scope(
         metadata,
         %{"scope" => scope_param},
         nil
       ) when is_binary(scope_param) do
    requested_scopes = Scope.Set.from_scope_param!(scope_param)

    # let's compute all the available scopes for the flows associated to the accepted
    # grant types
    allowed_scopes_for_flows =
      Enum.reduce(
        metadata["grant_types"],
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
      {:ok, Map.put(metadata, "scope", Scope.Set.to_scope_param(requested_scopes))}
    else
      {:error, %UnauthorizedRequestedScopesError{
        scopes: Scope.Set.difference(requested_scopes, allowed_scopes_for_flows)
      }}
    end
  end

  defp handle_scope(
         metadata,
         %{"scope" => scope_param},
         %Client{} = authorized_client
       ) when is_binary(scope_param) do
    attr_allowed_scope = "__asteroid_oauth2_endpoint_register_allowed_scopes"
    attr_auto_scope = "__asteroid_oauth2_endpoint_register_auto_scopes"

    client = Client.fetch_attributes(authorized_client, [attr_allowed_scope, attr_auto_scope])

    client_auto_scopes = Scope.Set.new(client.attrs[attr_auto_scope] || [])

    requested_scopes = Scope.Set.from_scope_param!(scope_param)

    if client.attrs[attr_allowed_scope] do
      client_allowed_scopes = Scope.Set.new(client.attrs[attr_allowed_scope] || [])

      if Scope.Set.subset?(requested_scopes, client_allowed_scopes) do
        result_scopes = Scope.Set.union(requested_scopes, client_auto_scopes)

        {:ok, Map.put(metadata, "scope", Scope.Set.to_scope_param(result_scopes))}
      else
        {:error, %UnauthorizedRequestedScopesError{
          scopes: Scope.Set.difference(requested_scopes, client_allowed_scopes)
        }}
      end
    else
      # let's compute all the available scopes for the flows associated to the accepted
      # grant types
      allowed_scopes_for_flows =
        Enum.reduce(
          metadata["grant_types"],
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

        {:ok, Map.put(metadata, "scope", Scope.Set.to_scope_param(result_scopes))}
      else
        {:error, %UnauthorizedRequestedScopesError{
          scopes: Scope.Set.difference(requested_scopes, allowed_scopes_for_flows)
        }}
      end
    end
  end

  defp handle_scope(_processed_metadata, %{"scope" => _}, _) do
    {:error, %InvalidClientMetadataFieldError{
      field: "scope",
      reason: "should be a string"
    }}
  end

  defp handle_scope(metadata, _input_metadata, nil) do
    # FIXME: allow default scopes here?

    {:ok, metadata}
  end

  defp handle_scope(metadata, _input_metadata, %Client{} = client) do
    attr_auto_scope = "__asteroid_oauth2_endpoint_register_auto_scopes"

    client = Client.fetch_attributes(client, [attr_auto_scope])

    if client.attrs[attr_auto_scope] do
      {:ok, Map.put(metadata, "scope", client.attrs[attr_auto_scope])}
    else
      {:ok, metadata}
    end
  end

  @spec handle_jwks_uri(Client.metadata(), Client.metadata()) :: result()
  defp handle_jwks_uri(metadata, %{"jwks_uri" => jwks_uri}) when is_binary(jwks_uri) do
    case URI.parse(jwks_uri) do
      # we force it to be an HTTPS URL because the spec is unclear about it and to avoid
      # schemes such as file:///
      %URI{scheme: "https"} ->
        {:ok, Map.put(metadata, "jwks_uri", jwks_uri)}

      _ ->
        {:error, %InvalidClientMetadataFieldError{
          field: "jwks_uri",
          reason: "must be an https:// URL"
        }}
    end
  end

  defp handle_jwks_uri(_metadata, %{"jwks_uri" => _}) do
    {:error, %InvalidClientMetadataFieldError{
      field: "jwks_uri",
      reason: "must be an URL"
    }}
  end

  defp handle_jwks_uri(metadata, _input_metadata) do
    {:ok, metadata}
  end

  @spec handle_jwks(Client.metadata(), Client.metadata()) :: result()
  defp handle_jwks(%{"jwks_uri" => _}, %{"jwks" => _}) do
    {:error, %InvalidClientMetadataFieldError{
      field: "jwks",
      reason: "`jwks_uri` and `jwks` fields cannot be present at the same time"
    }}
  end

  defp handle_jwks(metadata, %{"jwks" => jwks}) do
    case jwks do
      %{"keys" => keys} when is_list(keys) ->
        if Enum.all?(keys, fn key -> JOSEUtils.JWK.verify(key) == :ok end) do
          {:ok, Map.put(metadata, "jwks", keys)}
        else
          {:error, %InvalidClientMetadataFieldError{
            field: "jwks",
            reason: "invalid jwk `#{inspect(Enum.find(keys, fn key ->
              JOSEUtils.JWK.verify(key) != :ok end)
            )}`"
          }}
        end

      _ ->
        {:error, %InvalidClientMetadataFieldError{
          field: "jwks",
          reason: "jwks must have a `keys` key containing a list of keys"
        }}
    end
  end

  defp handle_jwks(metadata, _input_metadata) do
    {:ok, metadata}
  end

  @spec handle_software_id(Client.metadata(), Client.metadata()) :: result()
  defp handle_software_id(metadata, %{"software_id" => software_id})
    when is_binary(software_id) do
      {:ok, Map.put(metadata, "software_id", software_id)}
  end

  defp handle_software_id(_metadata, %{"software_id" => _}) do
    {:error, %InvalidClientMetadataFieldError{
        field: "software_id",
      reason: "must be a string"
    }}
  end

  defp handle_software_id(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_software_version(Client.metadata(), Client.metadata()) :: result()
  defp handle_software_version(metadata, %{"software_version" => software_version})
    when is_binary(software_version) do
      {:ok, Map.put(metadata, "software_version", software_version)}
  end

  defp handle_software_version(_metadata, %{"software_version" => _}) do
    {:error, %InvalidClientMetadataFieldError{
        field: "software_version",
      reason: "must be a string"
    }}
  end

  defp handle_software_version(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_application_type(Client.metadata(), Client.metadata()) :: result()
  defp handle_oidc_application_type(metadata, %{"application_type" => app_type})
    when app_type in ["native", "web"] do
      {:ok, Map.put(metadata, "application_type", app_type)}
  end

  defp handle_oidc_application_type(_processed_metadata, %{"application_type" => _}) do
    {:error, %InvalidClientMetadataFieldError{
      field: "application_type",
      reason: "must be `web` or `native`"
    }}
  end

  defp handle_oidc_application_type(metadata, _) do
    {:ok , Map.put(metadata, "application_type", "web")}
  end

  @spec handle_oidc_sector_identifier_uri(Client.metadata(), Client.metadata()) :: result()
  defp handle_oidc_sector_identifier_uri(
         metadata,
         %{"sector_identifier_uri" => sector_identifier_uri}
       ) do
    verify_redirect_uris_against_sector_identifier_uri(
      sector_identifier_uri,
      metadata["redirect_uris"]
    )
    |> case do
      :ok ->
        {:ok, Map.put(metadata, "sector_identifier_uri", sector_identifier_uri)}

      {:error, _} = error ->
        error
    end
  end

  defp handle_oidc_sector_identifier_uri(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_subject_type(Client.metadata(), Client.metadata()) :: result()
  defp handle_oidc_subject_type(metadata, %{"subject_type" => "pairwise"}) do
    redir_hosts = Enum.reduce(metadata, MapSet.new(), fn redirect_uri, acc ->
      MapSet.put(acc, URI.parse(redirect_uri).host) end
    )

    unless Enum.count(redir_hosts) > 1 and metadata["sector_identifier_uri"] == nil do
      {:ok, Map.put(metadata, "subject_type", "pairwise")}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "subject_type",
        reason:
          "`sector_identifier_uri` is mandatory when registering more than one " <>
            "redirect URIs with different hosts and `subject_type` with value `pairwise`"
      }}
    end
  end

  defp handle_oidc_subject_type(metadata, %{"subject_type" => "public"}) do
    {:ok, Map.put(metadata, "subject_type", "public")}
  end

  defp handle_oidc_subject_type(_metadata, %{"subject_type" => _}) do
    {:error, %InvalidClientMetadataFieldError{
      field: "subject_type",
      reason: "invalid subject type, must be one of: `pairwise`, `public`"
    }}
  end

  defp handle_oidc_subject_type(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_id_token_signed_response_alg(
    Client.metadata(), Client.metadata()
  ) :: result()
  defp handle_oidc_id_token_signed_response_alg(
         metadata,
         %{"id_token_signed_response_alg" => id_token_signed_response_alg}
       ) do
    if id_token_signed_response_alg in IDToken.signing_alg_values_supported() do
      {:ok, Map.put(metadata, "id_token_signed_response_alg", id_token_signed_response_alg)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "id_token_signed_response_alg",
        reason: "value provided not in supported signing algs"
      }}
    end
  end

  defp handle_oidc_id_token_signed_response_alg(metadata, _) do
    {:ok, Map.put(metadata, "id_token_signed_response_alg", "RS256")}
  end

  @spec handle_oidc_id_token_encrypted_response_alg(
    Client.metadata(), Client.metadata()
  ) :: result()
  defp handle_oidc_id_token_encrypted_response_alg(
         metadata,
         %{"id_token_encrypted_response_alg" => id_token_encrypted_response_alg}
       ) do
    if id_token_encrypted_response_alg in IDToken.encryption_alg_values_supported() do
      {
        :ok,
        Map.put(metadata, "id_token_encrypted_response_alg", id_token_encrypted_response_alg)
      }
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "id_token_encrypted_response_alg",
        reason: "value provided not in supported encryption algs"
      }}
    end
  end

  defp handle_oidc_id_token_encrypted_response_alg(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_id_token_encrypted_response_enc(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_id_token_encrypted_response_enc(
         metadata,
         %{
           "id_token_encrypted_response_enc" => id_token_encrypted_response_enc,
           "id_token_encrypted_response_alg" => _
         }
       ) do
    if id_token_encrypted_response_enc in IDToken.encryption_enc_values_supported() do
      {
        :ok,
        Map.put(metadata, "id_token_encrypted_response_enc", id_token_encrypted_response_enc)
      }
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "id_token_encrypted_response_enc",
        reason: "value provided not in supported encryption encs"
      }}
    end
  end

  defp handle_oidc_id_token_encrypted_response_enc(
         _,
         %{"id_token_encrypted_response_enc" => _}
  ) do
    {:error, %InvalidClientMetadataFieldError{
      field: "id_token_encrypted_response_enc",
      reason: "`id_token_encrypted_response_alg` must be registered along with this field"
    }}
  end

  defp handle_oidc_id_token_encrypted_response_enc(
         metadata,
         %{"id_token_encrypted_response_alg" => _}
       ) do
     {:ok, Map.put(metadata, "id_token_encrypted_response_enc", "A128CBC-HS256")}
  end

  defp handle_oidc_id_token_encrypted_response_enc(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_userinfo_signed_response_alg(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_userinfo_signed_response_alg(
         metadata,
         %{"userinfo_signed_response_alg" => userinfo_signed_response_alg}
       ) do
    if userinfo_signed_response_alg in opt(:oidc_userinfo_supported_signing_algs) do
      {
        :ok,
        Map.put(metadata, "userinfo_signed_response_alg", userinfo_signed_response_alg)
      }
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "userinfo_signed_response_alg",
        reason: "value provided not in supported signing algs"
      }}
    end
  end

  defp handle_oidc_userinfo_signed_response_alg(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_userinfo_encrypted_response_alg(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_userinfo_encrypted_response_alg(
         metadata,
         %{"userinfo_encrypted_response_alg" => userinfo_encrypted_response_alg}
       ) do
    if userinfo_encrypted_response_alg in opt(:oidc_userinfo_supported_encryption_algs) do
      {
        :ok,
        Map.put(metadata, "userinfo_encrypted_response_alg", userinfo_encrypted_response_alg)
      }
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "userinfo_encrypted_response_alg",
        reason: "value provided not in supported encryption algs"
      }}
    end
  end

  defp handle_oidc_userinfo_encrypted_response_alg(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_userinfo_encrypted_response_enc(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_userinfo_encrypted_response_enc(
         metadata,
         %{
           "userinfo_encrypted_response_enc" => userinfo_encrypted_response_enc,
           "userinfo_encrypted_response_alg" => _
         }
       ) do
    if userinfo_encrypted_response_enc in opt(:oidc_userinfo_supported_encryption_encs) do
      {
        :ok,
        Map.put(metadata, "userinfo_encrypted_response_enc", userinfo_encrypted_response_enc)
      }
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "userinfo_encrypted_response_enc",
        reason: "value provided not in supported encryption encs"
      }}
    end
  end

  defp handle_oidc_userinfo_encrypted_response_enc(
         _processed_metadata,
         %{"userinfo_encrypted_response_enc" => _}
  ) do
    {:error, %InvalidClientMetadataFieldError{
      field: "userinfo_encrypted_response_enc",
      reason: "`userinfo_encrypted_response_alg` must be registered along with this field"
    }}
  end

  defp handle_oidc_userinfo_encrypted_response_enc(
         metadata,
         %{"userinfo_encrypted_response_alg" => _}
       ) do
    {:ok, Map.put(metadata, "userinfo_encrypted_response_enc", "A128CBC-HS256")}
  end

  defp handle_oidc_userinfo_encrypted_response_enc(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_jar_signing_response_alg(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_jar_signing_response_alg(
         metadata,
         %{"request_object_signing_alg" => request_object_signing_alg}
       ) do
    if request_object_signing_alg in OAuth2.JAR.signing_alg_values_supported() do
      {:ok, Map.put(metadata, "request_object_signing_alg", request_object_signing_alg)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "request_object_signing_alg",
        reason: "value provided not in supported signing algs"
      }}
    end
  end

  defp handle_oidc_jar_signing_response_alg(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_jar_encryption_response_alg(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_jar_encryption_response_alg(
         metadata,
         %{"request_object_encryption_alg" => request_object_encryption_alg}
       ) do
    if request_object_encryption_alg in OAuth2.JAR.encryption_alg_values_supported() do
      {:ok, Map.put(metadata, "request_object_encryption_alg", request_object_encryption_alg)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "request_object_encryption_alg",
        reason: "value provided not in supported encryption algs"
      }}
    end
  end

  defp handle_oidc_jar_encryption_response_alg(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_jar_encryption_response_enc(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_jar_encryption_response_enc(
         metadata,
         %{
           "request_object_encryption_enc" => request_object_encryption_enc,
           "request_object_encryption_alg" => _
         }
  ) do
    if request_object_encryption_enc in OAuth2.JAR.encryption_enc_values_supported() do
      {
        :ok,
        Map.put(metadata, "request_object_encryption_enc", request_object_encryption_enc)
      }
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "request_object_encryption_enc",
        reason: "value provided not in supported encryption encs"
      }}
    end
  end

  defp handle_oidc_jar_encryption_response_enc(
         _processed_metadata,
         %{"request_object_encryption_enc" => _request_object_encrypted_response_enc}
  ) do
    {:error, %InvalidClientMetadataFieldError{
      field: "request_object_encryption_enc",
      reason: "`request_object_encryption_alg` must be registered along with this field"
    }}
  end

  defp handle_oidc_jar_encryption_response_enc(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_default_max_age(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_default_max_age(metadata, %{"default_max_age" => default_max_age})
  when is_integer(default_max_age) do
    {:ok, Map.put(metadata, "default_max_age", default_max_age)}
  end

  defp handle_oidc_default_max_age(_processed_metadata, %{"default_max_age" => _}) do
    {:error, %InvalidClientMetadataFieldError{
      field: "default_max_age",
      reason: "must be an integer"
    }}
  end

  defp handle_oidc_default_max_age(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_require_auth_time(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_require_auth_time(metadata, %{
         "require_auth_time" => require_auth_time
       })
  when is_boolean(require_auth_time) do
    {:ok, Map.put(metadata, "require_auth_time", require_auth_time)}
  end

  defp handle_oidc_require_auth_time(_processed_metadata, %{"require_auth_time" => _}) do
    {:error, %InvalidClientMetadataFieldError{
      field: "require_auth_time",
      reason: "must be a boolean"
    }}
  end

  defp handle_oidc_require_auth_time(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_oidc_default_acr_values(
    Client.metadata(),
    Client.metadata()
  ) :: result()
  defp handle_oidc_default_acr_values(metadata, %{
         "default_acr_values" => default_acr_values
       })
  when is_list(default_acr_values) do
    acr_values_supported = Enum.map(opt(:oidc_acr_config), fn {k, _} -> Atom.to_string(k) end)

    if Enum.all?(default_acr_values, &(&1 in acr_values_supported)) do
      {:ok, Map.put(metadata, "default_acr_values", default_acr_values)}
    else
      {:error, %InvalidClientMetadataFieldError{
        field: "default_acr_values",
        reason: "one request acr value not in supported acr values"
      }}
    end
  end

  defp handle_oidc_default_acr_values(_processed_metadata, %{"default_acr_values" => _}) do
    {:error, %InvalidClientMetadataFieldError{
      field: "default_acr_values",
      reason: "must be a list of ACRs"
    }}
  end

  defp handle_oidc_default_acr_values(metadata, _) do
    {:ok, metadata}
  end

  @spec handle_contacts(Client.metadata(), Client.metadata()) :: result()
  defp handle_contacts(metadata, %{"contacts" => contacts}) do
    case contacts do
      l when is_list(l) ->
        if Enum.all?(contacts, &is_binary/1) do
          {:ok, Map.put(metadata, "contacts", contacts)}
        else
          {:error, %InvalidClientMetadataFieldError{
            field: "contacts",
            reason: "one of the list value is not a string"
          }}
        end

      _ ->
        {:error, %InvalidClientMetadataFieldError{
          field: "contacts",
          reason: "not a list"
        }}
    end
  end

  defp handle_contacts(metadata, _input_metadata) do
    {:ok, metadata}
  end

  @spec handle_i18n_field(String.t(), Client.metadata(), Client.metadata()) :: result()
  defp handle_i18n_field(field_name, metadata, req_metadata) do
    {
      :ok,
      Enum.reduce(
        req_metadata,
        metadata,
        fn
          {key, value}, acc ->
            cond do
              field_name == key ->
                Map.put(acc, key, value)

              # for instance `client_name#fr`
              String.starts_with?(key, field_name <> "#") ->
                field_name_i18n = field_name <> "_i18n"

                [_, i18n_key] = String.split(key, "#")

                case acc[field_name_i18n] do
                  nil ->
                    Map.put(acc, field_name_i18n, %{i18n_key => value})

                  # key already exists
                  _ ->
                    put_in(acc, [field_name_i18n, i18n_key], value)
                end

              true ->
                acc
            end
        end
      )
    }
  end

  @spec handle_additional_fields(
    Client.metadata(),
    Client.metadata(),
    Client.t() | nil
  ) :: result()
  defp handle_additional_fields(metadata, req_metadata, nil) do
    keys = opt(:oauth2_endpoint_register_additional_metadata_field)

    {:ok, Map.merge(Map.take(req_metadata, keys), metadata)}
  end

  defp handle_additional_fields(metadata, req_metadata, %Client{} = authorized_client) do
    add_met = "__asteroid_oauth2_endpoint_register_additional_metadata_fields"

    client = Client.fetch_attributes(authorized_client, [add_met])

    keys = client.attrs[add_met] || opt(:oauth2_endpoint_register_additional_metadata_field)

    {:ok, Map.merge(Map.take(req_metadata, keys), metadata)}
  end

  @spec handle_client_id(
    Client.metadata(),
    Client.metadata(),
    Client.t() | nil
  ) :: result()
  defp handle_client_id(metadata, req_metadata, maybe_client) do
    client_id = opt(:oauth2_endpoint_register_gen_client_id_callback).(
      metadata, req_metadata, maybe_client
    )

    {:ok, Map.put(metadata, "client_id", client_id)}
  end

  @spec set_new_client_type(Client.t()) :: Client.t()
  defp set_new_client_type(client) do
    case opt(:oauth2_endpoint_register_client_type_callback).(client) do
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

  @spec set_client_secret(Client.t(), String.t() | nil) :: Client.t()
  defp set_client_secret(client, nil), do: client
  defp set_client_secret(client, hash), do: Client.add(client, "client_secret", hash)

  @spec tesla_middlewares() :: [Tesla.Client.middleware()]
  defp tesla_middlewares() do
    [Tesla.Middleware.DecodeJson]
    ++ opt(:tesla_middlewares)
    ++ opt(:tesla_middlewares_client_registration)
  end
end
