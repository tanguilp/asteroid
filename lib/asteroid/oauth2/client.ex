defmodule Asteroid.OAuth2.Client do
  alias Asteroid.Client
  alias Asteroid.OAuth2
  alias OAuth2Utils.Scope

  import Asteroid.Utils

  @moduledoc """
  Util function to work with OAuth2 clients
  """

  defmodule AuthenticationError do
    @moduledoc """
    Error raised when an client authentication error occurs
    """

    defexception [:reason]

    @type t :: %__MODULE__{
      reason: :unknown_client | :unauthenticated_request
    }

    @impl true

    def message(%__MODULE__{reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "authentication error: #{String.replace(Atom.to_string(reason), "_", " ")}"

        :normal ->
          "authentication error: #{String.replace(Atom.to_string(reason), "_", " ")}"

        :minimal ->
          ""
      end
    end
  end

  defmodule AuthorizationError do
    @moduledoc """
    Error raised when an client is not authorized to perform an action
    """

    defexception [:reason]

    @type t :: %__MODULE__{
      reason: :unauthorized_grant_type | :unauthorized_scope
    }

    def message(%__MODULE__{reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "The client is not authorized to perform this action (reason: #{inspect(reason)})"

        :normal ->
          "The client is not authorized to perform this action (reason: #{inspect(reason)})"

        :minimal ->
          ""
      end
    end
  end

  @typedoc """
  Client's type: confidential or public
  """

  @type type :: :confidential | :public

  @typedoc """
  String representation of a client type

  Must be the string conversion of a `t:type/0` atom.
  """

  @type type_str :: String.t()

  @doc """
  Returns the authenticated or **unauthenticated** client of a request

  To make sure that the client is authenticated, one shall use the `get_authenticated_client/1`
  function instead.
  """

  @spec get_client(Plug.Conn.t()) ::
  {:ok, Client.t()}
  | {:error, %AuthenticationError{}}

  def get_client(conn) do
    case get_authenticated_client(conn) do
      {:ok, client} ->
        {:ok, client}

      {:error, %AuthenticationError{reason: :unkown_client}} = error ->
        error

      {:error, _} ->
        get_unauthenticated_client(conn)
    end
  end

  @doc """
  Returns the APIac authenticated client, or an error if none was found
  """

  @spec get_authenticated_client(Plug.Conn.t()) ::
  {:ok, Client.t()}
  | {:error, %AuthenticationError{}}

  def get_authenticated_client(conn) do
    if APIac.authenticated?(conn) do
      case Client.load(APIac.client(conn)) do
        {:ok, client} ->
          {:ok, client}

        {:error, _} ->
          {:error, AuthenticationError.exception(reason: :unkown_client)}
      end
    else
      {:error, AuthenticationError.exception(reason: :unauthenticated_request)}
    end
  end

  @doc """
  Returns the unauthenticated client of a request

  It does so by reading the `"client_id"` body parameter and trying to find the associated
  **public** client in the client's attribute repository. If it is found and it has no
  credentials (calling the `has_credentials?/1` function), it returns the client. Otherwise
  an error is returned.
  """

  @spec get_unauthenticated_client(Plug.Conn.t()) ::
  {:ok, Client.t()}
  | {:error, %AuthenticationError{}}

  def get_unauthenticated_client(conn) do
    case conn.body_params["client_id"] do
      nil ->
        {:error, AuthenticationError.exception(reason: :unauthenticated_request)}

      client_id ->
        if OAuth2Utils.valid_client_id_param?(client_id) do
          case Client.load(client_id) do
            {:ok, client} ->
              if public?(client) do
                if not has_credentials?(client) do
                  {:ok, client}
                else
                  {:error, AuthenticationError.exception(reason:
                    :public_client_has_credentials_and_must_authenticate)}
                end
              else
                {:error, AuthenticationError.exception(reason:
                  :unauthenticated_request)}
              end

            {:error, _} ->
              {:error, AuthenticationError.exception(reason: :unkown_client)}
          end
        else
          {:error, OAuth2.Request.MalformedParamError.exception(name: "client_id",
                                                                value: client_id)}
        end
    end
  end

  @doc """
  Returns `true` if the client is allowed to use the grant type, `false` otherwise

  To be authorized to use a given grant type, the client's `"grant_types"` attribute
  must contain the given `t:Asteroid.OAuth2.grant_type_str/0`.
  """

  @spec grant_type_authorized?(Asteroid.Client.t(), Asteroid.OAuth2.grant_type_str()) ::
  :ok
  | {:error, %AuthorizationError{}}

  def  grant_type_authorized?(client, grant_type) do
    client = Client.fetch_attributes(client, ["grant_types"])

    if grant_type in client.attrs["grant_types"] do
      :ok
    else
      {:error, AuthorizationError.exception(reason: :unauthorized_grant_type)}
    end
  end

  @doc """
  Returns `true` if the client is allowed to use the response type, `false` otherwise

  To be authorized to use a given grant type, the client's `"response_types"` attribute
  must contain the given `t:Asteroid.OAuth2.response_type_str/0`.
  """

  @spec response_type_authorized?(Asteroid.Client.t(), Asteroid.OAuth2.response_type_str()) ::
  :ok
  | {:error, %AuthorizationError{}}

  def  response_type_authorized?(client, response_type) do
    client = Client.fetch_attributes(client, ["response_types"])

    if response_type in (client.attrs["response_types"] || []) do
      :ok
    else
      {:error, AuthorizationError.exception(reason: :unauthorized_response_type)}
    end
  end

  @doc """
  Returns `true` if the client is authorized to use the scopes, `false` otherwise

  Checks for each scope of the `Scope.Set.t()` if it's included in the  client's `"scope"`
  attribute.
  """

  @spec scopes_authorized?(Asteroid.Client.t(), Scope.Set.t()) ::
  :ok
  | {:error, %AuthorizationError{}}

  def  scopes_authorized?(client, scope_set) do
    client = Client.fetch_attributes(client, ["scope"])

    if Scope.Set.subset?(scope_set, Scope.Set.new(client.attrs["scope"] || [])) do
      :ok
    else
      {:error, AuthorizationError.exception(reason: :unauthorized_scope)}
    end
  end

  @doc """
  Returns `true` if the client is a public client, `false` otherwise
  """

  @spec public?(Client.t()) :: boolean()
  def public?(client) do
    client = Client.fetch_attributes(client, ["client_type"])

    client.attrs["client_type"] == "public"
  end

  @doc """
  Returns `true` if the client is a confidential client, `false` otherwise
  """

  @spec confidential?(Client.t()) :: boolean()
  def confidential?(client) do
    client = Client.fetch_attributes(client, ["client_type"])

    client.attrs["client_type"] == "confidential"
  end

  @doc """
  Returns `true` if the client has credentials, `false` otherwise

  A client that has credentials is a client that has a `client_secret` attribute
  """

  @spec has_credentials?(Client.t()) :: boolean()

  def has_credentials?(client) do
    client = Client.fetch_attributes(client, ["client_secret"])

    client.attrs["client_secret"] != nil
  end

  @doc """
  Returns `:ok` is the client is authorized to introspect tokens on the `"/introspect"`
  endpoint, `{:error, :unauthorized}` otherwise

  An authorized client is a client that has been granted the use of the `"asteroid.introspect"`
  scope. See [Configuring clients - Asteroid scopes](configuring-clients.html#asteroid-scopes)
  for information on scopes.
  """

  @spec endpoint_introspect_authorized?(Client.t()) :: :ok | {:error, :unauthorized}

  def endpoint_introspect_authorized?(client) do
    client = Client.fetch_attributes(client, ["scope"])

    if "asteroid.introspect" in (client.attrs["scope"] || []) do
      :ok
    else
      {:error, :unauthorized}
    end
  end

  @doc """
  Returns `true` is the client must use PKCE, `false` otherwise

  A client must use PKCE when its
  `"__asteroid_oauth2_flow_authorization_code_mandatory_pkce_use"` attribute is set to `true`.
  """

  @spec must_use_pkce?(Client.t()) :: boolean()

  def must_use_pkce?(client) do
    attribute = "__asteroid_oauth2_flow_authorization_code_mandatory_pkce_use"

    client = Client.fetch_attributes(client, [attribute])

    client.attrs[attribute] == true
  end

  @doc """
  Returns the client secret from the client id of a client

  Can be used in as a callback in `APIacAuthBasic` and `APIacAuthClientSecretPost` in the
  configuration files:

  ```elixir
  {APIacAuthBasic,
    realm: "Asteroid",
    callback: &Asteroid.OAuth2.Client.get_client_secret/2,
    set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
    error_response_verbosity: :debug}
  ```
  """

  @spec get_client_secret(String.t(), String.t()) :: String.t()

  def get_client_secret(_realm, client_id) do
    case Client.load(client_id, attributes: ["client_secret"]) do
      {:ok, client} ->
        client.attrs["client_secret"]

      {:error, _} ->
        nil
    end
  end
end
