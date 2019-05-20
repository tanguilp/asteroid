defmodule Asteroid.OAuth2.Client do
  alias Asteroid.Client
  alias Asteroid.OAuth2
  alias OAuth2Utils.Scope

  import Asteroid.Utils

  defmodule AuthenticationError do
    @moduledoc """
    Error raised when an client authentication error occurs
    """

    defexception [:reason]

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

    def message(%__MODULE__{reason: :unauthorized_grant_type}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "The grant type is not authorized for this client"

        :normal ->
          "The grant type is not authorized for this client"

        :minimal ->
          ""
      end
    end
  end

  defmodule UnauthorizedScopeError do
    defexception []

    @impl true

    def message(_), do: "Unauthorized scope for client" 
  end

  defmodule InvalidClientIdError do
    @moduledoc """
    Exception returned when the client id is invalid
    """

    defexception [:client_id]

    @impl true

    def message(%{client_id: client_id}) do
      "Invalid client_id `#{client_id}`"
    end
  end

  @doc """
  Returns the authenticated or **unauthenticated** client of a request

  To make sure that the client is authenticated, one shall use the `get_authenticated_client/1`
  function instead.
  """

  @spec get_client(Plug.Conn.t()) ::
  {:ok, Client.t()}
  | {:error, %__MODULE__.AuthenticationError{}}

  def get_client(conn) do
    case get_authenticated_client(conn) do
      {:ok, client} ->
        {:ok, client}

      {:error, %__MODULE__.AuthenticationError{reason: :unkown_client}} = error ->
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
  | {:error, %__MODULE__.AuthenticationError{}}

  def get_authenticated_client(conn) do
    if APIac.authenticated?(conn) do
      case Client.load(APIac.client(conn)) do
        {:ok, client} ->
          {:ok, client}

        {:error, _} ->
          {:error, __MODULE__.AuthenticationError.exception(reason: :unkown_client)}
      end
    else
      {:error, __MODULE__.AuthenticationError.exception(reason: :unauthenticated_request)}
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
  | {:error, %__MODULE__.AuthenticationError{}}

  def get_unauthenticated_client(conn) do
    case conn.body_params["client_id"] do
      nil ->
        {:error, __MODULE__.AuthenticationError.exception(reason: :unauthenticated_request)}

      client_id ->
        if OAuth2Utils.valid_client_id_param?(client_id) do
          case Client.load(client_id) do
            {:ok, client} ->
              if public?(client) do
                if not has_credentials?(client) do
                  {:ok, client}
                else
                  {:error, __MODULE__.AuthenticationError.exception(reason:
                    :public_client_has_credentials_and_must_authenticate)}
                end
              else
                {:error, __MODULE__.AuthenticationError.exception(reason:
                  :unauthenticated_request)}
              end

            {:error, _} ->
              {:error, __MODULE__.AuthenticationError.exception(reason: :unkown_client)}
          end
        else
          {:error, OAuth2.Request.MalformedParamError.exception(parameter_name: "client_id",
                                                                parameter_value: client_id)}
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
  | {:error, %__MODULE__.AuthorizationError{}}

  def  grant_type_authorized?(client, grant_type) do
    client = Client.fetch_attributes(client, ["grant_types"])

    if grant_type in client.attrs["grant_types"] do
      :ok
    else
      {:error, __MODULE__.AuthorizationError.exception(reason: :unauthorized_grant_type)}
    end
  end

  @doc """
  Returns `true` if the client is allowed to use the response type, `false` otherwise

  To be authorized to use a given grant type, the client's `"response_types"` attribute
  must contain the given `t:Asteroid.OAuth2.response_type_str/0`.
  """

  @spec response_type_authorized?(Asteroid.Client.t(), Asteroid.OAuth2.response_type_str()) ::
  :ok
  | {:error, %__MODULE__.AuthorizationError{}}

  def  response_type_authorized?(client, response_type) do
    client = Client.fetch_attributes(client, ["response_types"])

    if response_type in (client.attrs["response_types"] || []) do
      :ok
    else
      {:error, __MODULE__.AuthorizationError.exception(reason: :unauthorized_response_type)}
    end
  end

  @doc """
  Returns `true` if the client is authorized to use the scopes, `false` otherwise

  Checks for each scope of the `Scope.Set.t()` if it's included in the  client's `"scope"`
  attribute.
  """

  @spec scopes_authorized?(Asteroid.Client.t(), Scope.Set.t()) ::
  :ok
  | {:error, %__MODULE__.UnauthorizedScopeError{}}

  def  scopes_authorized?(client, scope_set) do
    client = Client.fetch_attributes(client, ["scope"])

    if Scope.Set.subset?(scope_set, Scope.Set.new(client.attrs["scope"] || [])) do
      :ok
    else
      {:error, __MODULE__.UnauthorizedScopeError.exception([])}
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

  @spec error_response(Plug.Conn.t(), Exception.t()) :: Plug.Conn.t

  def error_response(conn, %__MODULE__.AuthenticationError{} = error) do
    response =
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          %{
            "error" => "invalid_client",
            "error_description" =>
            Exception.message(error) <> " "
              <> "("
              <> inspect(APIac.AuthFailureResponseData.get(conn), limit: :infinity)
              <> ")"
          }

        _ ->
          %{
            "error" => "invalid_client",
            "error_description" => Exception.message(error)
          }
      end

    conn
    |> Plug.Conn.put_status(401)
    |> set_www_authenticate_header()
    |> Phoenix.Controller.json(response)
  end

  def error_response(conn, %__MODULE__.AuthorizationError{reason: :unauthorized_scope} = error) do
    response =
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          %{
            "error" => "invalid_scope",
            "error_description" =>
            Exception.message(error) <> " "
              <> "("
              <> inspect(APIac.AuthFailureResponseData.get(conn), limit: :infinity)
              <> ")"
          }

        _ ->
          %{
            "error" => "invalid_scope",
            "error_description" => Exception.message(error)
          }
      end

    conn
    |> Plug.Conn.put_status(400)
    |> set_www_authenticate_header()
    |> Phoenix.Controller.json(response)
  end

  def error_response(conn, %__MODULE__.AuthorizationError{} = error) do
    response =
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          %{
            "error" => "unauthorized_client",
            "error_description" =>
            Exception.message(error) <> " "
              <> "("
              <> inspect(APIac.AuthFailureResponseData.get(conn), limit: :infinity)
              <> ")"
          }

        _ ->
          %{
            "error" => "unauthorized_client",
            "error_description" => Exception.message(error)
          }
      end

    conn
    |> Plug.Conn.put_status(400)
    |> set_www_authenticate_header()
    |> Phoenix.Controller.json(response)
  end

  @spec set_www_authenticate_header(Plug.Conn.t()) :: Plug.Conn.t()
  defp set_www_authenticate_header(conn) do
    apisex_errors = APIac.AuthFailureResponseData.get(conn)

    failed_auth = Enum.find(
      apisex_errors,
      fn apisex_error ->
        apisex_error.reason != :credentials_not_found and
        is_tuple(apisex_error.www_authenticate_header)
      end
    )

    case failed_auth do
      # client tried to authenticate, as per RFC:
      #   If the
      #   client attempted to authenticate via the "Authorization"
      #   request header field, the authorization server MUST
      #   respond with an HTTP 401 (Unauthorized) status code and
      #   include the "WWW-Authenticate" response header field
      #   matching the authentication scheme used by the client.
      %APIac.AuthFailureResponseData{www_authenticate_header: {scheme, params}} ->
        APIac.set_WWWauthenticate_challenge(conn, scheme, params)

      # no failed authn at all or one that can return www-authenticate header
      nil ->
        Enum.reduce(
          apisex_errors,
          conn,
          fn
            %APIac.AuthFailureResponseData{www_authenticate_header: {scheme, params}}, conn ->
              APIac.set_WWWauthenticate_challenge(conn, scheme, params)

            _, conn ->
              conn
          end
        )
    end
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
end
