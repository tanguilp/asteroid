defmodule AsteroidWeb.AuthorizeController do
  @moduledoc false

  use AsteroidWeb, :controller

  require Logger

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.OAuth2
  alias Asteroid.Client
  alias Asteroid.Subject
  alias Asteroid.Token.{AccessToken, AuthorizationCode}

  defmodule Request do
    @moduledoc """
    Struct with the necessary information to process an web authorization request
    """

    @enforce_keys [:response_type, :client, :redirect_uri, :requested_scopes, :params]

    defstruct [
      :response_type,
      :client,
      :redirect_uri,
      :requested_scopes,
      :params
    ]

    @type t :: %__MODULE__{
      response_type: OAuth2.response_type(),
      client: Client.t(),
      redirect_uri: OAuth2.RedirectUri.t(),
      requested_scopes: Scope.Set.t(),
      params: map()
    }
  end

  def pre_authorize(conn,
                    %{"response_type" => "code",
                      "client_id" => client_id,
                      "redirect_uri" => redirect_uri
                    } = params)
  do
    requested_scopes =
      case params["scope"] do
        nil ->
          Scope.Set.new()

        val ->
          Scope.Set.from_scope_param!(val)
      end

    unless OAuth2.RedirectUri.valid?(redirect_uri) do
      raise OAuth2.RedirectUri.MalformedError, redirect_uri: redirect_uri
    end

    unless OAuth2Utils.valid_client_id_param?(client_id) do
      raise OAuth2.Client.InvalidClientIdError, client_id: client_id
    end

    with :ok <- Asteroid.OAuth2.response_type_enabled?(:code),
         {:ok, client} <- Client.load(client_id),
         :ok <- redirect_uri_registered_for_client?(client, redirect_uri),
         :ok <- OAuth2.Client.response_type_authorized?(client, "code"),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes)
    do
      authz_request =
        %__MODULE__.Request{
          response_type: :code,
          client: client,
          redirect_uri: redirect_uri,
          requested_scopes: requested_scopes,
          params: params
        }

      astrenv(:oauth2_flow_authorization_code_web_authorization_callback).(conn, authz_request)
    else
      {:error, :unregistered_redirect_uri} ->
        error_redirect_uri(conn, "Unregistered redirect_uri")

      {:error, reason} ->
        error(conn, reason, redirect_uri, params["state"])
    end
  rescue
    e in OAuth2.RedirectUri.MalformedError ->
      error_redirect_uri(conn, Exception.message(e))

    e in OAuth2.Client.InvalidClientIdError ->
      error_redirect_uri(conn, Exception.message(e))

    e ->
      error(conn, e, redirect_uri, params["state"])
  end

  def pre_authorize(conn,
                    %{"response_type" => "token",
                      "client_id" => client_id,
                      "redirect_uri" => redirect_uri
                    } = params)
  do
    requested_scopes =
      case params["scope"] do
        nil ->
          Scope.Set.new()

        val ->
          Scope.Set.from_scope_param!(val)
      end

    unless OAuth2.RedirectUri.valid?(redirect_uri) do
      raise OAuth2.RedirectUri.MalformedError, redirect_uri: redirect_uri
    end

    unless OAuth2Utils.valid_client_id_param?(client_id) do
      raise OAuth2.Client.InvalidClientIdError, client_id: client_id
    end

    with :ok <- Asteroid.OAuth2.response_type_enabled?(:token),
         {:ok, client} <- Client.load(client_id),
         :ok <- redirect_uri_registered_for_client?(client, redirect_uri),
         :ok <- OAuth2.Client.response_type_authorized?(client, "token"),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes)
    do
      authz_request =
        %__MODULE__.Request{
          response_type: :token,
          client: client,
          redirect_uri: redirect_uri,
          requested_scopes: requested_scopes,
          params: params
        }

      astrenv(:oauth2_flow_implicit_web_authorization_callback).(conn, authz_request)
    else
      {:error, :unregistered_redirect_uri} ->
        error_redirect_uri(conn, "Unregistered redirect_uri")

      {:error, reason} ->
        error(conn, reason, redirect_uri, params["state"])
    end
  rescue
    e in OAuth2.RedirectUri.MalformedError ->
      error_redirect_uri(conn, Exception.message(e))

    e in OAuth2.Client.InvalidClientIdError ->
      error_redirect_uri(conn, Exception.message(e))

    e ->
      error(conn, e, redirect_uri, params["state"])
  end

  def pre_authorize(conn, %{"redirect_uri" => redirect_uri, "client_id" => client_id} = params) do
    unless OAuth2.RedirectUri.valid?(redirect_uri) do
      raise OAuth2.RedirectUri.MalformedError, redirect_uri: redirect_uri
    end

    unless OAuth2Utils.valid_client_id_param?(client_id) do
      raise OAuth2.Client.InvalidClientIdError, client_id: client_id
    end

    with {:ok, client} <- Client.load(client_id),
         :ok <- redirect_uri_registered_for_client?(client, redirect_uri)
    do
      if params["response_type"] do
        error(conn, :unsupported_response_type, redirect_uri, params["state"])
      else
        error(conn, :missing_parameter, redirect_uri, params["state"])
      end
    else
      {:error, :unregistered_redirect_uri} ->
        error_redirect_uri(conn, "Unregistered redirect_uri")

      {:error, reason} ->
        error(conn, reason, redirect_uri, params["state"])
    end
  rescue
    e in OAuth2.RedirectUri.MalformedError ->
      error_redirect_uri(conn, Exception.message(e))

    e in OAuth2.Client.InvalidClientIdError ->
      error_redirect_uri(conn, Exception.message(e))

    e ->
      error(conn, e, redirect_uri, params["state"])
  end

  def pre_authorize(conn, _params) do
    error_redirect_uri(conn, "Missing parameter")
  end

  @doc """
  Callback to be called when the authorization is granted, typically after an authentication and
  authorization (approving scopes) process, or in case an authentication already occured
  recently (cookie).

  The `res` parameter is a `map()` whose keys are:
  - `:sub`: one of the following atoms (**mandatory**):
  """

  @spec authorization_granted(Plug.Conn.t(), __MODULE__.Request.t(), map()) :: Plug.Conn.t()

  def authorization_granted(conn, %__MODULE__.Request{response_type: :code} = authz_request, res)
  do
    client = Client.fetch_attributes(authz_request.client, ["client_id"])

    subject =
      res[:sub]
      |> Subject.load() # returns {:ok, subject}
      |> elem(1)
      |> Subject.fetch_attributes(["sub"])

    ctx =
      %{}
      |> Map.put(:endpoint, :authorize)
      |> Map.put(:flow, :authorization_code)
      |> Map.put(:requested_scopes, authz_request.requested_scopes)
      |> Map.put(:granted_scopes, res[:granted_scopes])
      |> Map.put(:client, client)
      |> Map.put(:subject, subject)
      |> Map.put(:flow_result, res)

    {:ok, authorization_code} =
      AuthorizationCode.gen_new()
      |> AuthorizationCode.put_value("iat", now())
      |> AuthorizationCode.put_value("exp",
        now() + astrenv(:oauth2_authorization_code_lifetime_callback).(ctx))
      |> AuthorizationCode.put_value("client_id", client.attrs["client_id"])
      |> AuthorizationCode.put_value("redirect_uri", authz_request.redirect_uri)
      |> AuthorizationCode.put_value("sub", subject.attrs["sub"])
      |> AuthorizationCode.put_value("scope", res[:granted_scopes])
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "authorization_code")
      |> AuthorizationCode.put_value("iss", OAuth2.issuer())
      |> AuthorizationCode.store(ctx)

    redirect_uri =
      authz_request.redirect_uri
      |> redirect_uri_add_params(
        %{
          "code" => AuthorizationCode.serialize(authorization_code)
        }
        |> put_if_not_nil("state", authz_request.params["state"])
      )  
      |> astrenv(:oauth2_endpoint_authorize_response_type_code_before_send_redirect_uri_callback).(ctx)

    Logger.debug("#{__MODULE__}: authorization granted (#{inspect(authz_request)}) with "
    <> "code: `#{inspect authorization_code}` and state: `#{inspect authz_request.params["state"]}`")

    conn
    |> astrenv(:oauth2_endpoint_authorize_response_type_code_before_send_conn_callback).(ctx)
    |> redirect(external: redirect_uri)
  end

  def authorization_granted(conn, %__MODULE__.Request{response_type: :token} = authz_request, res)
  do
    client = Client.fetch_attributes(authz_request.client, ["client_id"])

    subject =
      res[:sub]
      |> Subject.load() # returns {:ok, subject}
      |> elem(1)
      |> Subject.fetch_attributes(["sub"])

    ctx =
      %{}
      |> Map.put(:endpoint, :authorize)
      |> Map.put(:flow, :implicit)
      |> Map.put(:requested_scopes, authz_request.requested_scopes)
      |> Map.put(:granted_scopes, res[:granted_scopes])
      |> Map.put(:client, client)
      |> Map.put(:subject, subject)
      |> Map.put(:flow_result, res)

    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("iat", now())
      |> AccessToken.put_value("exp",
        now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))
      |> AccessToken.put_value("client_id", client.attrs["client_id"])
      |> AccessToken.put_value("redirect_uri", authz_request.redirect_uri)
      |> AccessToken.put_value("sub", subject.attrs["sub"])
      |> AccessToken.put_value("scope", res[:granted_scopes])
      |> AccessToken.put_value("__asteroid_oauth2_initial_flow", "implicit")
      |> AccessToken.put_value("iss", OAuth2.issuer())
      |> AccessToken.store(ctx)

    fragment_params =
      %{}
      |> Map.put("access_token", AccessToken.serialize(access_token))
      |> Map.put("token_type", "bearer")
      |> Map.put("expires_in", access_token.data["exp"] - now())
      |> put_scope_implicit_flow(authz_request.requested_scopes, res[:granted_scopes])
      |> put_if_not_nil("state", authz_request.params["state"])

    redirect_uri =
      authz_request.redirect_uri
      |> Kernel.<>("#")
      |> Kernel.<>(URI.encode_query(fragment_params))
      |> astrenv(:oauth2_endpoint_authorize_response_type_token_before_send_redirect_uri_callback).(ctx)

    Logger.debug("#{__MODULE__}: authorization granted (#{inspect(authz_request)}) with "
    <> "token: `#{inspect access_token}` and state: `#{inspect authz_request.params["state"]}`")

    conn
    |> astrenv(:oauth2_endpoint_authorize_response_type_token_before_send_conn_callback).(ctx)
    |> redirect(external: redirect_uri)
  end

  @doc """
  Callback to be called when the authorization is denied, either by the user or by the
  server

  The `res` parameter is a `map()` whose keys are:
  - `:reason`: one of the following atoms (**mandatory**):
    - `:access_denied`: the request has been denied by the user or the server (e.g. requirements
    are not met, such as approving some scopes)
    - `:server_error`: a server error has occured
    - `:temporarily_unavailable`: the service is momentarily unavailable
  - `:description`: a `String.t()` for a human-readable description on why the process has failed
  (may be displayed to the end user), or `nil` if no reason is to be given
  """

  @spec authorization_denied(Plug.Conn.t(), __MODULE__.Request.t(), map()) :: Plug.Conn.t()

  def authorization_denied(conn, authz_request, %{reason: reason} = res)
  when reason in [:access_denied, :server_error, :temporarily_unavailable]
  do
    redirect_uri = redirect_uri_add_params(
      authz_request.redirect_uri,
      %{
        "error" => to_string(reason),
      }
      |> put_if_not_nil("error_description", res[:description])
      |> put_if_not_nil("state", authz_request.params["state"])
    )

    Logger.debug("#{__MODULE__}: authorization denied (#{inspect(authz_request)}) with "
    <> "reason: `#{inspect reason}` and description: `#{inspect res[:description]}`")

    conn
    |> redirect(external: redirect_uri)
  end

  @spec error_redirect_uri(Plug.Conn.t(), String.t()) :: Plug.Conn.t()

  defp error_redirect_uri(conn, reason) do
    conn
    |> put_flash(:error, "An error has occured (#{reason})")
    |> put_status(400)
    |> render("error_redirect_uri.html")
  end

  @spec error(Plug.Conn.t(), Exception.t() | atom(), String.t(), String.t | nil) :: Plug.Conn.t()

  defp error(conn, %Scope.Set.InvalidScopeParam{} = e, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "invalid_scope",
        "error_description" => Exception.message(e)
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  defp error(conn, %OAuth2.Client.InvalidClientIdError{} = e, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "invalid_request",
        "error_description" => Exception.message(e)
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  defp error(conn, :missing_parameter, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "invalid_request",
        "error_description" => "Misssing parameter"
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  defp error(conn, :response_type_disabled, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "unsupported_response_type",
        "error_description" => "This response type is disabled"
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  defp error(conn, :unsupported_response_type, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "unsupported_response_type",
        "error_description" => "This response type is unsupported"
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  defp error(conn, %AttributeRepository.Read.NotFoundError{} = e, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "unauthorized_client",
        # FIXME: here we leak the presence of a client, send more generic error message instead?
        "error_description" => Exception.message(e)
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  defp error(conn, %AttributeRepository.ReadError{} = e, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "server_error",
        "error_description" => Exception.message(e)
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  defp error(conn, %OAuth2.Client.AuthorizationError{} = e, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "unauthorized_client",
        "error_description" => Exception.message(e)
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  defp error(conn, %OAuth2.Client.UnauthorizedScopeError{} = e, redirect_uri, maybe_state) do
    redirect_uri = redirect_uri_add_params(
      redirect_uri,
      %{
        "error" => "access_denied",
        "error_description" => Exception.message(e)
      }
      |> put_if_not_nil("state", maybe_state)
    )

    conn
    |> redirect(external: redirect_uri)
  end

  @spec redirect_uri_registered_for_client?(Client.t(), OAuth2.RedirectUri.t()) ::
  :ok
  | {:error, :unregistered_redirect_uri}

  defp redirect_uri_registered_for_client?(client, redirect_uri) do
    client = Client.fetch_attributes(client, ["redirect_uri"])

    if redirect_uri in (client.attrs["redirect_uris"] || []) do
      :ok
    else
      {:error, :unregistered_redirect_uri}
    end
  end

  @spec redirect_uri_add_params(String.t(), %{required(String.t()) => String.t()}) :: String.t()

  defp redirect_uri_add_params(redirect_uri, params) do
    case URI.parse(redirect_uri) do
      %URI{query: query} = parsed_uri when is_binary(query) ->
        parsed_uri
        |> Map.put(:query, URI.encode_query(URI.decode_query(query, params)))

      %URI{query: nil} = parsed_uri ->
        parsed_uri
        |> Map.put(:query, URI.encode_query(params))

    end
    |> URI.to_string()
  end

  @spec put_scope_implicit_flow(map(), Scope.Set.t(), Scope.Set.t()) :: map()

  defp put_scope_implicit_flow(m, requested_scopes, granted_scopes) do
    if Scope.Set.equal?(requested_scopes, granted_scopes) do
      m
    else
      Map.put(m, "scope", Enum.join(granted_scopes, " "))
    end
  end
end
