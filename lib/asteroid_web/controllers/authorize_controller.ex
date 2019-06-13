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

  defmodule AccessDeniedError do
    @moduledoc """
    Error returned when the access was denied either because of the user not consenting or
    the server's policy inadequation with the request (eg. scopes)
    """

    @enforce_keys [:reason]

    defexception [:reason]

    @type t :: %__MODULE__{
      reason: String.t()
    }

    @impl true

    def message(%{reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Access denied:" <> reason

        :normal ->
          "Access denied:" <> reason

        :minimal ->
          ""
      end
    end
  end

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
      :pkce_code_challenge,
      :pkce_code_challenge_method,
      :params
    ]

    @type t :: %__MODULE__{
      response_type: OAuth2.response_type(),
      client: Client.t(),
      redirect_uri: OAuth2.RedirectUri.t(),
      requested_scopes: Scope.Set.t(),
      pkce_code_challenge: OAuth2.PKCE.code_challenge() | nil,
      pkce_code_challenge_method: OAuth2.PKCE.code_challenge_method() | nil,
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

    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:authorization_code),
         :ok <- Asteroid.OAuth2.response_type_enabled?(:code),
         :ok <- client_id_valid?(client_id),
         :ok <- redirect_uri_valid?(redirect_uri),
         {:ok, client} <- Client.load(client_id),
         :ok <- redirect_uri_registered_for_client?(client, redirect_uri),
         :ok <- OAuth2.Client.response_type_authorized?(client, "code"),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes),
         {:ok, {maybe_code_challenge, maybe_code_challenge_method}} <- pkce_params(client, params)
    do
      authz_request =
        %Request{
          response_type: :code,
          client: client,
          redirect_uri: redirect_uri,
          requested_scopes: requested_scopes,
          pkce_code_challenge: maybe_code_challenge,
          pkce_code_challenge_method: maybe_code_challenge_method,
          params: params
        }

      astrenv(:oauth2_flow_authorization_code_web_authorization_callback).(conn, authz_request)
    else
      {:error, %OAuth2.Client.AuthorizationError{reason: :unauthorized_scope} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, AccessDeniedError.exception(
          reason: Exception.message(e)))

      {:error, %OAuth2.Client.AuthorizationError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %OAuth2.UnsupportedGrantTypeError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %OAuth2.UnsupportedResponseTypeError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %OAuth2.Request.InvalidRequestError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %OAuth2.Request.MalformedParamError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %AttributeRepository.Read.NotFoundError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.InvalidRequestError.exception(
          reason: Exception.message(e),
          parameter: "client_id"))
    end
  rescue
    _ in Scope.Set.InvalidScopeParam ->
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.MalformedParamError.exception(
          name: "scope", value: params["scope"]))
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

    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:implicit),
         :ok <- Asteroid.OAuth2.response_type_enabled?(:token),
         :ok <- client_id_valid?(client_id),
         :ok <- redirect_uri_valid?(redirect_uri),
         {:ok, client} <- Client.load(client_id),
         :ok <- redirect_uri_registered_for_client?(client, redirect_uri),
         :ok <- OAuth2.Client.response_type_authorized?(client, "token"),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes)
    do
      authz_request =
        %Request{
          response_type: :token,
          client: client,
          redirect_uri: redirect_uri,
          requested_scopes: requested_scopes,
          params: params
        }

      astrenv(:oauth2_flow_implicit_web_authorization_callback).(conn, authz_request)
    else
      {:error, %OAuth2.Client.AuthorizationError{reason: :unauthorized_scope} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, AccessDeniedError.exception(
          reason: Exception.message(e)))

      {:error, %OAuth2.Client.AuthorizationError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %OAuth2.UnsupportedGrantTypeError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %OAuth2.UnsupportedResponseTypeError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %OAuth2.Request.InvalidRequestError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %OAuth2.Request.MalformedParamError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %AttributeRepository.Read.NotFoundError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.InvalidRequestError.exception(
          reason: Exception.message(e),
          parameter: "client_id"))
    end
  rescue
    _ in Scope.Set.InvalidScopeParam ->
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.MalformedParamError.exception(
          name: "scope", value: params["scope"]))
  end

  def pre_authorize(conn, %{"redirect_uri" => redirect_uri, "client_id" => client_id} = params) do
    with :ok <- client_id_valid?(client_id),
         :ok <- redirect_uri_valid?(redirect_uri),
         {:ok, client} <- Client.load(client_id),
         :ok <- redirect_uri_registered_for_client?(client, redirect_uri)
    do
      if params["response_type"] do
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.UnsupportedResponseTypeError.exception(
          response_type: params["response_type"]))
      else
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.InvalidRequestError.exception(
          reason: "missing parameter", parameter: "response_type"))
      end
    else
      {:error, %OAuth2.Request.MalformedParamError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)

      {:error, %AttributeRepository.Read.NotFoundError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.InvalidRequestError.exception(
          reason: Exception.message(e),
          parameter: "client_id"))

      {:error, %OAuth2.Request.InvalidRequestError{} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, e)
    end
  end

  def pre_authorize(conn, _params) do
    AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.InvalidRequestError.exception(
      reason: "missing parameter", parameter: "client_id"))
  end

  @doc """
  Callback to be called when the authorization is granted, typically after an authentication and
  authorization (approving scopes) process, or in case an authentication already occured
  recently (cookie).

  The `res` parameter is a `map()` whose keys are:
  - `:sub`: one of the following atoms (**mandatory**):
  """

  @spec authorization_granted(Plug.Conn.t(), Request.t(), map()) :: Plug.Conn.t()

  def authorization_granted(conn, %Request{response_type: :code} = authz_request, res)
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
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge",
                                     authz_request.pkce_code_challenge)
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge_method",
                                     if authz_request.pkce_code_challenge_method != nil do
                                       to_string(authz_request.pkce_code_challenge_method)
                                     else
                                       nil
                                     end)
      |> AuthorizationCode.store(ctx)

    redirect_uri =
      authz_request.redirect_uri
      |> OAuth2.RedirectUri.add_params(
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

  def authorization_granted(conn, %Request{response_type: :token} = authz_request, res)
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
      |> OAuth2.RedirectUri.add_params(put_if_not_nil(%{}, "state", authz_request.params["state"]))
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

  @spec authorization_denied(Plug.Conn.t(), Request.t(), map()) :: Plug.Conn.t()

  def authorization_denied(conn, authz_request, %{reason: reason} = res)
  when reason in [:access_denied, :server_error, :temporarily_unavailable]
  do
    redirect_uri = OAuth2.RedirectUri.add_params(
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

  @spec redirect_uri_registered_for_client?(Client.t(), OAuth2.RedirectUri.t()) ::
  :ok
  | {:error, %OAuth2.Request.InvalidRequestError{}}

  defp redirect_uri_registered_for_client?(client, redirect_uri) do
    client = Client.fetch_attributes(client, ["redirect_uri"])

    if redirect_uri in (client.attrs["redirect_uris"] || []) do
      :ok
    else
      {:error, OAuth2.Request.InvalidRequestError.exception(
        reason: "unregistered `redirect_uri` for client",
        parameter: "redirect_uri")}
    end
  end

  @spec client_id_valid?(String.t()) ::
  :ok
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp client_id_valid?(client_id) do
    if OAuth2Utils.valid_client_id_param?(client_id) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "client_id", value: client_id)}
    end
  end


  @spec redirect_uri_valid?(String.t()) ::
  :ok
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp redirect_uri_valid?(redirect_uri) do
    if OAuth2.RedirectUri.valid?(redirect_uri) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(
        name: "redirect_uri",
        value: redirect_uri)}
    end
  end

  @spec put_scope_implicit_flow(map(), Scope.Set.t(), Scope.Set.t()) :: map()

  defp put_scope_implicit_flow(m, requested_scopes, granted_scopes) do
    if Scope.Set.equal?(requested_scopes, granted_scopes) do
      m
    else
      Map.put(m, "scope", Enum.join(granted_scopes, " "))
    end
  end

  @spec pkce_params(Client.t(), map()) ::
  {:ok, {OAuth2.PKCE.code_challenge() | nil, OAuth2.PKCE.code_challenge_method() | nil}}
  | {:error, %OAuth2.Request.InvalidRequestError{}}
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp pkce_params(client, params) do
    case astrenv(:oauth2_flow_authorization_code_pkce_policy) do
      :disabled ->
        {:ok, {nil, nil}}

      :optional ->
        if OAuth2.Client.must_use_pkce?(client) do
          if params["code_challenge"] != nil do
            pkce_params_when_mandatory(params)
          else
            {:error, OAuth2.Request.InvalidRequestError.exception(
              parameter: "code_challenge", reason: "missing `code_challenge` parameter")}
          end
        else
          if params["code_challenge"] != nil do
            pkce_params_when_mandatory(params)
          else
            {:ok, {nil, nil}}
          end
        end

      :mandatory ->
        pkce_params_when_mandatory(params)
    end
  end

  @spec pkce_params_when_mandatory(map()) ::
  {:ok, {OAuth2.PKCE.code_challenge(), OAuth2.PKCE.code_challenge_method()}}
  | {:error, %OAuth2.Request.InvalidRequestError{}}
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp pkce_params_when_mandatory(%{"code_challenge" => code_challenge} = params) do
    method =
      case params["code_challenge_method"] do
        method when is_binary(method) ->
          method

        nil ->
          "plain"
      end

    if OAuth2.PKCE.code_challenge_valid?(code_challenge) do
      case OAuth2.PKCE.code_challenge_method_from_string(method) do
        code_challenge_method when is_atom(code_challenge_method) ->
          if code_challenge_method in astrenv(:oauth2_flow_authorization_code_pkce_allowed_methods) do
            {:ok, {code_challenge, code_challenge_method}}
          else
            {:error, OAuth2.Request.InvalidRequestError.exception(
              reason: "unsupported code challenge method", parameter: "code_challenge_method")}
          end

        nil ->
          {:error, OAuth2.Request.InvalidRequestError.exception(
            reason: "unsupported code challenge method", parameter: "code_challenge_method")}
      end
    else
      {:error, OAuth2.Request.MalformedParamError.exception(
        name: "code_challenge", value: code_challenge)}
    end
  end

  defp pkce_params_when_mandatory(_) do
    {:error, OAuth2.Request.InvalidRequestError.exception(
      parameter: "code_challenge", reason: "missing `code_challenge` parameter")}
  end
end
