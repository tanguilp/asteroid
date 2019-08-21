defmodule AsteroidWeb.AuthorizeController do
  use AsteroidWeb, :controller

  require Logger

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.OAuth2
  alias Asteroid.OIDC
  alias Asteroid.OIDC.AuthenticatedSession
  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.Subject
  alias Asteroid.Token.{AccessToken, AuthorizationCode, IDToken}

  defmodule Request do
    @moduledoc """
    Struct with the necessary information to process an web authorization request
    """

    @enforce_keys [
      :flow,
      :response_type,
      :response_mode,
      :client_id,
      :redirect_uri,
      :requested_scopes,
      :params
    ]

    defstruct [
      :flow,
      :response_type,
      :response_mode,
      :client_id,
      :redirect_uri,
      :requested_scopes,
      :pkce_code_challenge,
      :pkce_code_challenge_method,
      :nonce,
      :display,
      :prompt,
      :max_age,
      :ui_locales,
      :id_token_hint,
      :login_hint,
      :acr_values,
      :preferred_acr,
      :claims,
      :params
    ]

    @type t :: %__MODULE__{
      flow: OAuth2.flow(),
      response_type: OAuth2.response_type(),
      response_mode: OAuth2.response_mode(),
      client_id: OAuth2.client_id(),
      redirect_uri: OAuth2.RedirectUri.t(),
      requested_scopes: Scope.Set.t(),
      pkce_code_challenge: OAuth2.PKCE.code_challenge() | nil,
      pkce_code_challenge_method: OAuth2.PKCE.code_challenge_method() | nil,
      nonce: String.t() | nil,
      display: String.t() | nil,
      prompt: String.t() | nil,
      max_age: non_neg_integer() | nil,
      ui_locales: [String.t()] | nil,
      id_token_hint: String.t() | nil,
      login_hint: String.t() | nil,
      acr_values: [Asteroid.OIDC.acr()] | nil,
      preferred_acr: Asteroid.OIDC.acr(),
      claims: map(),
      params: map()
    }
  end

  @type web_authorization_callback ::
  (Plug.Conn.t(), AsteroidWeb.AuthorizeController.Request.t() -> Plug.Conn.t())

  @doc false

  @spec pre_authorize(Plug.Conn.t(), map()) :: Plug.Conn.t()

  def pre_authorize(conn, %{"request" => _, "request_uri" => _}) do
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.InvalidRequestError.exception(
          reason: "`request` and `request_uri` parameters cannot be used simultaneously"))
  end

  def pre_authorize(conn, %{"request" => _} = params) do
    case protocol(params) do
      :oauth2 ->
        jar_pre_authorize_oauth2(conn, params)

      :oidc ->
        jar_pre_authorize_oidc(conn, params)
    end
  end

  def pre_authorize(conn, %{"request_uri" => _} = params) do
    case protocol(params) do
      :oauth2 ->
        jar_pre_authorize_oauth2(conn, params)

      :oidc ->
        jar_pre_authorize_oidc(conn, params)
    end
  end

  def pre_authorize(conn,
                    %{"response_type" => response_type_str,
                      "client_id" => client_id,
                      "redirect_uri" => redirect_uri
                    } = params)
  when response_type_str in [
    "code",
    "token",
    "id_token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token"
  ]
  do
    requested_scopes =
      case params["scope"] do
        nil ->
          Scope.Set.new()

        val ->
          Scope.Set.from_scope_param!(val)
      end

    protocol = if "openid" in requested_scopes, do: :oidc, else: :oauth2

    IO.inspect(:toto1)
    with {:ok, flow} <- OAuth2.response_type_to_flow(response_type_str, protocol),
         {:ok, response_type} <- Asteroid.OAuth2.to_response_type(response_type_str),
         :ok <- Asteroid.OAuth2.response_type_enabled?(response_type),
    a <- IO.inspect(:toto2),
         :ok <- client_id_valid?(client_id),
         :ok <- redirect_uri_valid?(redirect_uri),
         {:ok, client} <- Client.load_from_unique_attribute("client_id", client_id),
         :ok <- redirect_uri_registered_for_client?(client, redirect_uri),
         :ok <- OAuth2.Client.response_type_authorized?(client, response_type_str),
    a <- IO.inspect(:toto3),
         :ok <- OAuth2.Scope.scopes_enabled?(requested_scopes, flow),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes),
         {:ok, {maybe_code_challenge, maybe_code_challenge_method}} <-
           maybe_pkce_params(client, params, flow),
         :ok <-  nonce_parameter_present(params, flow),
         {:ok, response_mode} <- response_mode(params, flow),
         {:ok, claims_param} <- parse_claims_param(params)
    do
      client = Client.fetch_attributes(client, ["client_id"])

      case protocol do
        :oauth2 ->
          req =
            %Request{
              flow: flow,
              response_type: response_type,
              response_mode: response_mode,
              client_id: client.attrs["client_id"],
              redirect_uri: redirect_uri,
              requested_scopes: requested_scopes,
              pkce_code_challenge: maybe_code_challenge,
              pkce_code_challenge_method: maybe_code_challenge_method,
              params: params
            }

            astrenv(:web_authorization_callback).(conn, req)

        :oidc ->
          with :ok <- oidc_param_display_valid(params["display"]),
               :ok <- oidc_param_prompt_valid(params["prompt"]),
               {:ok, max_age_int} <- oidc_param_max_age_valid(params["max_age"]),
               {:ok, ui_locales_list} <- oidc_param_ui_locales_valid(params["ui_locales"]),
               {:ok, acr_values_list} <- oidc_param_acr_values_valid(params["acr_values"]),
               {:ok, preferred_acr} <- preferred_acr(claims_param, acr_values_list, client)
          do
            req =
              %Request{
                flow: flow,
                response_type: response_type,
                response_mode: response_mode,
                client_id: client.attrs["client_id"],
                redirect_uri: redirect_uri,
                requested_scopes: requested_scopes,
                pkce_code_challenge: maybe_code_challenge,
                pkce_code_challenge_method: maybe_code_challenge_method,
                nonce: params["nonce"],
                display: params["display"],
                prompt: params["prompt"],
                max_age: max_age_int,
                ui_locales: ui_locales_list,
                id_token_hint: params["id_token_hint"],
                login_hint: params["login_hint"],
                acr_values: acr_values_list,
                preferred_acr: preferred_acr,
                claims: claims_param,
                params: params
              }

              astrenv(:web_authorization_callback).(conn, req)
          else
            {:error, e} ->
              AsteroidWeb.Error.respond_authorize(conn, e)
          end
      end
    else
      {:error, %OAuth2.Client.AuthorizationError{reason: :unauthorized_scope} = e} ->
        AsteroidWeb.Error.respond_authorize(conn, OAuth2.AccessDeniedError.exception(
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

      {:error, %OAuth2.Scope.UnknownRequestedScopeError{} = e} ->
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
         {:ok, client} <- Client.load_from_unique_attribute("client_id", client_id),
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

  The `opts` parameter is a `map()` whose keys are:
  - `:authz_request`: the initial `t:AsteroidWeb.AuthorizeController.Request.t/0` authorization
  request (**mandatory**)
  - `:subject`: the `t:Asteroid.Subject.t/0` of the user having approved the request
  (**mandatory**)
  - `:granted_scopes`: a `t:OAuth2Utils.Scope.Set.t/0` for the granted scope. If none was granted
  (because none were requested, or because user did not authorize them), an empty
  `t:OAuth2Utils.Scope.Set.t/0` must be set (**mandatory**)
  - `:authenticated_session_id`: a `t:Asteroid.OIDC.AuthenticatedSession.id/0` for the
  authenticated session of the user
  - `:acr`: acr used if `:authenticated_session_id` is not set
  - `:amr`: amr used if `:authenticated_session_id` is not set
  - `:auth_time`: authentication time used if `:authenticated_session_id` is not set
  """

  @spec authorization_granted(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()

  def authorization_granted(conn, opts) do
    session_info = session_info(opts)

    case opts[:authz_request].claims["id_token"]["acr"] do
      %{"essential" => true, "values" => acr_list} ->
        if session_info[:acr] in acr_list do
          do_authorization_granted(conn, opts, session_info)
        else
          Logger.debug("#{__MODULE__}: authorization denied (#{inspect(opts[:authz_request])}) "
          <> "with reason: returned acr value doesn't match mandatory acr")

          conn
          |> assign(:authz_request, opts[:authz_request])
          |> AsteroidWeb.Error.respond_authorize(OAuth2.AccessDeniedError.exception([
            reason: "requested essential acr condition not satisfied"]))
        end

        _ ->
          do_authorization_granted(conn, opts, session_info)
    end
  end

  @spec do_authorization_granted(Plug.Conn.t(), Plug.opts(), map()) :: Plug.Conn.t()

  defp do_authorization_granted(conn, opts, session_info) do
    authz_request = opts[:authz_request]

    {:ok, client} =
      Client.load_from_unique_attribute("client_id",
                                        authz_request.client_id,
                                        attributes: ["client_id"])

    subject = Subject.fetch_attributes(opts[:subject], ["sub"])

    ctx =
      %{}
      |> Map.put(:endpoint, :authorize)
      |> Map.put(:flow, authz_request.flow)
      |> Map.put(:response_type, authz_request.response_type)
      |> Map.put(:requested_scopes, authz_request.requested_scopes)
      |> Map.put(:granted_scopes, opts[:granted_scopes])
      |> Map.put(:client, client)
      |> Map.put(:subject, subject)
      |> Map.put(:flow_result, opts)
      |> Map.put(:conn, conn)

    granted_scopes = astrenv(:oauth2_scope_callback).(opts[:granted_scopes], ctx)

    maybe_authorization_code_serialized =
      if authz_request.response_type in [
        :code, :"code id_token", :"code token", :"code id_token token"
      ] do
        {:ok, authorization_code} =
          AuthorizationCode.gen_new()
          |> AuthorizationCode.put_value("iat", now())
          |> AuthorizationCode.put_value("exp",
            now() + astrenv(:oauth2_authorization_code_lifetime_callback).(ctx))
          |> AuthorizationCode.put_value("client_id", client.attrs["client_id"])
          |> AuthorizationCode.put_value("redirect_uri", authz_request.redirect_uri)
          |> AuthorizationCode.put_value("sub", subject.attrs["sub"])
          |> AuthorizationCode.put_value("requested_scopes",
                                         Scope.Set.to_list(authz_request.requested_scopes))
          |> AuthorizationCode.put_value("granted_scopes", Scope.Set.to_list(granted_scopes))
          |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow",
                                         Atom.to_string(authz_request.flow))
          |> AuthorizationCode.put_value("iss", OAuth2.issuer())
          |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge",
                                         authz_request.pkce_code_challenge)
          |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge_method",
                                         if authz_request.pkce_code_challenge_method != nil do
                                           to_string(authz_request.pkce_code_challenge_method)
                                         end)
          |> AuthorizationCode.put_value("__asteroid_oidc_nonce", authz_request.nonce)
          |> AuthorizationCode.put_value("__asteroid_oidc_authenticated_session_id",
                                         opts[:authenticated_session_id])
          |> AuthorizationCode.put_value("__asteroid_oidc_initial_acr", session_info[:acr])
          |> AuthorizationCode.put_value("__asteroid_oidc_initial_amr", session_info[:amr])
          |> AuthorizationCode.put_value("__asteroid_oidc_initial_auth_time",
                                         session_info[:auth_time])
          |> AuthorizationCode.put_value("__asteroid_oidc_claims", authz_request.claims)
          |> AuthorizationCode.store(ctx)

        AuthorizationCode.serialize(authorization_code)
      end

    maybe_access_token =
      if authz_request.response_type in [
        :token, :"id_token token", :"code token", :"code id_token token"
      ] do
        {:ok, access_token} =
          new_access_token(ctx)
          |> AccessToken.put_value("iss", OAuth2.issuer())
          |> AccessToken.put_value("iat", now())
          |> AccessToken.put_value("exp",
                                   now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))
          |> AccessToken.put_value("client_id", client.attrs["client_id"])
          |> AccessToken.put_value("redirect_uri", authz_request.redirect_uri)
          |> AccessToken.put_value("sub", subject.attrs["sub"])
          |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))
          |> AccessToken.put_value("__asteroid_oidc_authenticated_session_id",
                                   opts[:authenticated_session_id])
          |> AccessToken.put_value("__asteroid_oauth2_initial_flow",
                                   Atom.to_string(authz_request.flow))
          |> AccessToken.put_value("__asteroid_oidc_claims", authz_request.claims)
          |> AccessToken.store(ctx)

          access_token
      end

    maybe_access_token_lifetime =
      if maybe_access_token do
        maybe_access_token.data["exp"] - maybe_access_token.data["iat"]
      end

    maybe_access_token_serialized =
      if maybe_access_token, do: AccessToken.serialize(maybe_access_token)

    maybe_id_token_serialized =
      if authz_request.response_type in [
        :id_token, :"id_token token", :"code id_token", :"code id_token token"
      ] do
        additional_claims = additional_claims(authz_request, granted_scopes)

        %IDToken{
          iss: OAuth2.issuer(),
          sub: astrenv(:oidc_subject_identifier_callback).(subject, client),
          aud: client.attrs["client_id"],
          exp: now() + astrenv(:oidc_id_token_lifetime_callback).(ctx),
          iat: now(),
          auth_time: session_info[:auth_time],
          acr: session_info[:acr],
          amr: session_info[:amr],
          nonce: authz_request.nonce,
          client: client,
          associated_access_token_serialized: maybe_access_token_serialized,
          associated_authorization_code_serialized: maybe_authorization_code_serialized
        }
        |> IDToken.add_sub_claims(additional_claims, subject)
        |> astrenv(:token_id_token_before_serialize_callback).(ctx)
        |> IDToken.serialize()
      else
        nil
      end

      params =
        %{}
        |> put_if_not_nil("code", maybe_authorization_code_serialized)
        |> put_if_not_nil("access_token", maybe_access_token_serialized)
        |> put_if_not_nil("id_token", maybe_id_token_serialized)
        |> put_if_not_nil("state", authz_request.params["state"])
        |> put_if_not_nil("token_type", (if maybe_access_token_serialized, do: "bearer"))
        |> put_if_not_nil("expires_in", maybe_access_token_lifetime)
        |> maybe_put_scope(authz_request.requested_scopes,
                           opts[:granted_scopes],
                           authz_request.response_type)

    case authz_request.response_mode do
      :query ->
        redirect_uri =
          authz_request.redirect_uri
          |> OAuth2.RedirectUri.add_params(params)
          |> astrenv(:oauth2_endpoint_authorize_before_send_redirect_uri_callback).(ctx)

        conn
        |> astrenv(:oauth2_endpoint_authorize_before_send_conn_callback).(ctx)
        |> redirect(external: redirect_uri)

      :fragment ->
        redirect_uri =
          authz_request.redirect_uri
          |> Kernel.<>("#")
          |> Kernel.<>(URI.encode_query(params))
          |> astrenv(:oauth2_endpoint_authorize_before_send_redirect_uri_callback).(ctx)

        conn
        |> astrenv(:oauth2_endpoint_authorize_before_send_conn_callback).(ctx)
        |> redirect(external: redirect_uri)

      :form_post ->
        conn
        |> put_status(200)
        |> put_resp_header("cache-control", "no-cache, no-store")
        |> put_resp_header("pragma", "no-cache")
        |> Plug.Conn.put_private(:plug_skip_csrf_protection, true)
        |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
        |> put_view(AsteroidWeb.AuthorizeView)
        |> astrenv(:oauth2_endpoint_authorize_before_send_conn_callback).(ctx)
        |> render("authorization_form_post_response.html",
                  params: params, target: authz_request.redirect_uri)
    end
  end

  @doc """
  Callback to be called when the authorization is denied, either by the user or by the
  server

  The options are a `map()` with the following keys (all **mandatory**):
  - `:authz_request`: the initial `t:AsteroidWeb.AuthorizeController.Request.t/0` authorization
  request
  - `:error`: one of the following exceptions:
    - `t:Asteroid.OAuth2.AccessDeniedError.t/0` when the request was denied either because of
    server
    policy or because of the user refusal
    - `t:Asteroid.OAuth2.ServerError.t/0` in case of server error
    - `t:Asteroid.OAuth2.TemporarilyUnavailableError.t/0` when the service is temporarily
    unavailable. Can be useful for maintenance mode
    - `t:Asteroid.OIDC.InteractionRequiredError.t/0`
    - `t:Asteroid.OIDC.LoginRequiredError.t/0`
    - `t:Asteroid.OIDC.AccountSelectionRequiredError.t/0`
    - `t:Asteroid.OIDC.ConsentRequiredError.t/0`
  """

  @spec authorization_denied(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()

  def authorization_denied(conn, opts)
  do
    authz_request = opts[:authz_request]

    Logger.debug("#{__MODULE__}: authorization denied (#{inspect(authz_request)}) with "
    <> "reason: `#{Exception.message(opts[:error])}`")

    conn
    |> assign(:authz_request, authz_request)
    |> AsteroidWeb.Error.respond_authorize(opts[:error])
  end

  @doc """
  Callback invoked to determine which callback function to call to continue the authorization
  process after the parameters were successfully verified

  If the protocol is OAuth2, it calls:
  - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_web_authorization_callback)}
  if the flow is authorization code
  - #{Asteroid.Config.link_to_option(:oauth2_flow_implicit_web_authorization_callback)}
  if the flow is implicit

  If the protocol is OpenID Connect, it uses the
  #{Asteroid.Config.link_to_option(:oidc_acr_config)} configuration option to determine which
  callback to use:
  - if a preferred acr was computed, it uses its associated callback
  - otherwise, if one entry in the config is marked as `default: true`, it uses it

  If this configuration option is not used, it fall backs to:
  - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_web_authorization_callback)}
  if the flow is authorization code
  - #{Asteroid.Config.link_to_option(:oidc_flow_implicit_web_authorization_callback)}
  if the flow is implicit
  - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_web_authorization_callback)}
  if the flow is hybrid
  """

  @spec select_web_authorization_callback(Plug.Conn.t(),
                                          AsteroidWeb.AuthorizeController.Request.t())
  :: Plug.Conn.t()

  def select_web_authorization_callback(conn, %Request{flow: :authorization_code} = authz_req) do
    astrenv(:oauth2_flow_authorization_code_web_authorization_callback).(conn, authz_req)
  end

  def select_web_authorization_callback(conn, %Request{flow: :implicit} = authz_req) do
    astrenv(:oauth2_flow_implicit_web_authorization_callback).(conn, authz_req)
  end

  def select_web_authorization_callback(conn, %Request{flow: flow} = authz_req) when flow in [
    :oidc_authorization_code,
    :oidc_implicit,
    :oidc_hybrid
  ] do
    oidc_acr_config = astrenv(:oidc_acr_config, [])

    maybe_preferred_acr =
      try do
        String.to_existing_atom(authz_req.preferred_acr)
      rescue
        _ ->
          nil
      end

    if oidc_acr_config[maybe_preferred_acr][:callback] do
      oidc_acr_config[maybe_preferred_acr][:callback].(conn, authz_req)
    else
      maybe_default_callback =
        Enum.find_value(
          oidc_acr_config,
          fn
            {_acr, acr_config} ->
              if acr_config[:default] == true do
                acr_config[:callback]
              else
                nil
              end
          end
        )

      if maybe_default_callback do
        maybe_default_callback.(conn, authz_req)
      else
        case flow do
          :oidc_authorization_code ->
            astrenv(:oidc_flow_authorization_code_web_authorization_callback).(conn, authz_req)

          :oidc_implicit ->
            astrenv(:oidc_flow_implicit_web_authorization_callback).(conn, authz_req)

          :oidc_hybrid ->
            astrenv(:oidc_flow_hybrid_web_authorization_callback).(conn, authz_req)
        end
      end
    end
  end

  @spec jar_pre_authorize_oauth2(Plug.Conn.t(), map()) :: Plug.Conn.t()

  defp jar_pre_authorize_oauth2(conn, %{"request" => request_object} = params) do
    if astrenv(:oauth2_jar_enabled) in [:request_only, :enabled] do
      case OAuth2.JAR.verify_and_parse(request_object) do
        {:ok, jar_req_params} ->
            req_params =
              Map.merge(jar_delete_oauth2_request_parameters(params), jar_req_params)

            pre_authorize(conn, req_params)

        {:error, e} ->
          AsteroidWeb.Error.respond_authorize(conn, e)
      end
    else
      AsteroidWeb.Error.respond_authorize(conn,
                                          OAuth2.JAR.RequestNotSupportedError.exception([]))
    end
  end

  defp jar_pre_authorize_oauth2(conn, %{"request_uri" => request_uri} = params) do
    if astrenv(:oauth2_jar_enabled) in [:request_uri_only, :enabled] do
      with {:ok, jar_req_obj} <- OAuth2.JAR.retrieve_object(request_uri),
           {:ok, jar_req_params} = OAuth2.JAR.verify_and_parse(jar_req_obj)
      do
        req_params =
          Map.merge(jar_delete_oauth2_request_parameters(params), jar_req_params)

        pre_authorize(conn, req_params)
      else
        {:error, e} ->
          AsteroidWeb.Error.respond_authorize(conn, e)
      end
    else
      AsteroidWeb.Error.respond_authorize(conn,
                                          OAuth2.JAR.RequestURINotSupportedError.exception([]))
    end
  end

  @spec jar_pre_authorize_oidc(Plug.Conn.t(), map()) :: Plug.Conn.t()

  defp jar_pre_authorize_oidc(
    conn,
    %{
      "request" => request_object,
      "response_type" => response_type,
      "client_id" => client_id,
      "scope" => scope_param
    } = params) do
    scopes = OAuth2Utils.Scope.Set.from_scope_param!(scope_param)

    if astrenv(:oauth2_jar_enabled) in [:request_only, :enabled] do
      case OAuth2.JAR.verify_and_parse(request_object) do
        {:ok, jar_req_params} ->
          if jar_req_params["response_type"] in [response_type, nil] and
             jar_req_params["client_id"] in [client_id, nil] and
             "openid" in scopes
          do
            req_params =
              Map.merge(Map.delete(params, "request"), jar_req_params)

            pre_authorize(conn, req_params)
          else
            AsteroidWeb.Error.respond_authorize(conn,
              OAuth2.JAR.InvalidRequestObjectError.exception([
                reason: "Request and request object `response_type` or `client_id` don't match"]))
          end

        {:error, e} ->
          AsteroidWeb.Error.respond_authorize(conn, e)
      end
    else
      AsteroidWeb.Error.respond_authorize(conn, OAuth2.JAR.RequestNotSupportedError.exception([]))
    end
  end

  defp jar_pre_authorize_oidc(
    conn,
    %{
      "request_uri" => request_uri,
      "response_type" => response_type,
      "client_id" => client_id,
      "scope" => scope_param
    } = params) do
    scopes = OAuth2Utils.Scope.Set.from_scope_param!(scope_param)

    if astrenv(:oauth2_jar_enabled) in [:request_uri_only, :enabled] do
      with {:ok, jar_req_obj} <- OAuth2.JAR.retrieve_object(request_uri),
           {:ok, jar_req_params} = OAuth2.JAR.verify_and_parse(jar_req_obj)
      do
        if jar_req_params["response_type"] in [response_type, nil] and
           jar_req_params["client_id"] in [client_id, nil] and
           "openid" in scopes
        do
          req_params =
            Map.merge(Map.delete(params, "request_uri"), jar_req_params)

          pre_authorize(conn, req_params)
        else
          AsteroidWeb.Error.respond_authorize(conn,
            OAuth2.JAR.InvalidRequestObjectError.exception([
              reason: "Request and request object `response_type` or `client_id` don't match"]))
        end
      else
        {:error, e} ->
          AsteroidWeb.Error.respond_authorize(conn, e)
      end
    else
      AsteroidWeb.Error.respond_authorize(conn,
                                          OAuth2.JAR.RequestURINotSupportedError.exception([]))
    end
  end

  defp jar_pre_authorize_oidc(conn, params) do
    missing_parameter =
      if params["response_type"] == nil do
        "response_type"
      else
        if params["client_id"] == nil do
          "client_id"
        else
          "scope"
        end
      end

    AsteroidWeb.Error.respond_authorize(conn, OAuth2.Request.InvalidRequestError.exception(
      reason: "missing parameter", parameter: missing_parameter))
  end

  @spec redirect_uri_registered_for_client?(Client.t(), OAuth2.RedirectUri.t()) ::
  :ok
  | {:error, %OAuth2.Request.InvalidRequestError{}}

  def redirect_uri_registered_for_client?(client, redirect_uri) do
    client = Client.fetch_attributes(client, ["redirect_uri"])

    if redirect_uri in (client.attrs["redirect_uris"] || []) do
      :ok
    else
      {:error, OAuth2.Request.InvalidRequestError.exception(
        reason: "unregistered `redirect_uri` for client",
        parameter: "redirect_uri")}
    end
  end

  @spec protocol(map()) :: OAuth2.protocol()

  defp protocol(params) do
    case OAuth2Utils.Scope.Set.from_scope_param(params["scope"] || "") do
      {:ok, scopes} ->
        if "openid" in scopes, do: :oidc, else: :oauth2

      {:error, _} ->
        :oauth2
    end
  end

  @spec client_id_valid?(String.t()) ::
  :ok
  | {:error, %OAuth2.Request.MalformedParamError{}}

  def client_id_valid?(client_id) do
    if OAuth2Utils.valid_client_id_param?(client_id) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "client_id", value: client_id)}
    end
  end


  @spec redirect_uri_valid?(String.t()) ::
  :ok
  | {:error, %OAuth2.Request.MalformedParamError{}}

  def redirect_uri_valid?(redirect_uri) do
    if OAuth2.RedirectUri.valid?(redirect_uri) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(
        name: "redirect_uri",
        value: redirect_uri)}
    end
  end

  @spec oidc_param_display_valid(String.t() | nil) ::
  :ok 
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp oidc_param_display_valid(nil), do: :ok
  defp oidc_param_display_valid("page"), do: :ok
  defp oidc_param_display_valid("popup"), do: :ok
  defp oidc_param_display_valid("touch"), do: :ok
  defp oidc_param_display_valid("wap"), do: :ok
  defp oidc_param_display_valid(val), do: OAuth2.Request.MalformedParamError.exception([
    name: "display", value: val])

  @spec oidc_param_prompt_valid(String.t() | nil) ::
  :ok 
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp oidc_param_prompt_valid(nil), do: :ok
  defp oidc_param_prompt_valid("none"), do: :ok
  defp oidc_param_prompt_valid("login"), do: :ok
  defp oidc_param_prompt_valid("consent"), do: :ok
  defp oidc_param_prompt_valid("select_account"), do: :ok
  defp oidc_param_prompt_valid(val), do: OAuth2.Request.MalformedParamError.exception([
    name: "prompt", value: val])

  @spec oidc_param_max_age_valid(String.t() | nil) ::
  {:ok, non_neg_integer() | nil}
  | {:error, %OAuth2.Request.MalformedParamError{}}

  def oidc_param_max_age_valid(nil) do
    {:ok, nil}
  end

  def oidc_param_max_age_valid(maybe_integer_str) do
    case Integer.parse(maybe_integer_str) do
      {max_age, _} ->
        {:ok, max_age}

      :error ->
        OAuth2.Request.MalformedParamError.exception([name: "max_age", value: maybe_integer_str])
    end
  end

  @spec oidc_param_ui_locales_valid(String.t() | nil) ::
  {:ok, [String.t()] | nil}
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp oidc_param_ui_locales_valid(nil) do
    {:ok, nil}
  end

  defp oidc_param_ui_locales_valid(ui_locales_param) do
    case String.split(ui_locales_param, " ") do
      [_ | _] = ui_locales_list ->
        {:ok, ui_locales_list}

      [] ->
        OAuth2.Request.MalformedParamError.exception([name: "ui_locales", value: ""])
    end
  end

  @spec oidc_param_acr_values_valid(String.t() | nil) ::
  {:ok, [OIDC.acr()] | nil}
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp oidc_param_acr_values_valid(nil) do
    {:ok, nil}
  end

  defp oidc_param_acr_values_valid(acr_values_param) do
    case String.split(acr_values_param, " ") do
      [_ | _] = acr_values_list ->
        {:ok, acr_values_list}

      [] ->
        OAuth2.Request.MalformedParamError.exception([name: "acr_values", value: ""])
    end
  end

  @spec preferred_acr(map() | nil, [OIDC.acr()] | nil, Client.t()) ::
  {:ok, OIDC.acr()}
  | {:ok, nil}
  | {:error, Exception.t()}

  defp preferred_acr(claims_param, acr_values, client) do
    case preferred_acr_from_claims_param(claims_param) do
      {:ok, acr} when is_binary(acr) ->
        {:ok, acr}

      {:error, _} = error ->
        error

      {:ok, nil} ->
        case preferred_acr_from_acr_values_param(acr_values) do
          {:ok, acr} when is_binary(acr) ->
            {:ok, acr}

          {:error, _} = error ->
            error

          {:ok, nil} ->
            acrs_config =
              Enum.map(astrenv(:oidc_acr_config, []), fn {k, _} -> Atom.to_string(k) end)

            client = Client.fetch_attributes(client, ["default_acr_values"])

            {:ok, Enum.find(client.attrs["default_acr_values"] || [], &(&1 in acrs_config))}
        end
    end
  end

  @spec preferred_acr_from_claims_param(map()) ::
  {:ok, OIDC.acr()}
  | {:ok, nil}
  | {:error, Exception.t()}

  defp preferred_acr_from_claims_param(nil) do
    {:ok, nil}
  end

  defp preferred_acr_from_claims_param(claims_param) do
    acrs_config = Enum.map(astrenv(:oidc_acr_config, []), fn {k, _} -> Atom.to_string(k) end)

    case claims_param["id_token"]["acr"] do
      %{"values" => [acr | _]} ->
        if acr in acrs_config do
          {:ok, acr}
        else
          {:error, OAuth2.Request.InvalidRequestError.exception(
            reason: "`acr` value of the `claims` parameter is unknown", parameter: "claims")}
        end

      %{"value" => acr} when is_binary(acr)->
        if acr in acrs_config do
          {:ok, acr}
        else
          {:error, OAuth2.Request.InvalidRequestError.exception(
            reason: "`acr` value of the `claims` parameter is unknown", parameter: "claims")}
        end

      _ ->
        {:ok, nil}
    end
  end

  @spec preferred_acr_from_acr_values_param([OIDC.acr()]) ::
  {:ok, OIDC.acr()}
  | {:ok, nil}
  | {:error, Exception.t()}

  defp preferred_acr_from_acr_values_param(nil) do
    {:ok, nil}
  end

  defp preferred_acr_from_acr_values_param([acr | _]) do
    acrs_config = Enum.map(astrenv(:oidc_acr_config, []), fn {k, _} -> Atom.to_string(k) end)

    if acr in acrs_config do
      {:ok, acr}
    else
      {:error, OAuth2.Request.InvalidRequestError.exception(
        reason: "unknown acr requested", parameter: "acr_values")}
    end
  end

  @spec nonce_parameter_present(map(), OAuth2.flow()) ::
  :ok
  | {:error, %OAuth2.Request.InvalidRequestError{}}

  defp nonce_parameter_present(%{"nonce" => _}, :oidc_implicit) do
    :ok
  end

  defp nonce_parameter_present(_, :oidc_implicit) do
    {:error, OAuth2.Request.InvalidRequestError.exception(
      reason: "missing parameter", parameter: "nonce")}
  end

  defp nonce_parameter_present(_, _) do
    :ok
  end

  @spec response_mode(map(), OAuth2.flow()) ::
  {:ok, OAuth2.response_mode()}
  | {:error, %OAuth2.Request.InvalidRequestError{}}

  defp response_mode(%{"response_mode" => response_mode_param}, flow) do
    if response_mode_param in ["query", "fragment", "form_post"] do
      response_mode =
        case response_mode_param do
          "query" ->
            :query

          "fragment" ->
            :fragment

          "form_post" ->
            :form_post
        end

      case astrenv(:oauth2_response_mode_policy, :oidc_only) do
        :disabled ->
          {:ok, OAuth2.default_response_mode(flow)}

        :oidc_only ->
          if flow in [:oidc_authorization_code, :oidc_implicit, :oidc_hybrid] do
            {:ok, response_mode}
          else
            {:ok, OAuth2.default_response_mode(flow)}
          end

        :enabled ->
          {:ok, response_mode}
      end
    else
      {:error, OAuth2.Request.InvalidRequestError.exception(
        parameter: "response_mode", reason: "unsupported value `#{response_mode_param}`")}
    end
  end

  defp response_mode(_params, flow) do
    {:ok, OAuth2.default_response_mode(flow)}
  end

  @spec parse_claims_param(map()) :: {:ok, map() | nil} | {:error, Exception.t()}

  defp parse_claims_param(%{"claims" => claims_param}) do
    case Jason.decode(claims_param) do
      {:ok, %{} = claims} ->
        {:ok, claims}

      _ ->
        {:error,
          OAuth2.Request.MalformedParamError.exception(name: "claims", value: claims_param)}
    end
  end

  defp parse_claims_param(_) do
    {:ok, nil}
  end

  @spec maybe_put_scope(map(), Scope.Set.t(), Scope.Set.t(), OAuth2.response_type()) :: map()

  defp maybe_put_scope(m, requested_scopes, granted_scopes, response_type)
  when response_type in [ :token, :"id_token token", :"code token", :"code id_token token"]
  do
    if Scope.Set.equal?(requested_scopes, granted_scopes) do
      m
    else
      Map.put(m, "scope", Enum.join(granted_scopes, " "))
    end
  end

  defp maybe_put_scope(m, _, _, _) do
    m
  end

  @spec maybe_pkce_params(Client.t(), map(), OAuth2.flow()) ::
  {:ok, {OAuth2.PKCE.code_challenge() | nil, OAuth2.PKCE.code_challenge_method() | nil}}
  | {:error, %OAuth2.Request.InvalidRequestError{}}
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp maybe_pkce_params(_client, _params, flow) when flow in [:implicit, :oidc_implicit] do
    {:ok, {nil, nil}}
  end

  defp maybe_pkce_params(client, params, flow) when flow in [
    :authorization_code,
    :oidc_authorization_code,
    :oidc_hybrid
  ] do
    case astrenv(:oauth2_pkce_policy, :optional) do
      :disabled ->
        {:ok, {nil, nil}}

      :optional ->
        if astrenv(:oauth2_pkce_must_use_callback).(client) do
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
        nil ->
          {:error, OAuth2.Request.InvalidRequestError.exception(
            reason: "unsupported code challenge method", parameter: "code_challenge_method")}

        code_challenge_method when is_atom(code_challenge_method) ->
          if code_challenge_method in astrenv(:oauth2_pkce_allowed_methods) do
            {:ok, {code_challenge, code_challenge_method}}
          else
            {:error, OAuth2.Request.InvalidRequestError.exception(
              reason: "unsupported code challenge method", parameter: "code_challenge_method")}
          end
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

  @spec new_access_token(Context.t(), Keyword.t()) :: AccessToken.t()

  defp new_access_token(ctx, access_token_opts \\ []) do
    serialization_format = astrenv(:oauth2_access_token_serialization_format_callback).(ctx)

    case serialization_format do
      :opaque ->
        AccessToken.gen_new(access_token_opts)

      :jws ->
        signing_key = astrenv(:oauth2_access_token_signing_key_callback).(ctx)
        signing_alg = astrenv(:oauth2_access_token_signing_alg_callback).(ctx)

        access_token_opts =
          access_token_opts
          |> Keyword.put(:serialization_format, serialization_format)
          |> Keyword.put(:signing_key, signing_key)
          |> Keyword.put(:signing_alg, signing_alg)

        AccessToken.gen_new(access_token_opts)
    end
  end

  # this function removes the OAuth2 request attributes as specified in the JAR specification:
  #    The Authorization Server MUST extract the set of Authorization
  #    Request parameters from the Request Object value.  The Authorization
  #    Server MUST only use the parameters in the Request Object even if the
  #    same parameter is provided in the query parameter.
  #
  # it also deletes any "request" and "request_uri" parameter

  @spec jar_delete_oauth2_request_parameters(map()) :: map()

  defp jar_delete_oauth2_request_parameters(params) do
    Enum.reduce(
      params,
      %{},
      fn
        {k, v}, acc ->
          standard_request_params =
            OAuth2Utils.get_parameters_for_location(:authorization_request, [:oauth2])

          if k not in standard_request_params do
            Map.put(acc, k, v)
          else
            acc
          end
      end
    )
    |> Map.delete("request")
    |> Map.delete("request_uri")
  end

  @spec session_info(map()) ::
  %{
    required(:acr) => Asteroid.OIDC.acr() | nil,
    required(:auth_time) => non_neg_integer() | nil,
    required(:amr) => [Asteroid.OIDC.amr(), ...]
  }
  | nil

  defp session_info(opts) do
    if opts[:authenticated_session_id] do
      AuthenticatedSession.info(opts[:authenticated_session_id])
    else
      %{
        acr: opts[:acr],
        amr: opts[:amr],
        auth_time: opts[:auth_time]
      }
    end
  end

  # The Claims requested by the profile, email, address, and phone scope values are returned
  # from the UserInfo Endpoint, as described in Section 5.3.2, when a response_type value is
  # used that results in an Access Token being issued. However, when no Access Token is issued
  # (which is the case for the response_type value id_token), the resulting Claims are returned
  # in the ID Token. 

  @spec additional_claims(Request.t(), Scope.Set.t()) :: [String.t()]

  defp additional_claims(authz_request, granted_scopes) do
    if authz_request.response_type == :id_token do
      Enum.reduce(
        OIDC.Userinfo.scope_claims_mapping(),
        [],
        fn
          {claim_scope, claim_values}, acc ->
            if claim_scope in granted_scopes do
              claim_values ++ acc
            else
              acc
            end
        end)
    else
      []
    end
    ++ Map.keys(authz_request.claims["id_token"] || %{})
  end
end
