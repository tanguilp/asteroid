defmodule AsteroidWeb.AuthorizeController do
  use AsteroidWeb, :controller

  require Logger

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.OAuth2
  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.Subject
  alias Asteroid.Token.{AccessToken, AuthorizationCode, IDToken}

  defmodule Request do
    @moduledoc """
    Struct with the necessary information to process an web authorization request
    """

    @enforce_keys [:flow, :response_type, :client_id, :redirect_uri, :requested_scopes, :params]

    defstruct [
      :flow,
      :response_type,
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
      :params
    ]

    @type t :: %__MODULE__{
      flow: OAuth2.flow(),
      response_type: OAuth2.response_type(),
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
        #FIXME: update when specification is issued
        jar_pre_authorize_oidc(conn, params)

      :oidc ->
        jar_pre_authorize_oidc(conn, params)
    end
  end

  def pre_authorize(conn, %{"request_uri" => _} = params) do
    case protocol(params) do
      :oauth2 ->
        #FIXME: update when specification is issued
        jar_pre_authorize_oidc(conn, params)

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

    # FIXME: with :ok <- Asteroid.OAuth2.grant_type_enabled?(:authorization_code),
    with {:ok, flow} <- OAuth2.response_type_to_flow(response_type_str, protocol),
         {:ok, response_type} <- Asteroid.OAuth2.to_response_type(response_type_str),
         :ok <- Asteroid.OAuth2.response_type_enabled?(response_type),
         :ok <- client_id_valid?(client_id),
         :ok <- redirect_uri_valid?(redirect_uri),
         {:ok, client} <- Client.load_from_unique_attribute("client_id", client_id),
         :ok <- redirect_uri_registered_for_client?(client, redirect_uri),
         :ok <- OAuth2.Client.response_type_authorized?(client, response_type_str),
         :ok <- OAuth2.Scope.scopes_enabled?(requested_scopes, flow),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes),
         {:ok, {maybe_code_challenge, maybe_code_challenge_method}} <-
           maybe_pkce_params(client, params, flow),
         :ok <-  nonce_parameter_present(params, flow)
    do
      client = Client.fetch_attributes(client, ["client_id"])

      authz_request =
        case protocol do
          :oauth2 ->
              %Request{
                flow: flow,
                response_type: response_type,
                client_id: client.attrs["client_id"],
                redirect_uri: redirect_uri,
                requested_scopes: requested_scopes,
                pkce_code_challenge: maybe_code_challenge,
                pkce_code_challenge_method: maybe_code_challenge_method,
                params: params
              }

          :oidc ->
            with :ok <- oidc_param_display_valid(params["display"]),
                 :ok <- oidc_param_prompt_valid(params["prompt"]),
                 {:ok, max_age_int} <- oidc_param_max_age_valid(params["max_age"]),
                 {:ok, ui_locales_list} <- oidc_param_ui_locales_valid(params["ui_locales"]),
                 {:ok, acr_values_list} <- oidc_param_acr_values_valid(params["acr_values"])
            do
              %Request{
                flow: flow,
                response_type: response_type,
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
                params: params
              }
            else
              {:error, %OAuth2.Request.MalformedParamError{} = e} ->
                AsteroidWeb.Error.respond_authorize(conn, e)
            end
        end

      astrenv(:web_authorization_callback).(conn, authz_request)
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

  The `opts` parameter is a `map()` whose keys are (all are **mandatory**):
  - `:authz_request`: the initial `t:AsteroidWeb.AuthorizeController.Request.t/0` authorization
  request
  - `:subject`: the `t:Asteroid.Subject.t/0` of the user having approved the request
  - `:granted_scopes`: a `t:OAuth2Utils.Scope.Set.t/0` for the granted scope. If none was granted
  (because none were requested, or because user did not authorize them), an empty
  `t:OAuth2Utils.Scope.Set.t/0` must be set
  """

  @spec authorization_granted(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()

  def authorization_granted(conn, %{authz_request: %Request{flow: flow}} = opts) when flow in [
    :authorization_code,
    :oidc_authorization_code
  ] do
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

    granted_scopes = astrenv(:oauth2_scope_callback).(opts[:granted_scopes], ctx)

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
                                     else
                                       nil
                                     end)
      |> AuthorizationCode.put_value("__asteroid_oidc_nonce", authz_request.nonce)
      |> AuthorizationCode.store(ctx)

    redirect_uri =
      authz_request.redirect_uri
      |> OAuth2.RedirectUri.add_params(
        %{
          "code" => AuthorizationCode.serialize(authorization_code)
        }
        |> put_if_not_nil("state", authz_request.params["state"])
      )  
      |> astrenv(:oauth2_endpoint_authorize_before_send_redirect_uri_callback).(ctx)

    Logger.debug("#{__MODULE__}: authorization granted (#{inspect(authz_request)}) with "
    <> "code: `#{inspect authorization_code}` and state: `#{inspect authz_request.params["state"]}`")

    conn
    |> astrenv(:oauth2_endpoint_authorize_before_send_conn_callback).(ctx)
    |> redirect(external: redirect_uri)
  end

  def authorization_granted(conn, %{authz_request: %Request{flow: flow}} = opts) when flow in [
    :implicit,
    :oidc_implicit
  ] do
    authz_request = opts[:authz_request]

    {:ok, client} =
      Client.load_from_unique_attribute("client_id",
                                        authz_request.client_id,
                                        attributes: ["client_id"])

    subject = Subject.fetch_attributes(opts[:subject], ["sub"])

    ctx =
      %{}
      |> Map.put(:endpoint, :authorize)
      |> Map.put(:flow, flow)
      |> Map.put(:response_type, authz_request.response_type)
      |> Map.put(:requested_scopes, authz_request.requested_scopes)
      |> Map.put(:granted_scopes, opts[:granted_scopes])
      |> Map.put(:client, client)
      |> Map.put(:subject, subject)
      |> Map.put(:flow_result, opts)

    granted_scopes = astrenv(:oauth2_scope_callback).(opts[:granted_scopes], ctx) #FIXME OIDC

    access_token_lifetime = astrenv(:oauth2_access_token_lifetime_callback).(ctx)

    maybe_access_token_serialized =
      if authz_request.response_type in [:token, :"id_token token"] do
        {:ok, access_token} =
          new_access_token(ctx)
          |> AccessToken.put_value("iat", now())
          |> AccessToken.put_value("exp", now() + access_token_lifetime)
          |> AccessToken.put_value("client_id", client.attrs["client_id"])
          |> AccessToken.put_value("redirect_uri", authz_request.redirect_uri)
          |> AccessToken.put_value("sub", subject.attrs["sub"])
          |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))
          |> AccessToken.put_value("__asteroid_oauth2_initial_flow", Atom.to_string(flow))
          |> AccessToken.put_value("iss", OAuth2.issuer())
          |> AccessToken.store(ctx)

          AccessToken.serialize(access_token)
      else
        nil
      end

    maybe_id_token_serialized =
      if authz_request.response_type in [:id_token, :"id_token token"] do
        %IDToken{
          iss: OAuth2.issuer(),
          sub: subject.attrs["sub"],
          aud: client.attrs["client_id"],
          exp: now() + astrenv(:oidc_id_token_lifetime_callback).(ctx),
          iat: now(),
          auth_time: nil, # FIXME
          nonce: authz_request.nonce,
          acr: nil, #FIXME
          amr: nil, #FIXME
          azp: nil,
          signing_key: astrenv(:oidc_id_token_signing_key_callback).(ctx),
          signing_alg: astrenv(:oidc_id_token_signing_alg_callback).(ctx),
          associated_access_token_serialized: maybe_access_token_serialized
        }
        |> astrenv(:token_id_token_before_serialize_callback).(ctx)
        |> IDToken.serialize()
      else
        nil
      end

    fragment_params =
      %{}
      |> put_if_not_nil("access_token", maybe_access_token_serialized)
      |> put_if_not_nil("id_token", maybe_id_token_serialized)
      |> put_if_not_nil("token_type", (if maybe_access_token_serialized, do: "bearer"))
      |> put_if_not_nil("expires_in",
                        (if maybe_access_token_serialized, do: access_token_lifetime))
      |> maybe_put_scope_implicit_flow(authz_request.requested_scopes, opts[:granted_scopes])
      |> put_if_not_nil("state", authz_request.params["state"])

    redirect_uri =
      authz_request.redirect_uri
      |> Kernel.<>("#")
      |> Kernel.<>(URI.encode_query(fragment_params))
      |> astrenv(:oauth2_endpoint_authorize_before_send_redirect_uri_callback).(ctx)

    Logger.debug("#{__MODULE__}: authorization granted (#{inspect(authz_request)}) with "
    <> "token: `#{maybe_access_token_serialized}` "
    <> "id_token: `#{maybe_id_token_serialized}` "
    <> "and state: `#{inspect authz_request.params["state"]}`")

    conn
    |> astrenv(:oauth2_endpoint_authorize_before_send_conn_callback).(ctx)
    |> redirect(external: redirect_uri)
  end

  def authorization_granted(conn, %{authz_request: %Request{flow: :oidc_hybrid}} = opts) do
    authz_request = opts[:authz_request]

    {:ok, client} =
      Client.load_from_unique_attribute("client_id",
                                        authz_request.client_id,
                                        attributes: ["client_id"])

    subject = Subject.fetch_attributes(opts[:subject], ["sub"])

    ctx =
      %{}
      |> Map.put(:endpoint, :authorize)
      |> Map.put(:flow, :oidc_hybrid)
      |> Map.put(:response_type, authz_request.response_type)
      |> Map.put(:requested_scopes, authz_request.requested_scopes)
      |> Map.put(:granted_scopes, opts[:granted_scopes])
      |> Map.put(:client, client)
      |> Map.put(:subject, subject)
      |> Map.put(:flow_result, opts)

    granted_scopes = astrenv(:oauth2_scope_callback).(opts[:granted_scopes], ctx) #FIXME OIDC

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
      |> AuthorizationCode.put_value("__asteroid_oauth2_initial_flow", "oidc_hybrid")
      |> AuthorizationCode.put_value("iss", OAuth2.issuer())
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge",
                                     authz_request.pkce_code_challenge)
      |> AuthorizationCode.put_value("__asteroid_oauth2_pkce_code_challenge_method",
                                     if authz_request.pkce_code_challenge_method != nil do
                                       to_string(authz_request.pkce_code_challenge_method)
                                     else
                                       nil
                                     end)
      |> AuthorizationCode.put_value("__asteroid_oidc_nonce", authz_request.nonce)
      |> AuthorizationCode.store(ctx)

    authorization_code_serialized = AuthorizationCode.serialize(authorization_code)

    access_token_lifetime = astrenv(:oauth2_access_token_lifetime_callback).(ctx)

    maybe_access_token_serialized =
      if authz_request.response_type in [:token, :"id_token token"] do
        {:ok, access_token} =
          new_access_token(ctx)
          |> AccessToken.put_value("iat", now())
          |> AccessToken.put_value("exp", now() + access_token_lifetime)
          |> AccessToken.put_value("client_id", client.attrs["client_id"])
          |> AccessToken.put_value("redirect_uri", authz_request.redirect_uri)
          |> AccessToken.put_value("sub", subject.attrs["sub"])
          |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))
          |> AccessToken.put_value("__asteroid_oauth2_initial_flow", "implicit")
          |> AccessToken.put_value("iss", OAuth2.issuer())
          |> AccessToken.store(ctx)

          AccessToken.serialize(access_token)
      else
        nil
      end

    maybe_id_token_serialized =
      if authz_request.response_type in [:id_token, :"id_token token"] do
        %IDToken{
          iss: OAuth2.issuer(),
          sub: subject.attrs["sub"],
          aud: client.attrs["client_id"],
          exp: now() + astrenv(:oidc_id_token_lifetime_callback).(ctx),
          iat: now(),
          auth_time: nil, # FIXME
          nonce: authz_request.nonce,
          acr: nil, #FIXME
          amr: nil, #FIXME
          azp: nil,
          signing_key: astrenv(:oidc_id_token_signing_key_callback).(ctx),
          signing_alg: astrenv(:oidc_id_token_signing_alg_callback).(ctx),
          associated_access_token_serialized: maybe_access_token_serialized,
          associated_authorization_code_serialized: authorization_code_serialized
        }
        |> astrenv(:token_id_token_before_serialize_callback).(ctx)
        |> IDToken.serialize()
      else
        nil
      end

    fragment_params =
      %{}
      |> Map.put("code", maybe_access_token_serialized)
      |> put_if_not_nil("access_token", maybe_access_token_serialized)
      |> put_if_not_nil("id_token", maybe_id_token_serialized)
      |> put_if_not_nil("token_type", (if maybe_access_token_serialized, do: "bearer"))
      |> put_if_not_nil("expires_in",
                        (if maybe_access_token_serialized, do: access_token_lifetime))
      |> maybe_put_scope_implicit_flow(authz_request.requested_scopes, opts[:granted_scopes])
      |> put_if_not_nil("state", authz_request.params["state"])

    redirect_uri =
      authz_request.redirect_uri
      |> Kernel.<>("#")
      |> Kernel.<>(URI.encode_query(fragment_params))
      |> astrenv(:oauth2_endpoint_authorize_before_send_redirect_uri_callback).(ctx)

    Logger.debug("#{__MODULE__}: authorization granted (#{inspect(authz_request)}) with "
    <> "code: `#{authorization_code_serialized}` "
    <> "token: `#{maybe_access_token_serialized}` "
    <> "id_token: `#{maybe_id_token_serialized}` "
    <> "and state: `#{inspect authz_request.params["state"]}`")

    conn
    |> astrenv(:oauth2_endpoint_authorize_before_send_conn_callback).(ctx)
    |> redirect(external: redirect_uri)
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
  #{Asteroid.Config.link_to_option(:oidc_loa_config)} configuration option to determine which
  callback to use. Refer to the OpenID Connect session documentation for further information.

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
    oidc_loa_config = astrenv(:oidc_loa_config, [])

    maybe_callback =
      Enum.find_value(
        authz_req.acr_values || [],
        fn
          acr_value ->
            try do
              loa_atom = String.to_existing_atom(acr_value)

              oidc_loa_config[loa_atom][:callback]
            rescue
              _ ->
                nil
            end
        end
      )

    if maybe_callback do
      maybe_callback.(conn, authz_req)
    else
      maybe_default_callback =
        Enum.find_value(
          oidc_loa_config,
          fn
            loa_config ->
              if loa_config[:default] == true do
                loa_config[:callback]
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
  {:ok, [String.t()] | nil}
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

  @spec maybe_put_scope_implicit_flow(map(), Scope.Set.t(), Scope.Set.t()) :: map()

  defp maybe_put_scope_implicit_flow(m, requested_scopes, granted_scopes) do
    if Scope.Set.equal?(requested_scopes, granted_scopes) do
      m
    else
      Map.put(m, "scope", Enum.join(granted_scopes, " "))
    end
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
    :oidc_implicit
  ] do
    #FIXME: not only this option
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
        nil ->
          {:error, OAuth2.Request.InvalidRequestError.exception(
            reason: "unsupported code challenge method", parameter: "code_challenge_method")}

        code_challenge_method when is_atom(code_challenge_method) ->
          if code_challenge_method in astrenv(:oauth2_flow_authorization_code_pkce_allowed_methods) do
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
end
