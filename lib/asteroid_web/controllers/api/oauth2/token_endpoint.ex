defmodule AsteroidWeb.API.OAuth2.TokenEndpoint do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.Context
  alias Asteroid.OAuth2
  alias Asteroid.OIDC.AuthenticatedSession
  alias Asteroid.Token
  alias Asteroid.Token.{RefreshToken, AccessToken, AuthorizationCode, DeviceCode, IDToken}
  alias Asteroid.{Client, Subject}

  defmodule ExceedingScopeError do
    @moduledoc """
    Error returned when the requested scopes exceed the scopes granted beforehand
    """

    @enforce_keys [:granted_scopes, :requested_scopes]

    defexception [:granted_scopes, :requested_scopes]

    @type t :: %__MODULE__{
      granted_scopes: Scope.Set.t(),
      requested_scopes: Scope.Set.t()
    }

    @impl true

    def message(%{granted_scopes: granted_scopes, requested_scopes: requested_scopes}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Requested scopes exceed granted scope " <>
          "(granted scopes: #{Scope.Set.to_list(granted_scopes)}, " <>
          "requested scopes: #{Scope.Set.to_list(requested_scopes)}, scopes in excess: " <>
          "#{Scope.Set.to_list(Scope.Set.difference(requested_scopes, granted_scopes))}"

        :normal ->
          "Requested scopes exceed granted scope"

        :minimal ->
          ""
      end
    end
  end

  # OAuth2 ROPC flow (resource owner password credentials)
  # https://tools.ietf.org/html/rfc6749#section-4.3.2

  def handle(conn,
    %{"grant_type" => "password", "username" => username, "password" => password} = params)
  when username != nil and password != nil do
    scope_param = params["scope"]

    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:password),
         :ok <- valid_username_param?(username),
         :ok <- valid_password_param?(password),
         {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "password"),
         {:ok, requested_scopes} <- get_scope(scope_param),
         :ok <- OAuth2.Scope.scopes_enabled?(requested_scopes, :ropc),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes),
         {:ok, subject} <-
           astrenv(:oauth2_flow_ropc_username_password_verify_callback).(conn, username, password)
    do
      ctx =
        %{}
        |> Map.put(:endpoint, :token)
        |> Map.put(:flow, :ropc)
        |> Map.put(:grant_type, :password)
        |> Map.put(:requested_scopes, requested_scopes)
        |> Map.put(:subject, subject)
        |> Map.put(:client, client)
        |> Map.put(:body_params, params)

      granted_scopes = astrenv(:oauth2_scope_callback).(requested_scopes, ctx)

      ctx = Map.put(ctx, :granted_scopes, granted_scopes)

      maybe_refresh_token =
        if astrenv(:oauth2_issue_refresh_token_callback).(ctx) do
          {:ok, refresh_token} = # FIXME: handle {:error, reason} failure case?
            RefreshToken.gen_new()
            |> RefreshToken.put_value("iat", now())
            |> RefreshToken.put_value("exp",
                now() + astrenv(:oauth2_refresh_token_lifetime_callback).(ctx))
            |> RefreshToken.put_value("client_id", client.id)
            |> RefreshToken.put_value("sub", subject.id)
            |> RefreshToken.put_value("scope", Scope.Set.to_list(granted_scopes))
            |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "ropc")
            |> RefreshToken.put_value("iss", OAuth2.issuer())
            |> RefreshToken.store(ctx)

          refresh_token
        else
          nil
        end

      access_token =
        if maybe_refresh_token do
          new_access_token(ctx, refresh_token: maybe_refresh_token.id)
        else
          new_access_token(ctx)
        end
        |> AccessToken.put_value("iat", now())
        |> AccessToken.put_value("exp",
            now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))
        |> AccessToken.put_value("client_id", client.id)
        |> AccessToken.put_value("sub", subject.id)
        |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))
        |> AccessToken.put_value("iss", OAuth2.issuer())

      # FIXME: handle failure case?
      {:ok, access_token} = AccessToken.store(access_token, ctx)

      resp =
        %{
          "access_token" => AccessToken.serialize(access_token),
          "expires_in" => access_token.data["exp"] - now(),
          "token_type" => "bearer"
        }
        |> maybe_put_refresh_token(maybe_refresh_token)
        |> put_scope_if_changed(requested_scopes, granted_scopes)
        |> astrenv(:oauth2_endpoint_token_grant_type_password_before_send_resp_callback).(ctx)

      conn
      |> put_status(200)
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")
      |> astrenv(:oauth2_endpoint_token_grant_type_password_before_send_conn_callback).(ctx)
      |> json(resp)
    else
      {:error, %OAuth2.Client.AuthenticationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Client.AuthorizationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Request.MalformedParamError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.UnsupportedGrantTypeError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %AttributeRepository.Read.NotFoundError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, OAuth2.InvalidGrantError.exception(
          grant: "password",
          reason: "incorrect username or password",
          debug_details: Exception.message(e)
        ))

      {:error, %OAuth2.InvalidGrantError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Scope.UnknownRequestedScopeError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)
    end
  end

  def handle(conn, %{"grant_type" => "password"}) do
    AsteroidWeb.Error.respond_api(conn, OAuth2.Request.InvalidRequestError.exception(
      reason: "Missing `username` or `password` parameter"))
  end

  def handle(conn, %{"grant_type" => "client_credentials"} = params) do
    scope_param = conn.body_params["scope"]

    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:client_credentials),
         {:ok, client} <- OAuth2.Client.get_authenticated_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "client_credentials"),
         {:ok, requested_scopes} <- get_scope(scope_param),
         :ok <- OAuth2.Scope.scopes_enabled?(requested_scopes, :client_credentials),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes)
    do
      ctx =
        %{}
        |> Map.put(:endpoint, :token)
        |> Map.put(:flow, :client_credentials)
        |> Map.put(:grant_type, :client_credentials)
        |> Map.put(:requested_scopes, requested_scopes)
        |> Map.put(:client, client)
        |> Map.put(:body_params, params)

      granted_scopes = astrenv(:oauth2_scope_callback).(requested_scopes, ctx)

      ctx = Map.put(ctx, :granted_scopes, granted_scopes)

      maybe_refresh_token =
        if astrenv(:oauth2_issue_refresh_token_callback).(ctx) do
          {:ok, refresh_token} = # FIXME: handle {:error, reason} failure case?
            RefreshToken.gen_new()
            |> RefreshToken.put_value("iat", now())
            |> RefreshToken.put_value("exp",
                now() + astrenv(:oauth2_refresh_token_lifetime_callback).(ctx))
            |> RefreshToken.put_value("client_id", client.id)
            |> RefreshToken.put_value("scope", Scope.Set.to_list(granted_scopes))
            |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "client_credentials")
            |> RefreshToken.put_value("iss", OAuth2.issuer())
            |> RefreshToken.store(ctx)

          refresh_token
        else
          nil
        end

      access_token =
        if maybe_refresh_token do
          new_access_token(ctx, refresh_token: maybe_refresh_token.id)
        else
          new_access_token(ctx)
        end
        |> AccessToken.put_value("iat", now())
        |> AccessToken.put_value("exp",
            now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))
        |> AccessToken.put_value("client_id", client.id)
        |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))
        |> AccessToken.put_value("iss", OAuth2.issuer())

        # FIXME: handle failure case?
      {:ok, access_token} = AccessToken.store(access_token, ctx)

      resp =
        %{
          "access_token" => AccessToken.serialize(access_token),
          "expires_in" => access_token.data["exp"] - now(),
          "token_type" => "bearer"
        }
        |> maybe_put_refresh_token(maybe_refresh_token)
        |> put_scope_if_changed(requested_scopes, granted_scopes)
        |> astrenv(:oauth2_endpoint_token_grant_type_client_credentials_before_send_resp_callback).(ctx)

      conn
      |> put_status(200)
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")
      |> astrenv(:oauth2_endpoint_token_grant_type_client_credentials_before_send_conn_callback).(ctx)
      |> json(resp)
    else
      {:error, %OAuth2.Client.AuthenticationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Client.AuthorizationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Request.MalformedParamError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.UnsupportedGrantTypeError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Scope.UnknownRequestedScopeError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)
    end
  end

  def handle(conn,
             %{"grant_type" => "refresh_token",
               "refresh_token" => refresh_token_param} = params)
  when refresh_token_param != nil do
    scope_param = conn.body_params["scope"]

    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:refresh_token),
         :ok <- valid_refresh_token_param?(refresh_token_param),
         {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "refresh_token"),
         {:ok, requested_scopes} <- get_scope(scope_param),
         # we let this check in case of dynamic change of the client's configuration
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes),
         {:ok, refresh_token} <- RefreshToken.get(refresh_token_param),
         :ok <- refresh_token_granted_to_client?(refresh_token, client)
    do
      if Scope.Set.subset?(requested_scopes,
                           Scope.Set.new(refresh_token.data["scope"] || [])) do
        maybe_subject =
          case Subject.load_from_unique_attribute("sub",
                                                  refresh_token.data["sub"],
                                                  attributes: ["sub"])
          do
            {:ok, subject} ->
              subject

            _ ->
              nil
          end

        maybe_initial_flow =
          if refresh_token.data["__asteroid_oauth2_initial_flow"] do
            OAuth2.to_flow(refresh_token.data["__asteroid_oauth2_initial_flow"])
          else
            nil
          end

        granted_scopes =
          if Scope.Set.size(requested_scopes) == 0 do
            Scope.Set.new(refresh_token.data["scope"] || [])
          else
            requested_scopes
          end

        ctx =
          %{}
          |> Map.put(:endpoint, :token)
          |> put_if_not_nil(:flow, maybe_initial_flow)
          |> Map.put(:grant_type, :refresh_token)
          |> Map.put(:requested_scopes, requested_scopes)
          |> Map.put(:granted_scopes, granted_scopes)
          |> put_if_not_nil(:subject, maybe_subject)
          |> Map.put(:client, client)
          |> put_if_not_nil(:scope, requested_scopes)
          |> Map.put(:body_params, params)

        maybe_new_refresh_token =
          if astrenv(:oauth2_issue_refresh_token_callback).(ctx) do
            :ok = RefreshToken.delete(refresh_token)
            #
            # FIXME: handle {:error, reason} failure case?
            {:ok, new_refresh_token} =
              Enum.reduce(
                refresh_token.data,
                RefreshToken.gen_new(),
                fn
                  {key, value}, acc ->
                    RefreshToken.put_value(acc, key, value)
                end
              )
              |> RefreshToken.put_value("iat", now())
              |> RefreshToken.put_value("exp",
                  now() + astrenv(:oauth2_refresh_token_lifetime_callback).(ctx))
              |> RefreshToken.store(ctx)

            new_refresh_token
          else
            nil
          end

        access_token =
          if maybe_new_refresh_token do
            new_access_token(ctx, refresh_token: maybe_new_refresh_token.id)
          else
            new_access_token(ctx, refresh_token: refresh_token.id)
          end
          |> AccessToken.put_value("iat", now())
          |> AccessToken.put_value("exp",
                                   now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))
          |> AccessToken.put_value("client_id", client.id)
          |> AccessToken.put_value("sub", (if maybe_subject, do: maybe_subject.attrs["sub"]))
          |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))
          |> AccessToken.put_value("iss", OAuth2.issuer())

        {:ok, access_token} = AccessToken.store(access_token, ctx)

        access_token_serialized = AccessToken.serialize(access_token)

        maybe_auth_session =
          if refresh_token.data["__asteroid_oidc_authenticated_session_id"] do
            case AuthenticatedSession.get(
              refresh_token.data["__asteroid_oidc_authenticated_session_id"])
            do
              {:ok, authenticated_session} ->
                authenticated_session

              _ ->
                nil
            end
          end

        maybe_id_token_serialized =
          if maybe_initial_flow in [:oidc_authorization_code, :oidc_hybrid] and
            astrenv(:oidc_issue_id_token_on_refresh_callback).(ctx)
          do
            %IDToken{
              iss: OAuth2.issuer(),
              sub: maybe_subject.attrs["sub"], # should be nil, crashes if so
              aud: refresh_token.data["client_id"],
              exp: now() + astrenv(:oidc_id_token_lifetime_callback).(ctx),
              iat: now(),
              auth_time: nil, # FIXME
              nonce: nil,
              acr: (if maybe_auth_session, do: maybe_auth_session.data["current_acr"]),
              amr: nil, #FIXME
              azp: nil,
              client: client
            }
            |> astrenv(:token_id_token_before_serialize_callback).(ctx)
            |> IDToken.serialize()
          else
            nil
          end

        resp =
          %{
            "access_token" => access_token_serialized,
            "expires_in" => access_token.data["exp"] - now(),
            "token_type" => "bearer"
          }
          |> maybe_put_refresh_token(maybe_new_refresh_token)
          |> put_if_not_nil("id_token", maybe_id_token_serialized)
          |> put_scope_if_changed(requested_scopes, granted_scopes)
          |> astrenv(:oauth2_endpoint_token_grant_type_refresh_token_before_send_resp_callback).(ctx)


        conn
        |> put_status(200)
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_header("pragma", "no-cache")
        |> astrenv(:oauth2_endpoint_token_grant_type_refresh_token_before_send_conn_callback).(ctx)
        |> json(resp)
      else
        AsteroidWeb.Error.respond_api(conn, ExceedingScopeError.exception(
          requested_scopes: requested_scopes,
          granted_scopes: Scope.Set.new(refresh_token.data["scope"] || [])))
      end
    else
      {:error, %OAuth2.Client.AuthenticationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Client.AuthorizationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Request.MalformedParamError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.UnsupportedGrantTypeError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.InvalidGrantError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %Token.InvalidTokenError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, OAuth2.InvalidGrantError.exception(
          grant: "authorization code",
          reason: "invalid refresh token",
          debug_details: Exception.message(e)))
    end
  end

  def handle(conn, %{"grant_type" => "refresh_token"})
  do
    AsteroidWeb.Error.respond_api(conn, OAuth2.Request.InvalidRequestError.exception(
      reason: "Missing `refresh_token` parameter"))
  end

  # authorization code

  def handle(conn, %{"grant_type" => "authorization_code",
                     "code" => code,
                     "redirect_uri" => redirect_uri} = params)
  do
    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:authorization_code),
         {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "authorization_code"),
         {:ok, authz_code} <- AuthorizationCode.get(code),
         :ok <- authorization_code_granted_to_client?(authz_code, client),
         :ok <- redirect_uris_match?(authz_code, redirect_uri),
         :ok <- pkce_code_verifier_valid?(authz_code, params["code_verifier"]),
         {:ok, subject} <- Subject.load_from_unique_attribute("sub", authz_code.data["sub"])
    do
      client = Client.fetch_attributes(client, ["client_id"])

      requested_scopes = Scope.Set.new(authz_code.data["requested_scopes"] || [])
      granted_scopes = Scope.Set.new(authz_code.data["granted_scopes"] || [])

      flow = OAuth2.to_flow(authz_code.data["__asteroid_oauth2_initial_flow"])

      ctx =
        %{}
        |> Map.put(:endpoint, :token)
        |> Map.put(:flow, flow)
        |> Map.put(:grant_type, :authorization_code)
        |> Map.put(:requested_scopes, requested_scopes)
        |> Map.put(:granted_scopes, granted_scopes)
        |> Map.put(:subject, subject)
        |> Map.put(:client, client)
        |> Map.put(:body_params, params)

      maybe_refresh_token =
        if astrenv(:oauth2_issue_refresh_token_callback).(ctx) do
          {:ok, refresh_token} =
            Enum.reduce(
              authz_code.data,
              RefreshToken.gen_new(),
              fn
              #FIXME: determine how to know which fields to copy, and rewrite more elegantly
                {"redirect_uri", _v}, acc ->
                  acc

                {"requested_scopes", _v}, acc ->
                  acc

                {"granted_scopes", _v}, acc ->
                  acc

                {"__asteroid_oidc_authenticated_session_id" = k, v}, acc ->
                  RefreshToken.put_value(acc, k, v)

                {"__asteroid_oauth2_initial_flow" = k, v}, acc ->
                  RefreshToken.put_value(acc, k, v)

                {"__asteroid" <> _, _v}, acc ->
                  acc

                {k, v}, acc ->
                  RefreshToken.put_value(acc, k, v)
              end
            )
            |> RefreshToken.put_value("iat", now())
            |> RefreshToken.put_value("exp",
                now() + astrenv(:oauth2_refresh_token_lifetime_callback).(ctx))
            |> RefreshToken.put_value("scope", Scope.Set.to_list(granted_scopes))
            |> RefreshToken.store(ctx)

          refresh_token
        else
          nil
        end

      access_token =
        Enum.reduce(
          authz_code.data,
          if maybe_refresh_token do
            new_access_token(ctx, refresh_token: maybe_refresh_token.id)
          else
            new_access_token(ctx)
          end,
          fn
          #FIXME: determine how to know which fields to copy, and rewrite more elegantly
            {"redirect_uri", _v}, acc ->
              acc

            {"requested_scopes", _v}, acc ->
              acc

            {"granted_scopes", _v}, acc ->
              acc

            {"__asteroid_oauth2_initial_flow" = k, v}, acc ->
              AccessToken.put_value(acc, k, v)

            {"__asteroid" <> _, _v}, acc ->
              acc

            {k, v}, acc ->
              AccessToken.put_value(acc, k, v)
          end
        )
        |> AccessToken.put_value("iat", now())
        |> AccessToken.put_value("exp",
            now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))
        |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))

      # FIXME: handle failure case?
      {:ok, access_token} = AccessToken.store(access_token, ctx)

      access_token_serialized = AccessToken.serialize(access_token)

      maybe_auth_session =
        if authz_code.data["__asteroid_oidc_authenticated_session_id"] do
          case AuthenticatedSession.get(
            authz_code.data["__asteroid_oidc_authenticated_session_id"])
          do
            {:ok, authenticated_session} ->
              authenticated_session

            _ ->
              nil
          end
        end

      maybe_id_token_serialized =
        if flow in [:oidc_authorization_code, :oidc_hybrid] do
          %IDToken{
            iss: OAuth2.issuer(),
            sub: authz_code.data["sub"],
            aud: client.attrs["client_id"],
            exp: now() + astrenv(:oidc_id_token_lifetime_callback).(ctx),
            iat: now(),
            auth_time: nil, # FIXME
            nonce: authz_code.data["__asteroid_oidc_nonce"],
            acr: (if maybe_auth_session, do: maybe_auth_session.data["current_acr"]),
            amr: nil, #FIXME
            azp: nil,
            client: client,
            associated_access_token_serialized:
              if flow == :oidc_authorization_code do
                access_token_serialized
              end
          }
          |> astrenv(:token_id_token_before_serialize_callback).(ctx)
          |> IDToken.serialize()
        else
          nil
        end

      resp =
        %{
          "access_token" => access_token_serialized,
          "expires_in" => access_token.data["exp"] - now(),
          "token_type" => "bearer"
        }
        |> maybe_put_refresh_token(maybe_refresh_token)
        |> put_if_not_nil("id_token", maybe_id_token_serialized)
        |> put_scope_if_changed(requested_scopes, granted_scopes)
        |> astrenv(:oauth2_endpoint_token_grant_type_authorization_code_before_send_resp_callback).(ctx)

      conn
      |> put_status(200)
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")
      |> astrenv(:oauth2_endpoint_token_grant_type_authorization_code_before_send_conn_callback).(ctx)
      |> json(resp)
    else
      {:error, %OAuth2.Client.AuthenticationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %Asteroid.OAuth2.Client.AuthorizationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %Asteroid.OAuth2.Request.InvalidRequestError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.UnsupportedGrantTypeError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.InvalidGrantError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %Token.InvalidTokenError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, OAuth2.InvalidGrantError.exception(
          grant: "authorization code",
          reason: "invalid authorization code",
          debug_details: Exception.message(e)))

      {:error, e} ->
        AsteroidWeb.Error.respond_api(conn, OAuth2.ServerError.exception(
          reason: Exception.message(e)))
    end
  end

  def handle(conn, %{"grant_type" => "authorization_code"}) do
    AsteroidWeb.Error.respond_api(conn, OAuth2.Request.InvalidRequestError.exception(
      reason: "Missing a mandatory parameter"))
  end

  # device code

  def handle(conn,
             %{"grant_type" => "urn:ietf:params:oauth:grant-type:device_code",
               "device_code" => device_code_param} = params)
  do
    with :ok <- OAuth2.DeviceAuthorization.rate_limited?(device_code_param),
         :ok <-
           Asteroid.OAuth2.grant_type_enabled?(:"urn:ietf:params:oauth:grant-type:device_code"),
         {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "urn:ietf:params:oauth:grant-type:device_code"),
         {:ok, device_code} <- DeviceCode.get(device_code_param),
         :ok <- device_code_granted_to_client?(device_code, client),
         :ok <- device_code_access_granted?(device_code),
         {:ok, subject} <- Subject.load_from_unique_attribute("sub", device_code.data["sjid"])
    do
      DeviceCode.delete(device_code)

      client = Client.fetch_attributes(client, ["client_id"])
      subject = Subject.fetch_attributes(subject, ["sub"])

      requested_scopes = Scope.Set.new(device_code.data["requested_scopes"] || [])
      granted_scopes = Scope.Set.new(device_code.data["granted_scopes"] || [])

      ctx =
        %{}
        |> Map.put(:endpoint, :token)
        |> Map.put(:flow, :device_authorization)
        |> Map.put(:grant_type, :"urn:ietf:params:oauth:grant-type:device_code")
        |> Map.put(:granted_scopes, granted_scopes)
        |> Map.put(:subject, subject)
        |> Map.put(:client, client)
        |> Map.put(:body_params, params)

      maybe_refresh_token =
        if astrenv(:oauth2_issue_refresh_token_callback).(ctx) do
          {:ok, refresh_token} = # FIXME: handle {:error, reason} failure case?
            RefreshToken.gen_new()
            |> RefreshToken.put_value("iat", now())
            |> RefreshToken.put_value("exp",
                now() + astrenv(:oauth2_refresh_token_lifetime_callback).(ctx))
            |> RefreshToken.put_value("client_id", client.attrs["client_id"])
            |> RefreshToken.put_value("sub", subject.attrs["sub"])
            |> RefreshToken.put_value("scope", Scope.Set.to_list(granted_scopes))
            |> RefreshToken.put_value("__asteroid_oauth2_initial_flow", "device_authorization")
            |> RefreshToken.put_value("iss", OAuth2.issuer())
            |> RefreshToken.store(ctx)

          refresh_token
        else
          nil
        end

      {:ok, access_token} =
        if maybe_refresh_token do
          new_access_token(ctx, refresh_token: maybe_refresh_token.id)
        else
          new_access_token(ctx)
        end
        |> AccessToken.put_value("iat", now())
        |> AccessToken.put_value("exp",
            now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))
        |> AccessToken.put_value("client_id", client.attrs["client_id"])
        |> AccessToken.put_value("sub", subject.attrs["sub"])
        |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))
        |> AccessToken.put_value("iss", OAuth2.issuer())
        |> AccessToken.store(ctx)

        resp =
          %{
            "access_token" => AccessToken.serialize(access_token),
            "expires_in" => access_token.data["exp"] - now(),
            "token_type" => "bearer"
          }
          |> maybe_put_refresh_token(maybe_refresh_token)
          |> put_scope_if_changed(requested_scopes, granted_scopes)
          |> astrenv(:oauth2_endpoint_token_grant_type_device_code_before_send_resp_callback).(ctx)


        conn
        |> put_status(200)
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_header("pragma", "no-cache")
        |> astrenv(:oauth2_endpoint_token_grant_type_device_code_before_send_conn_callback).(ctx)
        |> json(resp)
    else
      {:error, %OAuth2.Client.AuthenticationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Client.AuthorizationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.UnsupportedGrantTypeError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.InvalidGrantError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %Token.InvalidTokenError{reason: "expired code"}} ->
        AsteroidWeb.Error.respond_api(conn,
                                      OAuth2.DeviceAuthorization.ExpiredTokenError.exception([]))

      {:error, %Token.InvalidTokenError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, OAuth2.InvalidGrantError.exception(
          grant: "device code",
          reason: "invalid device code",
          debug_details: Exception.message(e)))

      {:error, %OAuth2.DeviceAuthorization.AuthorizationPendingError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.DeviceAuthorization.RateLimitedError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.AccessDeniedError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %AttributeRepository.Read.NotFoundError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, OAuth2.ServerError.exception(
          reason: "could not read object in attribute repository: #{Exception.message(e)}"))
    end
  end

  def handle(conn, %{"grant_type" => "urn:ietf:params:oauth:grant-type:device_code"})
  do
    AsteroidWeb.Error.respond_api(conn, OAuth2.Request.InvalidRequestError.exception(
      reason: "Missing `device_code` parameter"))
  end

  def handle(conn, %{"grant_type" => grant_type}) do
    AsteroidWeb.Error.respond_api(conn, OAuth2.UnsupportedGrantTypeError.exception(
      grant_type: grant_type))
  end

  def handle(conn, _params) do
    AsteroidWeb.Error.respond_api(conn, OAuth2.Request.InvalidRequestError.exception(
      reason: "Missing `grant_type` parameter"))
  end

  @spec get_scope(String.t() | nil) :: {:ok, Scope.Set.t()} | {:error, Exception.t()}

  def get_scope(nil), do: {:ok, Scope.Set.new()}

  def get_scope(scope_param) do
    if Scope.oauth2_scope_param?(scope_param) do
      {:ok, Scope.Set.from_scope_param!(scope_param)}
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "scope",
                                                            value: scope_param)}
    end
  end

  @spec refresh_token_granted_to_client?(RefreshToken.t(), Client.t()) ::
  :ok
  | {:error, %OAuth2.InvalidGrantError{}}

  def refresh_token_granted_to_client?(refresh_token, client) do
    if refresh_token.data["client_id"] == client.id do
      :ok
    else
      {:error, OAuth2.InvalidGrantError.exception(
        grant: "authorization_code",
        reason: "invalid authorization code",
        debug_details: "request and authorization code client ids do not match")}
    end
  end

  @spec device_code_granted_to_client?(DeviceCode.t(), Client.t()) ::
  :ok
  | {:error, %OAuth2.InvalidGrantError{}}

  def device_code_granted_to_client?(device_code, client) do
    if device_code.data["clid"] == client.id do
      :ok
    else
      {:error, OAuth2.InvalidGrantError.exception(
        grant: "device_code",
        reason: "invalid device code",
        debug_details: "device code does not match client id of the request")}
    end
  end

  @spec device_code_access_granted?(DeviceCode.t()) :: :ok | {:error, Exception.t()}

  defp device_code_access_granted?(device_code) do
    case device_code.data["status"] do
      "granted" ->
        :ok

      "authorization_pending" ->
        {:error, OAuth2.DeviceAuthorization.AuthorizationPendingError.exception([])}

      "denied" ->
        {:error, OAuth2.AccessDeniedError.exception(reason: "access denied by the user")}
    end
  end

  @spec authorization_code_granted_to_client?(AuthorizationCode.t(), Client.t()) ::
  :ok
  | {:error, %OAuth2.InvalidGrantError{}}

  def authorization_code_granted_to_client?(authz_code, client) do
    if authz_code.data["client_id"] == client.id do
      :ok
    else
      {:error, OAuth2.InvalidGrantError.exception(
        grant: "authorization_code",
        reason: "invalid authorization code",
        debug_details: "request and authorization code client ids do not match")}
    end
  end

  @spec redirect_uris_match?(AuthorizationCode.t(), OAuth2.RedirectUri.t()) ::
  :ok
  | {:error, %OAuth2.InvalidGrantError{}}

  defp redirect_uris_match?(authz_code, redirect_uri) do
    if authz_code.data["redirect_uri"] == redirect_uri do
      :ok
    else
      {:error, OAuth2.InvalidGrantError.exception(
        grant: "authorization_code",
        reason: "invalid authorization code",
        debug_details: "request and authorization code redirect uris do not match"
      )}
    end
  end

  @spec maybe_put_refresh_token(map(), RefreshToken.t()) :: map()

  defp maybe_put_refresh_token(map, %RefreshToken{} = refresh_token) do
    Map.put(map, "refresh_token", RefreshToken.serialize(refresh_token))
  end

  defp maybe_put_refresh_token(map, nil) do
    map
  end

  @spec put_scope_if_changed(map(), Scope.Set.t(), Scope.Set.t()) :: map()

  defp put_scope_if_changed(m, requested_scopes, granted_scopes) do
    if Scope.Set.equal?(requested_scopes, granted_scopes) do
      m
    else
      Map.put(m, "scope", Enum.join(granted_scopes, " "))
    end
  end

  @spec valid_username_param?(String.t()) :: :ok | {:error, %OAuth2.Request.MalformedParamError{}}

  defp valid_username_param?(username) do
    if OAuth2Utils.valid_username_param?(username) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "username",
                                                            value: username)}
    end
  end

  @spec valid_password_param?(String.t()) :: :ok | {:error, %OAuth2.Request.MalformedParamError{}}

  defp valid_password_param?(password) do
    if OAuth2Utils.valid_password_param?(password) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "password", value: "[HIDDEN]")}
    end
  end

  @spec valid_refresh_token_param?(String.t()) ::
  :ok
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp valid_refresh_token_param?(refresh_token) do
    if OAuth2Utils.valid_refresh_token_param?(refresh_token) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "refresh_token",
                                                            value: "[HIDDEN]")}
    end
  end

  @spec pkce_code_verifier_valid?(AuthorizationCode.t(), OAuth2.PKCE.code_verifier() | nil) ::
  :ok
  | {:error, Exception.t()}

  defp pkce_code_verifier_valid?(authorization_code, code_verifier) do
    case {authorization_code.data["__asteroid_oauth2_pkce_code_challenge"], code_verifier} do
      {nil, _} ->
        :ok

      {_, nil} ->
        {:error,
          OAuth2.Request.InvalidRequestError.exception(reason: "Missing PKCE code verifier")}

      {code_challenge, code_verifier} ->
        code_challenge_method =
          authorization_code.data["__asteroid_oauth2_pkce_code_challenge_method"]
          |> OAuth2.PKCE.code_challenge_method_from_string()

        OAuth2.PKCE.verify_code_verifier(code_verifier, code_challenge, code_challenge_method)
    end
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
end
