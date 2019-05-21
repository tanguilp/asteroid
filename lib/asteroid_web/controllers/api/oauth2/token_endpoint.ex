defmodule AsteroidWeb.API.OAuth2.TokenEndpoint do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.Token.{RefreshToken, AccessToken, AuthorizationCode}
  alias Asteroid.{Client, Subject}
  alias Asteroid.OAuth2

  # OAuth2 ROPC flow (resource owner password credentials)
  # https://tools.ietf.org/html/rfc6749#section-4.3.2
  #
  def handle(%Plug.Conn{body_params:
    %{"grant_type" => "password",
      "username" => username,
      "password" => password,
    }} = conn, _params)
  when username != nil and password != nil do
    scope_param = conn.body_params["scope"]

    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:password),
         :ok <- valid_username_param?(username),
         :ok <- valid_password_param?(password),
         {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "password"),
         {:ok, requested_scopes} <- get_scope(scope_param),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes),
         {:ok, subject} <-
           astrenv(:oauth2_ropc_username_password_verify_callback).(conn, username, password)
    do
      ctx =
        %{}
        |> Map.put(:endpoint, :token)
        |> Map.put(:flow, :ropc)
        |> Map.put(:grant_type, :password)
        |> Map.put(:requested_scopes, requested_scopes)
        |> Map.put(:subject, subject)
        |> Map.put(:client, client)

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
          AccessToken.gen_new(refresh_token: maybe_refresh_token.id)
        else
          AccessToken.gen_new()
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
      {:error, %Asteroid.OAuth2.Client.AuthenticationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, %Asteroid.OAuth2.Client.AuthorizationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, %Asteroid.OAuth2.Client.UnauthorizedScopeError{} = e} ->
        error_resp(conn, error: :invalid_scope, error_description: Exception.message(e))

      {:error, %Asteroid.OAuth2.Request.MalformedParamError{} = error} ->
        OAuth2.Request.error_response(conn, error)

      {:error, :grant_type_disabled} ->
        error_resp(conn, error: :unsupported_grant_type,
                   error_description: "Grant type password not enabled")

      {:error, :grant_type_not_authorized_for_client} ->
        error_resp(conn, error: :unauthorized_client,
                   error_description: "Client is not authorized to use this grant type")

      {:error, :malformed} ->
        error_resp(conn, error: :invalid_scope,
                   error_description: "Scope param is malformed")

      {:error, %AttributeRepository.Read.NotFoundError{}} ->
        error_resp(conn, error: :invalid_grant,
                    error_description: "Incorrect username or password")

      {:error, :invalid_username_or_password} ->
        error_resp(conn, error: :invalid_grant,
                    error_description: "Incorrect username or password")
    end
  end

  def handle(%Plug.Conn{body_params: %{"grant_type" => "password"}} = conn, _params) do
    error_resp(conn,
                   error: "invalid_request",
                   error_description: "Missing `username` or `password` parameter")
  end

  def handle(%Plug.Conn{body_params: %{"grant_type" => "client_credentials"}} = conn, _params) do
    scope_param = conn.body_params["scope"]

    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:client_credentials),
         {:ok, client} <- OAuth2.Client.get_authenticated_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "client_credentials"),
         {:ok, requested_scopes} <- get_scope(scope_param),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes)
    do
      ctx =
        %{}
        |> Map.put(:endpoint, :token)
        |> Map.put(:flow, :client_credentials)
        |> Map.put(:grant_type, :client_credentials)
        |> Map.put(:requested_scopes, requested_scopes)
        |> Map.put(:client, client)

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
          AccessToken.gen_new(refresh_token: maybe_refresh_token.id)
        else
          AccessToken.gen_new()
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
      {:error, %Asteroid.OAuth2.Client.AuthenticationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, %Asteroid.OAuth2.Client.AuthorizationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, %Asteroid.OAuth2.Client.UnauthorizedScopeError{} = e} ->
        error_resp(conn, error: :invalid_scope, error_description: Exception.message(e))

      {:error, %Asteroid.OAuth2.Request.MalformedParamError{} = error} ->
        OAuth2.Request.error_response(conn, error)

      {:error, :grant_type_disabled} ->
        error_resp(conn, error: :unsupported_grant_type,
                   error_description: "Grant type password not enabled")

      {:error, :grant_type_not_authorized_for_client} ->
        error_resp(conn, error: :unauthorized_client,
                   error_description: "Client is not authorized to use this grant type")

      {:error, :malformed} ->
        error_resp(conn, error: :invalid_scope,
                   error_description: "Scope param is malformed")
    end
  end

  def handle(%Plug.Conn{body_params:
    %{"grant_type" => "refresh_token",
      "refresh_token" => refresh_token_param,
    }} = conn, _params)
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
          case Subject.load(refresh_token.data["sub"]) do
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

        ctx =
          %{}
          |> Map.put(:endpoint, :token)
          |> put_if_not_nil(:flow, maybe_initial_flow)
          |> Map.put(:grant_type, :refresh_token)
          |> Map.put(:requested_scopes, requested_scopes)
          |> put_if_not_nil(:subject, maybe_subject)
          |> Map.put(:client, client)
          |> put_if_not_nil(:scope, requested_scopes)

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

        granted_scopes =
          if Scope.Set.size(requested_scopes) == 0 do
            Scope.Set.new(refresh_token.data["scope"] || [])
          else
            requested_scopes
          end

        access_token =
          if maybe_new_refresh_token do
            AccessToken.gen_new(refresh_token: maybe_new_refresh_token.id)
          else
            AccessToken.gen_new(refresh_token: refresh_token.id)
          end
          |> AccessToken.put_value("iat", now())
          |> AccessToken.put_value("exp",
                                   now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))
          |> AccessToken.put_value("client_id", client.id)
          |> AccessToken.put_value("sub", (if maybe_subject, do: maybe_subject.id, else: nil))
          |> AccessToken.put_value("scope", Scope.Set.to_list(granted_scopes))
          |> AccessToken.put_value("iss", OAuth2.issuer())

        AccessToken.store(access_token, ctx)

        resp =
          %{
            "access_token" => AccessToken.serialize(access_token),
            "expires_in" => access_token.data["exp"] - now(),
            "token_type" => "bearer"
          }
          |> maybe_put_refresh_token(maybe_new_refresh_token)
          |> put_scope_if_changed(requested_scopes, granted_scopes)
          |> astrenv(:oauth2_endpoint_token_grant_type_refresh_token_before_send_resp_callback).(ctx)


        conn
        |> put_status(200)
        |> put_resp_header("cache-control", "no-store")
        |> put_resp_header("pragma", "no-cache")
        |> astrenv(:oauth2_endpoint_token_grant_type_refresh_token_before_send_conn_callback).(ctx)
        |> json(resp)
      else
        error_resp(conn,
                   error: "invalid_scope",
                   error_description: "Requested scopes exceed scope granted to the refresh token"
        )
      end
    else
      {:error, %OAuth2.Client.AuthenticationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, %OAuth2.Request.MalformedParamError{} = error} ->
        OAuth2.Request.error_response(conn, error)

      {:error, %Asteroid.OAuth2.Client.UnauthorizedScopeError{} = e} ->
        error_resp(conn, error: :invalid_scope, error_description: Exception.message(e))

      {:error, :grant_type_disabled} ->
        error_resp(conn, error: :unsupported_grant_type,
                   error_description: "Grant type refresh token not enabled")

      {:error, :grant_type_not_authorized_for_client} ->
        error_resp(conn, error: :unauthorized_client,
                   error_description: "Client is not authorized to use this grant type")

      {:error, :malformed} ->
        error_resp(conn, error: :invalid_scope,
                   error_description: "Scope param is malformed")

      {:error, reason} when reason in [
        :inactive_refresh_token,
        :client_id_no_match,
        :nonexistent_refresh_token] ->
        error_resp(conn, error: :invalid_grant,
                    error_description: "Invalid refresh token")

      {:error, reason} ->
        error_resp(conn, error: :server_error,
                    error_description: "#{inspect reason}")
    end
  end

  def handle(%Plug.Conn{body_params: %{"grant_type" => "refresh_token"}} = conn, _params)
  do
    error_resp(conn,
               error: "invalid_request",
               error_description: "Missing `refresh_token` parameter")
  end

  # authorization code

  def handle(%Plug.Conn{body_params:
    %{"grant_type" => "authorization_code",
      "code" => code,
      "redirect_uri" => redirect_uri
    }} = conn, _params)
  do
    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:authorization_code),
         {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "authorization_code"),
         {:ok, authz_code} <- AuthorizationCode.get(code),
         :ok <- authorization_code_granted_to_client?(authz_code, client),
         :ok <- redirect_uris_match?(authz_code, redirect_uri),
         {:ok, subject} <- Subject.load(authz_code.data["sub"])
    do
      ctx =
        %{}
        |> Map.put(:endpoint, :token)
        |> Map.put(:flow, :authorization_code)
        |> Map.put(:grant_type, :authorization_code)
        |> Map.put(:granted_scopes, Scope.Set.new(authz_code.data["scope"] || []))
        |> Map.put(:subject, subject)
        |> Map.put(:client, client)

      maybe_refresh_token =
        if astrenv(:oauth2_issue_refresh_token_callback).(ctx) do
          {:ok, refresh_token} =
            Enum.reduce(
              authz_code.data,
              RefreshToken.gen_new(),
              fn
                {k, v}, acc ->
                  RefreshToken.put_value(acc, k, v)
              end
            )
            |> RefreshToken.put_value("iat", now())
            |> RefreshToken.put_value("exp",
                now() + astrenv(:oauth2_refresh_token_lifetime_callback).(ctx))
            |> RefreshToken.store(ctx)

          refresh_token
        else
          nil
        end

      access_token =
        Enum.reduce(
          authz_code.data,
          if maybe_refresh_token do
            AccessToken.gen_new(refresh_token: maybe_refresh_token.id)
          else
            AccessToken.gen_new()
          end,
          fn
            {k, v}, acc ->
              AccessToken.put_value(acc, k, v)
          end
        )
        |> AccessToken.put_value("iat", now())
        |> AccessToken.put_value("exp",
            now() + astrenv(:oauth2_access_token_lifetime_callback).(ctx))

      # FIXME: handle failure case?
      {:ok, access_token} = AccessToken.store(access_token, ctx)

      resp =
        %{
          "access_token" => AccessToken.serialize(access_token),
          "expires_in" => access_token.data["exp"] - now(),
          "token_type" => "bearer"
        }
        |> maybe_put_refresh_token(maybe_refresh_token)
        |> astrenv(:oauth2_endpoint_token_grant_type_authorization_code_before_send_resp_callback).(ctx)

      conn
      |> put_status(200)
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")
      |> astrenv(:oauth2_endpoint_token_grant_type_authorization_code_before_send_conn_callback).(ctx)
      |> json(resp)
    else
      {:error, %OAuth2.Client.AuthenticationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, %Asteroid.OAuth2.Client.AuthorizationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, :grant_type_disabled} ->
        error_resp(conn, error: :unsupported_grant_type,
                   error_description: "Grant type authorization code not enabled")

      {:error, :inactive_authorization_code} ->
        error_resp(conn, error: :invalid_grant,  error_description: "Invalid authorization code")

      {:error, :nonexistent_authorization_code} ->
        error_resp(conn, error: :invalid_grant,  error_description: "Invalid authorization code")

      {:error, :client_id_no_match} ->
        error_resp(conn, error: :invalid_grant,  error_description: "Invalid authorization code")

      {:error, :redirect_uri_no_match} ->
        error_resp(conn, error: :invalid_grant,  error_description: "Invalid redirect uri")

      {:error, reason} ->
        error_resp(conn, error: :server_error, error_description: inspect(reason))
    end
  end

  def handle(%Plug.Conn{body_params: %{"grant_type" => "authorization_code"}} = conn, _params) do
    error_resp(conn,
               error: "invalid_request",
               error_description: "Missing a mandatory parameter")
  end
  # unrecognized or unsupported grant

  def handle(%Plug.Conn{body_params: %{"grant_type" => grant}} = conn, _params) do
    error_resp(conn,
               error: "unsupported_grant_type",
               error_description: "Invalid grant #{grant}")
  end

  def handle(conn, _params) do
    error_resp(conn,
               error: "invalid_request",
               error_description: "Missing `grant_type` parameter"
    )
  end

  defp error_resp(conn, error_status \\ 400, error_data) do
    conn
    |> put_status(error_status)
    |> json(Enum.into(error_data, %{}))
  end

  @spec get_scope(String.t() | nil) :: {:ok, Scope.Set.t()} | {:error, Exception.t()}

  def get_scope(nil), do: {:ok, Scope.Set.new()}

  def get_scope(scope_param) do
    if Scope.oauth2_scope_param?(scope_param) do
      {:ok, Scope.Set.from_scope_param!(scope_param)}
    else
      {:error, OAuth2.Request.MalformedParamError.exception(parameter_name: "scope",
                                                            parameter_value: scope_param)}
    end
  end

  @spec refresh_token_granted_to_client?(RefreshToken.t(), Client.t()) :: :ok | {:error, any()}

  def refresh_token_granted_to_client?(refresh_token, client) do
    if refresh_token.data["client_id"] == client.id do
      :ok
    else
      {:error, :client_id_no_match}
    end
  end

  @spec authorization_code_granted_to_client?(AuthorizationCode.t(), Client.t()) ::
  :ok
  | {:error, any()}

  def authorization_code_granted_to_client?(authz_code, client) do
    if authz_code.data["client_id"] == client.id do
      :ok
    else
      {:error, :client_id_no_match}
    end
  end

  @spec redirect_uris_match?(AuthorizationCode.t(), OAuth2.RedirectUri.t()) ::
  :ok
  | {:error, :redirect_uri_no_match}

  defp redirect_uris_match?(authz_code, redirect_uri) do
    if authz_code.data["redirect_uri"] == redirect_uri do
      :ok
    else
      {:error, :redirect_uri_no_match}
    end
  end

  @spec maybe_put_refresh_token(map(), RefreshToken.t()) :: map()

  defp maybe_put_refresh_token(map, %RefreshToken{id: id}) do
    Map.put(map, "refresh_token", id)
  end

  defp maybe_put_refresh_token(map, _) do
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
      {:error, OAuth2.Request.MalformedParamError.exception(parameter_name: "username",
                                                            parameter_value: username)}
    end
  end

  @spec valid_password_param?(String.t()) :: :ok | {:error, %OAuth2.Request.MalformedParamError{}}

  defp valid_password_param?(password) do
    if OAuth2Utils.valid_password_param?(password) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(parameter_name: "password",
                                                            parameter_value: "[HIDDEN]")}
    end
  end

  @spec valid_refresh_token_param?(String.t()) ::
  :ok
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp valid_refresh_token_param?(refresh_token) do
    if OAuth2Utils.valid_refresh_token_param?(refresh_token) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(parameter_name: "refresh_token",
                                                            parameter_value: "[HIDDEN]")}
    end
  end
end
