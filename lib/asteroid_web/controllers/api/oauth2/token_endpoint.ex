defmodule AsteroidWeb.API.OAuth2.TokenEndpoint do
  use AsteroidWeb, :controller
  import Asteroid.Utils
  alias OAuth2Utils.Scope
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias Asteroid.{Client, Subject, Context}
  alias Asteroid.OAuth2

  # OAuth2 ROPC flow (resource owner password credentials)
  # https://tools.ietf.org/html/rfc6749#section-4.3.2
  def handle(%Plug.Conn{body_params:
    %{"grant_type" => "password",
      "username" => username,
      "password" => password,
    }} = conn, _params)
  when username != nil and password != nil do
    scope_param = conn.body_params["scope"]

    with :ok <- grant_type_enabled?(:password),
         {:ok, client} <- OAuth2.Client.get_client(conn, true),
         :ok <- client_grant_type_authorized?(client, :password),
         {:ok, requested_scope} <- get_scope(scope_param),
         :ok <- client_scope_authorized?(client, requested_scope),
         {:ok, subject} <-
           astrenv(:ropc_username_password_verify_callback).(conn, username, password)
    do
      ctx = %Asteroid.Context{
        request: %{
          :endpoint => :token,
          :flow => :ropc,
          :grant_type => :password,
          :scope => requested_scope
        },
        client: client,
        subject: subject,
        device: nil,
        scope: nil
      }

      scope = astrenv(:ropc_scope_callback).(requested_scope, ctx)

      ctx = %{ctx | scope: scope}

      maybe_refresh_token =
        if astrenv(:ropc_issue_refresh_token_callback).(ctx) do
          RefreshToken.new()
          |> RefreshToken.put_claim("iat", now())
          |> RefreshToken.put_claim("exp", now() + astrenv(:refresh_token_lifetime_callback).(ctx))
          |> RefreshToken.put_claim("client_id", client.id)
          |> RefreshToken.put_claim("sub", subject.id)
          |> RefreshToken.put_claim("scope", scope)
          |> RefreshToken.put_claim("context", ctx)
          |> RefreshToken.put_claim("iss", astrenv(:issuer_callback).(ctx))
          |> RefreshToken.store(ctx)
        else
          nil
        end

      access_token =
        if maybe_refresh_token do
          AccessToken.new(refresh_token: maybe_refresh_token)
        else
          AccessToken.new()
        end
        |> AccessToken.put_claim("iat", now())
        |> AccessToken.put_claim("exp", now() + astrenv(:access_token_lifetime_callback).(ctx))
        |> AccessToken.put_claim("client_id", client.id)
        |> AccessToken.put_claim("sub", subject.id)
        |> RefreshToken.put_claim("scope", scope)
        |> AccessToken.put_claim("context", ctx)
        |> AccessToken.put_claim("iss", astrenv(:issuer_callback).(ctx))

      AccessToken.store(access_token, ctx)

      resp =
        %{
          "access_token" => AccessToken.serialize(access_token),
          "expires_in" => access_token.claims["exp"] - now(),
          "token_type" => "bearer"
        }
        |> maybe_put_refresh_token(maybe_refresh_token)
        |> put_scope_if_changed(requested_scope, ctx.scope)
        |> astrenv(:ropc_before_send_resp_callback).(ctx)

      conn
      |> put_status(200)
      |> astrenv(:ropc_before_send_conn_callback).(ctx)
      |> json(resp)
    else
      {:error, %Asteroid.OAuth2.Client.AuthenticationError{} = error} ->
        OAuth2.Client.AuthenticationError.response(conn, error, nil) #FIXME: nil = ctx?

      {:error, :grant_type_disabled} ->
        error_resp(conn, error: :unsupported_grant_type,
                   error_description: "Grant type password not enabled")

      {:error, :grant_type_not_authorized_for_client} ->
        error_resp(conn, error: :unauthorized_client,
                   error_description: "Client is not authorized to use this grant type")

      {:error, :malformed} ->
        error_resp(conn, error: :invalid_scope,
                   error_description: "Scope param is malformed")

      {:error, :unauthorized_scope} ->
        error_resp(conn, error: :invalid_scope,
                    error_description: "The client has not been granted this scope")

      {:error, :invalid_password} ->
        error_resp(conn, error: :invalid_grant,
                    error_description: "Username or password is incorrect")
    end
  end

  def handle(%Plug.Conn{body_params: %{"grant_type" => "password"}} = conn, _params) do
    error_resp(conn,
                   error: "invalid_request",
                   error_description: "Missing username or password parameter")
  end

  def handle(%Plug.Conn{body_params:
    %{"grant_type" => "refresh_token",
      "refresh_token" => refresh_token_param,
    }} = conn, _params)
  when refresh_token_param != nil do
    scope_param = conn.body_params["scope"]

    with :ok <- grant_type_enabled?(:refresh_token),
         {:ok, client} <- OAuth2.Client.get_client(conn, true),
         :ok <- client_grant_type_authorized?(client, :refresh_token),
         {:ok, scope} <- get_scope(scope_param),
         :ok <- client_scope_authorized?(client, scope),
         {:ok, refresh_token} <- RefreshToken.get(refresh_token_param, check_active: true),
         :ok <- refresh_token_granted_to_client?(refresh_token, client),
         {:ok, subject} <- get_subject_from_refresh_token(refresh_token)
    do
      if Scope.Set.subset?(scope, refresh_token.claims["scope"]) do
        ctx = %Asteroid.Context{
          request: %{
            :endpoint => :token,
            :flow => refresh_token.claims["context"].request[:flow],
            :grant_type => :refresh_token,
            :scope => scope
          },
          client: client,
          subject: subject,
          device: nil
        }

        access_token =
          AccessToken.new(refresh_token: refresh_token)
          |> AccessToken.put_claim("iat", now())
          |> AccessToken.put_claim("exp", now() + astrenv(:access_token_lifetime_callback).(ctx))
          |> AccessToken.put_claim("client_id", client.id)
          |> AccessToken.put_claim("sub", subject.id)
          |> RefreshToken.put_claim("scope", scope)
          |> AccessToken.put_claim("iss", astrenv(:issuer_callback).(ctx))
          |> AccessToken.put_claim("context", ctx)

        AccessToken.store(access_token, ctx)

        resp =
          %{
            "access_token" => AccessToken.serialize(access_token),
            "expires_in" => access_token.claims["exp"] - now(),
            "token_type" => "bearer"
          }
          |> astrenv(:refresh_token_before_send_resp_callback).(ctx)

        conn
        |> put_status(200)
        |> astrenv(:refresh_token_before_send_conn_callback).(ctx)
        |> json(resp)
      else
        error_resp(conn,
                   error: "invalid_scope",
                   error_description: "Requested scopes exceed scope granted to the refresh token"
        )
      end
    else
      {:error, %Asteroid.OAuth2.Client.AuthenticationError{} = error} ->
        OAuth2.Client.AuthenticationError.response(conn, error, nil) #FIXME: nil = ctx?

      {:error, :grant_type_disabled} ->
        error_resp(conn, error: :unsupported_grant_type,
                   error_description: "Grant type password not enabled")

      {:error, :grant_type_not_authorized_for_client} ->
        error_resp(conn, error: :unauthorized_client,
                   error_description: "Client is not authorized to use this grant type")

      {:error, :malformed} ->
        error_resp(conn, error: :invalid_scope,
                   error_description: "Scope param is malformed")

      {:error, :unauthorized_scope} ->
        error_resp(conn, error: :unauthorized_scope,
                    error_description: "The client has not been granted this scope")

      {:error, reason} ->
        error_resp(conn, error: :server_error,
                    error_description: "#{inspect reason}")
    end
  end

  # unrecognized or unsupported grant

  def handle(%Plug.Conn{body_params: %{"grant_type" => grant}} = conn, _params) do
    error_resp(conn,
                   error: "invalid_grant",
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

  @spec grant_type_enabled?(Asteroid.GrantType.t()) :: :ok | {:error, :grant_type_disabled}
  defp grant_type_enabled?(_) do
    :ok
  end

  @spec client_grant_type_authorized?(Asteroid.Client.client_param(), Asteroid.GrantType.t()) ::
    :ok | {:error, :grant_type_not_authorized_for_client}
  defp  client_grant_type_authorized?(_client, _grant_type) do
    :ok
  end

  @spec get_scope(String.t() | nil)
    :: {:ok, Scope.Set.t()} | {:error, :malformed_scope_param}

  def get_scope(nil), do: {:ok, Scope.Set.new()}

  def get_scope(scope_param) do
    if Scope.oauth2_scope_param?(scope_param) do
      {:ok, Scope.Set.from_scope_param!(scope_param)}
    else
      {:error, :malformed_scope_param}
    end
  end

  @spec client_scope_authorized?(Client.t(), Scope.Set.t())
    :: :ok | {:error, :unauthorized_scope}
  def client_scope_authorized?(client, scope) do
    client = Client.fetch_attribute(client, "scope")

    if client.attrs["scope"] != nil and Scope.Set.subset?(scope, client.attrs["scope"]) do
      :ok
    else
      {:error, :unauthorized_scope}
    end
  end
    
  @spec get_subject_from_refresh_token(RefreshToken.t())
    :: {:ok, Subject.t()} | {:error, any()}

  def get_subject_from_refresh_token(%RefreshToken{claims: %{"sub" => sub}}) do
    case Subject.new_from_id(sub) do
      {:ok, subject} ->
        {:ok, subject}

      {:error, reason} ->
        {:error, reason}
    end
  end

  def get_subject_from_refresh_token(_), do: {:ok, nil}

  @spec refresh_token_granted_to_client?(RefreshToken.t(), Client.t())
    :: :ok | {:error, any()}
  def refresh_token_granted_to_client?(refresh_token, client) do
    if refresh_token.claims["client_id"] == client.id do
      :ok
    else
      {:error, :client_id_no_match}
    end
  end

  @spec maybe_put_refresh_token(map(), RefreshToken.t() | nil) :: map()
  def maybe_put_refresh_token(m, %RefreshToken{} = refresh_token) do
    Map.put(m, "refresh_token", RefreshToken.serialize(refresh_token))
  end

  def maybe_put_refresh_token(m, nil), do: m

  @spec put_scope_if_changed(map(), Scope.Set.t(), Scope.Set.t()) :: map()
  def put_scope_if_changed(m, requested_scope, scope) do
    if requested_scope == scope do
      m
    else
      Map.put(m, "scope", Enum.join(scope, " "))
    end
  end
end
