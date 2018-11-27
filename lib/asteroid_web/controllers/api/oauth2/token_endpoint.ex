defmodule AsteroidWeb.API.OAuth2.TokenEndpoint do
  use AsteroidWeb, :controller
  import Asteroid.Utils
  alias OAuth2Utils.Scope
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias Asteroid.{Client, Subject, Context}

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
         {:ok, client} <- get_client(conn),
         :ok <- client_grant_type_authorized?(client, :password),
         {:ok, scope} <- get_scope(scope_param),
         :ok <- client_scope_authorized?(client, scope),
         {:ok, subject} <-
           astrenv(:ropc_username_password_verify_callback).(conn, username, password)
    do
      ctx = %Asteroid.Context{
        request: %{
          :endpoint => :token,
          :flow => :ropc,
          :grant_type => :password,
          :scope => scope
        },
        client: client,
        subject: subject,
        device: nil
      }

      refresh_token =
        RefreshToken.new()
        |> RefreshToken.put_claim(:iat, now())
        |> RefreshToken.put_claim(:exp, now() + astrenv(:refresh_token_lifetime_callback).(ctx))
        |> RefreshToken.put_claim(:client_id, client.id)
        |> RefreshToken.put_claim(:sub, subject.id)
        |> RefreshToken.put_claim(:iss, astrenv(:issuer_callback).(ctx))

      access_token =
        AccessToken.new(refresh_token: refresh_token)
        |> AccessToken.put_claim(:iat, now())
        |> AccessToken.put_claim(:exp, now() + astrenv(:access_token_lifetime_callback).(ctx))
        |> AccessToken.put_claim(:client_id, client.id)
        |> AccessToken.put_claim(:sub, subject.id)
        |> AccessToken.put_claim(:iss, astrenv(:issuer_callback).(ctx))

      RefreshToken.store(refresh_token, ctx)
      AccessToken.store(access_token, ctx)

      resp =
        %{
          "access_token" => AccessToken.serialize(access_token),
          "refresh_token" => RefreshToken.serialize(refresh_token),
          "expires_in" => access_token.claims[:exp] - now(),
          "token_type" => "bearer"
        }
        |> astrenv(:ropc_before_send_resp_callback).(ctx)

      conn
      |> astrenv(:ropc_before_send_conn_callback).(ctx)
      |> put_status(200)
      |> json(resp)
    else
      {:error, :unauthenticated_client} ->
        error_resp(conn, 401, error: :invalid_client,
                   error_description: "Client authentication failed")

      {:error, :unauthenticated_public_client_has_credentials} ->
        error_resp(conn, 401, error: :invalid_client,
          error_description:
            "Client authentication failed: public client has credentials but did not use it")

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
    end
  end

  def handle(%Plug.Conn{body_params: %{"grant_type" => "password"}} = conn, _params) do
    error_resp(conn,
                   error: "invalid_request",
                   error_description: "Missing username or password parameter")
  end

  # unrecognized or unsupported grant

  def handle(%Plug.Conn{body_params: %{"grant_type" => grant}} = conn, _params) do
    error_resp(conn,
                   error: "invalid_grant",
                   error_description: "Invalid grant #{grant}")
  end

  @spec get_client(Plug.Conn.t()) ::
    {:ok, String.t} |
    {:error, :unauthenticated_client | :unauthenticated_public_client_has_credentials}
  defp get_client(conn) do
    if APISex.authenticated?(conn) do
      client = Client.new_from_id(APISex.client(conn))

      {:ok, client}
    else
      case conn.body_params["client_id"] do
        nil ->
          {:error, :unauthenticated_client}

        client_id ->
          client =
            Client.new_from_id(client_id)
            |> Client.fetch_attribute("client_type")
            |> Client.fetch_attribute("client_secret")

          case {client.attrs["client_type"], client.attrs["client_secret"]} do
          # only registered public clients with no credentials are acccepted
          {:public, nil} ->
            {:ok, client}

          # public client who have credentials shall use them
          {:public, _} ->
            {:error, :unauthenticated_public_client_has_credentials}

          _ ->
            {:error, :unauthenticated_client}
          end
      end
    end
  end

  defp error_resp(conn, error_status \\ 400, error_data) do
    conn
    |> put_status(error_status)
    |> json(Enum.into(error_data, %{}))
  end

  @spec grant_type_enabled?(Asteroid.GrantType.t()) :: :ok | {:error, :grant_type_disabled}
  defp grant_type_enabled?(:password) do
    if Application.get_env(:asteroid, :flow_ropc_enabled, false) do
      :ok
    else
      {:error, :grant_type_disabled}
    end
  end

  @spec client_grant_type_authorized?(Asteroid.Client.client_param(), Asteroid.GrantType.t()) ::
    :ok | {:error, :grant_type_not_authorized_for_client}
  defp  client_grant_type_authorized?(_client, :password) do
    :ok
  end

  @spec get_scope(String.t() | nil)
    :: {:ok, Scope.Set.t() | nil} | {:error, :malformed_scope_param}

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
end
