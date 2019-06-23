defmodule AsteroidWeb.API.OAuth2.DeviceAuthorizationEndpoint do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.OAuth2
  alias Asteroid.Token.DeviceCode
  alias AsteroidWeb.Router.Helpers, as: Routes

  def handle(conn, params) do
    scope_param = params["scope"]

    with :ok <- Asteroid.OAuth2.grant_type_enabled?(:"urn:ietf:params:oauth:grant-type:device_code"),
         {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- OAuth2.Client.grant_type_authorized?(client, "urn:ietf:params:oauth:grant-type:device_code"),
         {:ok, requested_scopes} <- get_scope(scope_param),
         :ok <- OAuth2.Client.scopes_authorized?(client, requested_scopes)
    do
      ctx =
        %{}
        |> Map.put(:endpoint, :device_authorization)
        |> Map.put(:flow, :device_authorization)
        |> Map.put(:requested_scopes, requested_scopes)
        |> Map.put(:client, client)

      {:ok, device_code} =
        DeviceCode.gen_new(user_code:
                           astrenv(:oauth2_flow_device_authorization_user_code_callback).(ctx))
          |> DeviceCode.put_value("exp",
             now() + astrenv(:oauth2_flow_device_authorization_device_code_lifetime))
          |> DeviceCode.put_value("clid", client.id)
          |> DeviceCode.put_value("requested_scopes", Scope.Set.to_list(requested_scopes))
          |> DeviceCode.put_value("status", "authorization_pending")
          |> DeviceCode.store(ctx)

      verif_uri = Routes.device_url(AsteroidWeb.Endpoint, :pre_authorize)

      resp =
        %{
          "device_code" => DeviceCode.serialize(device_code),
          "user_code" => device_code.user_code,
          "verification_uri" => verif_uri,
          "verification_uri_complete" => verif_uri <> "?user_code=" <> device_code.user_code,
          "expires_in" => device_code.data["exp"] - now()
        }
        |> put_if_not_nil("interval",
                          astrenv(:oauth2_flow_device_authorization_rate_limiter_interval))
        |> astrenv(:oauth2_endpoint_token_grant_type_password_before_send_resp_callback).(ctx)

      conn
      |> put_status(200)
      |> put_resp_header("cache-control", "no-store")
      |> put_resp_header("pragma", "no-cache")
      |> astrenv(:oauth2_endpoint_device_authorization_before_send_conn_callback).(ctx)
      |> json(resp)
    else
      {:error, %OAuth2.Client.AuthenticationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Client.AuthorizationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Request.MalformedParamError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.UnsupportedGrantTypeError{} = e} -> # OK
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %AttributeRepository.Read.NotFoundError{}} ->
        AsteroidWeb.Error.respond_api(conn, OAuth2.Client.AuthenticationError.exception(
          reason: :unknown_client))
    end
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
end
