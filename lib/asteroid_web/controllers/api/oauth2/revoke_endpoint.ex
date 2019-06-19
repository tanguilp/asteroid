defmodule AsteroidWeb.API.OAuth2.RevokeEndpoint do
  @moduledoc false

  use AsteroidWeb, :controller
  import Asteroid.Utils
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias Asteroid.Client
  alias Asteroid.OAuth2

  def handle(conn, %{"token" => token} = params) do
    with {:ok, client} <- OAuth2.Client.get_client(conn),
         :ok <- valid_token_parameter?(token, params["token_type_hint"])
    do
      case params["token_type_hint"] do
        token_type_hint when token_type_hint in [nil, "access_token"] ->
          case AccessToken.get(token) do
            {:ok, _} ->
              AccessToken.delete(token)

            {:error, _} ->
              RefreshToken.delete(token)
          end

          success_response(conn, client)

        "refresh_token" ->
          case RefreshToken.get(token) do
            {:ok, _} ->
              RefreshToken.delete(token)

            {:error, _} ->
              AccessToken.delete(token)
          end

          success_response(conn, client)

        _ ->
          error_resp(conn, 400, error: :unsupported_token_type,
                     error_description: "Unrecognized `token_type_hint`")
      end
    else
      {:error, %OAuth2.Client.AuthenticationError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

      {:error, %OAuth2.Request.MalformedParamError{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)

    end
  end

  def handle(conn, _) do
    error_resp(conn, 400, error: :invalid_request,
               error_description: "Missing `token` parameter")
  end

  @spec valid_token_parameter?(String.t(), String.t() | nil) ::
  :ok
  | {:error, %OAuth2.Request.MalformedParamError{}}

  defp valid_token_parameter?(token, "access_token") do
    if OAuth2Utils.valid_access_token_param?(token) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "token", value: token)}
    end
  end

  defp valid_token_parameter?(token, "refresh_token") do
    if OAuth2Utils.valid_refresh_token_param?(token) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "token", value: token)}
    end
  end

  defp valid_token_parameter?(token, _) do
    if OAuth2Utils.valid_access_token_param?(token) or
      OAuth2Utils.valid_refresh_token_param?(token) do
      :ok
    else
      {:error, OAuth2.Request.MalformedParamError.exception(name: "token", value: token)}
    end
  end

  @spec success_response(Plug.Conn.t(), Client.t()) :: Plug.Conn.t()

  defp success_response(conn, client) do
    ctx =
      %{}
      |> Map.put(:endpoint, :revoke)
      |> Map.put(:client, client)

    conn
    |> astrenv(:oauth2_endpoint_revoke_before_send_conn_callback).(ctx)
    |> Plug.Conn.resp(200, [])
  end

  defp error_resp(conn, error_status, error_data) do
    conn
    |> put_status(error_status)
    |> json(Enum.into(error_data, %{}))
  end
end
