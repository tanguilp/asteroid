defmodule AsteroidWeb.API.OAuth2.IntrospectEndpoint do
  use AsteroidWeb, :controller
  import Asteroid.Utils
  alias OAuth2Utils.Scope
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias Asteroid.{Client, Subject, Context}

  def handle(conn, params) do
    with {:ok, client} <- Client.Utils.get_client(conn, false),
         :ok <- client_authorized?(client)
    do
      do_handle(conn, params)
    else
      _ ->
        error_resp(conn, 400, %{"error" => "data"})
    end
  end

  def do_handle(%Plug.Conn{body_params: %{"token" => token}} = conn, _params) do
    case conn.body_params["token_type_hint"] do
      "access_token" ->
        case AccessToken.get(token) do
          {:ok, access_token} ->
            introspect_access_token(conn, access_token)

          {:error, _} ->
            token_not_found_resp(conn)
        end

      "refresh_token" ->
        case RefreshToken.get(token) do
          {:ok, refresh_token} ->
            introspect_refresh_token(conn, refresh_token)

          {:error, _} ->
            token_not_found_resp(conn)
        end

      nil ->
        case AccessToken.get(token) do
          {:ok, access_token} ->
            introspect_access_token(conn, access_token)

          {:error, _} ->
            case RefreshToken.get(token) do
              {:ok, refresh_token} ->
                introspect_refresh_token(conn, refresh_token)

              {:error, _} ->
                token_not_found_resp(conn)
            end
        end

      _ ->
        error_resp(conn, 400, error: :invalid_request,
                   error_description: "Unrecognized `token_type_hint`")
    end
  end

  def do_handle(conn, _) do
    error_resp(conn, 400, error: :invalid_request,
               error_description: "Missing `token` parameter")
  end

  @spec introspect_access_token(Plug.Conn.t(), String.t()) :: boolean
  defp introspect_access_token(conn, access_token) do
    resp = 
      access_token.claims
      |> astrenv(:introspect_before_send_resp_callback).()

    conn
    |> put_status(200)
    |> astrenv(:introspect_before_send_conn_callback).()
    |> json(resp)
  end

  @spec introspect_refresh_token(Plug.Conn.t(), String.t()) :: boolean
  defp introspect_refresh_token(conn, refresh_token) do
    resp = 
      refresh_token.claims
      |> astrenv(:introspect_before_send_resp_callback).()

    conn
    |> put_status(200)
    |> astrenv(:introspect_before_send_conn_callback).()
    |> json(resp)
  end

  @spec token_not_found_resp(Plug.Conn.t()) :: any()
  defp token_not_found_resp(conn) do
    resp =
      %{"active" => false}
      |> astrenv(:introspect_before_send_resp_callback).()

    conn
    |> put_status(200)
    |> astrenv(:introspect_before_send_conn_callback).()
    |> json(resp)
  end

  @spec client_authorized?(Client.t()) :: :ok | {:error, atom()}
  defp client_authorized?(client) do
    :ok
  end

  defp error_resp(conn, error_status \\ 400, error_data) do
    conn
    |> put_status(error_status)
    |> json(Enum.into(error_data, %{}))
  end
end
