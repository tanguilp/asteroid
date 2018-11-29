defmodule AsteroidWeb.API.OAuth2.IntrospectEndpoint do
  use AsteroidWeb, :controller
  import Asteroid.Utils
  alias OAuth2Utils.Scope
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias Asteroid.{Client, Subject, Context}

  def handle(%Plug.Conn{body_params: %{"token" => token}} = conn, _params) do
    token_type =
      case conn.body_params["token_type_hint"] do
        "access_token" ->
          introspect_access_token(conn, token)

        "refresh_token" ->
          introspect_refresh_token(conn, token)

        nil ->
          if introspect_access_token(conn, token) == false do
            introspect_refresh_token(conn, token)
          end

        _ ->
          error_resp(conn, 400, error: :invalid_request,
                     error_description: "Unrecognized `token_type_hint`")
    end
  end

  def handle(conn, _) do
    error_resp(conn, 400, error: :invalid_request,
               error_description: "Missing `token` parameter")
  end

  @spec introspect_access_token(Plug.Conn.t(), String.t()) :: boolean
  defp introspect_access_token(conn, token) do
    case astrenv(:access_token_store).get(token) do
      {:ok, access_token} ->
        resp = 
          access_token.claims
          |> astrenv(:introspect_before_send_resp_callback).()

        conn
        |> put_status(200)
        |> astrenv(:introspect_before_send_conn_callback).()
        |> json(resp)

        true

      {:error, _} ->
        token_not_found_resp(conn)

        false
    end
  end

  @spec introspect_refresh_token(Plug.Conn.t(), String.t()) :: boolean
  defp introspect_refresh_token(conn, token) do
    case astrenv(:refresh_token_store).get(token) do
      {:ok, refresh_token} ->
        resp = 
          refresh_token.claims
          |> astrenv(:introspect_before_send_resp_callback).()

        conn
        |> put_status(200)
        |> astrenv(:introspect_before_send_conn_callback).()
        |> json(resp)

        true

      {:error, _} ->
        token_not_found_resp(conn)

        false
    end
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

  defp error_resp(conn, error_status \\ 400, error_data) do
    conn
    |> put_status(error_status)
    |> json(Enum.into(error_data, %{}))
  end
end
