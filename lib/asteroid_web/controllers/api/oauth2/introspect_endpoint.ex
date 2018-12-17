defmodule AsteroidWeb.API.OAuth2.IntrospectEndpoint do
  use AsteroidWeb, :controller
  import Asteroid.Utils
  alias OAuth2Utils.Scope
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias Asteroid.{Client, Subject, Context}
  alias Asteroid.OAuth2

  def handle(conn, params) do
    with {:ok, client} <- OAuth2.Client.get_client(conn, false),
         :ok <- astrenv(:introspect_endpoint_authorized).(client)
    do
      do_handle(conn, params, client)
    else
      {:error, %Asteroid.OAuth2.Client.AuthenticationError{} = error} ->
        OAuth2.Client.error_response(conn, error)

      {:error, :unauthorized} ->
        error_resp(conn, 403,
                   %{"error" => "unauthorized_client",
                     "error_description" => "Client does not have the relevant permission"
                   })
    end
  end

  def do_handle(%Plug.Conn{body_params: %{"token" => token}} = conn, _params, client) do
    case conn.body_params["token_type_hint"] do
      "access_token" ->
        case AccessToken.get(token, check_active: true) do
          {:ok, access_token} ->
            introspect_access_token(conn, access_token, client)

          {:error, _} ->
            token_not_found_resp(conn, client)
        end

      "refresh_token" ->
        case RefreshToken.get(token, check_active: true) do
          {:ok, refresh_token} ->
            introspect_refresh_token(conn, refresh_token, client)

          {:error, _} ->
            token_not_found_resp(conn, client)
        end

      nil ->
        case AccessToken.get(token, check_active: true) do
          {:ok, access_token} ->
            introspect_access_token(conn, access_token, client)

          {:error, _} ->
            case RefreshToken.get(token, check_active: true) do
              {:ok, refresh_token} ->
                introspect_refresh_token(conn, refresh_token, client)

              {:error, _} ->
                token_not_found_resp(conn, client)
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

  @spec introspect_access_token(Plug.Conn.t(), String.t(), Client.t()) :: boolean
  defp introspect_access_token(conn, access_token, client) do
    ctx = %Asteroid.Context{
      request: %{
        :endpoint => :introspect,
        :token_sort => :access_token
      },
      client: client,
      subject: Subject.new_from_id(access_token.claims["sub"]),
      device: nil
    }

    response_claims = astrenv(:introspect_resp_claims).(ctx)

    resp = 
      access_token.claims
      |> Enum.filter(fn {k, _} -> k in response_claims end)
      |> Enum.into(%{}) # since Enum.filter/2 retunrs a list
      |> Map.put("active", "true")
      |> astrenv(:introspect_before_send_resp_callback).(ctx)

    conn
    |> put_status(200)
    |> astrenv(:introspect_before_send_conn_callback).(ctx)
    |> json(resp)
  end

  @spec introspect_refresh_token(Plug.Conn.t(), String.t(), Client.t()) :: boolean
  defp introspect_refresh_token(conn, refresh_token, client) do
    ctx = %Asteroid.Context{
      request: %{
        :endpoint => :introspect,
        :token_sort => :refresh_token
      },
      client: client,
      subject: Subject.new_from_id(refresh_token.claims["sub"]),
      device: nil
    }

    response_claims = astrenv(:introspect_resp_claims).(ctx)

    resp = 
      refresh_token.claims
      |> Enum.filter(fn {k, _} -> k in response_claims end)
      |> Enum.into(%{}) # since Enum.filter/2 retunrs a list
      |> Map.put("active", "true")
      |> astrenv(:introspect_before_send_resp_callback).(ctx)

    conn
    |> put_status(200)
    |> astrenv(:introspect_before_send_conn_callback).(ctx)
    |> json(resp)
  end

  @spec token_not_found_resp(Plug.Conn.t(), Client.t()) :: any()
  defp token_not_found_resp(conn, client) do
    ctx = %Asteroid.Context{
      request: %{
        :endpoint => :introspect
      },
      client: client
    }

    resp =
      %{"active" => false}
      |> astrenv(:introspect_before_send_resp_callback).(ctx)

    conn
    |> put_status(200)
    |> astrenv(:introspect_before_send_conn_callback).(ctx)
    |> json(resp)
  end

  defp error_resp(conn, error_status \\ 400, error_data) do
    conn
    |> put_status(error_status)
    |> json(Enum.into(error_data, %{}))
  end
end
