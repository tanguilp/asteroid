defmodule AsteroidWeb.API.OAuth2.IntrospectController do
  @moduledoc false

  use AsteroidWeb, :controller
  import Asteroid.Utils
  alias Asteroid.Token.{RefreshToken, AccessToken}
  alias Asteroid.{Client, Subject}
  alias Asteroid.OAuth2

  def handle(%Plug.Conn{body_params: %{"token" => token}} = conn, params) do
    with {:ok, client} <- OAuth2.Client.get_authenticated_client(conn),
         :ok <- valid_token_parameter?(token),
         :ok <- astrenv(:oauth2_endpoint_introspect_client_authorized).(client) do
      do_handle(conn, params, client)
    else
      {:error, e} ->
        AsteroidWeb.Error.respond_api(conn, e)
    end
  end

  def handle(conn, _) do
    error_resp(conn, 400,
      error: :invalid_request,
      error_description: "Missing `token` parameter"
    )
  end

  def do_handle(conn, %{"token" => token} = params, client) do
    case params["token_type_hint"] do
      token_type_hint when token_type_hint in [nil, "access_token"] ->
        case AccessToken.get(token) do
          {:ok, access_token} ->
            introspect_access_token(conn, access_token, client)

          {:error, _} ->
            case RefreshToken.get(token) do
              {:ok, refresh_token} ->
                introspect_refresh_token(conn, refresh_token, client)

              {:error, _} ->
                token_not_found_resp(conn, client)
            end
        end

      "refresh_token" ->
        case RefreshToken.get(token) do
          {:ok, refresh_token} ->
            introspect_refresh_token(conn, refresh_token, client)

          {:error, _} ->
            case AccessToken.get(token) do
              {:ok, refresh_token} ->
                introspect_access_token(conn, refresh_token, client)

              {:error, _} ->
                token_not_found_resp(conn, client)
            end
        end

      _ ->
        error_resp(conn, 400,
          error: :invalid_request,
          error_description: "Unrecognized `token_type_hint`"
        )
    end
  end

  @spec introspect_access_token(Plug.Conn.t(), AccessToken.t(), Client.t()) :: Plug.Conn.t()

  defp introspect_access_token(conn, access_token, client) do
    maybe_subject =
      case Subject.load_from_unique_attribute("sub", access_token.data["sub"]) do
        {:ok, subject} ->
          subject

        _ ->
          nil
      end

    ctx =
      %{}
      |> Map.put(:endpoint, :introspect)
      |> put_if_not_nil(:subject, maybe_subject)
      |> Map.put(:client, client)
      |> Map.put(:token, access_token)
      |> Map.put(:token_sort, :access_token)
      |> Map.put(:conn, conn)

    response_claims = astrenv(:oauth2_endpoint_introspect_claims_resp_callback).(ctx)

    resp =
      access_token.data
      |> Enum.filter(fn {k, _} -> k in response_claims end)
      |> Enum.into(%{})
      |> scope_list_to_param()
      |> Map.put("active", true)
      |> astrenv(:oauth2_endpoint_introspect_before_send_resp_callback).(ctx)

    conn
    |> put_status(200)
    |> astrenv(:oauth2_endpoint_introspect_before_send_conn_callback).(ctx)
    |> json(resp)
  end

  @spec introspect_refresh_token(Plug.Conn.t(), RefreshToken.t(), Client.t()) :: Plug.Conn.t()
  defp introspect_refresh_token(conn, refresh_token, client) do
    maybe_subject =
      case Subject.load_from_unique_attribute("sub", refresh_token.data["sub"]) do
        {:ok, subject} ->
          subject

        _ ->
          nil
      end

    ctx =
      %{}
      |> Map.put(:endpoint, :introspect)
      |> put_if_not_nil(:subject, maybe_subject)
      |> Map.put(:client, client)
      |> Map.put(:token, refresh_token)
      |> Map.put(:token_sort, :refresh_token)
      |> Map.put(:conn, conn)

    response_claims = astrenv(:oauth2_endpoint_introspect_claims_resp_callback).(ctx)

    resp =
      refresh_token.data
      |> Enum.filter(fn {k, _} -> k in response_claims end)
      # since Enum.filter/2 returns a list
      |> Enum.into(%{})
      |> scope_list_to_param()
      |> Map.put("active", true)
      |> astrenv(:oauth2_endpoint_introspect_before_send_resp_callback).(ctx)

    conn
    |> put_status(200)
    |> astrenv(:oauth2_endpoint_introspect_before_send_conn_callback).(ctx)
    |> json(resp)
  end

  @spec valid_token_parameter?(String.t()) ::
          :ok
          | {:error, %OAuth2.Request.MalformedParamError{}}

  defp valid_token_parameter?(token) do
    if OAuth2Utils.valid_access_token_param?(token) or
         OAuth2Utils.valid_refresh_token_param?(token) do
      :ok
    else
      {:error,
       OAuth2.Request.MalformedParamError.exception(
         name: "token",
         value: token
       )}
    end
  end

  @spec token_not_found_resp(Plug.Conn.t(), Client.t()) :: Plug.Conn.t()

  defp token_not_found_resp(conn, client) do
    ctx =
      %{}
      |> Map.put(:endpoint, :introspect)
      |> Map.put(:client, client)
      |> Map.put(:conn, conn)

    resp =
      %{"active" => false}
      |> astrenv(:oauth2_endpoint_introspect_before_send_resp_callback).(ctx)

    conn
    |> put_status(200)
    |> astrenv(:oauth2_endpoint_introspect_before_send_conn_callback).(ctx)
    |> json(resp)
  end

  defp error_resp(conn, error_status, error_data) do
    conn
    |> put_status(error_status)
    |> json(Enum.into(error_data, %{}))
  end

  @spec scope_list_to_param(map()) :: map()

  defp scope_list_to_param(%{"scope" => []} = m) do
    Map.delete(m, "scope")
  end

  defp scope_list_to_param(%{"scope" => scopes} = m) when is_list(scopes) do
    Map.put(m, "scope", Enum.join(scopes, " "))
  end

  defp scope_list_to_param(m) do
    m
  end
end
