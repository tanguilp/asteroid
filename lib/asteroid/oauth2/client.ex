defmodule Asteroid.OAuth2.Client do
  alias Asteroid.{Client, Context}

  @spec get_client(Plug.Conn.t(), boolean()) ::
    {:ok, String.t} |
    {:error, %__MODULE__.AuthenticationError{}}

  def get_client(conn, allow_unauthenticated_public_clients \\ false) do
    case get_authenticated_client(conn) do
      {:ok, client} ->
        {:ok, client}

      {:error, :client_not_found} ->
        {:error, __MODULE__.AuthenticationError.exception(:client_not_found)}

      {:error, :unauthenticated_client} ->
        if allow_unauthenticated_public_clients do
          case get_unauthenticated_client(conn) do
            {:ok, client} ->
              {:ok, client}

            {:error, reason} ->
              {:error, __MODULE__.AuthenticationError.exception(reason)}
          end
        else
          {:error, __MODULE__.AuthenticationError.exception(:unauthenticated_client)}
        end
    end
  end

  @spec get_authenticated_client(Plug.Conn.t()) :: {:ok, Client.t()} | {:error, atom()}
  defp get_authenticated_client(conn) do
    if APISex.authenticated?(conn) do
      case Client.new_from_id(APISex.client(conn)) do
        {:ok, client} ->
          {:ok, client}

        error ->
          #FIXME
          error
      end
    else
      {:error, :unauthenticated_client}
    end
  end

  @spec get_unauthenticated_client(Plug.Conn.t()) :: {:ok, Client.t()} | {:error, atom()}
  defp get_unauthenticated_client(conn) do
    case conn.body_params["client_id"] do
      nil ->
        {:error, :unauthenticated_client}

      client_id ->
        case Client.new_from_id(client_id) do
          {:ok, client} ->
            if public?(client) do
              if not has_credentials?(client) do
                {:ok, client}
              else
                {:error, :unauthenticated_public_client_has_credentials}
              end
            else
              {:error, :unauthenticated_client}
            end

          error ->
            error
        end
    end
  end

  @doc """
  Returns `true` if the client is a public client, `false` otherwise
  """

  @spec public?(Client.t()) :: boolean()
  def public?(client) do
    client = Client.fetch_attribute(client, "client_type")

    client.attrs["client_type"] == :public
  end

  @doc """
  Returns `true` if the client is a confidential client, `false` otherwise
  """

  @spec confidential?(Client.t()) :: boolean()
  def confidential?(client) do
    client = Client.fetch_attribute(client, "client_type")

    client.attrs["client_type"] == :confidential
  end

  @doc """
  Returns `true` if the client has credentials, `false` otherwise

  A client that has credentials is a client that has a `client_secret` attribute
  """
  @spec has_credentials?(Client.t()) :: boolean()
  def has_credentials?(client) do
    client = Client.fetch_attribute(client, "client_secret")

    client.attrs["client_secret"] != nil
  end

  defmodule AuthenticationError do
    @moduledoc """
    """

    defexception [:reason, :data]

    def exception(reason, data \\ %{}) do
      %__MODULE__{reason: reason, data: data}
    end

    @spec response(Plug.Conn.t(), Client.t(), Context.t()) :: Plug.Conn.t
    def response(conn, error, _ctx) do
      resp = %{
        "error" => "invalid_client",
        "error_description" => "#{inspect(error.reason)}"
      }

      conn
      |> Plug.Conn.put_status(401)
      |> set_www_authenticate_header()
      |> Phoenix.Controller.json(resp)
    end

    @spec set_www_authenticate_header(Plug.Conn.t()) :: Plug.Conn.t()
    defp set_www_authenticate_header(conn) do
      apisex_errors = APISex.AuthFailureResponseData.get(conn)

      failed_auth = Enum.find(
        apisex_errors,
        fn apisex_error ->
          apisex_error.reason != :credentials_not_found and
          is_tuple(apisex_error.www_authenticate_header)
        end
      )

      case failed_auth do
        # client tried to authenticate, as per RFC:
        #   If the
        #   client attempted to authenticate via the "Authorization"
        #   request header field, the authorization server MUST
        #   respond with an HTTP 401 (Unauthorized) status code and
        #   include the "WWW-Authenticate" response header field
        #   matching the authentication scheme used by the client.
        %APISex.AuthFailureResponseData{www_authenticate_header: {scheme, params}} ->
          APISex.set_WWWauthenticate_challenge(conn, scheme, params)

        # no failed authn at all or one that can return www-authenticate header
        nil ->
          Enum.reduce(
            apisex_errors,
            conn,
            fn
              %APISex.AuthFailureResponseData{www_authenticate_header: {scheme, params}}, conn ->
                APISex.set_WWWauthenticate_challenge(conn, scheme, params)

              _, conn ->
                conn
            end
          )
      end
    end
  end
end
