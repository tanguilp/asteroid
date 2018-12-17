defmodule Asteroid.OAuth2.Client do
  alias Asteroid.{Client, Context}
  alias Asteroid.OAuth2
  import Asteroid.Utils

  defmodule AuthenticationError do
    @moduledoc """
    Error raised when an client authentication error occurs
    """

    defexception [:reason]

    def message(%__MODULE__{reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "authentication error: #{String.replace(Atom.to_string(reason), "_", " ")}" 

        :normal ->
          "authentication error: #{String.replace(Atom.to_string(reason), "_", " ")}"

        :minimal ->
          ""
      end
    end
  end

  @spec get_client(Plug.Conn.t(), boolean()) ::
    {:ok, String.t} |
    {:error, %__MODULE__.AuthenticationError{}}

  def get_client(conn, allow_unauthenticated_public_clients \\ false) do
    case get_authenticated_client(conn) do
      {:ok, client} ->
        {:ok, client}

      {:error, %__MODULE__.AuthenticationError{reason: :unkown_client}} = error ->
        error

      {:error, exception} ->
        if allow_unauthenticated_public_clients do
          case get_unauthenticated_client(conn) do
            {:ok, client} ->
              {:ok, client}

            error ->
              error
          end
        else
          {:error, exception}
        end
    end
  end

  @spec get_authenticated_client(Plug.Conn.t()) :: {:ok, Client.t()} | {:error, atom()}
  defp get_authenticated_client(conn) do
    if APISex.authenticated?(conn) do
      case Client.new_from_id(APISex.client(conn)) do
        {:ok, client} ->
          {:ok, client}

        {:error, _} ->
          {:error, __MODULE__.AuthenticationError.exception(reason: :unkown_client)}
      end
    else
      {:error, __MODULE__.AuthenticationError.exception(reason: :unauthenticated_request)}
    end
  end

  @spec get_unauthenticated_client(Plug.Conn.t()) :: {:ok, Client.t()} | {:error, atom()}
  defp get_unauthenticated_client(conn) do
    case conn.body_params["client_id"] do
      nil ->
        {:error, __MODULE__.AuthenticationError.exception(reason: :unauthenticated_request)}

      client_id ->
        if OAuth2Utils.valid_client_id_param?(client_id) do
          case Client.new_from_id(client_id) do
            {:ok, client} ->
              if public?(client) do
                if not has_credentials?(client) do
                  {:ok, client}
                else
                  {:error, __MODULE__.AuthenticationError.exception(reason:
                    :public_client_has_credentials_and_must_authenticate)}
                end
              else
                {:error, __MODULE__.AuthenticationError.exception(reason:
                  :unauthenticated_request)}
              end

            error ->
              {:error, __MODULE__.AuthenticationError.exception(reason: :unkown_client)}
          end
        else
          {:error, OAuth2.Request.MalformedParamError.exception(parameter_name: "client_id",
                                                                parameter_value: client_id)}
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

  @spec error_response(Plug.Conn.t(), Exception.t()) :: Plug.Conn.t
  def error_response(conn, error) do
    response =
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          %{
            "error" => "invalid_client",
            "error_description" =>
            Exception.message(error) <> " "
              <> "("
              <> inspect(APISex.AuthFailureResponseData.get(conn), limit: :infinity)
              <> ")"
          }

        _ ->
          %{
            "error" => "invalid_client",
            "error_description" => Exception.message(error)
          }
      end

    conn
    |> Plug.Conn.put_status(401)
    |> set_www_authenticate_header()
    |> Phoenix.Controller.json(response)
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
