defmodule AsteroidWeb.Error do
  @moduledoc """
  Helper module to work with errors generated in the OAuth2 protocol flows
  """

  import Asteroid.Utils
  import Phoenix.Controller
  import Plug.Conn

  alias Asteroid.OAuth2
  alias AsteroidWeb.API.OAuth2.TokenEndpoint
  alias AsteroidWeb.API.OAuth2.RegisterEndpoint

  @doc """
  Responds with the appropriate error codes, headers and text to an OAuth2 protocol flow
  error
  """

  @spec respond(Plug.Conn.t(), Exception.t()) :: Plug.Conn.t()

  def respond(conn, %OAuth2.Client.AuthenticationError{} = e) do
    error_status = err_status(e)
    error_name = err_name(e)
    error_response =
      %{}
      |> Map.put("error", error_name)
      |> put_if_not_empty_string("error_description", Exception.message(e))

    conn
    |> put_status(error_status)
    |> set_www_authenticate_header()
    |> json(error_response)
  end

  def respond(conn, e) do
    error_status = err_status(e)
    error_name = err_name(e)
    error_response =
      %{}
      |> Map.put("error", error_name)
      |> put_if_not_empty_string("error_description", Exception.message(e))

    conn
    |> put_status(error_status)
    |> json(error_response)
  end

  @spec err_name(Exception.t()) :: String.t()

  defp err_name(%OAuth2.UnsupportedGrantTypeError{}), do: "unsupported_grant_type"
  defp err_name(%OAuth2.InvalidGrantError{}), do: "invalid_grant"
  defp err_name(%OAuth2.Client.AuthenticationError{}), do: "invalid_client"
  defp err_name(%OAuth2.Client.AuthorizationError{reason: :unauthorized_scope}), do: "invalid_scope"
  defp err_name(%OAuth2.Client.AuthorizationError{}), do: "unauthorized_client"
  defp err_name(%OAuth2.Request.InvalidRequestError{}), do: "invalid_request"
  defp err_name(%OAuth2.Request.MalformedParamError{name: "scope"}), do: "invalid_scope"
  defp err_name(%OAuth2.Request.MalformedParamError{}), do: "invalid_request"
  defp err_name(%TokenEndpoint.ExceedingScopeError{}), do: "invalid_scope"
  defp err_name(%RegisterEndpoint.InvalidClientMetadataFieldError{}), do: "invalid_client_metadata"
  defp err_name(%RegisterEndpoint.InvalidRedirectURIError{}), do: "invalid_redirect_uri"
  defp err_name(%RegisterEndpoint.UnauthorizedRequestedScopesError{}), do: "invalid_client_metadata"

  @spec err_status(Exception.t()) :: non_neg_integer()

  defp err_status(%OAuth2.Client.AuthenticationError{}), do: 401
  defp err_status(_), do: 400

  @spec set_www_authenticate_header(Plug.Conn.t()) :: Plug.Conn.t()

  defp set_www_authenticate_header(conn) do
    apisex_errors = APIac.AuthFailureResponseData.get(conn)

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
      %APIac.AuthFailureResponseData{www_authenticate_header: {scheme, params}} ->
        APIac.set_WWWauthenticate_challenge(conn, scheme, params)

      # no failed authn at all or one that can return www-authenticate header
      nil ->
        Enum.reduce(
          apisex_errors,
          conn,
          fn
            %APIac.AuthFailureResponseData{www_authenticate_header: {scheme, params}}, conn ->
              APIac.set_WWWauthenticate_challenge(conn, scheme, params)

            _, conn ->
              conn
          end
        )
    end
  end
end
