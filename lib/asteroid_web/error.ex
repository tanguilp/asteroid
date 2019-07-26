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

  @spec respond_api(Plug.Conn.t(), Exception.t()) :: Plug.Conn.t()

  def respond_api(conn, %OAuth2.Client.AuthenticationError{} = e) do
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

  def respond_api(conn, e) do
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

  @spec respond_authorize(Plug.Conn.t(), Exception.t()) :: Plug.Conn.t()

  def respond_authorize(conn, %OAuth2.Request.MalformedParamError{name: "redirect_uri"} = e) do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> render("error_redirect_uri.html")
  end

  def respond_authorize(conn, %OAuth2.Request.MalformedParamError{name: "client_id"} = e) do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> render("error_redirect_uri.html")
  end

  def respond_authorize(conn, %OAuth2.Request.InvalidRequestError{parameter: "redirect_uri"} = e)
  do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> render("error_redirect_uri.html")
  end

  def respond_authorize(conn, %OAuth2.Request.InvalidRequestError{parameter: "client_id"} = e)
  do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> render("error_redirect_uri.html")
  end

  # function used when the connection is directly returned with an error. In such a case, params
  # are in the Conn

  def respond_authorize(%Plug.Conn{query_params: %{"redirect_uri" => redirect_uri}} = conn, e) do
    redirect_uri = OAuth2.RedirectUri.add_params(
      redirect_uri,
      %{
        "error" => err_name(e),
        "error_description" => Exception.message(e)
      }
      |> put_if_not_nil("state", conn.query_params["state"])
    )

    conn
    |> redirect(external: redirect_uri)
  end

  # function used when coming back from an authn / authz process. The authorization request must
  # be put in the assigns under the :authz_request atom

  def respond_authorize(%Plug.Conn{assigns: %{:authz_request => authz_request}} = conn, e) do
    redirect_uri = OAuth2.RedirectUri.add_params(
      authz_request.redirect_uri,
      %{"error" => err_name(e)}
      |> put_if_not_empty_string("error_description", Exception.message(e))
      |> put_if_not_nil("state", authz_request.params["state"])
    )

    conn
    |> redirect(external: redirect_uri)
  end

  @spec err_name(Exception.t()) :: String.t()

  defp err_name(%OAuth2.UnsupportedGrantTypeError{}), do: "unsupported_grant_type"
  defp err_name(%OAuth2.UnsupportedResponseTypeError{}), do: "unsupported_response_type"
  defp err_name(%OAuth2.InvalidGrantError{}), do: "invalid_grant"
  defp err_name(%OAuth2.AccessDeniedError{}), do: "access_denied"
  defp err_name(%OAuth2.ServerError{}), do: "server_error"
  defp err_name(%OAuth2.TemporarilyUnavailableError{}), do: "temporarily_unavailable"
  defp err_name(%OAuth2.Client.AuthenticationError{}), do: "invalid_client"
  defp err_name(%OAuth2.Client.AuthorizationError{reason: :unauthorized_scope}), do: "invalid_scope"
  defp err_name(%OAuth2.Client.AuthorizationError{}), do: "unauthorized_client"
  defp err_name(%OAuth2.Request.InvalidRequestError{}), do: "invalid_request"
  defp err_name(%OAuth2.Request.MalformedParamError{name: "scope"}), do: "invalid_scope"
  defp err_name(%OAuth2.Request.MalformedParamError{}), do: "invalid_request"
  defp err_name(%OAuth2.Scope.UnknownRequestedScopeError{}), do: "invalid_scope"
  defp err_name(%OAuth2.DeviceAuthorization.ExpiredTokenError{}), do: "expired_token"
  defp err_name(%OAuth2.DeviceAuthorization.AuthorizationPendingError{}), do: "authorization_pending"
  defp err_name(%OAuth2.DeviceAuthorization.RateLimitedError{}), do: "slow_down"
  defp err_name(%OAuth2.JAR.RequestNotSupportedError{}), do: "request_not_supported"
  defp err_name(%OAuth2.JAR.RequestURINotSupportedError{}), do: "request_uri_not_supported"
  defp err_name(%OAuth2.JAR.InvalidRequestURIError{}), do: "invalid_request_uri"
  defp err_name(%OAuth2.JAR.InvalidRequestObjectError{}), do: "invalid_request_object"
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
