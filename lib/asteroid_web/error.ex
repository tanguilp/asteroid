defmodule AsteroidWeb.Error do
  @moduledoc """
  Helper module to work with errors generated in the OAuth2 protocol flows
  """

  import Asteroid.Utils
  import Phoenix.Controller
  import Plug.Conn

  alias Asteroid.Client
  alias Asteroid.OAuth2
  alias Asteroid.OAuth2.ClientRegistration
  alias Asteroid.OIDC
  alias AsteroidWeb.AuthorizeController
  alias AsteroidWeb.API.OAuth2.TokenController

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
    |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
    |> put_view(AsteroidWeb.AuthorizeView)
    |> render("error_redirect_uri.html")
  end

  def respond_authorize(conn, %OAuth2.Request.MalformedParamError{name: "client_id"} = e) do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
    |> put_view(AsteroidWeb.AuthorizeView)
    |> render("error_redirect_uri.html")
  end

  def respond_authorize(conn, %OAuth2.Request.InvalidRequestError{parameter: "redirect_uri"} = e) do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
    |> put_view(AsteroidWeb.AuthorizeView)
    |> render("error_redirect_uri.html")
  end

  def respond_authorize(conn, %OAuth2.Request.InvalidRequestError{parameter: "client_id"} = e) do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
    |> put_view(AsteroidWeb.AuthorizeView)
    |> render("error_redirect_uri.html")
  end

  # function used when the connection is directly returned with an error. In such a case, params
  # are in the Conn

  def respond_authorize(
        %Plug.Conn{query_params: %{"redirect_uri" => redirect_uri, "client_id" => client_id}} =
          conn,
        e
      ) do
    with :ok <- AuthorizeController.client_id_valid?(client_id),
         :ok <- AuthorizeController.redirect_uri_valid?(redirect_uri),
         {:ok, client} <- Client.load_from_unique_attribute("client_id", client_id),
         :ok <-
           AuthorizeController.redirect_uri_registered_for_client?(
             client,
             redirect_uri
           ) do
      redirect_uri =
        OAuth2.RedirectUri.add_params(
          redirect_uri,
          %{}
          |> Map.put("error", err_name(e))
          |> Map.put("error_description", Exception.message(e))
          |> put_if_not_nil("state", conn.query_params["state"])
        )

      conn
      |> redirect(external: redirect_uri)
    else
      _ ->
        conn
        |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
        |> put_status(400)
        |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
        |> put_view(AsteroidWeb.AuthorizeView)
        |> render("error_redirect_uri.html")
    end
  end

  # function used when coming back from an authn / authz process. The authorization request must
  # be put in the assigns under the :authz_request atom

  def respond_authorize(%Plug.Conn{assigns: %{:authz_request => authz_request}} = conn, e) do
    redirect_uri =
      OAuth2.RedirectUri.add_params(
        authz_request.redirect_uri,
        %{"error" => err_name(e)}
        |> put_if_not_empty_string("error_description", Exception.message(e))
        |> put_if_not_nil("state", authz_request.params["state"])
      )

    conn
    |> redirect(external: redirect_uri)
  end

  def respond_authorize(conn, %OAuth2.JAR.RequestNotSupportedError{} = e) do
    respond_authorize_jar(conn, e)
  end

  def respond_authorize(conn, %OAuth2.JAR.InvalidRequestObjectError{} = e) do
    respond_authorize_jar(conn, e)
  end

  # Here we certainly won't have a redirect URI since we couldn't didn/t resolve the request
  # object in the first place

  def respond_authorize(conn, %OAuth2.JAR.RequestURINotSupportedError{} = e) do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
    |> put_view(AsteroidWeb.AuthorizeView)
    |> render("error_redirect_uri.html")
  end

  def respond_authorize(conn, %OAuth2.JAR.InvalidRequestURIError{} = e) do
    conn
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(400)
    |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
    |> put_view(AsteroidWeb.AuthorizeView)
    |> render("error_redirect_uri.html")
  end

  # JAR request which do not have duplicate query params for client_id or redirect_uri
  # (if they do, another respond_authorize/2 clause will have caught it)
  #
  # We then try to read the request object anyway (obvisouly won't work for JWEs) to pick
  # client_id / redirect_uri, then validate them and if correct, redirect to the client.
  # Otherwise we show a local Asteroid error page

  @spec respond_authorize_jar(Plug.Conn.t(), Exception.t()) :: Plug.Conn.t()

  defp respond_authorize_jar(conn, e) do
    try do
      invalid_request_object =
        e.request_object
        |> JOSE.JWS.peek_payload()
        |> Jason.decode!()

      case invalid_request_object do
        %{"redirect_uri" => redirect_uri, "client_id" => client_id} ->
          with :ok <- AuthorizeController.client_id_valid?(client_id),
               :ok <- AuthorizeController.redirect_uri_valid?(redirect_uri),
               {:ok, client} <- Client.load_from_unique_attribute("client_id", client_id),
               :ok <-
                 AuthorizeController.redirect_uri_registered_for_client?(
                   client,
                   redirect_uri
                 ) do
            redirect_uri =
              OAuth2.RedirectUri.add_params(
                redirect_uri,
                %{}
                |> Map.put("error", err_name(e))
                |> Map.put("error_description", Exception.message(e))
                |> put_if_not_nil("state", conn.query_params["state"])
              )

            conn
            |> redirect(external: redirect_uri)
          else
            _ ->
              conn
              |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
              |> put_status(400)
              |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
              |> put_view(AsteroidWeb.AuthorizeView)
              |> render("error_redirect_uri.html")
          end

        _ ->
          conn
          |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
          |> put_status(400)
          |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
          |> put_view(AsteroidWeb.AuthorizeView)
          |> render("error_redirect_uri.html")
      end
    rescue
      _ ->
        conn
        |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
        |> put_status(400)
        |> Phoenix.Controller.put_layout({AsteroidWeb.LayoutView, "app.html"})
        |> put_view(AsteroidWeb.AuthorizeView)
        |> render("error_redirect_uri.html")
    end
  end

  @spec err_name(Exception.t()) :: String.t()

  defp err_name(%OAuth2.UnsupportedGrantTypeError{}), do: "unsupported_grant_type"
  defp err_name(%OAuth2.UnsupportedResponseTypeError{}), do: "unsupported_response_type"
  defp err_name(%OAuth2.InvalidGrantError{}), do: "invalid_grant"
  defp err_name(%OAuth2.AccessDeniedError{}), do: "access_denied"
  defp err_name(%OAuth2.ServerError{}), do: "server_error"
  defp err_name(%OAuth2.TemporarilyUnavailableError{}), do: "temporarily_unavailable"
  defp err_name(%OIDC.InteractionRequiredError{}), do: "interaction_required"
  defp err_name(%OIDC.LoginRequiredError{}), do: "login_required"
  defp err_name(%OIDC.AccountSelectionRequiredError{}), do: "account_selection_required"
  defp err_name(%OIDC.ConsentRequiredError{}), do: "consent_required"
  defp err_name(%OAuth2.Client.AuthenticationError{}), do: "invalid_client"

  defp err_name(%OAuth2.Client.AuthorizationError{reason: :unauthorized_scope}),
    do: "invalid_scope"

  defp err_name(%OAuth2.Client.AuthorizationError{}), do: "unauthorized_client"
  defp err_name(%OAuth2.Request.InvalidRequestError{}), do: "invalid_request"
  defp err_name(%OAuth2.Request.MalformedParamError{name: "scope"}), do: "invalid_scope"
  defp err_name(%OAuth2.Request.MalformedParamError{}), do: "invalid_request"
  defp err_name(%OAuth2.Scope.UnknownRequestedScopeError{}), do: "invalid_scope"
  defp err_name(%OAuth2.DeviceAuthorization.ExpiredTokenError{}), do: "expired_token"

  defp err_name(%OAuth2.DeviceAuthorization.AuthorizationPendingError{}),
    do: "authorization_pending"

  defp err_name(%OAuth2.DeviceAuthorization.RateLimitedError{}), do: "slow_down"
  defp err_name(%OAuth2.JAR.RequestNotSupportedError{}), do: "request_not_supported"
  defp err_name(%OAuth2.JAR.RequestURINotSupportedError{}), do: "request_uri_not_supported"
  defp err_name(%OAuth2.JAR.InvalidRequestURIError{}), do: "invalid_request_uri"
  defp err_name(%OAuth2.JAR.InvalidRequestObjectError{}), do: "invalid_request_object"
  defp err_name(%TokenController.ExceedingScopeError{}), do: "invalid_scope"

  defp err_name(%ClientRegistration.InvalidClientMetadataFieldError{}),
    do: "invalid_client_metadata"

  defp err_name(%ClientRegistration.InvalidRedirectURIError{}), do: "invalid_redirect_uri"

  defp err_name(%ClientRegistration.UnauthorizedRequestedScopesError{}),
    do: "invalid_client_metadata"

  @spec err_status(Exception.t()) :: non_neg_integer()

  defp err_status(%OAuth2.Client.AuthenticationError{}), do: 401
  defp err_status(_), do: 400

  @doc """
  Set the authentication error headers in accordance to RFC6749

  This function set the `"www-authenticate"` header in the following way:
  - if an authentication was attempted, sets the header for this authentication attempt only
  - otherwise, advertise all the authentication methods available

  As per the RFC:

  > If the
  > client attempted to authenticate via the "Authorization"
  > request header field, the authorization server MUST
  > respond with an HTTP 401 (Unauthorized) status code and
  > include the "WWW-Authenticate" response header field
  > matching the authentication scheme used by the client.
  """

  @spec set_www_authenticate_header(Plug.Conn.t()) :: Plug.Conn.t()

  def set_www_authenticate_header(conn) do
    apisex_errors = APIac.AuthFailureResponseData.get(conn)

    failed_auth =
      Enum.find(
        apisex_errors,
        fn apisex_error ->
          apisex_error.reason != :credentials_not_found and
            is_tuple(apisex_error.www_authenticate_header)
        end
      )

    case failed_auth do
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
