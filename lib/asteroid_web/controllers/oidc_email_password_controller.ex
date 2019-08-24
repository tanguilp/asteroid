defmodule AsteroidWeb.OIDCEmailPasswordController do
  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias Asteroid.OIDC
  alias Asteroid.OIDC.{AuthenticatedSession, AuthenticationEvent}
  alias Asteroid.Subject
  alias AsteroidWeb.AuthorizeController.Request

  def start_webflow(conn, %AsteroidWeb.AuthorizeController.Request{} = authz_request) do
    if authenticate?(conn, authz_request) do
      if "none" in authz_request.prompt do
        AsteroidWeb.AuthorizeController.authorization_denied(
          conn,
          %{
            authz_request: get_session(conn, :authz_request),
            error: OIDC.LoginRequiredError.exception(reason: "Login required")})
      else
        conn
        |> put_session(:authz_request, authz_request)
        |> redirect(to: "/oidc_email_password")
      end
    else
      conn
      |> put_session(:authz_request, authz_request)
      |> redirect(to: "/oidc_otp")
    end
  end

  def index(conn, _params) do
    conn
    |> put_status(200)
    |> render("form.html")
  end

  def put(conn, %{"email" => email, "password" => "123456"}) do
    if String.contains?(email, "@") do
      subject =
        case Subject.load_from_unique_attribute("email", email) do
          {:ok, subject} ->
            subject

          {:error, %AttributeRepository.Read.NotFoundError{}} ->
            subject =
              Subject.gen_new()
              |> Subject.add("sub", secure_random_b64())
              |> Subject.add("email", email)
              
            :ok = Subject.store(subject)

            subject
        end

      {:ok, authenticated_session} =
        AuthenticatedSession.gen_new(subject.id)
        |> AuthenticatedSession.store()

      {:ok, _} =
        AuthenticationEvent.gen_new(authenticated_session.id)
        |> AuthenticationEvent.put_value("name", "password")
        |> AuthenticationEvent.put_value("amr", "pwd")
        |> AuthenticationEvent.put_value("time", now())
        |> AuthenticationEvent.put_value("exp", now() + 60 * 10)
        |> AuthenticationEvent.store()

      conn
      |> put_session(:authenticated_session_id, authenticated_session.id)
      |> put_session(:subject, subject)
      |> redirect(to: "/oidc_otp")
    else
      conn
      |> put_flash(:error, "Invalid email or password")
      |> index(%{})
    end
  end

  def put(conn, _params) do
    conn
    |> put_flash(:error, "Invalid email or password")
    |> index(%{})
  end

  @spec authenticate?(Plug.Conn.t(), Request.t()) :: boolean()

  defp authenticate?(conn, authz_request) do
    if "login" in authz_request.prompt do
      true
    else
      case get_session(conn, :authenticated_session_id) do
        authenticated_session_id when is_binary(authenticated_session_id) ->
          case AuthenticatedSession.get(authenticated_session_id) do
            {:ok, authenticated_session} ->
              session_info =
                AuthenticatedSession.info(authenticated_session)

                "pwd" not in (session_info[:amr] || []) or
                (
                  authz_request.max_age != nil and
                  authz_request.max_age < now() - session_info[:auth_time]
                )

            {:error, _} ->
              true
          end
          
        _ ->
          true
      end
    end
  end
end
