defmodule AsteroidWeb.AccountSelectController do
  use AsteroidWeb, :controller

  alias Asteroid.Subject

  def start_webflow(conn, %AsteroidWeb.AuthorizeController.Request{} = authz_request) do
    conn
    |> clear_session()
    |> put_session(:authz_request, authz_request)
    |> redirect(to: "/account_select")
  end

  def index(conn, %{"selected" => username}) do
    case Subject.load_from_unique_attribute("sub", username) do
      {:ok, subject} ->
        IO.inspect(subject)
        subject = Subject.fetch_attributes(subject, ["webauthn_keys"]) |> IO.inspect()

        case subject.attrs["webauthn_keys"] do
          webauthn_keys when is_list(webauthn_keys) and webauthn_keys != [] ->
            conn
            |> put_session(:subject, subject)
            |> redirect(to: "/webauthn_login")

          _ ->
            conn
            |> put_session(:subject, subject)
            |> redirect(to: "/password")
        end

      {:error, %AttributeRepository.Read.NotFoundError{}} ->
        conn
        |> put_flash(:error, "User is not registered")
        |> index(%{})
    end
  end

  def index(conn, _params) do
    conn
    |> put_status(200)
    |> render("selector.html")
  end
end
