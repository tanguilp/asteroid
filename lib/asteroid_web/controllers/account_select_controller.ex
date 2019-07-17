defmodule AsteroidWeb.AccountSelectController do
  use AsteroidWeb, :controller

  alias Asteroid.Subject

  def index(conn, %{"selected" => username}) do
    case Subject.load_from_unique_attribute("sub", username) do
      {:ok, subject} ->
        subject = Subject.fetch_attributes(subject, ["webauthn_keys"])

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
