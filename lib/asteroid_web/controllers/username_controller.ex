defmodule AsteroidWeb.UsernameController do
  use AsteroidWeb, :controller

  alias Asteroid.Subject

  def index(conn, _params) do
    conn
    |> put_status(200)
    |> put_secure_browser_headers()
    |> put_resp_header("cache-control", "no-cache, no-store, must-revalidate")
    |> render("form.html")
  end

  def put(conn, %{"username" => username}) when username != "" do
    subject =
      case Subject.load_from_unique_attribute("sub", username) do
        {:ok, subject} ->
          subject

        {:error, %AttributeRepository.Read.NotFoundError{}} ->
          subject =
            Subject.gen_new()
            |> Subject.add("sub", username)
            
          :ok = Subject.store(subject)

          subject
      end

    conn
    |> put_session(:subject, subject)
    |> redirect(to: "/password")
  end

  def put(conn, _params) do
    conn
    |> put_flash(:error, "Missing username")
    |> index(%{})
  end
end
