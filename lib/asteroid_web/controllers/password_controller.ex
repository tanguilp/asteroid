defmodule AsteroidWeb.PasswordController do
  use AsteroidWeb, :controller

  def index(conn, _params) do
    conn
    |> put_status(200)
    |> render("form.html")
  end

  def put(conn, %{"password" => "123456"}) do
    conn
    |> put_flash(:info, "Successfully authenticated")
    |> put_session(:authenticated, true)
    |> redirect(to: "/register_webauthn_key")
  end

  def put(conn, _params) do
    conn
    |> put_flash(:error, "Invalid password")
    |> index(%{})
  end
end
