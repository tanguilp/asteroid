defmodule AsteroidWeb.PageController do
  use AsteroidWeb, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
