defmodule AsteroidWeb.PageController do
  @moduledoc false

  use AsteroidWeb, :controller

  def index(conn, _params) do
    render(conn, "index.html")
  end
end
