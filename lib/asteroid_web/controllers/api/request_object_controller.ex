defmodule AsteroidWeb.API.RequestObjectController do
  @moduledoc false

  use AsteroidWeb, :controller

  def show(conn, params) do
    conn
    |> put_status(200)
    |> json(params)
  end

  def create(conn, params) do
    conn
    |> put_status(200)
    |> json(params)
  end
end
