defmodule AsteroidWeb.API.RequestObjectController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias Asteroid.OAuth2
  alias AsteroidWeb.Router.Helpers, as: Routes

  def show(conn, %{"id" => key}) do
    case OAuth2.JAR.get_stored_request_object(key) do
      {:ok, request_object} ->
        conn
        |> put_status(200)
        |> text(request_object)

      {:error, _} ->
        conn
        # FIXME: verbose level
        |> send_resp(404, "")
    end
  end

  def create(conn, %{"request_object" => request_object}) do
    key = secure_random_b64()

    to_store = %{
      "request_object" => request_object,
      "exp" => now() + astrenv(:oauth2_jar_request_object_lifetime)
    }

    case OAuth2.JAR.put_request_object(key, to_store) do
      :ok ->
        conn
        |> put_resp_header(
          "location",
          Routes.request_object_url(AsteroidWeb.Endpoint, :show, key)
        )
        |> put_resp_content_type("application/jwt")
        |> send_resp(201, "")

      {:error, _} ->
        conn
        # FIXME: verbose level
        |> send_resp(500, "")
    end
  end
end
