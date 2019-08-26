defmodule Asteroid.Test.Callbacks do
  @moduledoc false

  alias Asteroid.Subject
  alias OAuth2Utils.Scope

  @doc false

  @spec test_ropc_username_password_callback(Plug.Conn.t(), String.t(), String.t()) ::
          {:ok, Asteroid.Subject.t()} | {:error, atom()}

  def test_ropc_username_password_callback(_conn, username, password) do
    case Subject.load_from_unique_attribute("sub", username, attributes: ["password"]) do
      {:ok, sub} ->
        if sub.attrs["password"] == password do
          {:ok, sub}
        else
          {:error,
           Asteroid.OAuth2.InvalidGrantError.exception(
             grant: "password",
             reason: "invalid username or password",
             debug_details: "passwords don't match"
           )}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @spec authorize_print_successful_request(
          Plug.Conn.t(),
          %AsteroidWeb.AuthorizeController.Request{}
        ) ::
          Plug.Conn.t()

  def authorize_print_successful_request(conn, request) do
    request_map =
      Map.from_struct(%{
        request
        | client_id: request.client_id,
          requested_scopes: Scope.Set.to_list(request.requested_scopes)
      })

    conn
    |> Plug.Conn.put_status(200)
    |> Phoenix.Controller.json(request_map)
  end
end
