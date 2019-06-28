defmodule Asteroid.Test.Callbacks do
  @moduledoc false

  alias Asteroid.Subject

  @doc false

  @spec test_ropc_username_password_callback(Plug.Conn.t(), String.t(), String.t())
    :: {:ok, Asteroid.Subject.t()} | {:error, atom()}

  def test_ropc_username_password_callback(_conn, username, password) do
    case Subject.load_from_unique_attribute("sub", username, attributes: ["password"]) do
      {:ok, sub} ->
        if sub.attrs["password"] == password do
          {:ok, sub}
        else
          {:error, Asteroid.OAuth2.InvalidGrantError.exception(
            grant: "password",
            reason: "invalid username or password",
            debug_details: "passwords don't match"
          )}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end
end
