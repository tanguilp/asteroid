defmodule CustomExample.Callback do
  @moduledoc false

  import Asteroid.Utils

  alias Asteroid.OIDC
  alias Asteroid.Token.AccessToken
  alias Asteroid.Subject

  def add_dad_joke(access_token, %{flow: :client_credentials}) do
    response = HTTPoison.get!("https://icanhazdadjoke.com/", [{"Accept", "text/plain"}])

    AccessToken.put_value(access_token, "dad_joke", response.body)
  end

  def add_dad_joke(access_token, _ctx) do
    access_token
  end

  def introspect_add_subject_attributes(response, %{subject: subject}) do
    subject = Subject.fetch_attributes(subject, ["mail", "permissions"])

    response
    |> put_if_not_nil("email_address", subject.attrs["mail"])
    |> put_if_not_nil("permissions", subject.attrs["permissions"])
  end

  def introspect_add_subject_attributes(response, _) do
    response
  end

  def introspect_add_authenticated_session_info(response, %{token: token}) do
    case token.data["__asteroid_oidc_authenticated_session_id"] do
      session_id when is_binary(session_id) ->
        session_info = OIDC.AuthenticatedSession.info(session_id) || %{}

        response
        |> put_if_not_nil("current_acr", session_info[:acr])
        |> put_if_not_nil("current_amr", session_info[:amr])
        |> put_if_not_nil("current_auth_time", session_info[:auth_time])

      nil ->
        response
    end
  end

  @spec test_ropc_username_password_callback(Plug.Conn.t(), String.t(), String.t())
    :: {:ok, Asteroid.Subject.t()} | {:error, atom()}

  def test_ropc_username_password_callback(_conn, username, password) do
    case Subject.load(username, attributes: ["password"]) do
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
