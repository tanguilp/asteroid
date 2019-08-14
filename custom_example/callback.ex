defmodule CustomExample.Callback do
  @moduledoc false

  import Asteroid.Utils

  alias Asteroid.OIDC
  alias Asteroid.Token.{AccessToken, RefreshToken}
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

  def introspect_add_authenticated_session_info(response,
                                                %{token: token, token_sort: token_sort})
  do
    maybe_authenticated_session_id =
      if token.data["__asteroid_oidc_authenticated_session_id"] do
       token.data["__asteroid_oidc_authenticated_session_id"]
      else
        # this attribute is not set on access tokens in non-implicit flows

        if token_sort == :access_token and token.refresh_token_id do
          {:ok, refresh_token} = RefreshToken.get(token.refresh_token_id)

          refresh_token.data["__asteroid_oidc_authenticated_session_id"]
        end
      end

    if maybe_authenticated_session_id do
      session_info = OIDC.AuthenticatedSession.info(maybe_authenticated_session_id) || %{}

      response
      |> put_if_not_nil("current_acr", session_info[:acr])
      |> put_if_not_nil("current_amr", session_info[:amr])
      |> put_if_not_nil("current_auth_time", session_info[:auth_time])
    else
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
