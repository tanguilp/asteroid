defmodule AsteroidWeb.WebauthnLoginController do
  use AsteroidWeb, :controller

  require Logger

  alias Asteroid.Subject
  alias AsteroidWeb.Router.Helpers, as: Routes

  def index(conn, _params) do
    subject = get_session(conn, :subject)

    subject = Subject.fetch_attributes(subject, ["webauthn_keys"])

    webauthn_creds = subject.attrs["webauthn_keys"]

    challenge =
      Wax.new_authentication_challenge(
        Enum.map(webauthn_creds,
                 fn %{"id" => cred_id, "key" => cose_key} -> {cred_id, cose_key} end),
        [origin: Routes.url(conn), rp_id: :auto]
      )

    Logger.debug("Wax: generated authentication challenge #{inspect(challenge)}")

    conn
    |> put_session(:authentication_challenge, challenge)
    |> render("login_form.html",
      challenge: Base.encode64(challenge.bytes),
      rp_id: challenge.rp_id,
      subject: subject,
      cred_ids: Enum.map(webauthn_creds, fn %{"id" => cred_id} -> cred_id end)
    )
  end

  def validate(conn, %{
        "webauthn" => %{
          "clientDataJSON" => client_data_json,
          "authenticatorData" => authenticator_data_b64,
          "sig" => sig_b64,
          "rawID" => raw_id_b64,
          "type" => "public-key"
        }
      }) do
    challenge = get_session(conn, :authentication_challenge)

    authenticator_data = Base.decode64!(authenticator_data_b64)

    sig = Base.decode64!(sig_b64)

    case Wax.authenticate(raw_id_b64, authenticator_data, sig, client_data_json, challenge) do
      {:ok, _} ->
        Logger.debug("Wax: successful authentication for challenge #{inspect(challenge)}")

        conn
        |> put_session(:authenticated, true)
        |> put_flash(:info, "Successfully authenticated with WebAuthn")
        |> redirect(to: "/authorize_scopes")

      {:error, _} = error ->
        Logger.debug("Wax: authentication failed with error #{inspect(error)}")

        conn
        |> put_flash(:error, "Authentication failed. Try another authenticator or fill password")
        |> index(%{})
    end
  end
end
