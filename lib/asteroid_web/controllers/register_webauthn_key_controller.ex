defmodule AsteroidWeb.RegisterWebauthnKeyController do
  use AsteroidWeb, :controller

  import Asteroid.Utils

  require Logger

  alias Asteroid.Subject
  alias AsteroidWeb.Router.Helpers, as: Routes

  def index(conn, _params) do
    case get_session(conn, :subject) do
      %Subject{} = subject ->
        subject = Subject.fetch_attributes(subject, ["sub", "webauthn_key_reg_last_proposed"])

        if (subject.attrs["webauthn_key_reg_last_proposed"] || 0) + 3600 < now() do
          :ok =
            subject
            |> Subject.add("webauthn_key_reg_last_proposed", now())
            |> Subject.store()

          challenge = Wax.new_registration_challenge(origin: Routes.url(conn), rp_id: :auto)

          Logger.debug("Wax: generated attestation challenge #{inspect(challenge)}")

          conn
          |> put_session(:challenge, challenge)
          |> render("register_key.html",
            challenge: Base.encode64(challenge.bytes),
            rp_id: challenge.rp_id,
            subject: subject
          )
        else
          redirect(conn, to: "/authorize_scopes")
        end

      nil ->
        # FIXME: return error
        redirect(conn, to: "/")
    end
  end

  def validate(conn, %{
        "key" => %{
          "attestationObject" => attestation_object_b64,
          "clientDataJSON" => client_data_json,
          "rawID" => raw_id_b64,
          "type" => "public-key"
        }
      }) do
    challenge = get_session(conn, :challenge)

    attestation_object = Base.decode64!(attestation_object_b64)

    case Wax.register(attestation_object, client_data_json, challenge) do
      {:ok, {cose_key, attestation_result}} ->
        Logger.debug(
          "Wax: attestation object validated with cose key #{inspect(cose_key)} " <>
            " and attestation result #{inspect(attestation_result)}"
        )

        subject =
          conn
          |> get_session(:subject)
          |> Subject.fetch_attributes(["webauthn_keys"])

        case subject.attrs["webauthn_keys"] do
          l when is_list(l) ->
            subject
            |> Subject.add("webauthn_keys", %{"id" => raw_id_b64, "key" => cose_key})
            |> Subject.store()

          nil ->
            subject
            |> Subject.add("webauthn_keys", [%{"id" => raw_id_b64, "key" => cose_key}])
            |> Subject.store()
        end

        conn
        |> put_flash(:info, "Key registered")
        |> redirect(to: "/authorize_scopes")

      {:error, _} = error ->
        Logger.debug("Wax: attestation object validation failed with error #{inspect(error)}")

        conn
        |> put_flash(:error, "Key registration failed")
        |> index(%{})
    end
  end
end
