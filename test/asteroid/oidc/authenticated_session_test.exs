defmodule Asteroid.OIDC.AuthenticatedSessionTest do
  use ExUnit.Case, async: true

  alias Asteroid.OIDC.AuthenticatedSession
  alias Asteroid.OIDC.AuthenticationEvent
  alias Asteroid.Token.RefreshToken

  test "OIDC associated refresh tokens are destroyed when no offline_access" do
    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.store()

    {:ok, rt1} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("authenticated_session_id", as.id)
      |> RefreshToken.put_value("scope", ["openid"])
      |> RefreshToken.store()

    {:ok, rt2} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("authenticated_session_id", as.id)
      |> RefreshToken.put_value("scope", ["openid"])
      |> RefreshToken.store()

    AuthenticatedSession.delete(as)

    assert {:error, _} = RefreshToken.get(rt1.id)
    assert {:error, _} = RefreshToken.get(rt2.id)
  end

  test "Associated refresh tokens are not destroyed when not OIDC" do
    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.store()

    {:ok, rt} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("authenticated_session_id", as.id)
      |> RefreshToken.store()

    AuthenticatedSession.delete(as)

    assert {:ok, _} = RefreshToken.get(rt.id)
  end

  test "OIDC associated refresh token is not destroyed when offline_access" do
    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.store()

    {:ok, rt} =
      RefreshToken.gen_new()
      |> RefreshToken.put_value("authenticated_session_id", as.id)
      |> RefreshToken.put_value("scope", ["openid", "offline_access"])
      |> RefreshToken.store()

    AuthenticatedSession.delete(as)

    assert {:ok, _} = RefreshToken.get(rt.id)
  end

  test "acr set with 1 auth event associated" do
    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.store()

    AuthenticationEvent.gen_new(as.id)
    |> AuthenticationEvent.put_value("name", "password")
    |> AuthenticationEvent.store()

    {:ok, as} = AuthenticatedSession.get(as.id)

    assert as.data["current_acr"] == "loa1"
  end

  test "acr set with 2 auth events associated" do
    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.store()

    AuthenticationEvent.gen_new(as.id)
    |> AuthenticationEvent.put_value("name", "password")
    |> AuthenticationEvent.store()

    AuthenticationEvent.gen_new(as.id)
    |> AuthenticationEvent.put_value("name", "webauthn")
    |> AuthenticationEvent.store()

    {:ok, as} = AuthenticatedSession.get(as.id)

    assert as.data["current_acr"] == "loa2"
  end

  test "acr set with 1 auth event associated then auth event deleted, session destroyed" do
    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.store()

    {:ok, ae} =
      AuthenticationEvent.gen_new(as.id)
      |> AuthenticationEvent.put_value("name", "password")
      |> AuthenticationEvent.store()

    {:ok, as} = AuthenticatedSession.get(as.id)

    assert as.data["current_acr"] == "loa1"

    AuthenticationEvent.delete(ae)

    assert {:error, as} = AuthenticatedSession.get(as.id)
  end

  test "acr set with 2 auth events associated then one deleted" do
    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.store()

    AuthenticationEvent.gen_new(as.id)
    |> AuthenticationEvent.put_value("name", "password")
    |> AuthenticationEvent.store()

    {:ok, ae} =
      AuthenticationEvent.gen_new(as.id)
      |> AuthenticationEvent.put_value("name", "webauthn")
      |> AuthenticationEvent.store()

    {:ok, as} = AuthenticatedSession.get(as.id)

    assert as.data["current_acr"] == "loa2"

    AuthenticationEvent.delete(ae)

    {:ok, as} = AuthenticatedSession.get(as.id)

    assert as.data["current_acr"] == "loa1"
  end

  test "info function" do
    Process.put(:oidc_acr_config,
      "3-factor": [
        callback: &AsteroidWeb.LOA3_webflow.start_webflow/2,
        auth_event_set: [["password", "otp", "webauthn"]]
      ],
      "2-factor": [
        callback: &AsteroidWeb.LOA2_webflow.start_webflow/2,
        auth_event_set: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
      ],
      "1-factor": [
        callback: &AsteroidWeb.LOA1_webflow.start_webflow/2,
        auth_event_set: [["password"], ["webauthn"]],
        default: true
      ]
    )

    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.store()

    AuthenticationEvent.gen_new(as.id)
    |> AuthenticationEvent.put_value("name", "password")
    |> AuthenticationEvent.put_value("amr", "pwd")
    |> AuthenticationEvent.put_value("time", 100_000)
    |> AuthenticationEvent.store()

    AuthenticationEvent.gen_new(as.id)
    |> AuthenticationEvent.put_value("name", "otp")
    |> AuthenticationEvent.put_value("amr", "otp")
    |> AuthenticationEvent.put_value("time", 200_000)
    |> AuthenticationEvent.store()

    AuthenticationEvent.gen_new(as.id)
    |> AuthenticationEvent.put_value("name", "otp")
    |> AuthenticationEvent.put_value("amr", "otp")
    |> AuthenticationEvent.put_value("time", 250_000)
    |> AuthenticationEvent.store()

    AuthenticationEvent.gen_new(as.id)
    |> AuthenticationEvent.put_value("name", "webauthn")
    |> AuthenticationEvent.put_value("amr", "phr")
    |> AuthenticationEvent.put_value("time", 300_000)
    |> AuthenticationEvent.store()

    {:ok, as} = AuthenticatedSession.get(as.id)

    assert as.data["current_acr"] == "3-factor"

    assert %{acr: "3-factor", amr: amr, auth_time: 300_000} = AuthenticatedSession.info(as.id)
    assert Enum.sort(amr) == ["otp", "phr", "pwd"]

    assert %{acr: "1-factor", amr: ["pwd"], auth_time: 100_000} ==
             AuthenticatedSession.info(as.id, "1-factor")

    assert %{acr: "2-factor", amr: amr, auth_time: 250_000} =
             AuthenticatedSession.info(as.id, "2-factor")

    assert Enum.sort(amr) == ["otp", "pwd"]

    assert %{acr: "3-factor", amr: amr, auth_time: 300_000} =
             AuthenticatedSession.info(as.id, "3-factor")

    assert Enum.sort(amr) == ["otp", "phr", "pwd"]
  end

  test "info function - no auth event associated" do
    Process.put(:oidc_acr_config,
      "3-factor": [
        callback: &AsteroidWeb.LOA3_webflow.start_webflow/2,
        auth_event_set: [["password", "otp", "webauthn"]]
      ],
      "2-factor": [
        callback: &AsteroidWeb.LOA2_webflow.start_webflow/2,
        auth_event_set: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
      ],
      "1-factor": [
        callback: &AsteroidWeb.LOA1_webflow.start_webflow/2,
        auth_event_set: [["password"], ["webauthn"]],
        default: true
      ]
    )

    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.put_value("current_acr", "2-factor")
      |> AuthenticatedSession.store()

    {:ok, as} = AuthenticatedSession.get(as.id)

    assert %{acr: "2-factor", amr: nil, auth_time: nil} == AuthenticatedSession.info(as.id)
  end

  test "info function - acr doesn't exist in config" do
    Process.put(:oidc_acr_config,
      "3-factor": [
        callback: &AsteroidWeb.LOA3_webflow.start_webflow/2,
        auth_event_set: [["password", "otp", "webauthn"]]
      ],
      "2-factor": [
        callback: &AsteroidWeb.LOA2_webflow.start_webflow/2,
        auth_event_set: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
      ],
      "1-factor": [
        callback: &AsteroidWeb.LOA1_webflow.start_webflow/2,
        auth_event_set: [["password"], ["webauthn"]],
        default: true
      ]
    )

    {:ok, as} =
      AuthenticatedSession.gen_new("user1id")
      |> AuthenticatedSession.put_value("current_acr", "some_inexistant_acr")
      |> AuthenticatedSession.store()

    {:ok, as} = AuthenticatedSession.get(as.id)

    assert %{acr: "some_inexistant_acr", amr: nil, auth_time: nil} ==
             AuthenticatedSession.info(as.id)
  end
end
