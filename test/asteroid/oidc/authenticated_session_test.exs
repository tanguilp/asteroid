defmodule Asteroid.OIDC.AuthenticatedSessionTest do
  use ExUnit.Case, async: true

  alias Asteroid.OIDC.AuthenticatedSession
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
end
