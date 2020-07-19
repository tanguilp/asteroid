defmodule AsteroidWeb.API.OAuth2.RegisterControllerTest do
  use AsteroidWeb.ConnCase, async: true

  alias OAuth2Utils.Scope
  alias AsteroidWeb.Router.Helpers, as: Routes
  alias Asteroid.Client
  alias Asteroid.Token.AccessToken

  # error cases

  test "invalid content-type", %{conn: conn} do
    assert_raise Plug.Parsers.UnsupportedMediaTypeError, fn ->
      conn
      |> put_req_header("content-type", "plain/text")
      |> post(Routes.register_path(conn, :handle), "Some plain text")
      |> json_response(400)
    end
  end

  test ":all policy, unauthenticated client authorized to create new clients", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number one",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    Process.put(:oauth2_endpoint_register_authorization_policy, :all)

    response =
      conn
      |> post(Routes.register_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_one"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert Enum.sort(response["grant_types"]) == ["authorization_code", "refresh_token"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load_from_unique_attribute("client_id", response["client_id"])
  end

  test ":authenticated_clients policy, unauthenticated client not authorized to create new clients",
       %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number two",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    Process.put(:oauth2_endpoint_register_authorization_policy, :authenticated_clients)

    conn = post(conn, Routes.register_path(conn, :handle), req_body)
    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
             ~s(Basic realm="Asteroid")

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
             ~s(Bearer realm="Asteroid")
  end

  test ":authenticated_clients policy, client with bad credentials not authorized to create new clients",
       %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number two",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    Process.put(:oauth2_endpoint_register_authorization_policy, :authenticated_clients)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "invalid"))
      |> post(Routes.register_path(conn, :handle), req_body)

    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"

    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
             ~s(Basic realm="Asteroid")
  end

  test ":authenticated_client policy, client authorized to create new clients", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number three",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    Process.put(:oauth2_endpoint_register_authorization_policy, :authenticated_clients)

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(Routes.register_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_three"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert response["grant_types"] == ["authorization_code"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load_from_unique_attribute("client_id", response["client_id"])
  end

  test ":authorized_clients policy, unauthenticated client not authorized to create new clients",
       %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number four",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    response =
      conn
      |> post(Routes.register_path(conn, :handle), req_body)
      |> json_response(401)

    assert response["error"] == "invalid_client"
  end

  test ":authorized_clients policy, authenticated but unauthorized client not authorized to create new clients",
       %{conn: conn} do
    Process.put(:oauth2_endpoint_register_authorization_policy, :authorized_clients)

    req_body = %{
      "client_name" => "Example client number five",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(Routes.register_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "unauthorized_client"
  end

  test ":authorized_clients policy, client authorized to create new clients, auth basic", %{
    conn: conn
  } do
    Process.put(:oauth2_endpoint_register_authorization_policy, :authorized_clients)

    req_body = %{
      "client_name" => "Example client number six",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(Routes.register_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_six"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert response["grant_types"] == ["authorization_code"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load_from_unique_attribute("client_id", response["client_id"])
  end

  test ":authorized_clients policy, client authorized to create new clients, auth bearer", %{
    conn: conn
  } do
    Process.put(:oauth2_endpoint_register_authorization_policy, :authorized_clients)

    req_body = %{
      "client_name" => "Example client number six'",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", "asteroid.register")
      |> AccessToken.store()

    response =
      conn
      |> put_req_header("authorization", "Bearer " <> AccessToken.serialize(access_token))
      |> post(Routes.register_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_six'"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert Enum.sort(response["grant_types"]) == ["authorization_code", "refresh_token"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load_from_unique_attribute("client_id", response["client_id"])
  end

  defp basic_auth_header(client, secret) do
    "Basic " <> Base.encode64(client <> ":" <> secret)
  end
end
