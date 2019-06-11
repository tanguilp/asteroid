defmodule AsteroidWeb.API.OAuth2.RegisterEndpointTest do
  use AsteroidWeb.ConnCase, async: true

  alias Asteroid.Client
  alias OAuth2Utils.Scope
  alias Asteroid.Token.AccessToken

  # error cases

  test "invalid content-type", %{conn: conn} do
    assert_raise Plug.Parsers.UnsupportedMediaTypeError, fn ->
      conn
      |> put_req_header("content-type", "plain/text")
      |> post(AsteroidWeb.Router.Helpers.introspect_endpoint_path(conn, :handle), "Some plain text")
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
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_one"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert response["grant_types"] == ["authorization_code"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load(response["client_id"])
  end

  test ":authenticated_clients policy, unauthenticated client not authorized to create new clients", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number two",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    Process.put(:oauth2_endpoint_register_authorization_policy, :authenticated_clients)

    conn = post(conn, AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
    response = json_response(conn, 401)

    assert response["error"] == "invalid_client"
    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Basic realm="Asteroid")
    assert Plug.Conn.get_resp_header(conn, "www-authenticate") |> List.first() =~
      ~s(Bearer realm="Asteroid")
  end

  test ":authenticated_clients policy, client with bad credentials not authorized to create new clients", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number two",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    Process.put(:oauth2_endpoint_register_authorization_policy, :authenticated_clients)

    conn =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "invalid"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)

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

    Process.put(:oauth2_endpoint_register_authorization_policy, :all)

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_three"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert response["grant_types"] == ["authorization_code"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load(response["client_id"])
  end

  test ":authorized_clients policy, unauthenticated client not authorized to create new clients", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number four",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    response =
      conn
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(401)

    assert response["error"] == "invalid_client"
  end

  test ":authorized_clients policy, authenticated but unauthorized client not authorized to create new clients", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number five",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_2", "password2"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "unauthorized_client"
  end

  test ":authorized_clients policy, client authorized to create new clients, auth basic", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number six",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_six"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert response["grant_types"] == ["authorization_code"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load(response["client_id"])
  end

  test ":authorized_clients policy, client authorized to create new clients, auth bearer", %{conn: conn} do
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
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_six'"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert response["grant_types"] == ["authorization_code"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load(response["client_id"])
  end

  test "invalid redirect uri", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number seven",
      "redirect_uris" => [
        "https://www.example.com/redirect_uri",
        "https://www.example2.com/redirect_uri",
        "invalid uri",
        "https://www.example3.com/redirect_uri",
      ]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_redirect_uri"
  end

  test "invalid token endpoint authentication method", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number eight",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "token_endpoint_auth_method" => "auth_invalid_scheme"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
  end

  test "invalid grant type authentication method", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number nine",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "grant_types" => ["authorization_code", "implicit", "invalid_grant_type"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "Invalid field `grant_types`"
  end

  test "invalid response type authentication method", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number ten",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "grant_types" => ["implicit", "authorization_code"],
      "response_types" => ["code", "invalid", "token"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "Invalid field `response_types`"
  end

  test "incoherent grant and response types 1", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number eleven",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "grant_types" => ["implicit", "client_credentials", "password"],
      "response_types" => ["code", "token"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "must be registered along with the response type"
  end

  test "incoherent grant and response types 2", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number twelve",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "grant_types" => ["implicit", "authorization_code", "client_credentials", "password"],
      "response_types" => ["token"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "must be registered along with the grant type"
  end

  test "Scope not declared neither at the client level or in the conf", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number thirteen",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "scope" => "scp99"
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "requested scopes"
  end

  test "jwks_uri and jwks at the same time is not allowed", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number fourteen",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "jwks_uri" => "https://appleid.apple.com/auth/keys",
      "jwks" => %{"keys" => [%{
         "e" => "AQAB",
         "n" => "nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
   HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
   lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
   RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
   2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
   qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
         "kty" => "RSA"}]}
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "`jwks_uri` and `jwks` fields cannot be present"
  end

  test "software_id is not a string leads to rejection", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number fifteen",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "software_id" => 56
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "software_id"
  end

  test "software_version is not a string leads to rejection", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number sixteen",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "software_version" => ["v5.1.0"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "software_version"
  end

  test "authorization code requested without any redirect_uri", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number seventeen",
      "redirect_uris" => [],
      "grant_types" => ["authorization_code"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "Missing redirect URI"
  end

  test "implicit requested without any redirect_uri", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number eighteen",
      "redirect_uris" => [],
      "grant_types" => ["implicit"],
      "response_types" => ["token"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
    assert response["error_description"] =~ "Missing redirect URI"
  end

  test "redirect_uri is not a list", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number nineteen",
      "redirect_uris" => %{"key" => "value"},
      "grant_types" => ["implicit"],
      "response_types" => ["token"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(400)

    assert response["error"] == "invalid_client_metadata"
  end

  test "mobile application redirect_uri", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number twenty",
      "redirect_uris" => ["com.example.app:/oauth2redirect/example-provider"]
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_twenty"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert response["grant_types"] == ["authorization_code"]
    assert response["response_types"] == ["code"]
    assert {:ok, _} = Client.load(response["client_id"])
  end

  test "additional metadata added to result pus all standard attributes", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number twenty one",
      "client_name#fr" => "Client d'exemple numéro un",
      "client_name#ru" => "Примерое приложение номер один",
      "redirect_uris" => [
        "https://www.example.com/auth",
        "https://www.example.org/auth",
        "com.example.app:/oauth2redirect/example-provider"
      ],
      "token_endpoint_auth_method" => "client_secret_basic",
      "grant_types" => ["authorization_code", "implicit", "client_credentials", "password"],
      "response_types" => ["code", "token"],
      "client_uri" => "https://www.example.com",
      "scope" => "scp1 scp2 scp3 scp4 scp5 scp6",
      "contacts" => ["info@example.com"],
      "tos_uri" => "https://www.example.com/tos",
      "policy_uri" => "https://www.example.com/policy",
      "jwks_uri" => "https://www.example.com/jwks",
      "software_id" => "client_01",
      "software_version" => "1.5.2",
      "field_1" => "value 1",
      "field_2" => "value 2",
      "field_3" => "value 3",
      "field_4" => "value 4"
    }

    Process.put(:scope_config, [scopes: %{"scp1" => []}])
    Process.put(:oauth2_scope_config, [scopes: %{"scp2" => []}])
    Process.put(:oauth2_flow_ropc_scope_config, [scopes: %{"scp3" => []}])
    Process.put(:oauth2_flow_client_credentials_scope_config, [scopes: %{"scp4" => []}])
    Process.put(:oauth2_flow_implicit_scope_config, [scopes: %{"scp5" => []}])
    Process.put(:oauth2_flow_authorization_code_scope_config, [scopes: %{"scp6" => []}])

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_twenty_one"
    assert response["client_name"] == "Example client number twenty one"
    assert response["client_name_i18n"]["fr"] == "Client d'exemple numéro un"
    assert response["client_name_i18n"]["ru"] == "Примерое приложение номер один"
    assert Enum.sort(response["redirect_uris"]) == Enum.sort([
        "https://www.example.com/auth",
        "https://www.example.org/auth",
        "com.example.app:/oauth2redirect/example-provider"
      ])
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert Enum.sort(response["grant_types"]) == Enum.sort([
      "authorization_code", "implicit", "client_credentials", "password"])
    assert Enum.sort(response["response_types"]) == ["code", "token"]
    assert response["client_uri"] == "https://www.example.com"
    assert Scope.Set.equal?(
      Scope.Set.new(Scope.Set.from_scope_param!(response["scope"])),
      Scope.Set.new(Scope.Set.from_scope_param!("scp1 scp2 scp3 scp4 scp5 scp6")))
    assert response["contacts"] == ["info@example.com"]
    assert response["tos_uri"] == "https://www.example.com/tos"
    assert response["policy_uri"] == "https://www.example.com/policy"
    assert response["jwks_uri"] == "https://www.example.com/jwks"
    assert response["software_id"] == "client_01"
    assert response["software_version"] == "1.5.2"
    assert response["field_1"] == "value 1"
    assert response["field_2"] == "value 2"
    assert response["field_3"] == nil
    assert response["field_4"] == "value 4"

    assert {:ok, client} = Client.load(response["client_id"])

    client = Client.fetch_attributes(client, [
      "client_name", "client_name_i18n", "redirect_uris", "token_endpoint_auth_method",
      "grant_types", "response_types", "client_uri", "scope", "contacts",
      "tos_uri", "policy_uri", "jwks_uri", "software_id", "software_version", "field_1",
      "field_2", "field_3", "field_4", "client_secret"
    ])

    assert client.attrs["client_id"] == "example_client_number_twenty_one"
    assert client.attrs["client_name"] == "Example client number twenty one"
    assert client.attrs["client_name_i18n"]["fr"] == "Client d'exemple numéro un"
    assert client.attrs["client_name_i18n"]["ru"] == "Примерое приложение номер один"
    assert Enum.sort(client.attrs["redirect_uris"]) == Enum.sort([
        "https://www.example.com/auth",
        "https://www.example.org/auth",
        "com.example.app:/oauth2redirect/example-provider"
      ])
    assert client.attrs["token_endpoint_auth_method"] == "client_secret_basic"
    assert Enum.sort(client.attrs["grant_types"]) == Enum.sort([
      "authorization_code", "implicit", "client_credentials", "password"])
    assert Enum.sort(client.attrs["response_types"]) == ["code", "token"]
    assert client.attrs["client_uri"] == "https://www.example.com"
    assert Scope.Set.equal?(
      Scope.Set.new(client.attrs["scope"]),
      Scope.Set.new(Scope.Set.from_scope_param!("scp1 scp2 scp3 scp4 scp5 scp6")))
    assert client.attrs["contacts"] == ["info@example.com"]
    assert client.attrs["tos_uri"] == "https://www.example.com/tos"
    assert client.attrs["policy_uri"] == "https://www.example.com/policy"
    assert client.attrs["jwks_uri"] == "https://www.example.com/jwks"
    assert client.attrs["software_id"] == "client_01"
    assert client.attrs["software_version"] == "1.5.2"
    assert client.attrs["__asteroid_created_by_client_id"] == "client_confidential_1"
    assert client.attrs["field_1"] == "value 1"
    assert client.attrs["field_2"] == "value 2"
    assert client.attrs["field_3"] == nil
    assert client.attrs["field_4"] == "value 4"

    assert Expwd.secure_compare(response["client_secret"], client.attrs["client_secret"])
  end

  test "auto scope granted at the client config level", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number twenty two",
      "redirect_uris" => ["https://www.example.com/auth"],
      "scope" => "scp11 scp13",
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_3", "password3"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_twenty_two"
    assert Scope.Set.equal?(
      Scope.Set.new(Scope.Set.from_scope_param!(response["scope"])),
      Scope.Set.new(Scope.Set.from_scope_param!("scp11 scp13 scp19 scp17 scp18")))

    assert {:ok, client} = Client.load(response["client_id"])

    client = Client.fetch_attributes(client, ["scope"])

    assert client.attrs["client_id"] == "example_client_number_twenty_two"
    assert client.attrs["client_name"] == "Example client number twenty two"
    assert Scope.Set.equal?(
      Scope.Set.new(client.attrs["scope"]),
      Scope.Set.new(Scope.Set.from_scope_param!("scp11 scp13 scp19 scp17 scp18")))
  end

  test "valid jwks", %{conn: conn} do
    key_1 = %{
      "e" => "AQAB",
      "n" => "nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
      HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
      lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
      RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
      2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
      qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ",
      "kty" => "RSA"}

    key_2 = %{"kty" => "EC",
      "crv" => "P-256",
      "x" => "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y" => "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "use" => "enc",
      "kid" => "1"}

    req_body = %{
      "client_name" => "Example client number twenty three",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "jwks" => %{"keys" => [key_1, key_2]}
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_1", "password1"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_twenty_three"
    assert response["token_endpoint_auth_method"] == "client_secret_basic"
    assert response["grant_types"] == ["authorization_code"]
    assert response["response_types"] == ["code"]

    assert {:ok, client} = Client.load(response["client_id"])

    client = Client.fetch_attributes(client, ["jwks"])

    assert {:binary_data, :erlang.term_to_binary(key_1)} in client.attrs["jwks"]
    assert {:binary_data, :erlang.term_to_binary(key_2)} in client.attrs["jwks"]
  end

  test "client defaults grant type and auth method", %{conn: conn} do
    req_body = %{
      "client_name" => "Example client number twenty four",
      "redirect_uris" => ["https://www.example.com/auth"],
    }

    response =
      conn
      |> put_req_header("authorization", basic_auth_header("client_confidential_3", "password3"))
      |> post(AsteroidWeb.Router.Helpers.register_endpoint_path(conn, :handle), req_body)
      |> json_response(201)

    assert response["client_id"] == "example_client_number_twenty_four"
    assert response["token_endpoint_auth_method"] == "client_secret_post"
    assert Enum.sort(response["grant_types"]) ==
      Enum.sort(["authorization_code", "client_credentials", "password"])
    assert response["response_types"] == ["code"]

    assert {:ok, client} = Client.load(response["client_id"])

    client = Client.fetch_attributes(client, [
      "client_id", "token_endpoint_auth_method", "grant_types", "response_types"])

    assert client.attrs["client_id"] == "example_client_number_twenty_four"
    assert client.attrs["token_endpoint_auth_method"] == "client_secret_post"
    assert Enum.sort(client.attrs["grant_types"]) ==
      Enum.sort(["authorization_code", "client_credentials", "password"])
    assert client.attrs["response_types"] == ["code"]
  end

  defp basic_auth_header(client, secret) do
    "Basic " <> Base.encode64(client <> ":" <> secret)
  end

end
