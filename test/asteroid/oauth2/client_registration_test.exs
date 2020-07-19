defmodule Asteroid.OAuth2.ClientRegistrationTest do
  use ExUnit.Case, async: true

  alias Asteroid.Client
  alias Asteroid.OAuth2.ClientRegistration
  alias OAuth2Utils.Scope

  setup_all do
    %{
      client_confidential_1: Client.load("client_confidential_1") |> elem(1),
      client_confidential_3: Client.load("client_confidential_3") |> elem(1)
    }
  end

  test "registering without client" do
    req_metadata = %{
      "client_name" => "Some client number one",
      "redirect_uris" => ["https://www.example.com/redirect_uri"]
    }

    Process.put(:oauth2_endpoint_register_authorization_policy, :all)

    assert {:ok, metadata} = ClientRegistration.register(req_metadata)
    assert metadata["client_id"] == "some_client_number_one"
    assert metadata["token_endpoint_auth_method"] == "client_secret_basic"
    assert Enum.sort(metadata["grant_types"]) == ["authorization_code", "refresh_token"]
    assert metadata["response_types"] == ["code"]
    assert {:ok, _} = Client.load_from_unique_attribute("client_id", metadata["client_id"])
  end

  test "registering additional metadata added to result plus all standard attributes",
  %{client_confidential_1: client} do
    req_metadata = %{
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

    Process.put(:scope_config, scopes: %{"scp1" => []})
    Process.put(:oauth2_scope_config, scopes: %{"scp2" => []})
    Process.put(:oauth2_flow_ropc_scope_config, scopes: %{"scp3" => []})
    Process.put(:oauth2_flow_client_credentials_scope_config, scopes: %{"scp4" => []})
    Process.put(:oauth2_flow_implicit_scope_config, scopes: %{"scp5" => []})
    Process.put(:oauth2_flow_authorization_code_scope_config, scopes: %{"scp6" => []})

    assert {:ok, metadata} = ClientRegistration.register(req_metadata, client)
    assert metadata["client_id"] == "example_client_number_twenty_one"
    assert metadata["client_name"] == "Example client number twenty one"
    assert metadata["client_name_i18n"]["fr"] == "Client d'exemple numéro un"
    assert metadata["client_name_i18n"]["ru"] == "Примерое приложение номер один"
    assert Enum.sort(metadata["redirect_uris"]) == Enum.sort(req_metadata["redirect_uris"])
    assert metadata["token_endpoint_auth_method"] == "client_secret_basic"
    assert Enum.sort(metadata["grant_types"]) == Enum.sort(req_metadata["grant_types"])
    assert Enum.sort(metadata["response_types"]) == Enum.sort(req_metadata["response_types"])
    assert metadata["client_uri"] == "https://www.example.com"
    assert Scope.Set.equal?(
             Scope.Set.new(Scope.Set.from_scope_param!(metadata["scope"])),
             Scope.Set.new(Scope.Set.from_scope_param!("scp1 scp2 scp3 scp4 scp5 scp6"))
           )
    assert metadata["contacts"] == ["info@example.com"]
    assert metadata["tos_uri"] == "https://www.example.com/tos"
    assert metadata["policy_uri"] == "https://www.example.com/policy"
    assert metadata["jwks_uri"] == "https://www.example.com/jwks"
    assert metadata["software_id"] == "client_01"
    assert metadata["software_version"] == "1.5.2"
    assert metadata["field_1"] == "value 1"
    assert metadata["field_2"] == "value 2"
    assert metadata["field_3"] == nil
    assert metadata["field_4"] == "value 4"

    assert {:ok, client} = Client.load_from_unique_attribute("client_id", metadata["client_id"])

    client =
      Client.fetch_attributes(client, [
        "client_name",
        "client_name_i18n",
        "redirect_uris",
        "token_endpoint_auth_method",
        "grant_types",
        "response_types",
        "client_uri",
        "scope",
        "contacts",
        "tos_uri",
        "policy_uri",
        "jwks_uri",
        "software_id",
        "software_version",
        "field_1",
        "field_2",
        "field_3",
        "field_4",
        "client_secret"
      ])

    assert client.attrs["client_id"] == "example_client_number_twenty_one"
    assert client.attrs["client_name"] == "Example client number twenty one"
    assert client.attrs["client_name_i18n"]["fr"] == "Client d'exemple numéro un"
    assert client.attrs["client_name_i18n"]["ru"] == "Примерое приложение номер один"
    assert Enum.sort(client.attrs["redirect_uris"]) ==
             Enum.sort([
               "https://www.example.com/auth",
               "https://www.example.org/auth",
               "com.example.app:/oauth2redirect/example-provider"
             ])
    assert client.attrs["token_endpoint_auth_method"] == "client_secret_basic"
    assert Enum.sort(client.attrs["grant_types"]) ==
             Enum.sort(["authorization_code", "implicit", "client_credentials", "password"])
    assert Enum.sort(client.attrs["response_types"]) == ["code", "token"]
    assert client.attrs["client_uri"] == "https://www.example.com"
    assert Scope.Set.equal?(
             Scope.Set.new(client.attrs["scope"]),
             Scope.Set.new(Scope.Set.from_scope_param!("scp1 scp2 scp3 scp4 scp5 scp6"))
           )
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
    assert Expwd.secure_compare(metadata["client_secret"], client.attrs["client_secret"])
  end

  test "auto scope granted at the client config level", %{client_confidential_3: client} do
    req_metadata = %{
      "client_name" => "Example client number twenty two",
      "redirect_uris" => ["https://www.example.com/auth"],
      "scope" => "scp11 scp13"
    }

    assert {:ok, metadata} = ClientRegistration.register(req_metadata, client)
    assert metadata["client_id"] == "example_client_number_twenty_two"
    assert Scope.Set.equal?(
             Scope.Set.new(Scope.Set.from_scope_param!(metadata["scope"])),
             Scope.Set.new(Scope.Set.from_scope_param!("scp11 scp13 scp19 scp17 scp18"))
           )

    assert {:ok, client} = Client.load_from_unique_attribute("client_id", metadata["client_id"])
    client = Client.fetch_attributes(client, ["scope"])
    assert client.attrs["client_id"] == "example_client_number_twenty_two"
    assert client.attrs["client_name"] == "Example client number twenty two"
    assert Scope.Set.equal?(
             Scope.Set.new(client.attrs["scope"]),
             Scope.Set.new(Scope.Set.from_scope_param!("scp11 scp13 scp19 scp17 scp18"))
           )
  end

  test "valid jwks", %{client_confidential_1: client} do
    key_1 = %{"e" => "AQAB", "n" => "nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
      HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
      lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
      RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
      2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
      qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ", "kty" => "RSA"}

    key_2 = %{
      "kty" => "EC",
      "crv" => "P-256",
      "x" => "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y" => "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "use" => "enc",
      "kid" => "1"
    }

    req_metadata = %{
      "client_name" => "Example client number twenty three",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "jwks" => %{"keys" => [key_1, key_2]}
    }

    {:ok, metadata} = ClientRegistration.register(req_metadata, client)
    assert metadata["client_id"] == "example_client_number_twenty_three"
    assert metadata["token_endpoint_auth_method"] == "client_secret_basic"
    assert metadata["grant_types"] == ["authorization_code", "refresh_token"]
    assert metadata["response_types"] == ["code"]
    assert {:ok, client} = Client.load_from_unique_attribute("client_id", metadata["client_id"])
    client = Client.fetch_attributes(client, ["jwks"])
    assert key_1 in client.attrs["jwks"]
    assert key_2 in client.attrs["jwks"]
  end

  test "client defaults grant type and auth method", %{client_confidential_3: client} do
    req_metadata = %{
      "client_name" => "Example client number twenty four",
      "redirect_uris" => ["https://www.example.com/auth"]
    }

    {:ok, metadata} = ClientRegistration.register(req_metadata, client)
    assert metadata["client_id"] == "example_client_number_twenty_four"
    assert metadata["token_endpoint_auth_method"] == "client_secret_post"
    assert Enum.sort(metadata["grant_types"]) ==
             Enum.sort(["authorization_code", "client_credentials", "password"])
    assert metadata["response_types"] == ["code"]
    assert {:ok, client} = Client.load_from_unique_attribute("client_id", metadata["client_id"])
    client =
      Client.fetch_attributes(client, [
        "client_id",
        "token_endpoint_auth_method",
        "grant_types",
        "response_types"
      ])
    assert client.attrs["client_id"] == "example_client_number_twenty_four"
    assert client.attrs["token_endpoint_auth_method"] == "client_secret_post"
    assert Enum.sort(client.attrs["grant_types"]) ==
             Enum.sort(["authorization_code", "client_credentials", "password"])
    assert client.attrs["response_types"] == ["code"]
  end

  test "mobile application redirect_uri", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number twenty",
      "redirect_uris" => ["com.example.app:/oauth2redirect/example-provider"]
    }

    assert {:ok, metadata} = ClientRegistration.register(req_metadata, client)
    assert metadata["client_id"] == "example_client_number_twenty"
    assert metadata["token_endpoint_auth_method"] == "client_secret_basic"
    assert Enum.sort(metadata["grant_types"]) == ["authorization_code", "refresh_token"]
    assert metadata["response_types"] == ["code"]
    assert {:ok, _} = Client.load_from_unique_attribute("client_id", metadata["client_id"])
  end

  test "invalid redirect uri", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number seven",
      "redirect_uris" => [
        "https://www.example.com/redirect_uri",
        "https://www.example2.com/redirect_uri",
        "invalid uri",
        "https://www.example3.com/redirect_uri"
      ]
    }

    assert {:error, %ClientRegistration.InvalidRedirectURIError{}} =
      ClientRegistration.register(req_metadata, client)
  end

  test "invalid token endpoint authentication method", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number eight",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "token_endpoint_auth_method" => "auth_invalid_scheme"
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{}} =
      ClientRegistration.register(req_metadata, client)
  end

  test "invalid response type authentication method", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number ten",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "grant_types" => ["implicit", "authorization_code"],
      "response_types" => ["code", "invalid", "token"]
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{}} =
      ClientRegistration.register(req_metadata, client)
  end

  test "incoherent grant and response types 1", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number eleven",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "grant_types" => ["implicit", "client_credentials", "password"],
      "response_types" => ["code", "token"]
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{} = e} =
      ClientRegistration.register(req_metadata, client)
  end

  test "scope not declared neither at the client level or in the conf",
  %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number thirteen",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "scope" => "scp99"
    }

    assert {:error, %ClientRegistration.UnauthorizedRequestedScopesError{} = e} =
      ClientRegistration.register(req_metadata, client)
  end

  test "jwks_uri and jwks at the same time is not allowed", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number fourteen",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "jwks_uri" => "https://appleid.apple.com/auth/keys",
      "jwks" => %{
        "keys" => [%{"e" => "AQAB", "n" => "nj3YJwsLUFl9BmpAbkOswCNVx17Eh9wMO-_AReZwBqfaWFcfG
   HrZXsIV2VMCNVNU8Tpb4obUaSXcRcQ-VMsfQPJm9IzgtRdAY8NN8Xb7PEcYyk
   lBjvTtuPbpzIaqyiUepzUXNDFuAOOkrIol3WmflPUUgMKULBN0EUd1fpOD70p
   RM0rlp_gg_WNUKoW1V-3keYUJoXH9NztEDm_D2MQXj9eGOJJ8yPgGL8PAZMLe
   2R7jb9TxOCPDED7tY_TU4nFPlxptw59A42mldEmViXsKQt60s1SLboazxFKve
   qXC_jpLUt22OC6GUG63p-REw-ZOr3r845z50wMuzifQrMI9bQ", "kty" => "RSA"}]
      }
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{} = e} =
      ClientRegistration.register(req_metadata, client)
  end

  test "software_id is not a string leads to rejection", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number fifteen",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "software_id" => 56
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{} = e} =
      ClientRegistration.register(req_metadata, client)
  end

  test "software_version is not a string leads to rejection", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number sixteen",
      "redirect_uris" => ["https://www.example.com/redirect_uri"],
      "software_version" => ["v5.1.0"]
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{} = e} =
      ClientRegistration.register(req_metadata, client)
  end

  test "authorization code requested without any redirect_uri", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number seventeen",
      "redirect_uris" => [],
      "grant_types" => ["authorization_code"]
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{} = e} =
      ClientRegistration.register(req_metadata, client)
  end

  test "implicit requested without any redirect_uri", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number eighteen",
      "redirect_uris" => [],
      "grant_types" => ["implicit"],
      "response_types" => ["token"]
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{} = e} =
      ClientRegistration.register(req_metadata, client)
  end

  test "redirect_uri is not a list", %{client_confidential_1: client} do
    req_metadata = %{
      "client_name" => "Example client number nineteen",
      "redirect_uris" => %{"key" => "value"},
      "grant_types" => ["implicit"],
      "response_types" => ["token"]
    }

    assert {:error, %ClientRegistration.InvalidClientMetadataFieldError{} = e} =
      ClientRegistration.register(req_metadata, client)
  end

end
