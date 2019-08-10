defmodule AsteroidWeb.UserinfoControllerTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias Asteroid.Subject
  alias Asteroid.Token.AccessToken
  alias AsteroidWeb.Router.Helpers, as: Routes

  setup_all do
    :ok =
      Subject.gen_new(id: "user_userinfo_test")
      |> Subject.add("sub", "user_userinfo_test")
      |> Subject.add("name", "Full Jr. Name")
      |> Subject.add("family_name", "Name")
      |> Subject.add("given_name", "Full")
      |> Subject.add("profile", "https://www.example.com/profiles/full_name")
      |> Subject.add("picture", "https://www.example.com/pictures/full_name")
      |> Subject.add("gender", "male")
      |> Subject.add("birthdate", DateTime.from_iso8601("2015-01-23T00:00:00Z") |> elem(1))
      |> Subject.add("updated_at", DateTime.from_iso8601("2019-07-17T21:02:47Z") |> elem(1))
      |> Subject.add("email", "full.name@example.com")
      |> Subject.add("email_verified", true)
      |> Subject.add("address", %{
        "street_address" => "42, Sir Example Street",
        "locality" => "St. Exampleburg",
        "postal_code" => "77852",
        "country" => "Groland"
      })
      |> Subject.add("phone_number", "+3942390027")
      |> Subject.add("non_standard_claim_1", "some value")
      |> Subject.store()

      rsa_enc_alg_all =
        JOSE.JWK.generate_key({:rsa, 1024})
        |> Crypto.Key.set_key_use(:enc)

      Client.gen_new(id: "client_userinfo_sig")
      |> Client.add("client_id", "client_userinfo_sig")
      |> Client.add("client_type", "confidential")
      |> Client.add("userinfo_signed_response_alg", "RS384")
      |> Client.add("jwks",
                    [rsa_enc_alg_all |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1)])
      |> Client.store()

      Client.gen_new(id: "client_userinfo_enc")
      |> Client.add("client_id", "client_userinfo_enc")
      |> Client.add("client_type", "confidential")
      |> Client.add("userinfo_signed_response_alg", "RS384")
      |> Client.add("userinfo_encrypted_response_alg", "RSA1_5")
      |> Client.add("userinfo_encrypted_response_enc", "A128GCM")
      |> Client.add("jwks",
                    [rsa_enc_alg_all |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1)])
      |> Client.store()

    %{rsa_enc_alg_all: rsa_enc_alg_all}
  end

  test "Success case - requesting using all scopes values, get req", %{conn: conn} do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["profile", "email", "address", "phone"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("sub", "user_userinfo_test")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.store()

    conn =
      conn
      |> put_req_header("authorization", "Bearer " <> AccessToken.serialize(access_token))
      |> get(Routes.userinfo_path(conn, :show))

    response = json_response(conn, 200)

    assert "application/json" in simplified_content_type_from_conn(conn)
    assert response["sub"] == "user_userinfo_test"
    assert response["name"] == "Full Jr. Name"
    assert response["family_name"] == "Name"
    assert response["given_name"] == "Full"
    refute Map.has_key?(response, "middle_name")
    refute Map.has_key?(response, "nickname")
    refute Map.has_key?(response, "preferred_username")
    assert response["profile"] == "https://www.example.com/profiles/full_name"
    assert response["picture"] == "https://www.example.com/pictures/full_name"
    refute Map.has_key?(response, "website")
    assert response["gender"] == "male"
    assert response["birthdate"] == "2015-01-23T00:00:00Z"
    refute Map.has_key?(response, "zoneinfo")
    refute Map.has_key?(response, "locale")
    assert response["updated_at"] == "2019-07-17T21:02:47Z"
    assert response["email"] == "full.name@example.com"
    assert response["email_verified"] == true
    assert response["address"] == %{
        "street_address" => "42, Sir Example Street",
        "locality" => "St. Exampleburg",
        "postal_code" => "77852",
        "country" => "Groland"
      }
    assert response["phone_number"] == "+3942390027"
    refute Map.has_key?(response, "phone_number_verified")
    refute Map.has_key?(response, "non_standard_claim_1")
  end

  test "Success case - requesting using all scopes values, post req", %{conn: conn} do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["profile", "email", "address", "phone"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("sub", "user_userinfo_test")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.store()

    conn = post(conn,
                Routes.userinfo_path(conn, :show),
                %{"access_token" => AccessToken.serialize(access_token)})

    response = json_response(conn, 200)

    assert "application/json" in simplified_content_type_from_conn(conn)
    assert response["sub"] == "user_userinfo_test"
    assert response["name"] == "Full Jr. Name"
    assert response["family_name"] == "Name"
    assert response["given_name"] == "Full"
    refute Map.has_key?(response, "middle_name")
    refute Map.has_key?(response, "nickname")
    refute Map.has_key?(response, "preferred_username")
    assert response["profile"] == "https://www.example.com/profiles/full_name"
    assert response["picture"] == "https://www.example.com/pictures/full_name"
    refute Map.has_key?(response, "website")
    assert response["gender"] == "male"
    assert response["birthdate"] == "2015-01-23T00:00:00Z"
    refute Map.has_key?(response, "zoneinfo")
    refute Map.has_key?(response, "locale")
    assert response["updated_at"] == "2019-07-17T21:02:47Z"
    assert response["email"] == "full.name@example.com"
    assert response["email_verified"] == true
    assert response["address"] == %{
        "street_address" => "42, Sir Example Street",
        "locality" => "St. Exampleburg",
        "postal_code" => "77852",
        "country" => "Groland"
      }
    assert response["phone_number"] == "+3942390027"
    refute Map.has_key?(response, "phone_number_verified")
    refute Map.has_key?(response, "non_standard_claim_1")
  end

  test "Success case - requesting using only profile and phone, get req", %{conn: conn} do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["profile", "phone"])
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("sub", "user_userinfo_test")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.store()

    conn = 
      conn
      |> put_req_header("authorization", "Bearer " <> AccessToken.serialize(access_token))
      |> get(Routes.userinfo_path(conn, :show))
    
    response = json_response(conn, 200)

    assert "application/json" in simplified_content_type_from_conn(conn)
    assert response["sub"] == "user_userinfo_test"
    assert response["name"] == "Full Jr. Name"
    assert response["family_name"] == "Name"
    assert response["given_name"] == "Full"
    refute Map.has_key?(response, "middle_name")
    refute Map.has_key?(response, "nickname")
    refute Map.has_key?(response, "preferred_username")
    assert response["profile"] == "https://www.example.com/profiles/full_name"
    assert response["picture"] == "https://www.example.com/pictures/full_name"
    refute Map.has_key?(response, "website")
    assert response["gender"] == "male"
    assert response["birthdate"] == "2015-01-23T00:00:00Z"
    refute Map.has_key?(response, "zoneinfo")
    refute Map.has_key?(response, "locale")
    assert response["updated_at"] == "2019-07-17T21:02:47Z"
    refute Map.has_key?(response, "email")
    refute Map.has_key?(response, "email_verified")
    refute Map.has_key?(response, "address")
    assert response["phone_number"] == "+3942390027"
    refute Map.has_key?(response, "phone_number_verified")
    refute Map.has_key?(response, "non_standard_claim_1")
  end

  test "Success case - requesting with no scopes, get req", %{conn: conn} do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("client_id", "client_confidential_1")
      |> AccessToken.put_value("sub", "user_userinfo_test")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.store()

    conn = 
      conn
      |> put_req_header("authorization", "Bearer " <> AccessToken.serialize(access_token))
      |> get(Routes.userinfo_path(conn, :show))
    
    response = json_response(conn, 200)

    assert "application/json" in simplified_content_type_from_conn(conn)
    assert response == %{"sub" => "user_userinfo_test"}
  end

  test "Success case - requesting using all scopes values, signed resp, get req", %{conn: conn} do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["profile", "email", "address", "phone"])
      |> AccessToken.put_value("client_id", "client_userinfo_sig")
      |> AccessToken.put_value("sub", "user_userinfo_test")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.store()

    conn =
      conn
      |> put_req_header("authorization", "Bearer " <> AccessToken.serialize(access_token))
      |> get(Routes.userinfo_path(conn, :show))

    response = response(conn, 200)

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, payload_str, _} = JOSE.JWS.verify_strict(jwk, ["RS384"], response)

    payload = Jason.decode!(payload_str)

    assert "application/jwt" in simplified_content_type_from_conn(conn)
    assert payload["iss"] == OAuth2.issuer()
    assert payload["aud"] == "client_userinfo_sig"
    assert payload["sub"] == "user_userinfo_test"
    assert payload["name"] == "Full Jr. Name"
    assert payload["family_name"] == "Name"
    assert payload["given_name"] == "Full"
    refute Map.has_key?(payload, "middle_name")
    refute Map.has_key?(payload, "nickname")
    refute Map.has_key?(payload, "preferred_username")
    assert payload["profile"] == "https://www.example.com/profiles/full_name"
    assert payload["picture"] == "https://www.example.com/pictures/full_name"
    refute Map.has_key?(payload, "website")
    assert payload["gender"] == "male"
    assert payload["birthdate"] == "2015-01-23T00:00:00Z"
    refute Map.has_key?(payload, "zoneinfo")
    refute Map.has_key?(payload, "locale")
    assert payload["updated_at"] == "2019-07-17T21:02:47Z"
    assert payload["email"] == "full.name@example.com"
    assert payload["email_verified"] == true
    assert payload["address"] == %{
        "street_address" => "42, Sir Example Street",
        "locality" => "St. Exampleburg",
        "postal_code" => "77852",
        "country" => "Groland"
      }
    assert payload["phone_number"] == "+3942390027"
    refute Map.has_key?(payload, "phone_number_verified")
    refute Map.has_key?(payload, "non_standard_claim_1")
  end

  test "Success case - requesting using all scopes values, signed and encrypted resp, get req",
  %{conn: conn, rsa_enc_alg_all: rsa_enc_alg_all}
  do
    {:ok, access_token} =
      AccessToken.gen_new()
      |> AccessToken.put_value("scope", ["profile", "email", "address", "phone"])
      |> AccessToken.put_value("client_id", "client_userinfo_enc")
      |> AccessToken.put_value("sub", "user_userinfo_test")
      |> AccessToken.put_value("exp", now() + 3600)
      |> AccessToken.put_value("iat", now())
      |> AccessToken.store()

    conn =
      conn
      |> put_req_header("authorization", "Bearer " <> AccessToken.serialize(access_token))
      |> get(Routes.userinfo_path(conn, :show))

    response = response(conn, 200)

    {payload_signed, _jwe} = JOSE.JWE.block_decrypt(rsa_enc_alg_all, response)

    {:ok, jwk} = Crypto.Key.get("key_auto_sig")
    jwk = JOSE.JWK.to_public(jwk)

    assert {true, payload_str, _} = JOSE.JWS.verify_strict(jwk, ["RS384"], payload_signed)

    payload = Jason.decode!(payload_str)

    assert "application/jwt" in simplified_content_type_from_conn(conn)
    assert payload["iss"] == OAuth2.issuer()
    assert payload["aud"] == "client_userinfo_enc"
    assert payload["sub"] == "user_userinfo_test"
    assert payload["name"] == "Full Jr. Name"
    assert payload["family_name"] == "Name"
    assert payload["given_name"] == "Full"
    refute Map.has_key?(payload, "middle_name")
    refute Map.has_key?(payload, "nickname")
    refute Map.has_key?(payload, "preferred_username")
    assert payload["profile"] == "https://www.example.com/profiles/full_name"
    assert payload["picture"] == "https://www.example.com/pictures/full_name"
    refute Map.has_key?(payload, "website")
    assert payload["gender"] == "male"
    assert payload["birthdate"] == "2015-01-23T00:00:00Z"
    refute Map.has_key?(payload, "zoneinfo")
    refute Map.has_key?(payload, "locale")
    assert payload["updated_at"] == "2019-07-17T21:02:47Z"
    assert payload["email"] == "full.name@example.com"
    assert payload["email_verified"] == true
    assert payload["address"] == %{
        "street_address" => "42, Sir Example Street",
        "locality" => "St. Exampleburg",
        "postal_code" => "77852",
        "country" => "Groland"
      }
    assert payload["phone_number"] == "+3942390027"
    refute Map.has_key?(payload, "phone_number_verified")
    refute Map.has_key?(payload, "non_standard_claim_1")
  end

  defp simplified_content_type_from_conn(conn) do
    Plug.Conn.get_resp_header(conn, "content-type")
    |> Enum.map(
      fn
        val ->
          case String.split(val, ";") do
            [_] ->
              val

            [type | _] ->
              type
          end
      end
    )
  end
end
