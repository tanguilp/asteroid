alias Asteroid.{Client, Subject}

ExUnit.start()
#Ecto.Adapters.SQL.Sandbox.mode(Asteroid.Repo, :manual)

Client.gen_new(id: "client_confidential_1")
|> Client.add("client_id", "client_confidential_1")
|> Client.add("client_type", "confidential")
|> Client.add("client_secret", "password1")
|> Client.add("grant_types", [
  "authorization_code",
  "implicit",
  "password",
  "client_credentials",
  "refresh_token",
  "urn:ietf:params:oauth:grant-type:device_code"
])
|> Client.add("response_types", [
  "code",
  "token",
  "id_token",
  "id_token token",
  "code id_token",
  "code token",
  "code id_token token"
])
|> Client.add("scope", [
  "scp1", "scp2", "scp3", "scp4", "scp5", "scp6",
  "asteroid.introspect",
  "asteroid.register",
  "openid"
])
|> Client.add("redirect_uris", ["https://www.example.com", "https://example.org/auth/web/"])
|> Client.add("resource_server_name", "https://client1.api")
|> Client.add("__asteroid_oauth2_endpoint_register_additional_metadata_fields",
              ["field_1", "field_2", "field_4"])
|> Client.store()

Client.gen_new(id: "client_confidential_2")
|> Client.add("client_id", "client_confidential_2")
|> Client.add("client_type", "confidential")
|> Client.add("client_secret", "password2")
|> Client.add("grant_types", ["implicit", "refresh_token"])
|> Client.add("scope", ["scp4", "scp5", "scp6", "scp7", "scp8", "scp9"])
|> Client.add("redirect_uris", ["https://www.example.com"])
|> Client.store()

Client.gen_new(id: "client_confidential_3")
|> Client.add("client_id", "client_confidential_3")
|> Client.add("client_type", "confidential")
|> Client.add("client_secret", "password3")
|> Client.add("grant_types", ["authorization_code"])
|> Client.add("response_types", ["code"])
|> Client.add("redirect_uris", ["https://www.example.com"])
|> Client.add("__asteroid_oauth2_mandatory_pkce_use", true)
|> Client.add("__asteroid_oauth2_endpoint_register_allowed_scopes", ["scp11", "scp12", "scp13"])
|> Client.add("__asteroid_oauth2_endpoint_register_auto_scopes", ["scp17", "scp18", "scp19"])
|> Client.add("__asteroid_oauth2_endpoint_register_default_token_endpoint_auth_method",
              "client_secret_post")
|> Client.add("__asteroid_oauth2_endpoint_register_default_grant_types",
              ["authorization_code", "client_credentials", "password"])
|> Client.add("scope", ["asteroid.register"])
|> Client.store()

Client.gen_new(id: "client_public_1")
|> Client.add("client_id", "client_public_1")
|> Client.add("client_type", "public")
|> Client.add("scope", ["scp1", "scp2", "scp3", "scp4", "scp5", "scp6"])
|> Client.add("grant_types", ["authorization_code", "implicit", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"])
|> Client.store()

Client.gen_new(id: "client_public_2")
|> Client.add("client_id", "client_public_2")
|> Client.add("client_type", "public")
|> Client.add("client_secret", "password2")
|> Client.add("scope", ["scp1", "scp2", "scp3", "scp4", "scp7", "scp8"])
|> Client.store()

Subject.gen_new(id: "user_1")
|> Subject.add("sub", "user_1")
|> Subject.add("password", "asteroidftw")
|> Subject.add("nickname", "UsEr OnE")
|> Subject.add("email", "user1@example.com")
|> Subject.add("phone_number", "+3942390027")
|> Subject.add("non_standard_claim_1", "some value")
|> Subject.store()
