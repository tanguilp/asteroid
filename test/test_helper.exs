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
  "refresh_token"
])
|> Client.add("response_types", ["code"])
|> Client.add("scope", ["scp1", "scp2", "scp3", "scp4", "scp5", "scp6", "asteroid.introspect"])
|> Client.add("redirect_uris", ["https://www.example.com", "https://example.org/auth/web/"])
|> Client.add("resource_server_name", "https://client1.api")
|> Client.store()

Client.gen_new(id: "client_confidential_2")
|> Client.add("client_id", "client_confidential_2")
|> Client.add("client_type", "confidential")
|> Client.add("client_secret", "password2")
|> Client.add("grant_types", ["implicit", "refresh_token"])
|> Client.add("scope", ["scp4", "scp5", "scp6", "scp7", "scp8", "scp9"])
|> Client.add("redirect_uris", ["https://www.example.com"])
|> Client.store()

Client.gen_new(id: "client_public_1")
|> Client.add("client_id", "client_public_1")
|> Client.add("client_type", "public")
|> Client.add("scope", ["scp1", "scp2", "scp3", "scp4", "scp5", "scp6"])
|> Client.add("grant_types", ["authorization_code", "implicit", "refresh_token"])
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
|> Subject.store()
