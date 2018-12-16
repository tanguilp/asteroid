alias Asteroid.{Client, Subject}

ExUnit.start()
#Ecto.Adapters.SQL.Sandbox.mode(Asteroid.Repo, :manual)

Client.new_from_id("client_confidential_1")
|> elem(1)
|> Client.put_attribute("client_id", "client_confidential_1")
|> Client.put_attribute("client_secret", "password1")
|> Client.put_attribute("grant_types", MapSet.new([
  "authorization_code",
  "implicit",
  "password",
  "client_credentials",
  "refresh_token"
]))
|> Client.put_attribute("scope", MapSet.new(["scp1", "scp2", "scp3", "scp4", "scp5", "scp6"]))
|> Client.put_attribute("permissions", %{"introspect" => true})
|> Client.put_attribute("resource_server_name", "https://client1.api")
|> Client.store()

Client.new_from_id("client_confidential_2")
|> elem(1)
|> Client.put_attribute("client_id", "client_confidential_2")
|> Client.put_attribute("client_secret", "password2")
|> Client.put_attribute("grant_types", MapSet.new([
  "authorization_code",
  "implicit",
  "refresh_token"
]))
|> Client.put_attribute("scope", MapSet.new(["scp4", "scp5", "scp6", "scp7", "scp8", "scp9"]))
|> Client.store()

Client.new_from_id("client_public_1")
|> elem(1)
|> Client.put_attribute("client_id", "client_public_1")
|> Client.put_attribute("scope", MapSet.new(["scp1", "scp2", "scp3", "scp4", "scp5", "scp6"]))
|> Client.put_attribute("grant_types", MapSet.new([
  "authorization_code",
  "implicit",
  "refresh_token"
]))
|> Client.store()

Client.new_from_id("client_public_2")
|> elem(1)
|> Client.put_attribute("client_id", "client_public_2")
|> Client.put_attribute("client_secret", "password2")
|> Client.put_attribute("scope", MapSet.new(["scp1", "scp2", "scp3", "scp4", "scp7", "scp8"]))
|> Client.store()

Subject.new_from_id("user_1")
|> elem(1)
|> Subject.put_attribute("sub", "user_1")
|> Subject.put_attribute("password", "asteroidftw")
|> Subject.store()
