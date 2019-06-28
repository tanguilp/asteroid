# Configuring clients

At first launch, there is no client configured in Asteroid.

To bootstrap Asteroid with a new client, open an iex shell and proceed with the creation
of a new client:

```elixir
iex> alias Asteroid.Client
iex> client = Client.gen_new(id: "test_client")
iex> client = Client.add(client, "client_id", "test_client")
iex> client = Client.add(client, "client_secret", "test_client_secret")
iex> client = Client.add(client, "client_type", "confidential")
iex> client = Client.add(client, "grant_types", ["password", "client_credentials", "refresh_token"])
iex> Client.store(client)
```

Loading the newly created client should display the following output:

```elixir
iex> Client.load("test_client")
{:ok,
 %Asteroid.Client{
   attrs: %{
     "client_id" => "test_client",
     "client_secret" => "test_client_secret",
     "client_type" => "confidential", 
     "grant_types" => ["client_credentials", "password", "refresh_token"]
   },
   id: "test_client",
   modifications: [],
   newly_created: false
 }}
```

Some client attributes are mandatory to make flows work, and are described in `Asteroid.Client`.
For instance, in the previous example:
- the client type is mandatory for client authentication
- the authorization code and implicit flows are *not* enabled. It would require:
  - adding the `"authorization_code"` and `"implicit"` `t:Asteroid.OAuth2.grant_type_str/0` values
  to the `"grant_types"` client attribute
  - adding the `"token"` and `"code"` `t:Asteroid.OAuth2.response_type_str/0` values
  to the `"response_type"` client attribute
  - registering redirect URIs (`"redirect_uris"` client attribute)
- the client secret is not hashed, which is not recommended

To automate the process, consider using
[Dynamic client registration](dynamic-client-registration.html).

Also note that creating subjects (`Asteroid.Subject`) can be done in the same manner.

## Asteroid scopes

Specific permissions can be granted to clients using scopes. Scopes are stored in the
`"scope"` attribute of a client as a list of `String.t()`. These scopes are prefixed with
`"asteroid."` and are:
- `"asteroid.introspect"`: allows a client to introspect tokens on the introspect endpoint.
Note that the client can introspect *all* tokens, not only those issued to it
- `"asteroid.register"`: allows a client to create new clients on the client registration
endpoints
