# Configuring resources

A resource is an instantiation of `AttributeRepository.Resource` with specific backend
configuration (LDAP, Mnesia, Riak...).

Asteroid defines 3 types of resources:
- `Asteroid.Client` (application)
- `Asteroid.Subject` (user)
- `Asteroid.Device`

## API to access resources

An `AttributeRepository.Resource` provides 2 functions to load a specific resource:
- `load/2`
- `load_from_unique_attribute/3`

It's important to have in mind that in the case of `Asteroid.Client` and `Asteroid.Subject`,
the resource id may be different of the natural id of these resources, respectively the
`"client_id"` and `"sub"` OAuth2 values.

It may happen that they are the same, but this is not always the case. For instance, when using
LDAP as the backend for a resource, it is unlikely that they will be similar since the resource
id would be the DN of the LDAP entry, and the `"client_id"` or the `"sub"` another value.

For example a resource from an LDAP instantiation would look like:

```elixir
%Asteroid.Subject{
  attrs: %{
    "cn" => ["John Doe"],
    "displayName" => "John Doe",
    "givenName" => ["John"],
    "mail" => ["john.doe@example.com"],
    "manager" => ["uid=46254,ou=People,dc=example,dc=org"],
    "sn" => ["Doe"],
    "sub" => "user32572",
    "uid" => "214241"
  },
  id: "uid=john,ou=People,dc=example,dc=org",
  modifications: [],
  newly_created: false
}
```

When retrieving a resource from data gathered during the OAuth2 flows, it is much more likely
that the `"client_id"` and `"sub"` attributes will be used than the technical id
(which are `t:AttributeRepository.Resource.id/0`s). Use of `load_from_unique_attribute/3` is much
more frequent than the use of `load/2`.

As a consequence:
- it is highly recommended that the backend is optimized for querying the `"client_id"` attribute
of the `Asteroid.Client` resource, and the `"sub"` of the `Asteroid.Subject` resource since
they are often queried, for instance by setting an index on them
- even if the resource id of a `Asteroid.Client` *is* its client id, it is necessary that the
`"client_id"` exists in the resource. The same applies for `Asteroid.Subject` with the `"sub"`
attribute.

When loading a resource, the aforementioned functions preload the attributes specified by the
configuration of that resource (the `:default_loaded_attributes` option). For instance, using
LDAP, one can configured the loading of 6 attributes this way:

```elixir
subject: [
  module: AttributeRepositoryLdap,
  init_opts: [
    name: :slapd,
    max_overflow: 10,
    ldap_args: [hosts: ['localhost'], base: 'ou=people,dc=example,dc=org']
  ],
  run_opts: [instance: :slapd, base_dn: 'ou=people,dc=example,dc=org'],
  auto_install: false, # AttributeRepositoryLdap has no install callback implemented
  default_loaded_attributes: ["cn", "displayName", "givenName", "mail", "manager", "sn"]
]
```

Some backends, such as Riak, will necessarily load all the attributes. Others will load none,
unless specified in the configuration options. This is why when working with resources, one
has to make sure to have the attributes loaded using the `fetch_attribute/2` function of the
resource, especially in callback functions. Not doing it could result in failure in the case
of change of backend (from one backend loaded all attributes to one loading none).

As an example, here is how to load needed attributes in a callback function:

```elixir
def introspect_add_subject_attributes(response, %{subject: subject}) do
  subject = Subject.fetch_attributes(subject, ["mail", "permissions"])

  # do something with the subject
end
```

For performance reasons, the backend repository will be requested only for attributes not already
present in the resource object (and will not be requested at all the attributes have already been
loaded).

Note that the dynamic client registration has a callback to compute a *client resource id* (in
addition to a callback to compute a new *client id*).

## Clients

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

## Asteroid scopes for clients

Specific permissions can be granted to clients using scopes. Scopes are stored in the
`"scope"` attribute of a client as a list of `String.t()`. These scopes are prefixed with
`"asteroid."` and are:
- `"asteroid.introspect"`: allows a client to introspect tokens on the introspect endpoint.
Note that the client can introspect *all* tokens, not only those issued to it
- `"asteroid.register"`: allows a client to create new clients on the client registration
endpoints

## Subjects

At first launch, there are no subjects configured neither. The only mandatory attribute
for subject is `"sub"`.

One can create a subject in the iex shell with the following command:

```elixir
iex> alias Asteroid.Subject                                                                       
Asteroid.Subject
iex> Subject.gen_new() |> Subject.add("sub", "sub_001") |> Subject.add("first_name", "Aliénor") |> Subject.add("last_name", "Dupond") |> Subject.store()
:ok
iex> Subject.load_from_unique_attribute("sub", "sub_001") 
{:ok,
 %Asteroid.Subject{
   attrs: %{
     "first_name" => "Aliénor",
     "last_name" => "Dupond",
     "sub" => "sub_001"
   },
   id: "sub-PTDVWXZYZshHlDR5JoeKWw",
   modifications: [],
   newly_created: false
 }}
```

(Example with the Mnesia backend and a custom function to generate resource ids. Refer to the
`AttributeRepository.Resource` documentation for resource id generation.)
