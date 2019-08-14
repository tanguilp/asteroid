# Customizing

## Web flows

There is no specific way to customize web flows, i.e. implementing the web processes
(authentication, authorization, device registration...) in the authorization code, implicit and
device authorization flows.

It is simply recommended to follow the Phoenix way, which is to code your flows in the
`/lib/asteroid_web` directory following Phoenixes' conventions.

## Using callbacks

As specified in `Asteroid.Config`, the configuration options ending with `"_callback"` can
be used to implement specific behaviour. See them as hooks on the Asteroid APIs and web flows.

A `t:Asteroid.Context.t/0` map will be passed to these callback. This can be useful, for
instance, to make the difference between an access token issued for the first time in the
ROPC flow (the grant type will be set to `:password`) and an access token release after
presentation of the refresh token obtained in the first request of this flow (grant type
will be `:refresh_token`.

Note that in that specific case, the refresh token keeps the information on the initial flow.

### Configuration

Asteroid ships with a `custom_example` directory at its root, that implements the functions for
the 2 following examples. It is recommended that you create your own `custom` directory.

When creating a new directory, it is necessary to modify the `mix.exs` file to include
the directory's path in the list of directories to be compiled. 

The `mix.exs` file shipped by default looks like:

```elixir
  defp elixirc_paths(:dev), do: ["lib", "custom_example"]
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]
```

After adding a `custom` directory and disabling the `custom_example` one, it would look like:

```elixir
  defp elixirc_paths(:dev), do: ["lib", "custom"]
  defp elixirc_paths(:test), do: ["lib", "test/support", "custom"]
  defp elixirc_paths(_), do: ["lib", "custom"]
```

### Example 1: dad joke in access tokens in the client credentials flow

The client credentials flow is sad and boring because of its simplicity. Its relevance is
sometimes questioned. Let's bring joy again to it. In this example, we will add a dad joke using
the
[`:token_store_access_token_before_store_callback`](Asteroid.Config.html#module-token_store_access_token_before_store_callback)
configuration option.

The joke is retrieved from [https://icanhazdadjoke.com/](https://icanhazdadjoke.com):
```bash
$ curl https://icanhazdadjoke.com/
Wife told me to take the spider out instead of killing it... We had some drinks, cool guy, wants to be a web developer.
```

or in the Elixir shell, using the HTTPoison library:

```elixir
iex> HTTPoison.get("https://icanhazdadjoke.com/", [{"Accept", "text/plain"}])
{:ok,
 %HTTPoison.Response{
   body: "I went to a book store and asked the saleswoman where the Self Help section was, she said if she told me it would defeat the purpose.",
   headers: [
     {"Date", "Wed, 26 Jun 2019 20:46:59 GMT"},
     {"Content-Type", "text/plain"},
     {"Content-Length", "133"},
     {"Connection", "keep-alive"},
     {"Set-Cookie",
      "__cfduid=db4a947725c3bfeb16091a20dcb677ab21561582019; expires=Thu, 25-Jun-20 20:46:59 GMT; path=/; domain=.icanhazdadjoke.com; HttpOnly"},
     {"Cache-Control",
      "max-age=0, must-revalidate, no-cache, no-store, public, s-maxage=0"},
     {"X-Frame-Options", "DENY"},
     {"X-Xss-Protection", "1; mode=block"},
     {"Strict-Transport-Security", "max-age=15552000; includeSubDomains"},
     {"X-Content-Type-Options", "nosniff"},
     {"Expect-CT",
      "max-age=604800, report-uri=\"https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct\""},
     {"Server", "cloudflare"},
     {"CF-RAY", "4ed208a2f9fc8f55-DME"}
   ],
   request: %HTTPoison.Request{
     body: "",
     headers: [{"Accept", "text/plain"}],
     method: :get,
     options: [],
     params: %{},
     url: "https://icanhazdadjoke.com/"
   },
   request_url: "https://icanhazdadjoke.com/",
   status_code: 200
 }}
```

First, let's create the callback function in `/custom_example/callback.ex`:

```elixir
alias Asteroid.Token.AccessToken

def add_dad_joke(access_token, %{flow: :client_credentials}) do
  response = HTTPoison.get!("https://icanhazdadjoke.com/", [{"Accept", "text/plain"}])

  AccessToken.put_value(access_token, "dad_joke", response.body)
end

def add_dad_joke(access_token, _ctx) do
  access_token
end
```

Notice that there is a second clause matching when the flow is not `:client_credentials`, which
simply returns the access token as is. Also, there is no error handling in this example.

Then change the related configuration option:

```elixir
config :asteroid, :token_store_access_token_before_store_callback,
  &Asteroid.Config.DefaultCallbacks.id_first_param/2
```

becomes:

```elixir
config :asteroid, :token_store_access_token_before_store_callback,
  &CustomExample.Callback.add_dad_joke/2
```

We also need to include the `"dad_joke"` in the claims returned by the `/api/oauth2/introspect`
endpoint, using the
[`:oauth2_endpoint_introspect_claims_resp`](Asteroid.Config.html#module-oauth2_endpoint_introspect_claims_resp)
configuration option:

```elixir
config :asteroid, :oauth2_endpoint_introspect_claims_resp,
  ["scope", "client_id", "username", "token_type", "exp", "iat", "nbf", "sub", "aud", "iss", "jti", "dad_joke"]
```

We need to create an authorized client, for instance using Elixir shell:

```elixir
iex> alias Asteroid.Client
Asteroid.Client
iex> Client.gen_new(id: "client1") |> Client.add("client_id", "client1") |> Client.add("client_secret", "password1") |> Client.add("grant_types", ["client_credentials"]) |> Client.add("scope", ["asteroid.introspect"]) |> Client.store()
:ok
```

(We add the `"asteroid.introspect"` scope so that the client is granted access to the
`/api/oauth2/introspect` endpoint.)

Then let's request a new access token:

```bash
$ curl -u client1:password1 -d "grant_type=client_credentials" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "328ToeX47XqKKyTAep-sZPYWek8",
  "expires_in": 599,
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}
```

and introspect it:

```bash
$ curl -u client1:password1 -d "token=328ToeX47XqKKyTAep-sZPYWek8" http://localhost:4000/api/oauth2/introspect | jq
{
  "active": true,
  "client_id": "client1",
  "dad_joke": "I was at the library and asked if they have any books on \"paranoia\", the librarian replied, \"yes, they are right behind you\"",
  "exp": 1561583853,
  "iat": 1561583253,
  "iss": "http://localhost:4000",
  "scope": [
    "scope-a",
    "scope-b",
    "scope-f"
  ]
}
```

### Example 2: adding subject data to `/introspect` response

In this example, we want to return additional subject data on the `/api/oauth2/introspect`
endpoint.

We will use the
[`:oauth2_endpoint_introspect_before_send_resp_callback`](Asteroid.Config.html#module-oauth2_endpoint_introspect_before_send_resp_callback)
for that.

First, we create a custom callback function in `/custom_example/callback.ex`:

```elixir
import Asteroid.Utils

alias Asteroid.Subject

def introspect_add_subject_attributes(response, %{subject: subject}) do
  subject = Subject.fetch_attributes(subject, ["mail", "permissions"])

  response
  |> put_if_not_nil("email_address", subject.attrs["mail"])
  |> put_if_not_nil("permissions", subject.attrs["permissions"])
end

def introspect_add_subject_attributes(response, _) do
  response
end
```

Fetching the attributes is recommended, because an `Asteroid.Subject` (or `Asteroid.Client`,
`Asteroid.Device`) may not have loaded all attributes upon creation. It depends on:
- the backend: LDAP and Mnesia allow selective loading of attributes. Riak, on the contrary,
will always load the whole object
- the attribute repository `:default_loaded_attributes` configuration

The repository will be requested only if there are unloaded attributes, and only the missing
attributes will be requested.

Again, we define a function clause that matches all cases for tokens that wouldn't have a
subject (those issued in the client credentials flow for example).

Configuration needs to be changed:

```elixir
config :asteroid, :oauth2_endpoint_introspect_before_send_resp_callback,
  &CustomExample.Callback.introspect_add_subject_attributes/2
```

Now let's create a client and a subject in the Elixir shell:

```elixir
iex> alias Asteroid.Subject
Asteroid.Subject
iex> alias Asteroid.Client
Asteroid.Client
iex> Client.gen_new(id: "client1") |> Client.add("client_id", "client1") |> Client.add("client_secret", "password1") |> Client.add("grant_types", ["password"]) |> Client.add("scope", ["asteroid.introspect"]) |> Client.store()
:ok
iex> Subject.gen_new(id: "sub1") |> Subject.add("sub", "sub1") |> Subject.add("password", "password1") |> Subject.add("mail", "eleonor.oreilly@example.com") |> Subject.add("permissions", ["obj_001_ro", "obj_003_rw", "obj_370_rw"]) |> Subject.store()
:ok
```

Request new credentials using the ROPC flow:

```bash
$ curl -u client1:password1 -d "grant_type=password&username=sub1&password=password1" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "Q4b0Ofi-qP9MM11GPezs2cnR51g",
  "expires_in": 600,
  "refresh_token": "HdAMNzuNX8kWWrumwJCGG_Ruqlp79i-qyKjZbbo0Ae0",
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}
```

and introspect it:

```bash
$ curl -u client1:password1 -d "token=Q4b0Ofi-qP9MM11GPezs2cnR51g" http://localhost:4000/api/oauth2/introspect | jq
{
  "active": true,
  "client_id": "client1",
  "email_address": "eleonor.oreilly@example.com",
  "exp": 1561651175,
  "iat": 1561650575,
  "iss": "http://localhost:4000",
  "permissions": [
    "obj_370_rw",
    "obj_003_rw",
    "obj_001_ro"
  ],
  "scope": [
    "scope-a",
    "scope-b",
    "scope-f"
  ],
  "sub": "sub1"
}
```

Since callbacks are called last (after other functions that help with forming the response), the
[`:oauth2_endpoint_introspect_claims_resp`](Asteroid.Config.html#module-oauth2_endpoint_introspect_claims_resp)
configuration option has already been applied, which is why there is no need to modify it to
include the `"email_address"` and `"permissions"` attributes.

### Example 3: adding current session information to `/introspect` response

In this example, we want to return information on the current web authenticated session, when
available, on the `/introspect` endpoint. Session information can be retrieved from an
authenticated session (or authenticated session id) using the
`Asteroid.OIDC.AuthenticatedSession.info/2` function.

We still need, however, to retrieve the authenticated session id from the access or refresh
token being introspected. This id, when set (i.e. in the OpenID Connect flows) is set as an
attribute of these tokens in the `__asteroid_oidc_authenticated_session_id` flow.

We will use the
[`:oauth2_endpoint_introspect_before_send_resp_callback`](Asteroid.Config.html#module-oauth2_endpoint_introspect_before_send_resp_callback)
as in the previous example.

First, we create a custom callback function in `/custom_example/callback.ex`:

```elixir
def introspect_add_authenticated_session_info(response,
                                              %{token: token, token_sort: token_sort})
do
  maybe_authenticated_session_id =
    if token.data["__asteroid_oidc_authenticated_session_id"] do
     token.data["__asteroid_oidc_authenticated_session_id"]
    else
      # this attribute is not set on access tokens in non-implicit flows

      if token_sort == :access_token and token.refresh_token_id do
        {:ok, refresh_token} = RefreshToken.get(token.refresh_token_id)

        refresh_token.data["__asteroid_oidc_authenticated_session_id"]
      end
    end

  if maybe_authenticated_session_id do
    session_info = OIDC.AuthenticatedSession.info(maybe_authenticated_session_id) || %{}

    response
    |> put_if_not_nil("current_acr", session_info[:acr])
    |> put_if_not_nil("current_amr", session_info[:amr])
    |> put_if_not_nil("current_auth_time", session_info[:auth_time])
  else
    response
  end
end
```

and then we set the callback in the configuration file:
```elixir
config :asteroid, :oauth2_endpoint_introspect_before_send_resp_callback,
  &CustomExample.Callback.introspect_add_authenticated_session_info/2
```

and introspect a token granted after using an OpenID Connect flow (using the client and subject
used in example 2):

```bash
$ curl -u client1:password1 -d "token=Q4b0Ofi-qP9MM11GPezs2cnR51g" http://localhost:4000/api/oauth2/introspect | jq
{
  "active": true,
  "client_id": "client1",
  "current_acr": "3-factor",
  "current_amr": [
    "otp",
    "phr",
    "pwd"
  ],
  "current_auth_time": 1561649841,
  "exp": 1561651175,
  "iat": 1561650575,
  "iss": "http://localhost:4000",
  "sub": "sub1"
}
```
