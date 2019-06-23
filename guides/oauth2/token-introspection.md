# Token Introspection (RFC7662)

Asteroid implements token introspection
([RFC7662](https://tools.ietf.org/html/rfc7662).

This protocols allows checking the validity of access and refresh tokens, and introspect
their information. It is reachable on the `/api/oauth2/introspect` endpoint.

## Support

Token sorts:
- [x] access tokens
- [x] refresh tokens

## Client authentication and authorization

Client authorized to access this endpoint are those having the `"asteroid.introspect"`scope
configured in their `"scope"` attribute as documented in
[Configuring clients](configuring-clients.html), independently of the authentication scheme
used. Note that authentication is mandatory on this endpoint, as per the specification.

## Issued metadata

Since tokens can store much more data fields than the standard ones, Asteroid filters out
which fields will be returned on this endpoint using the
[`:oauth2_endpoint_introspect_claims_resp_callback`](Asteroid.Config.html#module-oauth2_endpoint_introspect_claims_resp_callback)
configuration option which defaults to the
`Asteroid.OAuth2.Callback.endpoint_introspect_claims_resp/1` function, itself using the
[`:oauth2_endpoint_introspect_claims_resp`](Asteroid.Config.html#module-oauth2_endpoint_introspect_claims_resp)
configuration option which consists in a list of fields to be returned.

## Example

The following makes use of the ROPC flow.

First create new clients and subject in the elixir shell:

```elixir
iex> alias Asteroid.Client
Asteroid.Client
iex> alias Asteroid.Subject
Asteroid.Subject
iex> Client.gen_new(id: "client1") |> Client.add("client_id", "client1") |> Client.add("client_secret", "password1") |> Client.add("grant_types", ["password"]) |> Client.store()
:ok
iex> Client.gen_new(id: "api_1") |> Client.add("client_id", "api_1") |> Client.add("client_secret", "password1") |> Client.add("scope", ["asteroid.introspect"]) |> Client.store()
:ok
iex> Subject.gen_new(id: "sub1") |> Subject.add("sub", "sub1") |> Subject.add("password", "password1") |> Subject.store()
:ok
```

We simulate a client (`"client_1"`) and an API (`"api_1"`) on which the client will consume
access tokens.

Then request new tokens on the `/api/oauth2/token` endpoint:

```bash
$ curl -u client1:password1 -d "grant_type=password&username=sub1&password=password1" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "9JXdbywoSE1b9U7VSXIR0JgqE-g",
  "expires_in": 600,
  "refresh_token": "uNBWI1xZT8DbtRH2NXbCynLeF2DR1Mh9V7kuzQaG5s4",
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}
```

And introspect the access token with the API:

```bash
$ curl -u api_1:password1 -d "token=9JXdbywoSE1b9U7VSXIR0JgqE-g" http://localhost:4000/api/oauth2/introspect | jq
{
  "active": true,
  "client_id": "client1",
  "exp": 1561326489,
  "iat": 1561325889,
  "iss": "http://localhost:4000",
  "scope": [
    "scope-a",
    "scope-b",
    "scope-f"
  ],
  "sub": "sub1"
}
```

After a few minutes the token becomes inactive:

```bash
$ curl -u api_1:password1 -d "token=9JXdbywoSE1b9U7VSXIR0JgqE-g" http://localhost:4000/api/oauth2/introspect | jq
{
  "active": false
}
```
