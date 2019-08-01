# OAuth2 core (RFC6749)

Asteroid implements the OAuth 2.0 Authorization Framework
([RFC6749](https://tools.ietf.org/html/rfc6749)) which the core OAuth2 specifications (all
others being extensions of the OAuth2 protocol).

Endpointa re configured on the `/authorize` and `/api/oauth2/token` routes.

## Support

Grants:
- [x] Authorization code grant
- [x] Implicit grant
- [x] Resource Owner Password Credentials grant (*ROPC* grant)
- [x] Client Credentials grant

Features:
- refresh tokens:
  - [x] `t:Asteroid.Token.serialization_format/0`: `:opaque`
  - [x] new refresh token issued when renewing an access token (optional and configurable)
  - [x] lifetime configuration globally, per flow, per client and with a possibly capped lifetime
  depending on granted scopes
- access tokens:
  - [x] `t:Asteroid.Token.serialization_format/0`: `:opaque` and `jws` (signed access tokens)
  - [x] lifetime configuration per flow, per client and with a possibly capped lifetime
  depending on granted scopes
- authorization code:
  - [x] `t:Asteroid.Token.serialization_format/0`: `:opaque`
  - [x] lifetime configuration per flow or per client
- client types:
  - [x] public
  - [x] confidential
- authentication:
  - [x] authenticated requests (for confidential clients) on the `/api/oauth2/token` endpoint
  - [x] unauthenticated requests (for public clients) on the `/api/oauth2/token` endpoint
- scopes: see [Managing scopes](managing-scopes.html)
- client authentication: see [Protecting APIs](protecting-apis.html)

Deviations from the specification:
- the `"redirect_uri"` parameter is mandatory in the authorization and implicit flows

Miscellaneaous:
- the `"error_description"` message depends on the OAuth2 verbosity level #FIXME: link
- no `"error_uri"` parameter is returned in the web flows
- on the `/api/oauth2/token` endpoint, HTTP errors are returned in accordance to the
specification if it has been correctly set by the `APIac.Authenticator` plugs:
  - if credentials were provided and are invalid, sets the HTTP `Authorization` header for this
  unique authentication scheme
  - otherwise sets the HTTP `Authorization` header for all authentication schemes
- returned `"token_type"` is always `"Bearer"` (and no other type is specified)

# Security considerations

- The implicit grant is no longer recommended anymore, whatever the use-case (even SPAs).
It is recommended to use the authorization code grant instead. Asteroid implements the implicit
grant for
compatibility reasons only.
- An access token should never have a long life span, for security reasons (including token
guessing attacks).
- Using ROPC flow is not recommanded. In case of using it, you might consider:
  - rate-limiting the endpoint for this flow
  - verifying the implementation of passsword comparison (is it safe against timing attacks?)
  and storage (is it store with an appropriate hasing aalgorithm?)

## Web flows: implementing the authentication and authorization process

Web flows refer to the authorization code and implicit flows.

Asteroid doesn't implement the authentication and authorization web flows, which is to be
implemented by the Asteroid's developper. This process may include:
- authentication of the user thanks to login / password form, Webauthn authentication, OTP
verification, etc.
- user approval of requested scopes (authorization page)
- setting authentication cookie, for instance to make a session valid for 2 hours
- user account selection
- etc.

This authentication and authorization process is inserted between the following Asteroid
processes:
- input process: when calling the `/authorize` endpoint, Asteroid checks that the parameters are
correct (eg that the `"client_id"` is correct and the `"redirect_uri"` matches one of the
registered redirect URIs), handles PKCE parameters (for the authorization code flow) and:
  - calls the
  [`:oauth2_flow_authorization_code_web_authorization_callback`](Asteroid.Config.html#module-oauth2_flow_authorization_code_web_authorization_callback)
  or
  [`:oauth2_flow_implicit_web_authorization_callback`](Asteroid.Config.html#module-oauth2_flow_implicit_web_authorization_callback)
  depending on the OAuth2 flow (under the hood it calls the
  [`:web_authorization_callback`](Asteroid.Config.html#module-web_authorization_callback)
  callback - which means the callback called can be customized by replacing the default function
  configured for this callback)
  to hand over the request to the authentication and authorization process if the request is
  to hand over the request to the authentication and authorization process if the request is
  valid. The callback is called with the parsed
  `AsteroidWeb.AuthorizeController.Request` request data
  - returns the relevant OAuth2 error otherwise
- output process: when completed the user defined authentication and authorization process calls:
  - `AsteroidWeb.AuthorizeController.authorization_granted/2` in case of success
  - `AsteroidWeb.AuthorizeController.authorization_denied/2` in case of failure or user denial
    - this functions will redirect to the calling client with the OAuth2 parameters, and create
    the tokens (access token or authorization code) when needed

Note that in conformance with the specification, an Asteroid error page is shown in case of
invalid `"redirect_uri"` or `"client_id"` parameter, because it is not possible to redirect to
an unknown caller for security reasons or to an invalid redirect URI. Even though it is unlikely
that it will be even shown to an end-user, you might want to customize its aspect. The template
path is `"lib/asteroid_web/templates/authorize/error_redirect_uri.html.eex"`.

## Resource Owner Password Credentials

On the model of the web flows, the ROPC flow doesn't itself checks the user's password but
delegate it to a user-defined callback:
[`:oauth2_flow_ropc_username_password_verify_callback`](Asteroid.Config.html#module-oauth2_flow_ropc_username_password_verify_callback).

### Example

The following user-defined function is present in the `/custom_dev/callback.ex` file:

```elixir
def test_ropc_username_password_callback(_conn, username, password) do
  case Subject.load(username, attributes: ["password"]) do
    {:ok, sub} ->
      if sub.attrs["password"] == password do
        {:ok, sub}
      else
        {:error, Asteroid.OAuth2.InvalidGrantError.exception(
          grant: "password",
          reason: "invalid username or password",
          debug_details: "passwords don't match"
        )}
      end

    {:error, reason} ->
      {:error, reason}
  end
end
```

To test it, launch an iex shell and enter the following commands:

```elixir
iex> alias Asteroid.Client
Asteroid.Client
iex> alias Asteroid.Subject
Asteroid.Subject
iex> Client.gen_new(id: "client1") |> Client.add("client_secret", "password1") |> Client.add("grant_types", ["password"]) |> Client.store()
[debug] Elixir.AttributeRepositoryMnesia: written `%{"client_secret" => "password1", "grant_types" => ["password"]}` for resource_id `"client1"` of instance client
:ok
iex> Subject.gen_new(id: "sub1") |> Subject.add("password", "password1") |> Subject.store()
[debug] Elixir.AttributeRepositoryMnesia: written `%{"password" => "password1"}` for resource_id `"sub1"` of instance subject
:ok
```

and then launch the ROPC requests:

```bash
$ curl -u client1:password1 -d "grant_type=password&username=sub1&password=password1" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "eyJhbGciOiJSUzM4NCJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIiwiZXhwIjoxNTYxMDQ2MTQyLCJpYXQiOjE1NjEwNDU1NDIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMCIsInNjb3BlIjpbInNjb3BlLWEiLCJzY29wZS1iIiwic2NvcGUtZiJdLCJzdWIiOiJzdWIxIn0.YfPVdERzEFbsp8HJD-86Zg41zbt1jlvV1hIr2nhDNHNTQundMKeW8rLZp1KVk1xfEDUK8jKfgnuV_G-68ACSMk03SBng4FjByVa7slLrStNCdQoSK0F1XTxjv4z94f1ScZ8zB3dQoDKaWjB83-ZFBGsdghCFSEs31yZaOt3OebgoiVrEoNjjzEc_vqhU8zD4m4HrJxCOEFYYSs4ql-nTMePTH5_ii7qH9G9PcOYXZcf-KtisFd3cYjGivybjT_CH0fBnFEsyBGu38MIKpm1i8lJ6fiNlDXRPZV-1hhcbrQ9xRe-pt-cS34ulLo2LttwssOBknqz2rJGHYg7ybSPKPQ",
  "expires_in": 600,
  "refresh_token": "_nFr_GX92Ku4Got90gFZJ9Wd1rLlglzUY259T5Tz9Ew",
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}

$ curl -u client1:password1 -d "grant_type=password&username=sub1&password=wrongpassword" http://localhost:4000/api/oauth2/token | jq
{
  "error": "invalid_grant",
  "error_description": "Invalid grant `password`: invalid username or password"
}
```

Setting the verbosity to debug:

```elixir
iex> Application.put_env(:asteroid, :api_error_response_verbosity, :debug)
```

```bash
$ curl -u client1:password1 -d "grant_type=password&username=sub1&password=wrongpassword" http://localhost:4000/api/oauth2/token | jq
{
  "error": "invalid_grant",
  "error_description": "Invalid grant `password`: invalid username or password (passwords don't match)"
}
```

## Signed access tokens
