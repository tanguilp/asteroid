# Token revocation (RFC7009)

Asteroid implements token revocation
([RFC7009](https://tools.ietf.org/html/rfc7009).

This protocols allows revoking access and refresh tokens.
It is reachable on the `/api/oauth2/revoke` endpoint.

## Support

Token sorts:
- [x] access tokens
- [x] refresh tokens

Deviation from the specification:
- This endpoint returns an HTTP status 200 when the submitted token belongs to another client
without revoking it. According to the specification, an error should be returned, but it
would allow a malicious client to guess other's tokens. See also
[OAuth2: what to return when revoking a token which is not the client's? RFC7009](https://security.stackexchange.com/questions/210609/oauth2-what-to-return-when-revoking-a-token-which-is-not-the-clients-rfc7009).

## Example

The following exemple makes use of the ROPC flow.

First create new client and subject in the elixir shell:

```elixir
iex> alias Asteroid.Client
Asteroid.Client
iex> alias Asteroid.Subject
Asteroid.Subject
iex> Client.gen_new(id: "client1") |> Client.add("client_id", "client1") |> Client.add("client_secret", "password1") |> Client.add("grant_types", ["password", "refresh_token"]) |> Client.store()
:ok
iex> Subject.gen_new(id: "sub1") |> Subject.add("sub", "sub1") |> Subject.add("password", "password1") |> Subject.store()
:ok
```

Then request a new refresh token:

```bash
$ curl -u client1:password1 -d "grant_type=password&username=sub1&password=password1" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "UKViEefWCHGwWvcqia_9TsCWhIc",
  "expires_in": 600,
  "refresh_token": "LcdVyy2KOfRRHh_JnEYDCFgdDGeKw8oZ65EncvUhnU0",
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}
```

and new access tokens:

```bash
$ curl -u client1:password1 -d "grant_type=refresh_token&refresh_token=LcdVyy2KOfRRHh_JnEYDCFgdDGeKw8oZ65EncvUhnU0" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "lteEyKvvUxM-AQw05pCAsY1ONTw",
  "expires_in": 600,
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}

$ curl -u client1:password1 -d "grant_type=refresh_token&refresh_token=LcdVyy2KOfRRHh_JnEYDCFgdDGeKw8oZ65EncvUhnU0" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "_gOOisNpDARl8BvtTEOherQ17cs",
  "expires_in": 600,
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}

$ curl -u client1:password1 -d "grant_type=refresh_token&refresh_token=LcdVyy2KOfRRHh_JnEYDCFgdDGeKw8oZ65EncvUhnU0" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "KqmpmUfWDwSPbbpwXU7oQ23WevY",
  "expires_in": 600,
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}
```

Then let's revoke the refresh token:

```bash
$ curl -v -u client1:password1 -d "token=LcdVyy2KOfRRHh_JnEYDCFgdDGeKw8oZ65EncvUhnU0" http://localhost:4000/api/oauth2/revoke
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 4000 (#0)
* Server auth using Basic with user 'client1'
> POST /api/oauth2/revoke HTTP/1.1
> Host: localhost:4000
> Authorization: Basic Y2xpZW50MTpwYXNzd29yZDE=
> User-Agent: curl/7.61.0
> Accept: */*
> Content-Length: 49
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 49 out of 49 bytes
< HTTP/1.1 200 OK
< cache-control: max-age=0, private, must-revalidate
< content-length: 0
< date: Sun, 23 Jun 2019 21:58:21 GMT
< server: Cowboy
< x-request-id: FaryuiEJ8J86_4UAAAkB
< 
* Connection #0 to host localhost left intact
```

A plain `200` HTTP status code is returned, in accordance with the specification.

Let's try to request a new access token:

```bash
$ curl -u client1:password1 -d "grant_type=refresh_token&refresh_token=LcdVyy2KOfRRHh_JnEYDCFgdDGeKw8oZ65EncvUhnU0" http://localhost:4000/api/oauth2/token | jq
{
  "error": "invalid_grant",
  "error_description": "Invalid grant `authorization code`: invalid refresh token"
}
```

The refresh token has been successfully revoked.
