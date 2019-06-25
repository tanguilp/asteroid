# JWT Profile for Access Tokens

In addition to opaque access token that must be verified against the `/api/oauth2/introspect`
endpoint, Asteroid supports the issuance of signed JWT (i.e. JWS) access tokens.

Although the use of JWS is widespread, it is not standardized as of today (06.19). There is
however a [draft RFC](https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-00) that
documents it, and the following sections of this guide will refer to it as the authoritative
standard as for the other RFCs.

Issuing JWEs are not supported, and self-sufficient JWS tokens are supported only for access
tokens but neither for refresh tokens and authorization codes.

## Support

Signing algorithms:
  - [x] symmetric
  - [x] asymmetric

Included claims:
  - [x] `"iss"`
  - [x] `"exp"`
  - [ ] `"aud"`
  - [x] `"sub"`
  - [x] `"client_id"`
  - [x] `"iat"`
  - [x] `"scope"`
  - [ ] `"auth_time"`
  - [ ] `"jti"`
  - [ ] `"acr"`
  - [ ] `"amr"`

Deviations from the (draft) specification:
- `"sub"` is not set to the client id in the client credentials flow and will not be present as
a claim ; instead the `"client_id"` claim will be used

## Configuration

To determine the `t:Asteroid.Token.serialization_format/0` serialization format of a token,
Asteroid calls the callback defined by the
[`:oauth2_access_token_serialization_format_callback`](Asteroid.Config.html#module-oauth2_access_token_serialization_format_callback)
configuration option and which defaults to `Asteroid.Token.AccessToken.serialization_format/1`.

This defaults function makes use of client configuration (see `Asteroid.Client`) and the
following configuration option callbacks to determine key name and signing algorithm:
- [`:oauth2_access_token_signing_alg_callback`](Asteroid.Config.html#module-oauth2_access_token_signing_alg_callback)
- [`:oauth2_access_token_signing_key_callback`](Asteroid.Config.html#module-oauth2_access_token_signing_key_callback)

## Storage

Such access tokens are not stored and therefore cannot:
- be inspected on the `/api/oauth2/introspect` endpoint
- be revoked on the `/api/oauth2/revoked` endpoint

## Example

The following configuration is used:

```elixir
config :asteroid, :crypto_keys, %{
  "key_auto" => {:auto_gen, [params: {:rsa, 2048}, use: :sig, advertise: false]}
}

config :asteroid, :oauth2_flow_ropc_access_token_serialization_format, :jws

config :asteroid, :oauth2_flow_ropc_access_token_signing_key, "key_auto"

config :asteroid, :oauth2_flow_client_credentials_access_token_serialization_format, :jws

config :asteroid, :oauth2_flow_client_credentials_access_token_signing_key, "key_auto"

config :asteroid, :oauth2_flow_client_credentials_access_token_signing_alg, "RS384"
```

After loading test data in the shell:

```elixir
iex> alias Asteroid.Client
Asteroid.Client
iex> alias Asteroid.Subject
Asteroid.Subject
iex> Client.gen_new(id: "client1") |> Client.add("client_secret", "password1") |> Client.add("grant_types", ["password", "client_credentials"]) |> Client.store()
[debug] Elixir.AttributeRepositoryMnesia: written `%{"client_secret" => "password1", "grant_types" => ["password", "client_credentials"]}` for resource_id `"client1"` of instance client
:ok
iex> Subject.gen_new(id: "sub1") |> Subject.add("password", "password1") |> Subject.store()
[debug] Elixir.AttributeRepositoryMnesia: written `%{"password" => "password1"}` for resource_id `"sub1"` of instance subject
:ok
```

the following commands output access tokens:

```bash
$ curl -u client1:password1 -d "grant_type=password&username=sub1&password=password1" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIiwiZXhwIjoxNTYxMDU1MDYzLCJpYXQiOjE1NjEwNTQ0NjMsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMCIsInNjb3BlIjpbInNjb3BlLWEiLCJzY29wZS1iIiwic2NvcGUtZiJdLCJzdWIiOiJzdWIxIn0.kBQD250ggbMhz9VscJtulbDkhCW08gypt_7plhJja0lP_JnXk6TkcQhYl0uha8KDSmUdgkZxzok8IF7sW7lxw3QCAoYtrbm4VB9Ab4Pka_FVcTugysnBzHc8llvUnqy5XzNn5fvBrI7A3FdFjPopmHT3-kpDqrdPo214F6aXnlO_RDuAwfowQwVI0CL-sjTD4lTGx7A_F3jN7MrSK5tAVGO69pF6kIUpZpXOJ2-clv_u069FEjjkic4rUhNAG4dgdw7nohjuqUmoFsPVLcirPeaWd1VC1Ke5znVfO5jjJugJVHuZmnCjLlRhWvMDeB3RhnG9oHsS0jdNrCQuB2YWVA",
  "expires_in": 600,
  "refresh_token": "mGd2MuxWfiXkUx2HZE1-tw-L941Z33nIoGQ5PmcXLEQ",
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}

$ curl -u client1:password1 -d "grant_type=client_credentials" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "eyJhbGciOiJSUzM4NCJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIiwiZXhwIjoxNTYxMDU1MDY0LCJpYXQiOjE1NjEwNTQ0NjQsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMCIsInNjb3BlIjpbInNjb3BlLWEiLCJzY29wZS1iIiwic2NvcGUtZiJdfQ.d1YYVkojH5FeRCCIZAaeDJ2sqWnlUnTxv7UP3MqVr5PDiCae1g2723wTj5-zJwxsGmtTEjgW4Jitx93AHrto3e-gS7omPaEoCiTGeyEISGzl8sv-0uzUpFHqVvajw3-UFYinrc_Eh4XBvwY8WNwYstHHeyprfKIXWvlquzLcQWYkKD0ycQKo5x17Nsvkjb0CyeOywh8DLLW3oFN1ScLUSld8JZsOKLwYWHU8D9y5S-6IwSfMzNegHe1Y2DX3Pp2vwanQ05vUl5KqHf4bKo3aGfqf3xRR4U4O_ZEU0sInBl6rPqgbccvq_qT0N47YvZEcqlLqDbfFGr-VYhQ3R7b1TA",
  "expires_in": 600,
  "scope": "scope-a scope-b scope-f",
  "token_type": "bearer"
}
```

Once decoded the access tokens look like:

```elixir
iex> JOSE.JWS.verify(Asteroid.Crypto.Key.get("key_auto") |> elem(1), "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIiwiZXhwIjoxNTYxMDU1MDYzLCJpYXQiOjE1NjEwNTQ0NjMsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMCIsInNjb3BlIjpbInNjb3BlLWEiLCJzY29wZS1iIiwic2NvcGUtZiJdLCJzdWIiOiJzdWIxIn0.kBQD250ggbMhz9VscJtulbDkhCW08gypt_7plhJja0lP_JnXk6TkcQhYl0uha8KDSmUdgkZxzok8IF7sW7lxw3QCAoYtrbm4VB9Ab4Pka_FVcTugysnBzHc8llvUnqy5XzNn5fvBrI7A3FdFjPopmHT3-kpDqrdPo214F6aXnlO_RDuAwfowQwVI0CL-sjTD4lTGx7A_F3jN7MrSK5tAVGO69pF6kIUpZpXOJ2-clv_u069FEjjkic4rUhNAG4dgdw7nohjuqUmoFsPVLcirPeaWd1VC1Ke5znVfO5jjJugJVHuZmnCjLlRhWvMDeB3RhnG9oHsS0jdNrCQuB2YWVA")
{true,
 "{\"client_id\":\"client1\",\"exp\":1561055063,\"iat\":1561054463,\"iss\":\"http://localhost:4000\",\"scope\":[\"scope-a\",\"scope-b\",\"scope-f\"],\"sub\":\"sub1\"}",
 %JOSE.JWS{
   alg: {:jose_jws_alg_rsa_pss, :PS256},
   b64: :undefined,
   fields: %{"typ" => "JWT"}
 }}
iex> JOSE.JWS.verify(Asteroid.Crypto.Key.get("key_auto") |> elem(1), "eyJhbGciOiJSUzM4NCJ9.eyJjbGllbnRfaWQiOiJjbGllbnQxIiwiZXhwIjoxNTYxMDU1MDY0LCJpYXQiOjE1NjEwNTQ0NjQsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6NDAwMCIsInNjb3BlIjpbInNjb3BlLWEiLCJzY29wZS1iIiwic2NvcGUtZiJdfQ.d1YYVkojH5FeRCCIZAaeDJ2sqWnlUnTxv7UP3MqVr5PDiCae1g2723wTj5-zJwxsGmtTEjgW4Jitx93AHrto3e-gS7omPaEoCiTGeyEISGzl8sv-0uzUpFHqVvajw3-UFYinrc_Eh4XBvwY8WNwYstHHeyprfKIXWvlquzLcQWYkKD0ycQKo5x17Nsvkjb0CyeOywh8DLLW3oFN1ScLUSld8JZsOKLwYWHU8D9y5S-6IwSfMzNegHe1Y2DX3Pp2vwanQ05vUl5KqHf4bKo3aGfqf3xRR4U4O_ZEU0sInBl6rPqgbccvq_qT0N47YvZEcqlLqDbfFGr-VYhQ3R7b1TA")  {true,                         
 "{\"client_id\":\"client1\",\"exp\":1561055064,\"iat\":1561054464,\"iss\":\"http://localhost:4000\",\"scope\":[\"scope-a\",\"scope-b\",\"scope-f\"]}",
 %JOSE.JWS{
   alg: {:jose_jws_alg_rsa_pkcs1_v1_5, :RS384},
   b64: :undefined,
   fields: %{}
 }}
```

Notice how the signing algorithms differ: when not set in the configuration file, and as
described by the `Asteroid.Token.AccessToken.serialize/1` function, a default algorithm is used
by the underlying JOSE library.
