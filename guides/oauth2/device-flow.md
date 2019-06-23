# Device Authorization Grant (draft RFC)

Asteroid implements the OAuth 2.0 Device Authorization Grant which is still a draft RFC
as of 06.19 (
[https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15](https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15)).

This RFC is designed to allow IOT devices with low input capabilities (eg a connected toothbrush)
to move the authentication and authorization process to a smartphone or a computer.

Support of this protocol adds the `/api/oauth2/device_authorization` endpoint, which is
advertised in the OAuth2 metadata. Web flow starts on `/device`, which has been chosen for
its conciseness.

## Support

Clients :
  - [x] confidential clients
  - [x] public clients

Specific error codes:
  - [x] `"authorization_pending"`
  - [x] `"slow_down"`
    - Rate-limiting is supported
  - [x] `"access_denied"`
  - [x] `"expired_token"`

## Security consideration

### Device code DOS

The `/api/oauth2/device_authorization` endpoint may be subject to DOS, especially when public
clients are allowed to use it. Consider using throttling.

### User code brute-forcing

Due to its relatively low entropy, the user code may be subject to brute-forcing. It is necessary
to carefully design the web flow, for instance (and not exclusively):
- having the user code entered after the authentication flow
- not displaying an error when the user code was not found in the device code store, or limiting
the number of times such an error is displayed
- rate-limiting trying a user code, blocking it for a few seconds or requiring resolving a
CAPTCHA

## Process initiation: device request

The flow statrs with a request to the `/api/oauth2/device_authorization` endpoint and results
in obtaining a device code along with a user code. Any authorized client can request as many
codes (an authorized client is a client that has the value
`"urn:ietf:params:oauth:grant-type:device_code"` set in its `"grant_types"` attribute), including
public clients. A malicious user could spam this endpoint so as to saturate the server with
newly created device codes. Consider rate-limiting this API (which is different from
rate-limiting *use* of device codes on the `/api/oauth2/token` endpoint) for instance using
a `APIacFilterThrottle` plug.

This flow comes with its own token store, whose behaviour is described in
`Asteroid.TokenStore.DeviceCode`. Note that there is no store for the user codes: a generated
user code is attached to a generated device code. Two stores are implemented:
- `Asteroid.TokenStore.DeviceCode.Mnesia`
- `Asteroid.TokenStore.DeviceCode.Riak`

This store is configured with the
[`:token_store_device_code`](Asteroid.Config.html#module-token_store_device_code) configuration
option.

Riak example:
```elixir
config :asteroid, :token_store_device_code, [
  module: Asteroid.TokenStore.DeviceCode.Riak,
  opts: [bucket_type: "ephemeral_token"]
]
```

Mnesia example:
```elixir
config :asteroid, :token_store_device_code, [
  module: Asteroid.TokenStore.DeviceCode.Mnesia
]
```

After making sure the grant type is enabled, one can request the endpoint to get new device and
user code:

```bash
$ curl -u client1:password1 -d "" http://localhost:4000/api/oauth2/device_authorization | jq
{
  "device_code": "nd86SGhG-yGvJb8Vvcvv0fwP2OKIDyALdqGyU0mFeCc",
  "expires_in": 900,
  "interval": 5,
  "user_code": "BLGBTRQ3",
  "verification_uri": "http://localhost:4000/device",
  "verification_uri_complete": "http://localhost:4000/device?user_code=BLGBTRQ3"
}
```

## User code generation

The user code is meant to be displayed and typed by the user. It's expected to be short and
error prone, which is why it doesn't look like the other tokens that are base-64 strings
generated from secure PRNG.

Asteroid calls the callback configured by the
[`:oauth2_flow_device_authorization_user_code_callback`](Asteroid.Config.html#module-oauth2_flow_device_authorization_user_code_callback)
configuration option for user code generation. By default, it uses the
`Asteroid.OAuth2.DeviceAuthorization.user_code/1` function to generate them. Refer to the
function's documentation for further information.

## Web flow

The second step consists in having the user opening the verification URI, either by typing it
or using an automated way (QR code, Bluetooth...).

The user is then expected to:
- type the user code (except if it was transmitted along with the QR code, etc.)
- authenticate
- authorize scopes (optionally)

The web flow is triggered by calling the callback configured by the
[`:oauth2_flow_device_authorization_web_authorization_callback`](Asteroid.Config.html#module-oauth2_flow_device_authorization_web_authorization_callback)
similarly to the authorization code and implicit flows.

This web flow process can have 3 outcomes:
1. the user successfully grants access
2. the user denies access
3. an error occurs (eg. the code has timed out)

At the end of the web flow for any of these outcomes, it is necessary to call one of the
corresponding callback (same order as the former list):
1. `AsteroidWeb.DeviceController.authorization_granted/2`
2. `AsteroidWeb.DeviceController.authorization_denied/2` with an
`Asteroid.OAuth2.AccessDeniedError` exception as the error
3. `AsteroidWeb.DeviceController.authorization_denied/2` with an
`Asteroid.OAuth2.ServerError` or `Asteroid.OAuth2.TemporarilyUnavailableError` exception
as the error

These functions will do the necessary backend work (such as changing the device code to granted
in the first case) and redirect to one of these templates (still same order):
1. `lib/asteroid_web/templates/device/device_authorization_granted.html.eex`
2. `lib/asteroid_web/templates/device/device_authorization_denied.html.eex`
3. `lib/asteroid_web/templates/device/device_authorization_error.html.eex`

They display simple message (eg. "Device paired") and one might consider changing it.

Note that you can access the device code during the web flow thanks to the
`Asteroid.Token.DeviceCode.get_from_user_code/1` function. You should not modify its state
though: Asteroid deals with that in its callbacks.

## Token retrieval

Access and (optionnaly) refresh tokens are retrieved on the `/api/oauth2/token` endpoint
using the `"urn:ietf:params:oauth:grant-type:device_code"` grant type and sending a generated
device code.

Asteroid implements all the error codes specified by the draft RFC.

Upon successful exchange, the device code is deleted (this is not required by the
specification).

### Rate limiting

Device code rate-limiting is implemented (`"slow_down"` error message) by a module implementing
the `Asteroid.OAuth2.DeviceAuthorization.RateLimiter` behaviour. It can be configured by the
following configuration options:
- [`:oauth2_flow_device_authorization_rate_limiter`](Asteroid.Config.html#module-oauth2_flow_device_authorization_rate_limiter)
- [`:oauth2_flow_device_authorization_rate_limiter_interval`](Asteroid.Config.html#module-oauth2_flow_device_authorization_rate_limiter_interval)

Asteroid ships with a default implementation
(`Asteroid.OAuth2.DeviceAuthorization.RateLimiter.Hammer`) based on the Hammer library. It uses
an ETS backend as its default, and is as a consequence local to the EVM instance. In other words
rate-limiting is not shared by different clustered instances when using the default backend.
Since rate-limiting of the device code is mainly designed to prevent having devices flooding the
authorization server and the device code is a high-entropy string, this is probably not a
problem.

## Full request example

Without a proper device implementing this protocol, it is possible to simulated it in the
Unix and Elixir shells.

First create the client and subject in the Elixir shell:

```elixir
iex> alias Asteroid.Client
Asteroid.Client
iex> alias Asteroid.Subject
Asteroid.Subject
iex> alias Asteroid.Token.DeviceCode
Asteroid.Token.DeviceCode
iex> Client.gen_new(id: "client1") |> Client.add("client_id", "client1") |> Client.add("client_secret", "password1") |> Client.add("grant_types", ["password", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code"]) |> Client.store()
:ok
iex> Subject.gen_new(id: "sub1") |> Subject.add("sub", "sub1") |> Subject.add("password", "password1") |> Subject.store()
:ok
```

Then request a device code:

```bash
$ curl -u client1:password1 -d "" http://localhost:4000/api/oauth2/device_authorization | jq
{
  "device_code": "GnfMFmyH603q2pRcaTuvvsx2XiwKH1T4ZM2nBjrU9XU",
  "expires_in": 900,
  "interval": 5,
  "user_code": "32PNJCQJ",
  "verification_uri": "http://localhost:4000/device",
  "verification_uri_complete": "http://localhost:4000/device?user_code=32PNJCQJ"
}
```

It has not be granted has shown on the following request:

```bash
$ curl -u client1:password1 -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=GnfMFmyH603q2pRcaTuvvsx2XiwKH1T4ZM2nBjrU9XU" http://localhost:4000/api/oauth2/token | jq
{
  "error": "authorization_pending",
  "error_description": "The device code authorization is pending"
}

$ curl -u client1:password1 -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=GnfMFmyH603q2pRcaTuvvsx2XiwKH1T4ZM2nBjrU9XU" http://localhost:4000/api/oauth2/token | jq
{
  "error": "slow_down",
  "error_description": "Too many requests"
}

```

Set it to granted in the Elixir shell typing:
```elixir
iex> DeviceCode.get("GnfMFmyH603q2pRcaTuvvsx2XiwKH1T4ZM2nBjrU9XU") |> elem(1) |> DeviceCode.put_value("status", "granted") |> DeviceCode.put_value("sjid", "sub1") |> DeviceCode.store(%{})
{:ok,
 %Asteroid.Token.DeviceCode{
   data: %{
     "clid" => "client1",
     "exp" => 1561322983,
     "requested_scopes" => [],
     "sjid" => "sub1",
     "status" => "granted"
   },
   id: "GnfMFmyH603q2pRcaTuvvsx2XiwKH1T4ZM2nBjrU9XU",
   serialization_format: :opaque,
   user_code: "32PNJCQJ"
 }}
```

It can now be exchange against tokens:

```bash
$ curl -u client1:password1 -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=GnfMFmyH603q2pRcaTuvvsx2XiwKH1T4ZM2nBjrU9XU" http://localhost:4000/api/oauth2/token | jq
{
  "access_token": "9FCyNM21XBzr7Xl1yOi497OxkHc",
  "expires_in": 600,
  "refresh_token": "lnSxdQjxRiSP7Nsw4XcDx3oYq-3kQBcpteznGgAiv-M",
  "token_type": "bearer"
}
```
