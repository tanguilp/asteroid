# Token backends

Token stores are responsible for storing tokens. OAuth2 is heavily stateful, and several tokens
need to be stored:
- Access tokens
- Refresh tokens
- Authorization codes
- Cookies
- State
- PKCE code challenge
- Device codes
- ...

As for attribute repositories, these stores are initialised and launched at startup.

Asteroid allows using different backends for storing different tokens. It is therefore possible,
for instance, to store ephemeral tokens such as access tokens and authorization codes in memory
caches (ETS, Mnesia, Redis...) and tokens that must be persisted, such as refresh tokens, in
backends that store them on disk (Mnesia, Riak...).

Asteroid defines the following behaviours and implementations:

|   Token type          |          Behaviour                   | Implementation                              |
|:---------------------:|:------------------------------------:|---------------------------------------------|
| Refresh token         |`Asteroid.Store.RefreshToken`         |`Asteroid.Store.RefreshToken.Mnesia`         |
|                       |                                      |`Asteroid.Store.RefreshToken.Riak`           |
| Access token          |`Asteroid.Store.AccessToken`          |`Asteroid.Store.AccessToken.Mnesia`          |
|                       |                                      |`Asteroid.Store.AccessToken.Riak`            |
| Authorization code    |`Asteroid.Store.AuthorizationCode`    |`Asteroid.Store.AuthorizationCode.Mnesia`    |
|                       |                                      |`Asteroid.Store.AuthorizationCode.Riak`      |
| Device code	        |`Asteroid.Store.DeviceCode` 	       |`Asteroid.Store.DeviceCode.Mnesia` 	     |
|                       |                                      |`Asteroid.Store.DeviceCode.Riak`             |
| Authenticated session |`Asteroid.Store.AuthenticatedSession` |`Asteroid.Store.AuthenticatedSession.Mnesia` |
|                       |                                      |`Asteroid.Store.AuthenticatedSession.Riak`   |
| Authentication event	|`Asteroid.Store.AuthenticationEvent`  |`Asteroid.Store.AuthenticationEvent.Mnesia`  |
|                       |                                      |`Asteroid.Store.AuthenticationEvent.Riak`    |

Note that you don't necessarily need to configure token stores for all the token types, but only
for those who you'll be using. For instance, there's no need to configure a refresh token
store if you never release refresh tokens.

## Security considerations

- When storing tokens on disc, make sure to properly protect stored tokens
  - Threats to take into account: access to tokens by an unauthorized party, long lasting tokens
  leak by getting an unencrypted hard drive or a VM snapshot
  - Countermeasures: proper configuration of filesystem rights, hard drive encryption or backend
  store encryption

## Configuration

Token stores are each configured under their own key:

|    Token type      | Configuration key            |
|:------------------:|------------------------------|
| Refresh token      | [`:token_store_refresh_token`](Asteroid.Config.html#module-token_store_refresh_token) |
| Access token       | [`:token_store_access_token`](Asteroid.Config.html#module-token_store_access_token)  |
| Authorization code | [`:token_store_authorization_code`](Asteroid.Config.html#module-token_store_authorization_code)  |
| Device code 	     | [`:token_store_device_code`](Asteroid.Config.html#module-token_store_device_code)  |

The options for a token store are:
- `:module`: the name of the module implementing the token's behaviours. No default, **mandatory**
- `:opts`: options that will be passed to the all token's implementation functions. Refer to the
implementation documentation. Defaults to `[]`
- `:auto_install`: `boolean()` indicating whether the `install/1` callback of the impementation
should be called at Asteroid startup. Defaults to `true`
- `:auto_start`: `boolean()` indicating whether the `start_link/1` or `start/1` callback of the
Implementation should be called at Asteroid startup. Defaults to `true`

## Example (Riak only)

```elixir
config :asteroid, :token_store_access_token, [
  module: Asteroid.Store.AccessToken.Riak,
  opts: [bucket_type: "ephemeral_token", purge_interval: 10]
]

config :asteroid, :token_store_refresh_token, [
  module: Asteroid.Store.RefreshToken.Riak,
  opts: [bucket_type: "token"]
]

config :asteroid, :token_store_authorization_code, [
  module: Asteroid.Store.AuthorizationCode.Riak,
  opts: [bucket_type: "ephemeral_token"]
]

```

## Example (Riak and Mnesia)

```elixir
config :asteroid, :token_store_access_token, [
  module: Asteroid.Store.AccessToken.Mnesia
]

config :asteroid, :token_store_refresh_token, [
  module: Asteroid.Store.RefreshToken.Riak,
  opts: [bucket_type: "token"]
]

config :asteroid, :token_store_authorization_code, [
  module: Asteroid.Store.AuthorizationCode.Mnesia
]

config :asteroid, :token_store_device_code, [
  module: Asteroid.Store.DeviceCode.Mnesia
]
```

## Startup

At startup, Asteroid reads the configuration file and executes the following actions for each
token store found:
1. calling the `install/1` callback of the module (except if the `auto_install` option is set
to `false`)
2. trying to start the token store by (and except if the `auto_start` option is set
to `false`):
    - calling the `start_link/1` callback if it exists, so as to create a supervised process
    - otherwise calling the `start/1` callback

Should any function fail, Asteroid will immediately stop.
