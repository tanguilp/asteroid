# Object stores

Object stores are responsible for storing tokens and other objects, such as sessions.
OAuth2 and OpenID Connect are heavily stateful, and several objects need to be stored:
- Access tokens
- Refresh tokens
- Authorization codes
- Device codes
- Object request
- Session information
- ...

As for attribute repositories, these stores are initialised and launched at startup.

Asteroid allows using different backends for storing different tokens. It is therefore possible,
for instance, to store ephemeral tokens such as access tokens and authorization codes in memory
caches (ETS, Mnesia, Redis...) and tokens that must be persisted, such as refresh tokens, in
backends that store them on disk (Mnesia, Riak...).

Asteroid defines the following behaviours and implementations:

|   Token type          |          Behaviour                         | Implementation                                  |
|:---------------------:|:------------------------------------------:|-------------------------------------------------|
| Refresh token         |`Asteroid.ObjectStore.RefreshToken`         |`Asteroid.Store.RefreshToken.Mnesia`             |
|                       |                                            |`Asteroid.ObjectStore.RefreshToken.Riak`         |
| Access token          |`Asteroid.ObjectStore.AccessToken`          |`Asteroid.Store.AccessToken.Mnesia`              |
|                       |                                            |`Asteroid.ObjectStore.AccessToken.Riak`          |
| Authorization code    |`Asteroid.ObjectStore.AuthorizationCode`    |`Asteroid.Store.AuthorizationCode.Mnesia`        |
|                       |                                            |`Asteroid.ObjectStore.AuthorizationCode.Riak`    |
| Device code	        |`Asteroid.ObjectStore.DeviceCode`           |`Asteroid.Store.DeviceCode.Mnesia` 	       |
|                       |                                            |`Asteroid.ObjectStore.DeviceCode.Riak`           |
| Authenticated session |`Asteroid.ObjectStore.AuthenticatedSession` |`Asteroid.Store.AuthenticatedSession.Mnesia`     |
|                       |                                            |`Asteroid.ObjectStore.AuthenticatedSession.Riak` |
| Authentication event	|`Asteroid.ObjectStore.AuthenticationEvent`  |`Asteroid.Store.AuthenticationEvent.Mnesia`      |
|                       |                                            |`Asteroid.ObjectStore.AuthenticationEvent.Riak`  |
| Object request 	|`Asteroid.ObjectStore.GenericKV`            |`Asteroid.Store.GenericKV.Mnesia`      |

Note that you don't necessarily need to configure object stores for all the token types, but only
for those who you'll be using. For instance, there's no need to configure a refresh token
store if you never release refresh tokens.

## Security considerations

- When storing tokens on disc, make sure to properly protect stored tokens
  - Threats to take into account: access to tokens by an unauthorized party, long lasting tokens
  leak by getting an unencrypted hard drive or a VM snapshot
  - Countermeasures: proper configuration of filesystem rights, hard drive encryption or backend
  store encryption

## Configuration

Object stores are each configured under their own key:

|    Token type         | Configuration key            |
|:---------------------:|------------------------------|
| Refresh token         | [`:object_store_refresh_token`](Asteroid.Config.html#module-object_store_refresh_token) |
| Access token          | [`:object_store_access_token`](Asteroid.Config.html#module-object_store_access_token)  |
| Authorization code    | [`:object_store_authorization_code`](Asteroid.Config.html#module-object_store_authorization_code)  |
| Device code 	        | [`:object_store_device_code`](Asteroid.Config.html#module-object_store_device_code)  |
| Authenticated session | [`:object_store_device_code`](Asteroid.Config.html#module-object_store_authenticated_session)  |
| Authentication event  | [`:object_store_device_code`](Asteroid.Config.html#module-object_store_authentication_event)  |
| Object request        | [`:object_store_device_code`](Asteroid.Config.html#module-object_store_object_request)  |

The options for a object store are:
- `:module`: the name of the module implementing the token's behaviours. No default, **mandatory**
- `:opts`: options that will be passed to the all token's implementation functions. Refer to the
implementation documentation. Defaults to `[]`
- `:auto_install`: `boolean()` indicating whether the `install/1` callback of the impementation
should be called at Asteroid startup. Defaults to `true`
- `:auto_start`: `boolean()` indicating whether the `start_link/1` or `start/1` callback of the
Implementation should be called at Asteroid startup. Defaults to `true`

## Example (Riak only)

```elixir
config :asteroid, :object_store_access_token, [
  module: Asteroid.ObjectStore.AccessToken.Riak,
  opts: [bucket_type: "ephemeral_token", purge_interval: 10]
]

config :asteroid, :object_store_refresh_token, [
  module: Asteroid.ObjectStore.RefreshToken.Riak,
  opts: [bucket_type: "token"]
]

config :asteroid, :object_store_authorization_code, [
  module: Asteroid.ObjectStore.AuthorizationCode.Riak,
  opts: [bucket_type: "ephemeral_token"]
]

```

## Example (Riak and Mnesia)

```elixir
config :asteroid, :object_store_access_token, [
  module: Asteroid.ObjectStore.AccessToken.Mnesia
]

config :asteroid, :object_store_refresh_token, [
  module: Asteroid.ObjectStore.RefreshToken.Riak,
  opts: [bucket_type: "token"]
]

config :asteroid, :object_store_authorization_code, [
  module: Asteroid.ObjectStore.AuthorizationCode.Mnesia
]

config :asteroid, :object_store_device_code, [
  module: Asteroid.ObjectStore.DeviceCode.Mnesia
]
```

## Startup

At startup, Asteroid reads the configuration file and executes the following actions for each
object store found:
1. calling the `install/1` callback of the module (except if the `auto_install` option is set
to `false`)
2. trying to start the object store by (and except if the `auto_start` option is set
to `false`):
    - calling the `start_link/1` callback if it exists, so as to create a supervised process
    - otherwise calling the `start/1` callback

Should any function fail, Asteroid will immediately stop.
