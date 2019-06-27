# General configuration

Asteroid comes with a significant number of *configuration options*. These configuration options
are set in the Elixir configuration files located in the `/config` directory:
- `config.exs`: configuration options shared between environments
- `dev.exs`: configuration options for the development environment
- `test.exs`: configuration options for the test environment
  - modifying existing configuration options can result in test failures since tests use them
- `prod.exs`: configuration options for the production environment
- `prod.secret.exs`: secrets for the production environment. Beware of:
  - including it at the last moment, in accordance to Elixir releases best practice
  - not generating documentation (`mix docs`) when the file is present, as some secret
  configuration option values could be inserted in the HTML documentation

## Reading the configuration option documentation

All the Asteroid configuration options are documented in the `Asteroid.Config` module.
Additional metadata is added for each configuration option:
- Configuration: can have the values:
  - "runtime": this value is dynamically set on application startup. It can be changed live in
  the system. For instance, some tests set some configuration option at runtime to test some
  specific values
  - "compile-time": the configuration option is evaluated at compile-time using Elixir's
  metaprogramming, such as the API plugs. Changing it at runtime will have no effect.
- Type: the type of the option, for documentation purpose. It is not enforced.
- Default value (env): the default value set in the configuration files for the environment.
Generates a link if the value is a named function
  - Note that using anonymous functions in configuration files is not possible: these won't be
  available in releases even if it looks like it's working in development environment
- Used by: the callback configuration option whose default (function) value uses this
configuration option. Does not apply if you change the callback
- Uses: the configuration options used by the default (function) value configured for a callback
- Unit: the unit for the configuration option (such as "seconds"), for documentation purpose

Note that changing configuration at runtime is possible, nut will *not* be persisted.

## Configuration inheritance

Some configuration values (but not all) follow a inheritance pattern consisting in
- using the client configuration value, if present
- using a flow-specific configuration value, if set
- fall backing to a default value

Indeed, in addition to the configuration options that can be configured in the Elixir
configuration files, many of them can be configured at the client level. It allows, for example,
to set a specific refresh token lifetime value for the authorization flow for a specific client,
and fallback to another value for all other clients. Client's configuration options are
documented in the `Asteroid.Client` module.

For instance, the refresh token lifetime in the device authorization flow will be configured
(in order of precedence):
- using the `"__asteroid_oauth2_flow_device_authorization_refresh_token_lifetime"` attribute
of the requesting client, if any
- using the [`:oauth2_flow_device_authorization_refresh_token_lifetime`](Asteroid.Config.html#module-oauth2_flow_device_authorization_refresh_token_lifetime)
configuration, if set
- to `0` otherwise (which will make the token immediately invalid)

## Callbacks

Asteroid makes available numerous callback, and strives to make available for each API and web
flow (when relevant):
- a callback on the response (JSON response, URI parameter in the redirect-based flows...)
- a callback on the HTTP response, so that the HTTP headers or even body can be modified. This
also registering callbacks using `Plug.Conn.register_before_send/2`

These callbacks are always called with a `t:Asteroid.Context.t/0` map that contains
information about the endpoint, request, client, subject, requested and eventually granted
scopes, etc. that can be useful for
customizing.

See the [Customizing](customizing.html) section for examples.
