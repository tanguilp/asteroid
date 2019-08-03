# Protecting APIs

Asteroid provides with numerous APIs and web endpoints as shown by the `mix phx.routes` commande:

```bash
$ mix phx.routes
                          authorize_path  GET   /authorize                               AsteroidWeb.AuthorizeController :pre_authorize
                             device_path  GET   /device                                  AsteroidWeb.DeviceController :pre_authorize
                     request_object_path  GET   /api/request_object/:id                  AsteroidWeb.API.RequestObjectController :show
                     request_object_path  POST  /api/request_object                      AsteroidWeb.API.RequestObjectController :create
                           userinfo_path  GET   /api/oidc/userinfo                       AsteroidWeb.API.OIDC.UserinfoController :show
                     token_endpoint_path  POST  /api/oauth2/token                        AsteroidWeb.API.OAuth2.TokenEndpoint :handle
                introspect_endpoint_path  POST  /api/oauth2/introspect                   AsteroidWeb.API.OAuth2.IntrospectEndpoint :handle
                    revoke_endpoint_path  POST  /api/oauth2/revoke                       AsteroidWeb.API.OAuth2.RevokeEndpoint :handle
                  register_endpoint_path  POST  /api/oauth2/register                     AsteroidWeb.API.OAuth2.RegisterEndpoint :handle
      device_authorization_endpoint_path  POST  /api/oauth2/device_authorization         AsteroidWeb.API.OAuth2.DeviceAuthorizationEndpoint :handle
oauth_authorization_server_endpoint_path  GET   /.well-known/oauth-authorization-server  AsteroidWeb.WellKnown.OauthAuthorizationServerEndpoint :handle
oauth_authorization_server_endpoint_path  GET   /.well-known/openid-configuration        AsteroidWeb.WellKnown.OauthAuthorizationServerEndpoint :handle
                      keys_endpoint_path  GET   /discovery/keys                          AsteroidWeb.Discovery.KeysEndpoint :handle
```

At compile-time, Asteroid loads from configuration a list of plugs to configure on each
of this routes. This plugs can be either [`APIac`](https://github.com/tanguilp/apiac) plugs, or
any other plug.

The following schema lists the configuration keys used to install plugs:
```elixir
authorize……………………………………………………………………………………………… :browser_plugs
device……………………………………………………………………………………………………… :browser_plugs
api
├─ oauth2……………………………………………………………………………………………… :api_oauth2_plugs
│  ├ token…………………………………………………………………………………………… :api_oauth2_endpoint_token_plugs
│  ├ introspect……………………………………………………………………………… :api_oauth2_endpoint_introspect_plugs
│  ├ revoke………………………………………………………………………………………… :api_oauth2_endpoint_revoke_plugs
│  ├ register…………………………………………………………………………………… :api_oauth2_endpoint_register_plugs
│  ╰ device_authorization…………………………………………………… :api_oauth2_endpoint_device_authorization_plugs
│
├─ oidc…………………………………………………………………………………………………… :api_oidc_plugs
│  ╰ userinfo…………………………………………………………………………………… :api_oidc_endpoint_userinfo_plugs
│
╰─ request_object………………………………………………………………………… :api_request_object_plugs
discovery……………………………………………………………………………………………… :discovery_plugs
╰─ keys
.well-known………………………………………………………………………………………… :well_known_plugs
├─ oauth-authorization-server
╰─ openid-configuration
```

Plugs configured at an upper level are not discarded but on the contrary exexcuted first.

## Configuration

The expected configuration consists in a list of `{module(), Keyword.t()}` where:
- `module()` is a module implementing the `Plug` behaviour
- `Keyword.t()` are the options of that plug

Plugs are set in Phoenix's router at **compile-time**.

## Example

```elixir
config :asteroid, :api_oauth2_plugs,
  [
    {APIacFilterIPWhitelist, [whitelist: ["127.0.0.1/32"], error_response_verbosity: :debug]},
    {APIacAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.Config.DefaultCallbacks.get_client_secret/2,
      set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
      error_response_verbosity: :debug}
  ]

config :asteroid, :api_oauth2_endpoint_token_plugs,
  [
    {APIacFilterThrottler,
      key: &APIacFilterThrottler.Functions.throttle_by_ip_path/1,
      scale: 60_000,
      limit: 50,
      exec_cond: &Asteroid.Config.DefaultCallbacks.conn_not_authenticated?/1,
      error_response_verbosity: :debug},
    {APIacAuthBearer,
      realm: "Asteroid",
      bearer_validator:
        {...},
      set_error_response: &APIacAuthBearer.save_authentication_failure_response/3,
      error_response_verbosity: :debug}
  ]
```

## Understanding `APIac.Authenticator` implementations' callbacks

The existing `APIac.Authenticator` ship with several callbacks. For instance, the
`APIacAuthBasic` implementation makes available:
- `APIacAuthBasic.send_error_response/3`
- `APIacAuthBasic.set_WWWauthenticate_header/3`
- `APIacAuthBasic.save_authentication_failure_response/3`

It has been design for maximum flexibility (and you can write your own callback implementation)
since it can be used not only with Asteroid. Respectively, these 3 callbacks do the following in
case of authentication error:
- immediately sends an error response should authentication fail
- sets the `"WWW-authenticate"` header with the correct error, and let the connection continue
- saves in the connection (`t:Plug.Conn.t/0`) the error data without modifying HTTP information,
and let the connection continue

This allows chaining such plugs. On its OAuth2 endpoints, Asteroid uses the 3<sup>rd</sup>
version because OAuth2 requires special processing of error response (using the
`AsteroidWeb.Error.set_www_authenticate_header/1` function). It therefore uses the saved
error data to build the error response.

Other endpoints, such as the `/api/request_object` are 'dumb' and therefore need to be configured
with the first type of callback (or the second, as long as the last authenticator plug responds
to the connection), since there are no post-processing function dealing with returning an error
message. For instance, this endpoint can be configured as:

```elixir
config :asteroid, :api_request_object_plugs,
  [
    {APIacAuthBasic,
      realm: "Asteroid",
      callback: &Asteroid.OAuth2.Client.get_client_secret/2,
      set_error_response: &APIacAuthBasic.send_error_response/3,
      error_response_verbosity: :normal}
  ]
```
