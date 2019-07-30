# Sessions and LOAs

Even though it's up to the developper to implement authentication and authorization web
workflows, Asteroid is capable of managing sessions, Level Of Assurances (LOAs) and associated
concepts.

It supports the following use-cases:
- authentication step-up
- LOA decay
- offline access

It does not support any OpenID Connect logout specification.

This guide explains how to work with sessions.

## LOA configuration

LOAs are configured in the configuration file under the
[`oidc_loa_config`](Asteroid.Config.html#module-oidc_loa_config).

Here is one example of LOA confgiuration:

```elixir
config :asteroid, :oidc_loa_config, [
  loa1: [
    callback: AsteroidWeb.LOA1_webflow.start_webflow/2,
    auth_events: [["password"], ["webauthn"], ["otp"]],
    default: true
  ],
  loa2: [
    callback: AsteroidWeb.LOA2_webflow.start_webflow/2,
    auth_events: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
  ]
]
```

Note that the LOA name is an atom, which is converted back and forth to string when needed. To
encode an LOA that needs escaping, for instance `"skolfederation.se-loa3"`, one shall write
`:"skolfederation.se-loa3"`.

When initiating an OpenID Connect request on the authorize endpoint, Asteroid analyzes the
request to determine which LOA is requested, thanks to the the `"acr_values"` and `"claims"`
OpenID Connect parameters. It then processes it such as:
- if no LOA is requested, it uses the callback of the first configured LOA which is set as
`default: true`. If none of then is set as a default, it fall backs to the
[`:oauth2_flow_authorization_code_web_authorization_callback`](Asteroid.Config.html#module-oauth2_flow_authorization_code_web_authorization_callback)
or
[`:oauth2_flow_implicit_web_authorization_callback`](Asteroid.Config.html#module-oauth2_flow_implicit_web_authorization_callback)
callback
- if one or more LOAs are requested as the `"acr_values"`, or if one or more `"acr"` is requested
in the `"claims"` parameter as non essential, it uses the callback of the first
matching LOA of the above configuration option. If none matchs, it fall backs to
[`:oauth2_flow_authorization_code_web_authorization_callback`](Asteroid.Config.html#module-oauth2_flow_authorization_code_web_authorization_callback)
or
[`:oauth2_flow_implicit_web_authorization_callback`](Asteroid.Config.html#module-oauth2_flow_implicit_web_authorization_callback)
- if one or more `"acr"` is requested using the `"claims"` parameter as essential, it uses
the first matching LOA in the configuration option. In case there's no match, it returns an
error to the requester immediately, without calling any callback

## Authentication events

An authentication event is an event saved after successful authentication of a user, using a
specific authentication mechanism. Such an event can be:
- login with password
- login with WebAuthn
- login using an SMS OTP
- etc.

Those events ought to be registered in the authentication event store.

FIXME: describe configuration

An authentication event bears the following information:
- `:event_name`: the name of the event
- `:event_time`: the UNIX timestamp of the authentication event
- `:exp`: the UNIX time in the future when this authentication will be considered expired
- `:amr`: the authentication method reference. A `t:String.t/0` that gives information on the
specific mechanism used.
[OpenID Connect MODRNA Authentication Profile 1.0 - section 5](https://openid.net/specs/openid-connect-modrna-authentication-1_0.html#rfc.section.5)
gives such examples
- `:authenticated_session_id`: the identifier of the authenticated session

Note that having different `:event_name` and `:amr` allows implementing different authentication
policies for the same authentication mechanism, or different means used for the same
authentication event (eg with AMRs being either `"smsotp"` or `"emailotp"`).

## Authenticated session

An authenticated session represents a continuous period of time during which a user is
authenticated. By authenticated, it means that:
- one or more active authenticated events ongoing (and valid)
- this or these authentication events match a least an LOA in the LOA configuration

If these conditions are not met, the user is considered unauthenticated.

It is decorrelated from any client session mechanism such as web cookies. In other words, a
cookie used for authentication can be active a long time, but the user be unauthenticated. This
allows, for example, to save known users (for the "Select an account" interface) in the cookie
data without keeping the user authenticated.

It does not mean that the session mechanism is not aware of the authenticated session id. On the
contrary, it is probably needed that the web cookie is aware of the authenticated session id
since it cannot be found in another way (using the user id (`"sub"`) would not be sufficient as
the user can be logged in from several browsers).

An authenticated session is an object that bears the following data:
- `:authenticated_session_id`: the id of the object
- `:sub`: the user id
- `:current_acr`: the current acr, as calculated by Asteroid

An authenticated session can be destroyed in the following cases:
- it is manually destroyed, using convenience functions provided by the
`Asteroid.OIDC.AuthenticatedSession` module
- the last authenticated event related to an authenticated session is destroyed. In this case,
Asteroid detects that there is no longer a valid authentication event remaining
  - this allows manually using authenticated sessions without using associated authentication
  events, and therefore handling the LOA lifecycle in a non-automated way, bypassing Asteroid's
  authenticated session management

It is stored in the authenticated session store: FIXME

## Processes calculating the current acr

The acr of an authenticated session object is recalculated:
- when an authentication event is created
- when an authentication event is destroyed

A process reads the existing valid authentication events from the authentication event store
and uses the [`oidc_loa_config`](Asteroid.Config.html#module-oidc_loa_config) configuration
option to determine the current acr. More specifically, it looks for a combination of
`:auth_events` that is equal or a subset (in the sense of comparing sets) of the current valid
authentication events of the session.

**Beware**, this search is done in list order of the configuration option. For instance, if the
current authentication events of a session is `["password", "otp"]` and with the following
configuration:

```elixir
config :asteroid, :oidc_loa_config, [
  loa1: [
    callback: AsteroidWeb.LOA1_webflow.start_webflow/2,
    auth_events: [["password"], ["webauthn"], ["otp"]],
    default: true
  ],
  loa2: [
    callback: AsteroidWeb.LOA2_webflow.start_webflow/2,
    auth_events: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
  ]
]
```

the result would be `"loa1"`, since `["password", "otp"]` is sufficient to be considered
logged with a LOA of `"loa1"`. Order matters, so to have the expected result it is necessary
to change the order as follows:

```elixir
config :asteroid, :oidc_loa_config, [
  loa2: [
    callback: AsteroidWeb.LOA2_webflow.start_webflow/2,
    auth_events: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
  ],
  loa1: => [
    callback: AsteroidWeb.LOA1_webflow.start_webflow/2,
    auth_events: [["password"], ["webauthn"], ["otp"]],
    default: true
  ]
]
```

The following schema illustrates how the current LOA can vary during the lifetime of an
authenticated session:

![Session with LOAs example](../guides/media/authenticated-session-loa-example.svg)

## `offline_access`

By default, when requesting access to refresh tokens using an OpenID Connect flow, the refresh
token is destroyed when the web authenticated session end. In Asteroid's terms, it means that
a refresh token is destroyed when its associated authenticated session is destroyed if the
initial flow was an OpenID Connect flow.

To request a refresh token that will remain valid after web session expiration, it is
necessary that the client includes the `"offline_access"` scope in its request to the
authorization endpoint in addition to the `"openid"` scope (otherwise it is not an OpenID Connect
flow and this paragraph doesn't apply).

## Relation between authentication objects and tokens

In a nutshell, in an OpenID Connect flow:
- the expiration of an authentication event may lead to its authenticated session object being
discarded...
- which may in turn destroy the refresh token**s** associated to it (if it wasn't requested with
the `"offline_access"` scope)...
- which will result in having the stored access tokens associated to this or these refresh
tokens being discarded altogether
