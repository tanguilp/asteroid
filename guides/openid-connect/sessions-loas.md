# Sessions and ACRs

Even though it's up to the developper to implement authentication and authorization web
workflows, Asteroid is capable of managing sessions, authentication class references (ACRs),
and associated concepts.

It supports the following use-cases:
- authentication step-up
- LOA decay
- offline access

It does not support any OpenID Connect logout specification.

This guide explains how to work with sessions.

## ACR configuration

LOAs are configured in the configuration file under the
[`oidc_acr_config`](Asteroid.Config.html#module-oidc_acr_config).

Here is one example of LOA confgiuration:

```elixir
config :asteroid, :oidc_acr_config, [
  "3-factor": [
    callback: &AsteroidWeb.LOA3_webflow.start_webflow/2,
    auth_event_set: [["password", "otp", "webauthn"]]
  ],
  "2-factor": [
    callback: &AsteroidWeb.LOA2_webflow.start_webflow/2,
    auth_event_set: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
  ],
  "1-factor": [
    callback: &AsteroidWeb.LOA1_webflow.start_webflow/2,
    auth_event_set: [["password"], ["webauthn"]],
    default: true
  ]
]
```

Note that the ACR name is an atom, which is converted back and forth to string when needed.

When initiating an OpenID Connect request on the authorize endpoint, Asteroid analyzes the
request to determine which ACR is requested, thanks to the the `"acr_values"` and `"claims"`
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
- `:name`: the name of the event
- `:time`: the UNIX timestamp of the authentication event
- `:exp`: the UNIX time in the future when this authentication will be considered expired
- `:amr`: the authentication method reference. A `t:String.t/0` that gives information on the
specific mechanism used.
[OpenID Connect MODRNA Authentication Profile 1.0 - section 5](https://openid.net/specs/openid-connect-modrna-authentication-1_0.html#rfc.section.5)
gives such examples
- `:authenticated_session_id`: the identifier of the authenticated session

Note that having different `:event_name` and `:amr` allows implementing different authentication
policies for the same authentication mechanism, or different means used for the same
authentication event (eg with AMRs being either `"smsotp"` or `"emailotp"`).

## Authenticated session with the use of authentication events

An authenticated session represents a continuous period of time during which a user is
authenticated. By authenticated, it means that:
- one or more active authenticated events ongoing (and valid)
- this or these authentication events match a least an LOA in the LOA configuration

If these conditions are not met, the authenticated session is destroyed.

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
- `:subject_id`: the user id
- `:current_acr`: the current acr, as calculated by Asteroid

An authenticated session can be destroyed in the following cases:
- it is manually destroyed, using convenience functions provided by the
`Asteroid.OIDC.AuthenticatedSession` module
- the last authenticated event related to an authenticated session is destroyed. In this case,
Asteroid detects that there is no longer a valid authentication event remaining
  - this allows manually using authenticated sessions without using associated authentication
  events, and therefore handling the LOA lifecycle in a non-automated way, bypassing Asteroid's
  authenticated session management

## Stores

Authentication events and authenticated sessions are stored in their own stores. Refer to
[Token backends](token-stores.html#content) for more information.

## Processes calculating the current acr

The acr of an authenticated session object is recalculated:
- when an authentication event is created
- when an authentication event is destroyed

A process reads the existing valid authentication events from the authentication event store
and uses the [`oidc_acr_config`](Asteroid.Config.html#module-oidc_acr_config) configuration
option to determine the current acr. More specifically, it looks for a combination of
`:auth_event_set` that is equal or a subset (in the sense of comparing sets) of the current valid
authentication events of the session.

**Beware**, this search is done in list order of the configuration option. For instance, if the
current authentication events of a session is `["password", "otp"]` and with the following
configuration:

```elixir
config :asteroid, :oidc_loa_config, [
  loa1: [
    callback: AsteroidWeb.LOA1_webflow.start_webflow/2,
    auth_event_set: [["password"], ["webauthn"], ["otp"]],
    default: true
  ],
  loa2: [
    callback: AsteroidWeb.LOA2_webflow.start_webflow/2,
    auth_event_set: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
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
    auth_event_set: [["password", "otp"], ["password", "webauthn"], ["webauthn", "otp"]]
  ],
  loa1: => [
    callback: AsteroidWeb.LOA1_webflow.start_webflow/2,
    auth_event_set: [["password"], ["webauthn"], ["otp"]],
    default: true
  ]
]
```

The following schema illustrates how the current LOA can vary during the lifetime of an
authenticated session:

![Session with LOAs example](../guides/media/authenticated-session-loa-example.svg)

## Retrieving AMR and authentication time

The `Asteroid.OIDC.AuthenticatedSession.info/2` function allows retrieving the AMR and
authentication time of an authenticated session. It also allows requesting this information
for a specific acr.

Indeed, event if a user has just logged in,for example, with a second factor, some OpenID Connect
request can still request ID tokens for the 1-factor ACR. In this case, the amr will be a
unique factor, and the authentication time will be the authentication time with this first factor,
and not the second one.

### Example

```elixir
iex> Asteroid.Utils.astrenv(:oidc_acr_config)
[
  "3-factor": [
    callback: &AsteroidWeb.LOA3_webflow.start_webflow/2,
    auth_event_set: [["password", "otp", "webauthn"]]
  ],
  "2-factor": [
    callback: &AsteroidWeb.LOA2_webflow.start_webflow/2,
    auth_event_set: [
      ["password", "otp"],
      ["password", "webauthn"],
      ["webauthn", "otp"]
    ]
  ],
  "1-factor": [
    callback: &AsteroidWeb.LOA1_webflow.start_webflow/2,
    auth_event_set: [["password"], ["webauthn"]],
    default: true
  ]
]
iex> alias Asteroid.OIDC.AuthenticationEvent, as: AE
Asteroid.OIDC.AuthenticationEvent
iex> alias Asteroid.OIDC.AuthenticatedSession, as: AS
Asteroid.OIDC.AuthenticatedSession
iex> {:ok, as} = AS.gen_new("user_1") |> AS.store()
{:ok,
 %Asteroid.OIDC.AuthenticatedSession{
   data: %{},
   id: "gvycEhbeig9RjwUu36UEGTxO1MNRE3qQ9WHisfpk0Zk",
   subject_id: "user_1"
 }}
iex> AE.gen_new(as.id) |> AE.put_value("name", "password") |> AE.put_value("amr", "pwd") |> AE.put_value("time", 100000) |> AE.store()
{:ok,
 %Asteroid.OIDC.AuthenticationEvent{
   authenticated_session_id: "gvycEhbeig9RjwUu36UEGTxO1MNRE3qQ9WHisfpk0Zk",
   data: %{"amr" => "pwd", "name" => "password", "time" => 100000},
   id: "WxQ6AHMRthQlk9cqsGUMVWsFNZ3EeNjyFfNCRYkiF20"
 }}
iex> AE.gen_new(as.id) |> AE.put_value("name", "otp") |> AE.put_value("amr", "otp") |> AE.put_value("time", 200000)|> AE.store()
{:ok,
 %Asteroid.OIDC.AuthenticationEvent{
   authenticated_session_id: "gvycEhbeig9RjwUu36UEGTxO1MNRE3qQ9WHisfpk0Zk",
   data: %{"amr" => "otp", "name" => "otp", "time" => 200000},
   id: "QnZZE82I4St41JieLpLg8z3HG_T8l6yutlt3dPo_Yx8"
 }}
iex> AE.gen_new(as.id) |> AE.put_value("name", "webauthn") |> AE.put_value("amr", "phr") |> AE.put_value("time", 300000)|> AE.store()
{:ok,
 %Asteroid.OIDC.AuthenticationEvent{
   authenticated_session_id: "gvycEhbeig9RjwUu36UEGTxO1MNRE3qQ9WHisfpk0Zk",
   data: %{"amr" => "phr", "name" => "webauthn", "time" => 300000},
   id: "N_V4i9lz5obd-3C0XZagZGtOFuDMZo0ywXSBjoum0KY"
 }}
iex> AS.info(as.id)            
%{acr: "3-factor", amr: ["otp", "phr", "pwd"], auth_time: 300000}
iex> AS.info(as.id, "1-factor")
%{acr: "1-factor", amr: ["pwd"], auth_time: 100000}
iex> AS.info(as.id, "2-factor")
%{acr: "2-factor", amr: ["otp", "pwd"], auth_time: 200000}
iex> AS.info(as.id, "3-factor")
%{acr: "3-factor", amr: ["otp", "phr", "pwd"], auth_time: 300000}
```

## Using authenticated session without authenticated events

Since an authenticated session is updated or destroyed when using authentication events, it is
possible to manually manage an authenticated session not using any authentication event linked
to this object.

This way, the current acr and other properties of an authenticated session can be updated
programmatically, with no automatic processes updating it.

## Relation between authentication objects and tokens

In a nutshell, in an OpenID Connect flow:
- the expiration of an authentication event may lead to its authenticated session object being
discarded...
- which may in turn destroy the refresh token**s** associated to it (if it wasn't requested with
the `"offline_access"` scope)...
- which will result in having the stored access tokens associated to this or these refresh
tokens being discarded altogether
