defmodule Asteroid.OIDC.ACR do
  @moduledoc """
  Functions to work with OpenID Connect ACRs
  """

  @type config :: [{atom(), [config_option()]}]

  @typedoc """
  # FIXME
  """

  @type config_option ::
          {:callback, AsteroidWeb.AuthorizeController.web_authorization_callback()}
          | {:auth_event_set, [auth_event_set()]}
          | {:default, boolean()}

  @typedoc """
  An authentication event set, containing the names of the events

  For instance: `["password", "otp"]`, `["webauthn", "otp"]`
  """

  @type auth_event_set :: [String.t(), ...]
end
