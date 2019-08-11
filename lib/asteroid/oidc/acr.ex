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
  | {:auth_events, [[String.t()]]}
  | {:default, boolean()}
end
