defmodule Asteroid.OIDC.LOA do
  @moduledoc """
  Functions to work with OpenID Connect LOAs
  """

  @type t :: String.t()

  @type config :: [{atom(), [config_option()]}]

  @typedoc """
  # FIXME
  """

  @type config_option ::
  {:callback, AsteroidWeb.AuthorizeController.web_authorization_callback()}
  | {:auth_events, [[String.t()]]}
  | {:default, boolean()}
end
