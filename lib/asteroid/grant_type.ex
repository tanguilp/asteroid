defmodule Asteroid.GrantType do
  @moduledoc """
  """

  @type t ::
  :authorization_code
  | :implicit
  | :password
  | :client_credentials
  | :refresh_token
  | :jwt_bearer
  | :saml2_bearer
end
