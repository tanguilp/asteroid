defmodule Asteroid.Token do
  @moduledoc """
  """

  @typedoc """
  The different formats a token may have once serialized
  """
  @type serialization_format ::
    :opaque
    | :jwt
    | :saml1
    | :saml2
end
