defmodule Asteroid.Token do
  require Logger

  @moduledoc """
  """

  @typedoc """
  The different formats a token may have once serialized, i.e. send on the wire (in opposition
  to the token internally used by Asteroid)
  """

  @type serialization_format ::
    :opaque
    | :jwt
    | :saml1
    | :saml2

  @typedoc """
  Serialized token, as sent on the wire

  For instance, an refresh token as used internally by Asteroid would look like:

  ```elixir
  %Asteroid.Token.RefreshToken{
    data: %{},
    id: "F1XFSdm11N2XJ9OOPT7__Y0NqedjPwKgdT-ifQeuS3c",
    serialization_format: :opaque
  }
  ```

  One serialized, for instance sent by the `/token endpoint`, it looks like:
  ```elixir
  "F1XFSdm11N2XJ9OOPT7__Y0NqedjPwKgdT-ifQeuS3c"
  ```

  which is its id. If the serialization format had been `:jwt`, the serialized form would result
  in a JWT.
  """

  @type serialized_token :: String.t()
end
