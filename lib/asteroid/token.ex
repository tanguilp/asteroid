defmodule Asteroid.Token do
  require Logger

  @moduledoc """
  Types and exceptions for tokens
  """

  defmodule InvalidTokenError do
    @moduledoc """
    Error returned when a token was requested but an error happened when retrieving it
    """

    @enforce_keys [:sort, :id]

    defexception [:sort, :id, reason: ""]

    @type t :: %__MODULE__{
            sort: String.t(),
            reason: String.t(),
            id: String.t()
          }

    @impl true

    def message(%{sort: sort, reason: nil, id: id}) do
      "Invalid #{sort} `#{id}`"
    end

    def message(%{sort: sort, reason: reason, id: id}) do
      "Invalid #{sort} `#{id}`: #{reason}"
    end
  end

  @typedoc """
  Token sort (access token, refresh token, authorization code...)

  Token type is not used because it refers to how it's used by a client in OAuth2 specification
  (which defines the `"bearer"` token type).
  """

  @type sort :: :access_token | :refresh_token | :authorization_code

  @typedoc """
  String representation of a `t:sort/0`

  Must be the string conversion of a `t:sort/0` atom.
  """

  @type sort_str :: String.t()

  @typedoc """
  The different formats a token may have once serialized, i.e. send on the wire (in opposition
  to the token internally used by Asteroid)
  """

  @type serialization_format ::
          :opaque
          | :jwt

  @typedoc """
  String representation of a `t:serialization_format/0`

  Must be the string conversion of a `t:serialization_format/0` atom.
  """

  @type serialization_format_str :: String.t()

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
