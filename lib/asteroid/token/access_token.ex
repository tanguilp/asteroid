defmodule Asteroid.Token.AccessToken do
  import Asteroid.Utils

  @moduledoc """
  """
  @enforce_keys [:id]
  defstruct [:id, :refresh_token, :serialization_format, :claims]

  @type id :: binary()

  @type t :: %__MODULE__{
    id: __MODULE__.id(),
    refresh_token: binary(),
    #serialization_format: Asteroid.Token.serialization_format(),
    claims: map()
  }

  @doc """
  """
  @spec new(Keyword.t()) :: t()
  def new(opts \\ []) do
    %__MODULE__{
      id: secure_random_b64(),
      refresh_token: (if opts[:refresh_token], do: opts[:refresh_token].id, else: nil),
      serialization_format: (if opts[:format], do: opts[:format], else: :opaque)
    }
  end

  @doc """
  """
  #FIXME: shouldn't the val be necessarily a String.t()?
  @spec put_claim(t(), any(), any()) :: t()
  def put_claim(access_token, _key, nil), do: access_token

  def put_claim(access_token, key, val) do
    %{access_token | claims: Map.put(access_token.data, key, val)}
  end

  @spec store(t(), Asteroid.Context.t()) :: t()
  def store(access_token, ctx) do
    astrenv(:access_token_store).put(access_token, ctx)

    access_token
  end

  @spec serialize(t()) :: String.t()
  def serialize(access_token) do
    access_token.id
  end
end
