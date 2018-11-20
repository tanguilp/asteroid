defmodule Asteroid.Token.RefreshToken do
  import Asteroid.Utils

  @moduledoc """
  """
  @enforce_keys [:id]
  defstruct [:id, :claims, :serialization_format]

  @type id :: binary()

  @type t :: %__MODULE__{
    id: __MODULE__.id(),
    serialization_format: Asteroid.Token.serialization_format(),
    claims: map()
  }

  @doc """
  """
  @spec new(Keyword.t()) :: t()
  def new(opts \\ []) do
    %__MODULE__{
      id: secure_random_b64(),
      serialization_format: (if opts[:format], do: opts[:format], else: :opaque)
    }
  end

  @doc """
  """
  #FIXME: shouldn't the val be necessarily a String.t()?
  @spec put_claim(t(), any(), any()) :: t()
  def put_claim(refresh_token, _key, nil), do: refresh_token

  def put_claim(refresh_token, key, val) do
    %{refresh_token | claims: Map.put(refresh_token.data, key, val)}
  end

  @spec store(t(), Asteroid.Context.t()) :: t()
  def store(refresh_token, ctx) do
    astrenv(:refresh_token_store).put(refresh_token, ctx)

    refresh_token
  end

  @spec serialize(t()) :: String.t()
  def serialize(refresh_token) do
    refresh_token.id
  end
end
