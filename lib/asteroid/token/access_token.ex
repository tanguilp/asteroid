defmodule Asteroid.Token.AccessToken do
  import Asteroid.Utils

  @moduledoc """
  """
  @enforce_keys [:id]
  defstruct [:id, :refresh_token_id, :serialization_format, :claims]

  @type id :: binary()

  @type t :: %__MODULE__{
    id: __MODULE__.id(),
    refresh_token_id: binary(),
    #serialization_format: Asteroid.Token.serialization_format(),
    claims: map()
  }

  @doc """
  """
  @spec new(Keyword.t()) :: t()
  def new(opts \\ []) do
    %__MODULE__{
      id: secure_random_b64(),
      refresh_token_id: (if opts[:refresh_token], do: opts[:refresh_token].id, else: nil),
      claims: %{},
      serialization_format: (if opts[:format], do: opts[:format], else: :opaque)
    }
  end

  @spec get(id()) :: {:ok, t()} | {:error, any()}
  def get(access_token_id) do
    case astrenv(:store_access_token)[:impl].get(access_token_id) do
      {:ok, access_token} ->
        {:ok, access_token}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  """
  #FIXME: shouldn't the val be necessarily a String.t()?
  @spec put_claim(t(), any(), any()) :: t()
  def put_claim(access_token, _key, nil), do: access_token

  def put_claim(access_token, key, val) do
    %{access_token | claims: Map.put(access_token.claims, key, val)}
  end

  @spec store(t(), Asteroid.Context.t()) :: t()
  def store(access_token, ctx) do
    astrenv(:store_access_token)[:impl].put(access_token)

    access_token
  end

  @spec serialize(t()) :: String.t()
  def serialize(access_token) do
    access_token.id
  end
end
