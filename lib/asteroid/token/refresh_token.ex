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
      claims: %{},
      serialization_format: (if opts[:format], do: opts[:format], else: :opaque)
    }
  end

  @spec get(id()) :: {:ok, t()} | {:error, any()}
  def get(refresh_token_id) do
    case astrenv(:store_refresh_token)[:impl].get(refresh_token_id) do
      {:ok, refresh_token} ->
        {:ok, refresh_token}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  """
  #FIXME: shouldn't the val be necessarily a String.t()?
  @spec put_claim(t(), any(), any()) :: t()
  def put_claim(refresh_token, _key, nil), do: refresh_token

  def put_claim(refresh_token, key, val) do
    %{refresh_token | claims: Map.put(refresh_token.claims, key, val)}
  end

  @spec store(t(), Asteroid.Context.t()) :: t()
  def store(refresh_token, ctx) do
    refresh_token
    |> astrenv(:refresh_token_before_store_callback).(ctx)
    |> astrenv(:store_refresh_token)[:impl].put()

    refresh_token
  end

  @spec serialize(t()) :: String.t()
  def serialize(refresh_token) do
    refresh_token.id
  end
end
