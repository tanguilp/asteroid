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

  @spec get(id(), Keyword.t()) :: {:ok, t()} | {:error, any()}
  def get(refresh_token_id, opts \\ []) do
    case astrenv(:store_refresh_token)[:impl].get(refresh_token_id) do
      {:ok, refresh_token} ->
        if opts[:check_active] != true or active?(refresh_token) do
          {:ok, refresh_token}
        else
          {:error, :inactive_token}
        end

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

  @doc """
  Returns `true` if the token is active, `false` otherwise

  The following claims, *when set*, are used to determine that a token is active:
  - `"nbf"`: must be lower than current time
  - `"exp"`: must be higher than current time
  - `"revoked"`: must be the boolean `false`
  """
  @spec active?(t()) :: boolean()
  def active?(access_token) do
    (is_nil(access_token.claims["nbf"]) or access_token.claims["nbf"] < now())
    and
    (is_nil(access_token.claims["exp"]) or access_token.claims["exp"] > now())
    and
    (is_nil(access_token.claims["revoked"]) or access_token.claims["revoked"] == false)
    #FIXME: implement the following items from https://tools.ietf.org/html/rfc7662#section-4
    #   o  If the token has been signed, the authorization server MUST
    #  validate the signature.
    #   o  If the token can be used only at certain resource servers, the
    #  authorization server MUST determine whether or not the token can
    #  be used at the resource server making the introspection call.
  end
end
