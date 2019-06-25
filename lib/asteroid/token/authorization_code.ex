defmodule Asteroid.Token.AuthorizationCode do
  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.Token

  @moduledoc """
  Authorization code structure

  ## Field naming
  The `data` field holds the token data. The following field names are standard and are used
  by Asteroid:
  - `"exp"`: the expiration unix timestamp of the authorization code
  - `"sub"`: the `t:Asteroid.Subject.id/0` of the authorization code
  - `"client_id"`: the `t:Asteroid.Client.id/0` of the authorization code
  - `"device_id"`: the `t:Asteroid.Device.id/0` of the authorization code
  - `"requested_scopes"`: a list of `OAuth2Utils.Scope.scope()` requested scopes
  - `"granted_scopes"`: a list of `OAuth2Utils.Scope.scope()` granted scopes
  - `"__asteroid_oauth2_initial_flow"`: the initial `t:Asteroid.OAuth2.flow_str/0` during which
  the authorization code was granted
  - `"__asteroid_oauth2_pkce_code_challenge"`: the PKCE code challenge, if any
  - `"__asteroid_oauth2_pkce_code_challenge_method"`: the PKCE code challenge method, if any,
  stored as a `t:Asteroid.OAuth2.PKCE.code_challenge_method_str/0`
  """

  @enforce_keys [:id, :serialization_format, :data]

  defstruct [:id, :data, :serialization_format]

  @type id :: binary()

  @type t :: %__MODULE__{
    id: __MODULE__.id(),
    serialization_format: Asteroid.Token.serialization_format(),
    data: map()
  }

  @doc ~s"""
  Creates a new authorization code struct

  ## Options
  - `:id`: `String.t()` id, **mandatory**
  - `:data`: a data `map()`
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  """

  @spec new(Keyword.t()) :: t()

  def new(opts) do
    %__MODULE__{
      id: opts[:id] || (raise "Missing authorization code id"),
      data: opts[:data] || %{},
      serialization_format: opts[:serialization_format] || :opaque
    }
  end

  @doc """
  Generates a new authorization code

  ## Options
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  """

  @spec gen_new(Keyword.t()) :: t()

  def gen_new(opts \\ []) do
    %__MODULE__{
      id: secure_random_b64(),
      data: %{},
      serialization_format: opts[:format] || :opaque
    }
  end

  @doc """
  Gets a authorization code from the authorization code store

  Unlike the `c:Asteroid.TokenStore.AuthorizationCode.get/2`, this function returns
  `{:error, %Asteroid.Token.InvalidTokenError{}}` if the authorization code is not found in
  the token store.

  ## Options
  - `:check_active`: determines whether the validity of the authorization code should be checked.
  Defaults to `true`. For validity checking details, see `active?/1`
  """

  @spec get(id(), Keyword.t()) :: {:ok, t()} | {:error, Exception.t()}

  def get(authorization_code_id, opts \\ [check_active: true]) do
    token_store_module = astrenv(:token_store_authorization_code)[:module]
    token_store_opts = astrenv(:token_store_authorization_code)[:opts] || []

    case token_store_module.get(authorization_code_id, token_store_opts) do
      {:ok, authorization_code} when not is_nil(authorization_code) ->
        if opts[:check_active] != true or active?(authorization_code) do
          {:ok, authorization_code}
        else
          {:error, Token.InvalidTokenError.exception(
            sort: "authorization code",
            reason: "inactive token",
            id: authorization_code_id)}
        end

      {:ok, nil} ->
        {:error, Token.InvalidTokenError.exception(
          sort: "authorization code",
          reason: "not found in the token store",
          id: authorization_code_id)}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Stores a authorization code
  """

  @spec store(t(), Context.t()) :: {:ok, t()} | {:error, any()}

  def store(authorization_code, ctx \\ %{}) do
    token_store_module = astrenv(:token_store_authorization_code)[:module]
    token_store_opts = astrenv(:token_store_authorization_code)[:opts] || []

    authorization_code =
      astrenv(:token_store_authorization_code_before_store_callback).(authorization_code, ctx)

    case token_store_module.put(authorization_code, token_store_opts) do
      :ok ->
        {:ok, authorization_code}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Deletes a authorization code from its store
  """

  @spec delete(t() | id()) :: :ok | {:error, any()}

  def delete(%__MODULE__{id: id}) do
    delete(id)
  end

  def delete(authorization_code_id) do
    authorization_code_store_module = astrenv(:token_store_authorization_code)[:module]
    authorization_code_store_opts = astrenv(:token_store_authorization_code)[:opts] || []

    authorization_code_store_module.delete(authorization_code_id, authorization_code_store_opts)
  end

  @doc """
  Puts a value into the `data` field of an authorization code

  If the value is `nil`, the authorization code is not changed and the field is not added.
  """

  @spec put_value(t(), any(), any()) :: t()

  def put_value(authorization_code, _key, nil), do: authorization_code

  def put_value(authorization_code, key, val) do
    %{authorization_code | data: Map.put(authorization_code.data, key, val)}
  end

  @doc """
  Removes a value from the `data` field of a authorization code

  If the value does not exist, does nothing.
  """

  @spec delete_value(t(), any()) :: t()

  def delete_value(authorization_code, key) do
    %{authorization_code | data: Map.delete(authorization_code.data, key)}
  end

  @doc """
  Serializes the authorization code, using its inner `t:Asteroid.Token.serialization_format/0`
  information

  Supports serialization to `:opaque` serialization format.
  """

  @spec serialize(t()) :: String.t()

  def serialize(%__MODULE__{id: id, serialization_format: :opaque}) do
    id
  end

  @doc """
  Returns `true` if the token is active, `false` otherwise

  The following data, *when set*, are used to determine that a token is active:
  - `"nbf"`: must be lower than current time
  - `"exp"`: must be higher than current time
  """

  @spec active?(t()) :: boolean()

  def active?(authorization_code) do
    (is_nil(authorization_code.data["nbf"]) or authorization_code.data["nbf"] < now())
    and
    (is_nil(authorization_code.data["exp"]) or authorization_code.data["exp"] > now())
  end

  @doc """
  Returns the authorization code lifetime

  ## Processing rules
  - If the client has the following field set to an integer value for the corresponding flow
  returns that value:
    - `"__asteroid_oauth2_flow_authorization_code_authorization_code_lifetime"`
  - Otherwise, if the following configuration option is set to an integer for the corresponding
  flow, returns its value:
    - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_authorization_code_lifetime)}
  - Otherwise returns `0`
  """

  def lifetime(%{flow: :authorization_code, endpoint: :authorize, client: client}) do
    attr = "__asteroid_oauth2_flow_authorization_code_authorization_code_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oauth2_flow_authorization_code_authorization_code_lifetime, 0)
    end
  end

  def lifetime(_) do
    0
  end
end
