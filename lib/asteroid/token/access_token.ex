defmodule Asteroid.Token.AccessToken do
  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.Token

  @moduledoc """
  Access token structure

  ## Field naming
  The `data` field holds the token data. The following field names are standard and are used
  by Asteroid:
  - `"exp"`: the expiration unix timestamp of the access token
  - `"sub"`: the `t:Asteroid.Subject.id()` of the access token
  - `"client_id"`: the `t:Asteroid.Client.id()` of the access token
  - `"scope"`: a list of `OAuth2Utils.Scope.scope()` scopes granted to the refresh token
  - `"device_id"`: the `t:Asteroid.Device.id()` of the access token
  - `"status"`: a `String.t()` for the status of the token. A token that has been revoked is not
  necessarily still present in the token store (e.g. for stateful tokens it will be probably
  deleted). Optionally one of:
    - `"active"`: active token
    - `"revoked"`: revoked token
  """

  @enforce_keys [:id, :serialization_format, :data]

  defstruct [:id, :refresh_token_id, :serialization_format, :data]

  @type id :: binary()

  @type t :: %__MODULE__{
    id: __MODULE__.id(),
    refresh_token_id: binary() | nil,
    serialization_format: Asteroid.Token.serialization_format(),
    data: map()
  }

  @doc ~s"""
  Creates a new access token

  ## Options
  - `:id`: `String.t()` id, **mandatory**
  - `:refresh_token_id`: the `t:Asteroid.Token.RefreshToken.id/0` of the refresh token associated
  to this access token if any. Defaults to `nil`
  - `:data`: a data `map()`
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  """

  @spec new(Keyword.t()) :: t()

  def new(opts) do
    %__MODULE__{
      id: opts[:id] || (raise "Missing access token id"),
      refresh_token_id: opts[:refresh_token_id] || nil,
      data: opts[:data] || %{},
      serialization_format: opts[:serialization_format] || :opaque
    }
  end

  @doc """
  Generates a new access token

  ## Options
  - `:refresh_token_id`: the `t:Asteroid.Token.RefreshToken.id/0` of the refresh token associated
  to this access token if any. Defaults to `nil`
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  """

  @spec gen_new(Keyword.t()) :: t()
  def gen_new(opts \\ []) do
    %__MODULE__{
      id: secure_random_b64(20),
      refresh_token_id: opts[:refresh_token],
      data: %{},
      serialization_format: (if opts[:format], do: opts[:format], else: :opaque)
    }
  end

  @doc """
  Gets a access token from the access token store

  Unlike the `c:Asteroid.TokenStore.AccessToken.get/2`, this function returns
  `{:error, :nonexistent_access_token}` if the access token is not found in the token
  store.

  ## Options
  - `:check_active`: determines whether the validity of the access token should be checked.
  Defaults to `true`. For validity checking details, see `active?/1`
  """

  @spec get(id(), Keyword.t()) :: {:ok, t()} | {:error, Exception.t()}

  def get(access_token_id, opts \\ [check_active: true]) do
    token_store_module = astrenv(:token_store_access_token)[:module]
    token_store_opts = astrenv(:token_store_access_token)[:opts] || []

    case token_store_module.get(access_token_id, token_store_opts) do
      {:ok, access_token} when not is_nil(access_token) ->
        if opts[:check_active] != true or active?(access_token) do
          {:ok, access_token}
        else
          {:error, Token.InvalidTokenError.exception(
            sort: "access token",
            reason: "inactive token",
            id: access_token_id)}
        end

      {:ok, nil} ->
        {:error, Token.InvalidTokenError.exception(
          sort: "access token",
          reason: "not found in the token store",
          id: access_token_id)}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Stores an access token
  """

  @spec store(t(), Context.t()) :: {:ok, t()} | {:error, any()}

  def store(access_token, ctx \\ %{}) do
    token_store_module = astrenv(:token_store_access_token)[:module]
    token_store_opts = astrenv(:token_store_access_token)[:opts] || []

    access_token = astrenv(:token_store_access_token_before_store_callback).(access_token, ctx)

    case token_store_module.put(access_token, token_store_opts) do
      :ok ->
        {:ok, access_token}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Deletes an access token
  """

  @spec delete(t() | id()) :: :ok | {:error, any()}

  def delete(%__MODULE__{id: id}) do
    delete(id)
  end

  def delete(access_token_id) do
    token_store_module = astrenv(:token_store_access_token)[:module]
    token_store_opts = astrenv(:token_store_access_token)[:opts] || []

    token_store_module.delete(access_token_id, token_store_opts)
  end

  @doc """
  Puts a value into the `data` field of access token

  If the value is `nil`, the access token is not changed and the filed is not added.
  """

  @spec put_value(t(), any(), any()) :: t()

  def put_value(access_token, _key, nil), do: access_token

  def put_value(access_token, key, val) do
    %{access_token | data: Map.put(access_token.data, key, val)}
  end

  @doc """
  Removes a value from the `data` field of a access token

  If the value does not exist, does nothing.
  """

  @spec delete_value(t(), any()) :: t()

  def delete_value(access_token, key) do
    %{access_token | data: Map.delete(access_token.data, key)}
  end

  @doc """
  Serializes the access token, using its inner `t:Asteroid.Token.serialization_format/0`
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
  - `"revoked"`: must be the boolean `false`
  """

  @spec active?(t()) :: boolean()
  def active?(access_token) do
    (is_nil(access_token.data["nbf"]) or access_token.data["nbf"] < now())
    and
    (is_nil(access_token.data["exp"]) or access_token.data["exp"] > now())
    and
    (is_nil(access_token.data["status"]) or access_token.data["status"] != "revoked")
    #FIXME: implement the following items from https://tools.ietf.org/html/rfc7662#section-4
    #   o  If the token has been signed, the authorization server MUST
    #  validate the signature.
    #   o  If the token can be used only at certain resource servers, the
    #  authorization server MUST determine whether or not the token can
    #  be used at the resource server making the introspection call.
  end

  @doc """
  Returns the access token lifetime

  ## Processing rules
  - If the client has the following field set to an integer value for the corresponding flow
  returns that value:
    - `"__asteroid_oauth2_flow_ropc_access_token_lifetime"`
    - `"__asteroid_oauth2_flow_client_credentials_access_token_lifetime"`
    - `"__asteroid_oauth2_flow_authorization_code_access_token_lifetime"`
    - `"__asteroid_oauth2_flow_implicit_access_token_lifetime"`
  - Otherwise, if the following configuration option is set to an integer for the corresponding
  flow, returns its value:
    - #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_implicit_access_token_lifetime)}
  - Otherwise returns `0`
  """

  def lifetime(%{flow: :ropc, client: client}) do
    attr = "__asteroid_oauth2_flow_ropc_access_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oauth2_flow_ropc_access_token_lifetime, 0)
    end
  end

  def lifetime(%{flow: :client_credentials, client: client}) do
    attr = "__asteroid_oauth2_flow_client_credentials_access_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oauth2_flow_client_credentials_access_token_lifetime, 0)
    end
  end

  def lifetime(%{flow: :authorization_code, client: client}) do
    attr = "__asteroid_oauth2_flow_authorization_code_access_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oauth2_flow_authorization_code_access_token_lifetime, 0)
    end
  end

  def lifetime(%{flow: :implicit, client: client}) do
    attr = "__asteroid_oauth2_flow_implicit_access_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oauth2_flow_implicit_access_token_lifetime, 0)
    end
  end

  def lifetime(_) do
    0
  end
end
