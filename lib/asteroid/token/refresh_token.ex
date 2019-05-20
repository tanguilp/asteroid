defmodule Asteroid.Token.RefreshToken do
  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.Client

  @moduledoc """
  Refresh token structure

  ## Field naming
  The `data` field holds the token data. The following field names are standard and are used
  by Asteroid:
  - `"exp"`: the expiration unix timestamp of the refresh token
  - `"sub"`: the `t:Asteroid.Subject.id/0` of the refresh token
  - `"client_id"`: the `t:Asteroid.Client.id/0` of the refresh token
  - `"device_id"`: the `t:Asteroid.Device.id/0` of the refresh token
  - `"scope"`: a list of `OAuth2Utils.Scope.scope()` scopes granted to the refresh token
  - `"__asteroid_oauth2_initial_flow"`: the initial `t:Asteroid.OAuth2.flow_str/0` during which
  the refresh token was granted
  - `"status"`: a `String.t()` for the status of the token. A token that has been revoked is not
  necessarily still present in the token store (e.g. for stateful tokens it will be probably
  deleted). Optionally one of:
    - `"active"`: active token
    - `"revoked"`: revoked token
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
  Creates a new refresh token

  ## Options
  - `:id`: `String.t()` id, **mandatory**
  - `:data`: a data `map()`
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  """

  @spec new(Keyword.t()) :: t()

  def new(opts) do
    %__MODULE__{
      id: opts[:id] || (raise "Missing refresh token id"),
      data: opts[:data] || %{},
      serialization_format: opts[:serialization_format] || :opaque
    }
  end

  @doc """
  Generates a new refresh token

  ## Options
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  """

  @spec gen_new(Keyword.t()) :: t()

  def gen_new(opts \\ []) do
    %__MODULE__{
      id: secure_random_b64(),
      data: %{},
      serialization_format: (if opts[:format], do: opts[:format], else: :opaque)
    }
  end

  @doc """
  Gets a refresh token from the refresh token store

  Unlike the `c:Asteroid.TokenStore.RefreshToken.get/2`, this function returns
  `{:error, :nonexistent_refresh_token}` if the refresh token is not found in the token
  store.

  ## Options
  - `:check_active`: determines whether the validity of the refresh token should be checked.
  Defaults to `true`. For validity checking details, see `active?/1`
  """

  @spec get(id(), Keyword.t()) :: {:ok, t()} | {:error, any()}

  def get(refresh_token_id, opts \\ [check_active: true]) do
    token_store_module = astrenv(:token_store_refresh_token)[:module]
    token_store_opts = astrenv(:token_store_refresh_token)[:opts] || []

    case token_store_module.get(refresh_token_id, token_store_opts) do
      {:ok, refresh_token} when not is_nil(refresh_token) ->
        if opts[:check_active] != true or active?(refresh_token) do
          {:ok, refresh_token}
        else
          {:error, :inactive_refresh_token}
        end

      {:ok, nil} ->
        {:error, :nonexistent_refresh_token}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Stores a refresh token
  """

  @spec store(t(), Context.t()) :: {:ok, t()} | {:error, any()}

  def store(refresh_token, ctx \\ %{}) do
    token_store_module = astrenv(:token_store_refresh_token)[:module]
    token_store_opts = astrenv(:token_store_refresh_token)[:opts] || []

    refresh_token =
      astrenv(:token_store_refresh_token_before_store_callback).(refresh_token, ctx)

    case token_store_module.put(refresh_token, token_store_opts) do
      :ok ->
        {:ok, refresh_token}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Deletes a refresh token
  """

  @spec delete(t() | id()) :: :ok | {:error, any()}

  def delete(%__MODULE__{id: id}) do
    delete(id)
  end

  def delete(refresh_token_id) do
    refresh_token_store_module = astrenv(:token_store_refresh_token)[:module]
    refresh_token_store_opts = astrenv(:token_store_refresh_token)[:opts] || []

    access_token_store_module = astrenv(:token_store_access_token)[:module]
    access_token_store_opts = astrenv(:token_store_access_token)[:opts] || []

    refresh_token_store_module.delete(refresh_token_id,
                                      refresh_token_store_opts,
                                      {access_token_store_module, access_token_store_opts})
  end

  @doc """
  Puts a value into the `data` field of refresh token

  If the value is `nil`, the refresh token is not changed and the filed is not added.
  """

  @spec put_value(t(), any(), any()) :: t()

  def put_value(refresh_token, _key, nil), do: refresh_token

  def put_value(refresh_token, key, val) do
    %{refresh_token | data: Map.put(refresh_token.data, key, val)}
  end

  @doc """
  Removes a value from the `data` field of a refresh token

  If the value does not exist, does nothing.
  """

  @spec delete_value(t(), any()) :: t()

  def delete_value(refresh_token, key) do
    %{refresh_token | data: Map.delete(refresh_token.data, key)}
  end

  @doc """
  Serializes the refresh token, using its inner `t:Asteroid.Token.serialization_format/0`
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

  def active?(refresh_token) do
    (is_nil(refresh_token.data["nbf"]) or refresh_token.data["nbf"] < now())
    and
    (is_nil(refresh_token.data["exp"]) or refresh_token.data["exp"] > now())
    and
    (is_nil(refresh_token.data["status"]) or refresh_token.data["status"] != "revoked")
    #FIXME: implement the following items from https://tools.ietf.org/html/rfc7662#section-4
    #   o  If the token has been signed, the authorization server MUST
    #  validate the signature.
    #   o  If the token can be used only at certain resource servers, the
    #  authorization server MUST determine whether or not the token can
    #  be used at the resource server making the introspection call.
  end

  @doc """
  Returns `true` if a refresh token is to be issued, `false` otherwise

  ## Processing rules
  - If the client has the following field set to `true` for the corresponding flow and
  grant type, returns `true`:
    - `"__asteroid_oauth2_flow_ropc_issue_refresh_token_init"`
    - `"__asteroid_oauth2_flow_ropc_issue_refresh_token_refresh"`
    - `"__asteroid_oauth2_flow_client_credentials_issue_refresh_token_init"`
    - `"__asteroid_oauth2_flow_client_credentials_issue_refresh_token_refresh"`
    - `"__asteroid_oauth2_flow_authorization_code_issue_refresh_token_init"`
    - `"__asteroid_oauth2_flow_authorization_code_issue_refresh_token_refresh"`
  - Otherwise, if the following configuration option is set to `true` for the corresponding flow
  and grant type, returns `true`:
    - #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_issue_refresh_token_init)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_issue_refresh_token_refresh)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_issue_refresh_token_init)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_issue_refresh_token_refresh)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_issue_refresh_token_init)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_issue_refresh_token_refresh)}
  - Otherwise returns `false`
  """

  @spec issue_refresh_token?(Context.t()) :: boolean()

  def issue_refresh_token?(%{flow: :ropc, grant_type: :password, client: client}) do
    attr = "__asteroid_oauth2_flow_ropc_issue_refresh_token_init"

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      astrenv(:oauth2_flow_ropc_issue_refresh_token_init, false)
    end
  end

  def issue_refresh_token?(%{flow: :ropc, grant_type: :refresh_token, client: client}) do
    attr = "__asteroid_oauth2_flow_ropc_issue_refresh_token_refresh"

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      astrenv(:oauth2_flow_ropc_issue_refresh_token_refresh, false)
    end
  end

  def issue_refresh_token?(%{
    flow: :client_credentials,
    grant_type: :client_credentials,
    client: client})
  do
    attr = "__asteroid_oauth2_flow_client_credentials_issue_refresh_token_init"

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      astrenv(:oauth2_flow_client_credentials_issue_refresh_token_init, false)
    end
  end

  def issue_refresh_token?(%{
    flow: :client_credentials,
    grant_type: :refresh_token,
    client: client})
  do
    attr = "__asteroid_oauth2_flow_client_credentials_issue_refresh_token_refresh"

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      astrenv(:oauth2_flow_client_credentials_issue_refresh_token_refresh, false)
    end
  end

  def issue_refresh_token?(%{
    flow: :authorization_code,
    grant_type: :authorization_code,
    client: client})
  do
    attr = "__asteroid_oauth2_flow_authorization_code_issue_refresh_token_init"

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      astrenv(:oauth2_flow_authorization_code_issue_refresh_token_init, false)
    end
  end

  def issue_refresh_token?(%{
    flow: :authorization_code,
    grant_type: :refresh_token,
    client: client})
  do
    attr = "__asteroid_oauth2_flow_authorization_code_issue_refresh_token_refresh"

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      astrenv(:oauth2_flow_authorization_code_issue_refresh_token_refresh, false)
    end
  end

  def issue_refresh_token?(_) do
    false
  end

  @doc """
  Returns the refresh token lifetime

  ## Processing rules
  - If the client has the following field set to an integer value for the corresponding flow
  returns that value:
    - `"__asteroid_oauth2_flow_ropc_refresh_token_lifetime"`
    - `"__asteroid_oauth2_flow_client_credentials_refresh_token_lifetime"`
    - `"__asteroid_oauth2_flow_authoirzation_code_refresh_token_lifetime"`
  - Otherwise, if the following configuration option is set to an integer for the corresponding
  flow, returns its value:
    - #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_refresh_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_refresh_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_refresh_token_lifetime)}
  - Otherwise returns `0`
  """

  def lifetime(%{flow: :ropc, client: client}) do
    attr = "__asteroid_oauth2_flow_ropc_refresh_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oauth2_flow_ropc_refresh_token_lifetime, 0)
    end
  end

  def lifetime(%{flow: :client_credentials, client: client}) do
    attr = "__asteroid_oauth2_flow_client_credentials_refresh_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oauth2_flow_client_credentials_refresh_token_lifetime, 0)
    end
  end

  def lifetime(%{flow: :authorization_code, client: client}) do
    attr = "__asteroid_oauth2_flow_authoirzation_code_refresh_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oauth2_flow_authorization_code_refresh_token_lifetime, 0)
    end
  end

  def lifetime(_) do
    0
  end
end
