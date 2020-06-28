defmodule Asteroid.Token.AccessToken do
  import Asteroid.Config, only: [opt: 1]
  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.Crypto
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
  - `"__asteroid_oauth2_initial_flow"`: the initial `t:Asteroid.OAuth2.flow_str/0` that led to
  the issuance of this token
  - `"__asteroid_oidc_authenticated_session_id"`: the `t:Asteroid.OIDC.AuthenticatedSession.id/0`
  , if any
  - `"__asteroid_oidc_claims"`: the claims that were requested, if any
  """

  @enforce_keys [:id, :serialization_format, :data]

  defstruct [:id, :refresh_token_id, :serialization_format, :signing_key_selector, :data]

  @type id :: binary()

  @type t :: %__MODULE__{
          id: __MODULE__.id(),
          refresh_token_id: binary() | nil,
          serialization_format: Asteroid.Token.serialization_format(),
          signing_key_selector: JOSEUtils.JWK.key_selector() | nil,
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
  - `:signing_key`: an `Asteroid.Crypto.Key.name()` for the signing key
  """

  @spec new(Keyword.t()) :: t()

  def new(opts) do
    %__MODULE__{
      id: opts[:id] || raise("Missing access token id"),
      refresh_token_id: opts[:refresh_token_id] || nil,
      data: opts[:data] || %{},
      serialization_format: opts[:serialization_format] || :opaque,
      signing_key_selector: opts[:signing_key_selector]
    }
  end

  @doc """
  Generates a new access token

  ## Options
  - `:refresh_token_id`: the `t:Asteroid.Token.RefreshToken.id/0` of the refresh token associated
  to this access token if any. Defaults to `nil`
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  - `:signing_key`: an `Asteroid.Crypto.Key.name()` for the signing key
  """

  @spec gen_new(Keyword.t()) :: t()
  def gen_new(opts \\ []) do
    %__MODULE__{
      id: secure_random_b64(20),
      refresh_token_id: opts[:refresh_token],
      data: %{},
      serialization_format:
        if(opts[:serialization_format], do: opts[:serialization_format], else: :opaque),
      signing_key_selector: opts[:signing_key_selector]
    }
  end

  @doc """
  Gets a access token from the access token store

  Unlike the `c:Asteroid.ObjectStore.AccessToken.get/2`, this function returns
  `{:error, Exception.t()}` if the access token is not found in the token
  store.

  ## Options
  - `:check_active`: determines whether the validity of the access token should be checked.
  Defaults to `true`. For validity checking details, see `active?/1`
  """

  @spec get(id(), Keyword.t()) :: {:ok, t()} | {:error, Exception.t()}

  def get(access_token_id, opts \\ [check_active: true]) do
    at_store_module = opt(:object_store_access_token)[:module]
    at_store_opts = opt(:object_store_access_token)[:opts] || []

    case at_store_module.get(access_token_id, at_store_opts) do
      {:ok, access_token} when not is_nil(access_token) ->
        if opts[:check_active] != true or active?(access_token) do
          {:ok, access_token}
        else
          {:error,
           Token.InvalidTokenError.exception(
             sort: "access token",
             reason: "inactive token",
             id: access_token_id
           )}
        end

      {:ok, nil} ->
        {:error,
         Token.InvalidTokenError.exception(
           sort: "access token",
           reason: "not found in the token store",
           id: access_token_id
         )}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Stores an access token

  This function only stores access tokens that have an `:opaque` serialization format.
  """

  @spec store(t(), Context.t()) :: {:ok, t()} | {:error, any()}

  def store(access_token, ctx \\ %{})

  def store(%__MODULE__{serialization_format: :opaque} = access_token, ctx) do
    at_store_module = opt(:object_store_access_token)[:module]
    at_store_opts = opt(:object_store_access_token)[:opts] || []

    access_token = opt(:object_store_access_token_before_store_callback).(access_token, ctx)

    case at_store_module.put(access_token, at_store_opts) do
      :ok ->
        {:ok, access_token}

      {:error, _} = error ->
        error
    end
  end

  def store(access_token, _ctx) do
    {:ok, access_token}
  end

  @doc """
  Deletes an access token
  """

  @spec delete(t() | id()) :: :ok | {:error, any()}

  def delete(%__MODULE__{id: id}) do
    delete(id)
  end

  def delete(access_token_id) do
    at_store_module = opt(:object_store_access_token)[:module]
    at_store_opts = opt(:object_store_access_token)[:opts] || []

    at_store_module.delete(access_token_id, at_store_opts)
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

  Supports serialization to `:opaque` and `:jwt` serialization formats.
  """

  @spec serialize(t(), Client.t()) :: String.t()
  def serialize(%__MODULE__{id: id, serialization_format: :opaque}, _client) do
    id
  end

  def serialize(%__MODULE__{serialization_format: :jwt} = access_token, client) do
    jwt =
      Enum.reduce(
        access_token.data,
        %{},
        fn
          {"__asteroid" <> _, _v}, acc ->
            acc

          {k, v}, acc ->
            Map.put(acc, k, v)
        end
      )

    case Crypto.JOSE.sign(jwt, client, access_token.signing_key_selector || []) do
      {:ok, {jws, _}} ->
        jws

      {:error, e} ->
        raise e
    end
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
    (is_nil(access_token.data["nbf"]) or access_token.data["nbf"] < now()) and
      (is_nil(access_token.data["exp"]) or access_token.data["exp"] > now()) and
      (is_nil(access_token.data["status"]) or access_token.data["status"] != "revoked")

    # FIXME: implement the following items from https://tools.ietf.org/html/rfc7662#section-4
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
    - `"__asteroid_oauth2_flow_device_authorization_access_token_lifetime"`
    - `"__asteroid_oidc_flow_authorization_code_access_token_lifetime"`
    - `"__asteroid_oidc_flow_implicit_access_token_lifetime"`
    - `"__asteroid_oidc_flow_hybrid_access_token_lifetime"`
  - Otherwise, if the following configuration option is set to an integer for the corresponding
  flow, returns its value:
    - #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_implicit_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_device_authorization_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_implicit_access_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_access_token_lifetime)}
  - Otherwise returns
  #{Asteroid.Config.link_to_option(:oauth2_access_token_lifetime)}, or `0` if not set

  In any case, the returned value is capped by the scope configuration.
  """

  @spec lifetime(Context.t()) :: non_neg_integer()

  def lifetime(%{flow: flow, granted_scopes: granted_scopes} = ctx) do
    scope_config = Asteroid.OAuth2.Scope.configuration_for_flow(flow)

    case Asteroid.OAuth2.Scope.max_access_token_lifetime(granted_scopes, scope_config) do
      capped_lifetime when is_integer(capped_lifetime) ->
        min(lifetime_for_client(ctx), capped_lifetime)

      nil ->
        lifetime_for_client(ctx)
    end
  end

  # no scopes
  def lifetime(ctx) do
    lifetime_for_client(ctx)
  end

  @spec lifetime_for_client(Context.t()) :: non_neg_integer()

  def lifetime_for_client(%{flow: flow, client: client}) do
    attr =
      case flow do
        :ropc ->
          "__asteroid_oauth2_flow_ropc_access_token_lifetime"

        :client_credentials ->
          "__asteroid_oauth2_flow_client_credentials_access_token_lifetime"

        :authorization_code ->
          "__asteroid_oauth2_flow_authorization_code_access_token_lifetime"

        :implicit ->
          "__asteroid_oauth2_flow_implicit_access_token_lifetime"

        :device_authorization ->
          "__asteroid_oauth2_flow_device_authorization_access_token_lifetime"

        :oidc_authorization_code ->
          "__asteroid_oidc_flow_authorization_code_access_token_lifetime"

        :oidc_implicit ->
          "__asteroid_oidc_flow_implicit_access_token_lifetime"

        :oidc_hybrid ->
          "__asteroid_oidc_flow_hybrid_access_token_lifetime"
      end

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        conf_opt =
          case flow do
            :ropc ->
              :oauth2_flow_ropc_access_token_lifetime

            :client_credentials ->
              :oauth2_flow_client_credentials_access_token_lifetime

            :authorization_code ->
              :oauth2_flow_authorization_code_access_token_lifetime

            :implicit ->
              :oauth2_flow_implicit_access_token_lifetime

            :device_authorization ->
              :oauth2_flow_device_authorization_access_token_lifetime

            :oidc_authorization_code ->
              :oidc_flow_authorization_code_access_token_lifetime

            :oidc_implicit ->
              :oidc_flow_implicit_access_token_lifetime

            :oidc_hybrid ->
              :oidc_flow_hybrid_access_token_lifetime
          end

        opt(conf_opt) || opt(:oauth2_access_token_lifetime)
    end
  end

  @doc """
  Returns the serialization format for an access token

  Formalisation format is necessarily `:opaque`, except for access tokens for which the
  following rules apply (<FLOW> is to be replace by a `t:Asteroid.OAuth2.flow_str()/0`):
  - if the `__asteroid_oauth2_flow_<FLOW>_access_token_serialization_format` is set, returns
  this value
  - otherwise, if the `:oauth2_flow_<FLOW>_access_token_serialization_format` is set, returns
  this value
  - otherwise, returns the value of the
  #{Asteroid.Config.link_to_option(:oauth2_access_token_serialization_format)} configuration
  option
  - otherwise, returns `:opaque`
  """

  @spec serialization_format(Context.t()) :: Asteroid.Token.serialization_format()

  def serialization_format(%{flow: flow, client: client}) do
    attr = "__asteroid_oauth2_flow_#{Atom.to_string(flow)}_access_token_serialization_format"

    case flow do
      :ropc ->
        "__asteroid_oauth2_flow_ropc_access_token_serialization_format"

      :client_credentials ->
        "__asteroid_oauth2_flow_client_credentials_access_token_serialization_format"

      :authorization_code ->
        "__asteroid_oauth2_flow_authorization_code_access_token_serialization_format"

      :implicit ->
        "__asteroid_oauth2_flow_implicit_access_token_serialization_format"

      :device_authorization ->
        "__asteroid_oauth2_flow_device_authorization_access_token_serialization_format"

      :oidc_authorization_code ->
        "__asteroid_oidc_flow_authorization_code_access_token_serialization_format"

      :oidc_implicit ->
        "__asteroid_oidc_flow_implicit_access_token_serialization_format"

      :oidc_hybrid ->
        "__asteroid_oidc_flow_hybrid_access_token_serialization_format"
    end

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == "jwt" do
      :jwt
    else
      conf_opt =
        case flow do
          :ropc ->
            :oauth2_flow_ropc_access_token_serialization_format

          :client_credentials ->
            :oauth2_flow_client_credentials_access_token_serialization_format

          :authorization_code ->
            :oauth2_flow_authorization_code_access_token_serialization_format

          :implicit ->
            :oauth2_flow_implicit_access_token_serialization_format

          :device_authorization ->
            :oauth2_flow_device_authorization_access_token_serialization_format

          :oidc_authorization_code ->
            :oidc_flow_authorization_code_access_token_serialization_format

          :oidc_implicit ->
            :oidc_flow_implicit_access_token_serialization_format

          :oidc_hybrid ->
            :oidc_flow_hybrid_access_token_serialization_format
        end

      opt(conf_opt) || opt(:oauth2_access_token_serialization_format)
    end
  end

  @doc """
  Returns the signing key name for an access token

  The following rules apply (<FLOW> is to be replace by a `t:Asteroid.OAuth2.flow_str()/0`):
  - if the `__asteroid_oauth2_flow_<FLOW>_access_token_signing_key_selector` is set, returns
  this value
  - otherwise, if the `:oauth2_flow_<FLOW>_access_token_signing_key_selector` is set, returns
  this value
  - otherwise, returns the value of the
  #{Asteroid.Config.link_to_option(:oauth2_access_token_signing_key_selector)} configuration
  option
  - otherwise, returns `nil`
  """
  @spec signing_key_selector(Context.t()) :: JOSEUtils.JWK.key_selector()
  def signing_key_selector(%{flow: flow, client: client}) do
    attr =
      case flow do
        :ropc ->
          "__asteroid_oauth2_flow_ropc_access_token_signing_key_selector"

        :client_credentials ->
          "__asteroid_oauth2_flow_client_credentials_access_token_signing_key_selector"

        :authorization_code ->
          "__asteroid_oauth2_flow_authorization_code_access_token_signing_key_selector"

        :implicit ->
          "__asteroid_oauth2_flow_implicit_access_token_signing_key_selector"

        :device_authorization ->
          "__asteroid_oauth2_flow_device_authorization_access_token_signing_key_selector"

        :oidc_authorization_code ->
          "__asteroid_oidc_flow_authorization_code_access_token_signing_key_selector"

        :oidc_implicit ->
          "__asteroid_oidc_flow_implicit_access_token_signing_key_selector"

        :oidc_hybrid ->
          "__asteroid_oidc_flow_hybrid_access_token_signing_key_selector"
      end

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] != nil do
      client.attrs[attr]
    else
      conf_opt =
        case flow do
          :ropc ->
            :oauth2_flow_ropc_access_token_signing_key_selector

          :client_credentials ->
            :oauth2_flow_client_credentials_access_token_signing_key_selector

          :authorization_code ->
            :oauth2_flow_authorization_code_access_token_signing_key_selector

          :implicit ->
            :oauth2_flow_implicit_access_token_signing_key_selector

          :device_authorization ->
            :oauth2_flow_device_authorization_access_token_signing_key_selector

          :oidc_authorization_code ->
            :oidc_flow_authorization_code_access_token_signing_key_selector

          :oidc_implicit ->
            :oidc_flow_implicit_access_token_signing_key_selector

          :oidc_hybrid ->
            :oidc_flow_hybrid_access_token_signing_key_selector
        end

      opt(conf_opt) || opt(:oauth2_access_token_signing_key_selector)
    end
  end
end
