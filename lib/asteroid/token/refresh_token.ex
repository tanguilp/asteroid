defmodule Asteroid.Token.RefreshToken do
  import Asteroid.Config, only: [opt: 1]
  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.Token

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
  - `"__asteroid_oidc_authenticated_session_id"`: the `t:Asteroid.OIDC.AuthenticatedSession.id/0`
  of the refresh token
  - `"__asteroid_oidc_claims"`: the claims that were requested, if any
  - `"__asteroid_oidc_initial_acr"`: the `t:Asteroid.OIDC.acr/0` of the refresh token, if
  any. This is the value got from the session when the token was first released
  - `"__asteroid_oidc_initial_amr"`: a list of `t:Asteroid.OIDC.acr/0` of the refresh token,
  if any. This is the value got from the session when the token was first released
  - `"__asteroid_oidc_initial_auth_time"`: a `non_neg_integer()` of the refresh token,
  if any. This is the value got from the session when the token was first released
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
      id: opts[:id] || raise("Missing refresh token id"),
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
      serialization_format: if(opts[:format], do: opts[:format], else: :opaque)
    }
  end

  @doc """
  Gets a refresh token from the refresh token store

  Unlike the `c:Asteroid.ObjectStore.RefreshToken.get/2`, this function returns
  `{:error, :nonexistent_refresh_token}` if the refresh token is not found in the token
  store.

  ## Options
  - `:check_active`: determines whether the validity of the refresh token should be checked.
  Defaults to `true`. For validity checking details, see `active?/1`
  """

  @spec get(id(), Keyword.t()) :: {:ok, t()} | {:error, Exception.t()}

  def get(refresh_token_id, opts \\ [check_active: true]) do
    rt_store_module = opt(:object_store_refresh_token)[:module]
    rt_store_opts = opt(:object_store_refresh_token)[:opts] || []

    case rt_store_module.get(refresh_token_id, rt_store_opts) do
      {:ok, refresh_token} when not is_nil(refresh_token) ->
        if opts[:check_active] != true or active?(refresh_token) do
          {:ok, refresh_token}
        else
          {:error,
           Token.InvalidTokenError.exception(
             sort: "refresh token",
             reason: "inactive token",
             id: refresh_token_id
           )}
        end

      {:ok, nil} ->
        {:error,
         Token.InvalidTokenError.exception(
           sort: "refresh token",
           reason: "not found in the token store",
           id: refresh_token_id
         )}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Stores a refresh token
  """

  @spec store(t(), Context.t()) :: {:ok, t()} | {:error, any()}

  def store(refresh_token, ctx \\ %{}) do
    rt_store_module = opt(:object_store_refresh_token)[:module]
    rt_store_opts = opt(:object_store_refresh_token)[:opts] || []

    refresh_token =
      opt(:object_store_refresh_token_before_store_callback).(refresh_token, ctx)

    case rt_store_module.put(refresh_token, rt_store_opts) do
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
    rt_store_module = opt(:object_store_refresh_token)[:module]
    rt_store_opts = opt(:object_store_refresh_token)[:opts] || []

    rt_store_module.delete(refresh_token_id, rt_store_opts)

    at_store_module = opt(:object_store_access_token)[:module]
    at_store_opts = opt(:object_store_access_token)[:opts] || []

    case at_store_module.get_from_refresh_token_id(refresh_token_id, rt_store_opts) do
      {:ok, access_token_ids} ->
        for access_token_id <- access_token_ids do
          at_store_module.delete(access_token_id, at_store_opts)
        end

        :ok

      {:error, _} = error ->
        error
    end
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
    (is_nil(refresh_token.data["nbf"]) or refresh_token.data["nbf"] < now()) and
      (is_nil(refresh_token.data["exp"]) or refresh_token.data["exp"] > now()) and
      (is_nil(refresh_token.data["status"]) or refresh_token.data["status"] != "revoked")

    # FIXME: implement the following items from https://tools.ietf.org/html/rfc7662#section-4
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
    - `"__asteroid_oauth2_flow_device_authorization_issue_refresh_token_init"`
    - `"__asteroid_oauth2_flow_device_authorization_issue_refresh_token_refresh"`
    - `"__asteroid_oidc_flow_authorization_code_issue_refresh_token_init"`
    - `"__asteroid_oidc_flow_authorization_code_issue_refresh_token_refresh"`
    - `"__asteroid_oidc_flow_hybrid_issue_refresh_token_init"`
    - `"__asteroid_oidc_flow_hybrid_issue_refresh_token_refresh"`
  - Otherwise, if the following configuration option is set to `true` for the corresponding flow
  and grant type, returns `true`:
    - #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_issue_refresh_token_init)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_issue_refresh_token_refresh)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_issue_refresh_token_init)}
    - #{
    Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_issue_refresh_token_refresh)
  }
    - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_issue_refresh_token_init)}
    - #{
    Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_issue_refresh_token_refresh)
  }
    - #{
    Asteroid.Config.link_to_option(:oauth2_flow_device_authorization_issue_refresh_token_init)
  }
    - #{
    Asteroid.Config.link_to_option(:oauth2_flow_device_authorization_issue_refresh_token_refresh)
  }
    - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_issue_refresh_token_init)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_issue_refresh_token_refresh)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_issue_refresh_token_init)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_issue_refresh_token_refresh)}
  - Otherwise, uses the following configuration options:
    - #{Asteroid.Config.link_to_option(:oauth2_issue_refresh_token_init)}
    - #{Asteroid.Config.link_to_option(:oauth2_issue_refresh_token_refresh)}
  - Otherwise returns `false`
  """

  @spec issue_refresh_token?(Context.t()) :: boolean()

  def issue_refresh_token?(%{flow: :ropc, grant_type: :password} = ctx),
    do: do_issue_refresh_token?(:oauth2_flow_ropc_issue_refresh_token_init, ctx)
  def issue_refresh_token?(%{flow: :ropc, grant_type: :refresh_token} = ctx),
    do: do_issue_refresh_token?(:oauth2_flow_ropc_issue_refresh_token_refresh, ctx)
  def issue_refresh_token?(%{flow: :client_credentials, grant_type: :client_credentials} = ctx),
    do: do_issue_refresh_token?(:oauth2_flow_client_credentials_issue_refresh_token_init, ctx)
  def issue_refresh_token?(%{flow: :client_credentials, grant_type: :refresh_token} = ctx),
    do: do_issue_refresh_token?(:oauth2_flow_client_credentials_issue_refresh_token_refresh, ctx)
  def issue_refresh_token?(%{flow: :authorization_code, grant_type: :authorization_code} = ctx),
    do: do_issue_refresh_token?(:oauth2_flow_authorization_code_issue_refresh_token_init, ctx)
  def issue_refresh_token?(%{flow: :authorization_code, grant_type: :refresh_token} = ctx),
    do: do_issue_refresh_token?(:oauth2_flow_authorization_code_issue_refresh_token_refresh, ctx)
  def issue_refresh_token?(%{flow: :device_authorization, grant_type: :"urn:ietf:params:oauth:grant-type:device_code"} = ctx),
    do: do_issue_refresh_token?(:oauth2_flow_device_authorization_issue_refresh_token_init, ctx)
  def issue_refresh_token?(%{flow: :device_authorization, grant_type: :refresh_token} = ctx),
    do: do_issue_refresh_token?(:oauth2_flow_device_authorization_issue_refresh_token_refresh,ctx)
  def issue_refresh_token?(%{flow: :oidc_authorization_code, grant_type: :authorization_code} = ctx),
    do: do_issue_refresh_token?(:oidc_flow_authorization_code_issue_refresh_token_init, ctx)
  def issue_refresh_token?(%{flow: :oidc_authorization_code, grant_type: :refresh_token} = ctx),
    do: do_issue_refresh_token?(:oidc_flow_authorization_code_issue_refresh_token_refresh, ctx)
  def issue_refresh_token?(%{flow: :oidc_hybrid, grant_type: :authorization_code} = ctx),
    do: do_issue_refresh_token?(:oidc_flow_hybrid_issue_refresh_token_init, ctx)
  def issue_refresh_token?(%{flow: :oidc_hybrid, grant_type: :refresh_token} = ctx),
    do: do_issue_refresh_token?(:oidc_flow_authorization_code_issue_refresh_token_refresh, ctx)

  def do_issue_refresh_token?(opt_name, ctx) do
    attr = "__asteroid_#{opt_name}"

    client = Client.fetch_attributes(ctx.client, [attr])

    if is_boolean(client.attrs[attr]) do
      true
    else
      if opt_name |> opt() |> is_boolean(),
        do: opt(opt_name),
        else: opt(:oauth2_issue_refresh_token_refresh)
    end
  end

  @doc """
  Returns the refresh token lifetime

  ## Processing rules
  - If the client has the following field set to an integer value for the corresponding flow
  returns that value:
    - `"__asteroid_oauth2_flow_ropc_refresh_token_lifetime"`
    - `"__asteroid_oauth2_flow_client_credentials_refresh_token_lifetime"`
    - `"__asteroid_oauth2_flow_authorization_code_refresh_token_lifetime"`
    - `"__asteroid_oauth2_flow_device_authorization_refresh_token_lifetime"`
    - `"__asteroid_oidc_flow_authorization_code_refresh_token_lifetime"`
    - `"__asteroid_oidc_flow_hybrid_refresh_token_lifetime"`
  - Otherwise, if the following configuration option is set to an integer for the corresponding
  flow, returns its value:
    - #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_refresh_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_refresh_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_refresh_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oauth2_flow_device_authorization_refresh_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_refresh_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_refresh_token_lifetime)}
  - Otherwise returns the value of the
  #{Asteroid.Config.link_to_option(:oauth2_refresh_token_lifetime)} configuration option
  - Otherwise returns `0`

  In any case, the returned value is capped by the scope configuration.
  """

  @spec lifetime(Context.t()) :: non_neg_integer()

  def lifetime(%{flow: flow, granted_scopes: granted_scopes} = ctx) do
    scope_config = Asteroid.OAuth2.Scope.configuration_for_flow(flow)

    case Asteroid.OAuth2.Scope.max_refresh_token_lifetime(granted_scopes, scope_config) do
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

  defp lifetime_for_client(%{flow: flow, client: client}) do
    attr =
      case flow do
        :ropc ->
          "__asteroid_oauth2_flow_ropc_refresh_token_lifetime"

        :client_credentials ->
          "__asteroid_oauth2_flow_client_credentials_refresh_token_lifetime"

        :authorization_code ->
          "__asteroid_oauth2_flow_authorization_code_refresh_token_lifetime"

        :device_authorization ->
          "__asteroid_oauth2_flow_device_authorization_refresh_token_lifetime"

        :oidc_authorization_code ->
          "__asteroid_oidc_flow_authorization_code_refresh_token_lifetime"

        :oidc_hybrid ->
          "__asteroid_oidc_flow_hybrid_refresh_token_lifetime"
      end

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        conf_opt =
          case flow do
            :ropc ->
              :oauth2_flow_ropc_refresh_token_lifetime

            :client_credentials ->
              :oauth2_flow_client_credentials_refresh_token_lifetime

            :authorization_code ->
              :oauth2_flow_authorization_code_refresh_token_lifetime

            :device_authorization ->
              :oauth2_flow_device_authorization_refresh_token_lifetime

            :oidc_authorization_code ->
              :oidc_flow_authorization_code_refresh_token_lifetime

            :oidc_hybrid ->
              :oidc_flow_hybrid_refresh_token_lifetime
          end

        opt(conf_opt) || opt(:oauth2_refresh_token_lifetime)
    end
  end

  defp lifetime_for_client(_) do
    0
  end
end
