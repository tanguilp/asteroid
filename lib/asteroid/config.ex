defmodule Asteroid.Config do
  @moduledoc """
  Specification of configuration options and callbacks, and testouille
  """

  require Asteroid.Config.Builder

  @typedoc """
  A map describing scope configuration

  The map keys are the scope's names. The map values are `Keyword.t/0` with the following
  options:
  - `:auto`: if true, the scope is automatically granted

  ## Example
  ```elixir
  %{
    "scope-a" => [auto: true],
    "scope-b" => [auto: true],
    "scope-c" => [auto: false],
    "scope-d" => [],
    "scope-f" => [auto: true],
  }
  ```
  """

  @type scope_config :: map()

  Asteroid.Config.Builder.defconfig do
    @doc """
    Access token store configuration

    #### Options
    - `:module`: the name of the module implementing the token's behaviours. No default,
    **mandatory**
    - `:opts`: options that will be passed to the all token's implementation functions. Refer to
    the implementation documentation. Defaults to `[]`
    - `:auto_install`: `boolean()` indicating whether the `install/1` callback of the
    impementation should be called at Asteroid startup. Defaults to `true`
    - `:auto_start`: `boolean()` indicating whether the `start_link/1` or `start/1` callback of
    the Implementation should be called at Asteroid startup. Defaults to `true`

    #### Example

    ```elixir
    config :asteroid, :token_store_access_token, [
      module: Asteroid.TokenStore.AccessToken.Riak,
      opts: [bucket_type: "ephemeral_token", purge_interval: 10]
    ]
    ```
    """

    @type token_store_access_token :: Keyword.t()

    field :token_store_access_token,
      config_time: :runtime

    @doc """
    Refresh token store configuration

    #### Options
    - `:module`: the name of the module implementing the token's behaviours. No default,
    **mandatory**
    - `:opts`: options that will be passed to the all token's implementation functions. Refer to
    the implementation documentation. Defaults to `[]`
    - `:auto_install`: `boolean()` indicating whether the `install/1` callback of the
    impementation should be called at Asteroid startup. Defaults to `true`
    - `:auto_start`: `boolean()` indicating whether the `start_link/1` or `start/1` callback of
    the Implementation should be called at Asteroid startup. Defaults to `true`

    #### Example

    ```elixir
    config :asteroid, :token_store_refresh_token, [
      module: Asteroid.TokenStore.RefreshToken.Mnesia
    ]
    ```
    """

    @type token_store_refresh_token :: Keyword.t()

    field :token_store_refresh_token,
      config_time: :runtime

    @doc """
    Callback invoked before storing a refresh token
    """

    @type token_store_refresh_token_before_store_callback ::
    (Asteroid.Token.RefreshToken.t(), Asteroid.Context.t() -> Asteroid.Token.RefreshToken.t())

    field :token_store_refresh_token_before_store_callback,
    config_time: :runtime

    @doc """
    Callback invoked before storing an access token
    """

    @type token_store_access_token_before_store_callback ::
    (Asteroid.Token.AccessToken.t(), Asteroid.Context.t() -> Asteroid.Token.RefreshToken.t())

    field :token_store_access_token_before_store_callback,
    config_time: :runtime

    @doc """
    Plugs installed on `"/api/oauth2"`

    See also [protecting APIs](protecting-apis.html)
    """

    @type api_oauth2_plugs :: [{module(), Keyword.t()}]

    field :api_oauth2_plugs,
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oauth2/token"`

    See also [protecting APIs](protecting-apis.html)
    """

    @type api_oauth2_endpoint_token_plugs :: [{module(), Keyword.t()}]

    field :api_oauth2_endpoint_token_plugs,
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oauth2/introspect"`

    See also [protecting APIs](protecting-apis.html)
    """

    @type api_oauth2_endpoint_introspect_plugs :: [{module(), Keyword.t()}]

    field :api_oauth2_endpoint_introspect_plugs,
      config_time: :compile

    @doc """
    List of enabled grant types

    It is used in OAuth2 APIs (such as `/token`) so as to determine support, and for metadata
    generation.
    """

    @type oauth2_grant_types_enabled :: [Asteroid.OAuth2.grant_type()]

    field :oauth2_grant_types_enabled,
      config_time: :runtime

    @doc """
    Callback to verify username and password in the ROPC flow.
    """

    @typedoc """
    Callback function for the `:oauth2_ropc_username_password_verify_callback` configuration
    option.

    Calls the callback `callback` with `callback.(conn, username, password)`
    """

    @type oauth2_ropc_username_password_verify_callback ::
    (Plug.Conn.t(), String.t(), String.t() ->
      {:ok, Asteroid.Subject.t()} | {:error, :invalid_username_or_password})

    field :oauth2_ropc_username_password_verify_callback,
      config_time: :runtime

    @doc """
    Scope configuration for the ROPC flow
    """

    @type oauth2_flow_ropc_scope_config :: scope_config()

    field :oauth2_flow_ropc_scope_config,
    config_time: :runtime,
    used_by: [:oauth2_scope_callback]

    @doc """
    Callback called to set scopes according to the configuration
    """

    @type oauth2_scope_callback ::
    (OAuth2Utils.Scope.Set.t(), Asteroid.Context.t() -> OAuth2Utils.Scope.Set.t())

    field :oauth2_scope_callback,
      config_time: :runtime,
      uses: [:oauth2_flow_ropc_scope_config]

    @doc """
    Defines whether a refresh token should be issued when initiating an ROPC flow
    """

    @type oauth2_flow_ropc_issue_refresh_token_init :: boolean()

    field :oauth2_flow_ropc_issue_refresh_token_init,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens
    """

    @type oauth2_flow_ropc_issue_refresh_token_refresh :: boolean()

    field :oauth2_flow_ropc_issue_refresh_token_refresh,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Callback called to determine whether a refresh token should be issued

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """

    @type oauth2_issue_refresh_token_callback :: (Asteroid.Context.t() -> boolean())

    field :oauth2_issue_refresh_token_callback,
    config_time: :runtime,
    uses: [
      :oauth2_flow_ropc_issue_refresh_token_init,
      :oauth2_flow_ropc_issue_refresh_token_refresh
    ]

    @doc """
    Defines the lifetime of a refresh token in the ROPC flow
    """

    @type oauth2_flow_ropc_refresh_token_lifetime :: non_neg_integer()

    field :oauth2_flow_ropc_refresh_token_lifetime,
    config_time: :runtime,
    used_by: [:oauth2_refresh_token_lifetime_callback],
    unit: "seconds"

    @doc """
    Callback called to determine the lifetime of a refresh token

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """

    @type oauth2_refresh_token_lifetime_callback :: (Asteroid.Context.t() -> non_neg_integer())

    field :oauth2_refresh_token_lifetime_callback,
    config_time: :runtime,
    uses: [
      :oauth2_flow_ropc_refresh_token_lifetime
    ]

    @doc """
    Defines the lifetime of an access token in the ROPC flow
    """

    @type oauth2_flow_ropc_access_token_lifetime :: non_neg_integer()

    field :oauth2_flow_ropc_access_token_lifetime,
    config_time: :runtime,
    used_by: [:oauth2_access_token_lifetime_callback],
    unit: "seconds"

    @doc """
    Callback called to determine the lifetime of an access refresh token

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """

    @type oauth2_access_token_lifetime_callback :: (Asteroid.Context.t() -> non_neg_integer())

    field :oauth2_access_token_lifetime_callback,
    config_time: :runtime,
    uses: [
      :oauth2_flow_ropc_access_token_lifetime
    ]

    @doc """
    Callback invoked on the json response when the grant_type is "password"
    """

    @type oauth2_grant_type_password_before_send_resp_callback ::
    (map(), Asteroid.Context.t() -> map())

    field :oauth2_grant_type_password_before_send_resp_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is "password"
    """

    @type oauth2_grant_type_password_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_grant_type_password_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the json response when the grant_type is "refresh_token"
    """

    @type oauth2_grant_type_refresh_token_before_send_resp_callback ::
    (map(), Asteroid.Context.t() -> map())

    field :oauth2_grant_type_refresh_token_before_send_resp_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is "refresh_token"
    """

    @type oauth2_grant_type_refresh_token_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_grant_type_refresh_token_before_send_conn_callback,
    config_time: :runtime

  end

  @doc """
  Returns the markdown link to the documentation of a configuration option
  """

  @spec link_to_option(atom()) :: String.t()

  def link_to_option(configuration_option) do
    configuration_option = to_string(configuration_option)

    "[`:#{configuration_option}`](Asteroid.Config.html#module-#{configuration_option})"
  end
end
