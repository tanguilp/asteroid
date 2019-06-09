defmodule Asteroid.Config do
  @moduledoc """
  Specification of configuration options and callbacks
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
    Authorization code store configuration

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
    config :asteroid, :token_store_authorization_code, [
      module: Asteroid.TokenStore.AuthorizationCode.Mnesia
    ]
    ```
    """

    @type token_store_authorization_code :: Keyword.t()

    field :token_store_authorization_code,
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
    Callback invoked before storing an authorization code
    """

    @type token_store_authorization_code_before_store_callback ::
    (Asteroid.Token.AuthorizationCode.t(), Asteroid.Context.t() ->
      Asteroid.Token.AuthorizationCode.t())

    field :token_store_authorization_code_before_store_callback,
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
    Plugs installed on `"/api/oauth2/revoke"`

    See also [protecting APIs](protecting-apis.html)
    """

    @type api_oauth2_endpoint_revoke_plugs :: [{module(), Keyword.t()}]

    field :api_oauth2_endpoint_revoke_plugs,
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oauth2/register"`

    See also [protecting APIs](protecting-apis.html)
    """

    @type api_oauth2_endpoint_register_plugs :: [{module(), Keyword.t()}]

    field :api_oauth2_endpoint_register_plugs,
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
    List of enabled response types

    It is used in OAuth2 web authentication flows (`/authorize`) so as to determine support,
    and for metadata generation.
    """

    @type oauth2_response_types_enabled :: [Asteroid.OAuth2.response_type()]

    field :oauth2_response_types_enabled,
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
      uses: [
        :oauth2_flow_ropc_scope_config,
        :oauth2_flow_client_credentials_scope_config
      ]

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
      :oauth2_flow_ropc_issue_refresh_token_refresh,
      :oauth2_flow_client_credentials_issue_refresh_token_init,
      :oauth2_flow_client_credentials_issue_refresh_token_refresh,
      :oauth2_flow_authorization_code_issue_refresh_token_init,
      :oauth2_flow_authorization_code_issue_refresh_token_refresh
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
      :oauth2_flow_ropc_refresh_token_lifetime,
      :oauth2_flow_client_credentials_refresh_token_lifetime,
      :oauth2_flow_authorization_code_refresh_token_lifetime
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
      :oauth2_flow_ropc_access_token_lifetime,
      :oauth2_flow_client_credentials_access_token_lifetime,
      :oauth2_flow_authorization_code_access_token_lifetime,
      :oauth2_flow_implicit_access_token_lifetime
    ]

    @doc """
    Callback called to determine the lifetime of an authorization code

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """

    @type oauth2_authorization_code_lifetime_callback ::
    (Asteroid.Context.t() -> non_neg_integer())

    field :oauth2_authorization_code_lifetime_callback,
    config_time: :runtime,
    uses: [
      :oauth2_flow_authorization_code_authorization_code_lifetime
    ]

    @doc """
    Defines the lifetime of an authorization code in the code flow
    """

    @type oauth2_flow_authorization_code_authorization_code_lifetime :: non_neg_integer()

    field :oauth2_flow_authorization_code_authorization_code_lifetime,
    config_time: :runtime,
    used_by: [:oauth2_authorization_code_lifetime_callback],
    unit: "seconds"

    @doc """
    Callback invoked on the json response when the grant_type is "password"
    """

    @type oauth2_endpoint_token_grant_type_password_before_send_resp_callback ::
    (map(), Asteroid.Context.t() -> map())

    field :oauth2_endpoint_token_grant_type_password_before_send_resp_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is "password"
    """

    @type oauth2_endpoint_token_grant_type_password_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_token_grant_type_password_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the json response when the grant_type is "refresh_token"
    """

    @type oauth2_endpoint_token_grant_type_refresh_token_before_send_resp_callback ::
    (map(), Asteroid.Context.t() -> map())

    field :oauth2_endpoint_token_grant_type_refresh_token_before_send_resp_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is "refresh_token"
    """

    @type oauth2_endpoint_token_grant_type_refresh_token_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_token_grant_type_refresh_token_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Callback invoked to determine if a client is authorized to introspect tokens on the
    `"/introspect"` endpoint
    """

    @type oauth2_endpoint_introspect_client_authorized ::
    (Asteroid.Client.t() -> boolean())

    field :oauth2_endpoint_introspect_client_authorized,
    config_time: :runtime

    @doc """
    Defines the default claims to be returned from the `"/introspect"` endpoint

    Note that client's configuration takes precedence over this configuration option.
    """

    @type oauth2_endpoint_introspect_claims_resp :: [String.t()]

    field :oauth2_endpoint_introspect_claims_resp,
    config_time: :runtime,
    used_by: [:oauth2_endpoint_introspect_claims_resp_callback]

    @doc """
    Callback invoked to determine the claims to be returned from the `"/introspect"` endpoint
    """

    @type oauth2_endpoint_introspect_claims_resp_callback ::
    (Asteroid.Client.t() -> [String.t()])

    field :oauth2_endpoint_introspect_claims_resp_callback,
    config_time: :runtime,
    uses: [:oauth2_endpoint_introspect_claims_resp]

    @doc """
    Callback invoked on the json response on the `"/introspect"` endpoint
    """

    @type oauth2_endpoint_introspect_before_send_resp_callback ::
    (map(), Asteroid.Context.t() -> map())

    field :oauth2_endpoint_introspect_before_send_resp_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response on the `"/introspect"` endpoint
    """

    @type oauth2_endpoint_introspect_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_introspect_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Scope configuration for the client credentials flow
    """

    @type oauth2_flow_client_credentials_scope_config :: scope_config()

    field :oauth2_flow_client_credentials_scope_config,
    config_time: :runtime,
    used_by: [:oauth2_scope_callback]

    @doc """
    Defines whether a refresh token should be issued when initiating a client credentials
    flow

    Note that you should note, according to the specification, release a refresh token in
    this flow.
    """

    @type oauth2_flow_client_credentials_issue_refresh_token_init :: boolean()

    field :oauth2_flow_client_credentials_issue_refresh_token_init,
    config_time: :runtime,
    used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens
    """

    @type oauth2_flow_client_credentials_issue_refresh_token_refresh :: boolean()

    field :oauth2_flow_client_credentials_issue_refresh_token_refresh,
    config_time: :runtime,
    used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines the lifetime of a refresh token in the clienjt credentials flow
    """

    @type oauth2_flow_client_credentials_refresh_token_lifetime :: non_neg_integer()

    field :oauth2_flow_client_credentials_refresh_token_lifetime,
    config_time: :runtime,
    used_by: [:oauth2_refresh_token_lifetime_callback],
    unit: "seconds"

    @doc """
    Defines the lifetime of an access token in the client credentials flow
    """

    @type oauth2_flow_client_credentials_access_token_lifetime :: non_neg_integer()

    field :oauth2_flow_client_credentials_access_token_lifetime,
    config_time: :runtime,
    used_by: [:oauth2_access_token_lifetime_callback],
    unit: "seconds"

    @doc """
    Callback invoked on the json response when the grant_type is `"client_credentials"`
    """

    @type oauth2_endpoint_token_grant_type_client_credentials_before_send_resp_callback ::
    (map(), Asteroid.Context.t() -> map())

    field :oauth2_endpoint_token_grant_type_client_credentials_before_send_resp_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is
    `"client_credentials"`
    """

    @type oauth2_endpoint_token_grant_type_client_credentials_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_token_grant_type_client_credentials_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `/authorize` endpoint to trigger the web authorization process flow
    for the OAuth2 authorization code flow

    This workflow is in charge of authenticating and authorizing (scopes...) the user in regards
    to the request. It will typically involve several step, i.e. display of web pages. It does
    returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the process,
    one of these callback shall be called:
    - `AsteroidWeb.AuthorizeController.authorization_granted/3`
    - `AsteroidWeb.AuthorizeController.authorization_denied/3`
    """

    @type oauth2_flow_authorization_code_web_authorization_callback ::
    (Plug.Conn.t(), AsteroidWeb.AuthorizeController.Request.t() -> Plug.Conn.t())

    field :oauth2_flow_authorization_code_web_authorization_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Asteroid.OAuth2.RedirectUri.t/0` response when response type is
    `"code"` on the `/authorize` endpoint
    """

    @type oauth2_endpoint_authorize_response_type_code_before_send_redirect_uri_callback ::
    (Asteroid.OAuth2.RedirectUri.t(), Asteroid.Context.t() -> Asteroid.OAuth2.RedirectUri.t())

    field :oauth2_endpoint_authorize_response_type_code_before_send_redirect_uri_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when response type is `"code"` on
    the `/authorize` endpoint

    The connection is redirected immediatly after this callback returns.
    """

    @type oauth2_endpoint_authorize_response_type_code_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_authorize_response_type_code_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Defines whether a refresh token should be issued when submitting an authorization code
    in the authorization code flow
    """

    @type oauth2_flow_authorization_code_issue_refresh_token_init :: boolean()

    field :oauth2_flow_authorization_code_issue_refresh_token_init,
    config_time: :runtime,
    used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens in the authorization
    code flow
    """

    @type oauth2_flow_authorization_code_issue_refresh_token_refresh :: boolean()

    field :oauth2_flow_authorization_code_issue_refresh_token_refresh,
    config_time: :runtime,
    used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines the lifetime of a refresh token in the authorization code flow
    """

    @type oauth2_flow_authorization_code_refresh_token_lifetime :: non_neg_integer()

    field :oauth2_flow_authorization_code_refresh_token_lifetime,
    config_time: :runtime,
    used_by: [:oauth2_refresh_token_lifetime_callback],
    unit: "seconds"

    @doc """
    Defines the lifetime of an access token in the authorization code flow
    """

    @type oauth2_flow_authorization_code_access_token_lifetime :: non_neg_integer()

    field :oauth2_flow_authorization_code_access_token_lifetime,
    config_time: :runtime,
    used_by: [:oauth2_access_token_lifetime_callback],
    unit: "seconds"

    @doc """
    Callback invoked on the json response when the grant_type is "authorization_code"
    """

    @type oauth2_endpoint_token_grant_type_authorization_code_before_send_resp_callback ::
    (map(), Asteroid.Context.t() -> map())

    field :oauth2_endpoint_token_grant_type_authorization_code_before_send_resp_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is
    "authorization_code"
    """

    @type oauth2_endpoint_token_grant_type_authorization_code_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_token_grant_type_authorization_code_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` in the `/revoke` endpoint
    """

    @type oauth2_endpoint_revoke_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_revoke_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `/authorize` endpoint to trigger the web authorization process flow
    for the OAuth2 implicit flow

    This workflow is in charge of authenticating and authorizing (scopes...) the user in regards
    to the request. It will typically involve several step, i.e. display of web pages. It does
    returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the process,
    one of these callback shall be called:
    - `AsteroidWeb.AuthorizeController.authorization_granted/3`
    - `AsteroidWeb.AuthorizeController.authorization_denied/3`
    """

    @type oauth2_flow_implicit_web_authorization_callback ::
    (Plug.Conn.t(), AsteroidWeb.AuthorizeController.Request.t() -> Plug.Conn.t())

    field :oauth2_flow_implicit_web_authorization_callback,
    config_time: :runtime

    @doc """
    Defines the lifetime of an access token in the implicit flow
    """

    @type oauth2_flow_implicit_access_token_lifetime :: non_neg_integer()

    field :oauth2_flow_implicit_access_token_lifetime,
    config_time: :runtime,
    used_by: [:oauth2_access_token_lifetime_callback],
    unit: "seconds"

    @doc """
    Callback invoked on the `t:Asteroid.OAuth2.RedirectUri.t/0` response when response type is
    `"token"` on the `/authorize` endpoint
    """

    @type oauth2_endpoint_authorize_response_type_token_before_send_redirect_uri_callback ::
    (Asteroid.OAuth2.RedirectUri.t(), Asteroid.Context.t() -> Asteroid.OAuth2.RedirectUri.t())

    field :oauth2_endpoint_authorize_response_type_token_before_send_redirect_uri_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when response type is `"token"` on
    the `/authorize` endpoint

    The connection is redirected immediatly after this callback returns.
    """

    @type oauth2_endpoint_authorize_response_type_token_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_authorize_response_type_token_before_send_conn_callback,
    config_time: :runtime

    @doc """
    The PKCE policy

    This configuration option can have 3 values:
    - `:disabled`: PKCE support is disabled
    - `:mandatory`: all requests using the authorization code flow must use PKCE
    - `:optional`: use of PKCE is optional, except for clients marked as forced to use it
    """

    @type oauth2_flow_authorization_code_pkce_policy :: :disabled | :optional | :mandatory

    field :oauth2_flow_authorization_code_pkce_policy,
    config_time: :runtime

    @doc """
    Code challenge methods supported

    Supported methods are the following atoms:
    - `:plain`
    - `:S256`
    """

    @type oauth2_flow_authorization_code_pkce_allowed_methods :: [atom()]

    field :oauth2_flow_authorization_code_pkce_allowed_methods,
    config_time: :runtime

    @doc """
    Returns `true` if the client has to use PKCE, `false` otherwise

    Used only when the `:oauth2_flow_authorization_code_pkce_policy` configuration option is
    set to `:optional`
    """

    @type oauth2_flow_authorization_code_pkce_client_callback ::
    (Client.t() -> boolean())

    field :oauth2_flow_authorization_code_pkce_client_callback,
    config_time: :runtime

    @doc """
    Callback called to determine whether a client is authorized to create new clients on
    the register endpoint or not
    """

    @type oauth2_endpoint_register_authorization_callback ::
    (Plug.Conn.t(), Asteroid.Client.t() ->
      :ok | {:error, %Asteroid.OAuth2.Register.UnauthorizedRequestError{}})

    field :oauth2_endpoint_register_authorization_callback,
    config_time: :runtime,
    uses: [:oauth2_endpoint_register_authorization_policy]

    @doc """
    The client registration policy

    This configuration option can have 3 values:
    - `:all`: all clients are allowed to register new clients. Be careful when using this
    value because public clients and the clients created by these public clients could DDOS the
    client registration endpoint. You might consider severely rate-limiting these requests in
    this case
    - `:authenticated_clients`: only authenticated clients are allowed to create new clients
    - `:authorized_clients`: clients that have the `"asteroid.register"` scope set or that
    authenticate to that endpoint with an access token containing that scope
    """

    @type oauth2_endpoint_register_authorization_policy ::
    :all
    | :authenticated_clients
    | :authorized_clients

    field :oauth2_endpoint_register_authorization_policy,
    config_time: :runtime,
    used_by: [:oauth2_endpoint_register_authorization_callback]

    @doc """
    Additional fields that are saved when registering new clients

    Note that this option is overriden by client configuration, if existing.
    """

    @type oauth2_endpoint_register_additional_metadata_field :: [String.t()]

    field :oauth2_endpoint_register_additional_metadata_field,
    config_time: :runtime

    @doc """
    Callback invoked on the json response when on the register endpoint
    """

    @type oauth2_endpoint_register_before_send_resp_callback ::
    (map(), Asteroid.Context.t() -> map())

    field :oauth2_endpoint_register_before_send_resp_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response on the register endpoint
    """

    @type oauth2_endpoint_register_before_send_conn_callback ::
    (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_register_before_send_conn_callback,
    config_time: :runtime

    @doc """
    Callback invoked on the `t:Asteroid.Client.t()` before it's being saved
    """

    @type oauth2_endpoint_register_client_before_save_callback ::
    (Client.t(), Asteroid.Context.t() -> Client.t())

    field :oauth2_endpoint_register_client_before_save_callback,
    config_time: :runtime

    @doc """
    Callback invoked to generate the client id of a newly created client

    The callback should ensure that the client id does not already exists.
    """

    @type oauth2_endpoint_register_gen_client_id_callback :: (map() -> String.t())

    field :oauth2_endpoint_register_gen_client_id_callback,
    config_time: :runtime

    @doc """
    Callback called to determine the supported authentication of the token endpoint
    """

    @type oauth2_endpoint_token_auth_methods_supported_callback ::
    (-> [Asteroid.OAuth2.Endpoint.auth_method()])

    field :oauth2_endpoint_token_auth_methods_supported_callback,
    config_time: :runtime

    ### end of configuration options
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
