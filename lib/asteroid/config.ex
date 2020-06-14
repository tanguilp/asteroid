defmodule Asteroid.Config do
  @moduledoc """
  Specification of configuration options and callbacks
  """

  require Specify

  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OIDC
  alias Asteroid.Subject

  defmodule NotAConfigurationOptionError do
    defexception [:opt]

    @impl true
    def message(%{opt: opt}), do: "the `#{inspect(opt)}` configuration option does not exist"
  end

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

  Specify.defconfig sources: [Specify.Provider.MixEnv.new(:asteroid)] do
    @doc """
    """
    field :attribute_repositories, {:list, :option},
      default: [
        subject: [
          module: AttributeRepositoryMnesia,
          init_opts: [instance: :subject],
          run_opts: [instance: :subject]
        ],
        client: [
          module: AttributeRepositoryMnesia,
          init_opts: [instance: :client],
          run_opts: [instance: :client]
        ],
        device: [
          module: AttributeRepositoryMnesia,
          init_opts: [instance: :device],
          run_opts: [instance: :device]
        ]
      ],
      config_time: :runtime

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
    config :asteroid, :object_store_access_token, [
      module: Asteroid.ObjectStore.AccessToken.Riak,
      opts: [bucket_type: "ephemeral_token", purge_interval: 10]
    ]
    ```
    """
    @type object_store_access_token :: Keyword.t()
    field :object_store_access_token, {:list, :term},
      default: [module: Asteroid.ObjectStore.AccessToken.Mnesia],
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
    config :asteroid, :object_store_refresh_token, [
      module: Asteroid.ObjectStore.RefreshToken.Mnesia
    ]
    ```
    """
    @type object_store_refresh_token :: Keyword.t()
    field :object_store_refresh_token, {:list, :term},
      default: [module: Asteroid.ObjectStore.RefreshToken.Mnesia],
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
    config :asteroid, :object_store_authorization_code, [
      module: Asteroid.ObjectStore.AuthorizationCode.Mnesia
    ]
    ```
    """
    @type object_store_authorization_code :: Keyword.t()
    field :object_store_authorization_code, {:list, :term},
      default: [module: Asteroid.ObjectStore.AuthorizationCode.Mnesia],
      config_time: :runtime

    @doc """
    Device code store configuration

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
    config :asteroid, :object_store_device_code, [
      module: Asteroid.ObjectStore.DeviceCode.Mnesia
    ]
    ```
    """
    @type object_store_device_code :: Keyword.t()
    field :object_store_device_code, {:list, :term},
      default: [module: Asteroid.ObjectStore.DeviceCode.Mnesia],
      config_time: :runtime

    @doc """
    Request object store configuration

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
    config :asteroid, :object_store_request_object, [
      module: Asteroid.ObjectStore.GenericKV.Mnesia
    ]
    ```
    """
    @type object_store_request_object :: Keyword.t()
    field :object_store_request_object, {:list, :term},
      default: [
        module: Asteroid.ObjectStore.GenericKV.Mnesia,
        opts: [table_name: :request_object]
      ],
      config_time: :runtime

    @doc """
    Authenticated session store configuration

    #### Options
    - `:module`: the name of the module implementing the object's behaviours. No default,
    **mandatory**
    - `:opts`: options that will be passed to the all object's implementation functions. Refer
    to the implementation documentation. Defaults to `[]`
    - `:auto_install`: `boolean()` indicating whether the `install/1` callback of the
    impementation should be called at Asteroid startup. Defaults to `true`
    - `:auto_start`: `boolean()` indicating whether the `start_link/1` or `start/1` callback of
    the Implementation should be called at Asteroid startup. Defaults to `true`

    #### Example

    ```elixir
    config :asteroid, :object_store_authenticated_session, [
      module: Asteroid.ObjectStore.AuthenticatedSession.Mnesia
    ]
    ```
    """
    @type object_store_authenticated_session :: Keyword.t()
    field :object_store_authenticated_session, {:list, :term},
      default: [module: Asteroid.ObjectStore.AuthenticatedSession.Mnesia],
      config_time: :runtime

    @doc """
    Authentication event store configuration

    #### Options
    - `:module`: the name of the module implementing the object's behaviours. No default,
    **mandatory**
    - `:opts`: options that will be passed to the all object's implementation functions. Refer
    to the implementation documentation. Defaults to `[]`
    - `:auto_install`: `boolean()` indicating whether the `install/1` callback of the
    impementation should be called at Asteroid startup. Defaults to `true`
    - `:auto_start`: `boolean()` indicating whether the `start_link/1` or `start/1` callback of
    the Implementation should be called at Asteroid startup. Defaults to `true`

    #### Example

    ```elixir
    config :asteroid, :object_store_authenticated_session, [
      module: Asteroid.ObjectStore.AuthenticationEvent.Mnesia
    ]
    ```
    """
    @type object_store_authentication_event :: Keyword.t()
    field :object_store_authentication_event, {:list, :term},
      default: [module: Asteroid.ObjectStore.AuthenticationEvent.Mnesia],
      config_time: :runtime

    @doc """
    Callback invoked before storing a refresh token
    """
    @type object_store_refresh_token_before_store_callback ::
            (Asteroid.Token.RefreshToken.t(), Asteroid.Context.t() ->
               Asteroid.Token.RefreshToken.t())
    field :object_store_refresh_token_before_store_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked before storing an access token
    """
    @type object_store_access_token_before_store_callback ::
            (Asteroid.Token.AccessToken.t(), Asteroid.Context.t() ->
               Asteroid.Token.RefreshToken.t())
    field :object_store_access_token_before_store_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked before storing an authorization code
    """
    @type object_store_authorization_code_before_store_callback ::
            (Asteroid.Token.AuthorizationCode.t(), Asteroid.Context.t() ->
               Asteroid.Token.AuthorizationCode.t())
    field :object_store_authorization_code_before_store_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked before storing a device code
    """
    @type object_store_device_code_before_store_callback ::
            (Asteroid.Token.DeviceCode.t(), Asteroid.Context.t() ->
               Asteroid.Token.DeviceCode.t())
    field :object_store_device_code_before_store_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked before storing authenticated session
    """
    @type object_store_authenticated_session_before_store_callback ::
            (Asteroid.OIDC.AuthenticatedSession.t(), Asteroid.Context.t() ->
               Asteroid.OIDC.AuthenticatedSession.t())
    field :object_store_authenticated_session_before_store_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked before storing authentication event
    """
    @type object_store_authentication_event_before_store_callback ::
            (Asteroid.OIDC.AuthenticationEvent.t(), Asteroid.Context.t() ->
               Asteroid.OIDC.AuthenticationEvent.t())
    field :object_store_authentication_event_before_store_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Plugs installed on `"/api/oauth2"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_oauth2_plugs :: [{module(), Keyword.t()}]
    field :api_oauth2_plugs, {:list, :option},
      default: [
        {
          APIacAuthBasic,
          realm: "Asteroid",
          callback: &Asteroid.OAuth2.Client.get_client_secret/2,
          set_error_response: &APIacAuthBasic.save_authentication_failure_response/3,
          error_response_verbosity: :debug
        }
      ],
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oauth2/token"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_oauth2_endpoint_token_plugs :: [{module(), Keyword.t()}]
    field :api_oauth2_endpoint_token_plugs, {:list, :option},
      default: [{Corsica, origins: "*"}],
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oauth2/introspect"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_oauth2_endpoint_introspect_plugs :: [{module(), Keyword.t()}]
    field :api_oauth2_endpoint_introspect_plugs, {:list, :option},
      default: [],
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oauth2/revoke"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_oauth2_endpoint_revoke_plugs :: [{module(), Keyword.t()}]
    field :api_oauth2_endpoint_revoke_plugs, {:list, :option},
      default: [{Corsica, origins: "*"}],
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oauth2/register"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_oauth2_endpoint_register_plugs :: [{module(), Keyword.t()}]
    field :api_oauth2_endpoint_register_plugs, {:list, :option},
      default: [],
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oauth2/device_authorization"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_oauth2_endpoint_device_authorization_plugs :: [{module(), Keyword.t()}]
    field :api_oauth2_endpoint_device_authorization_plugs, {:list, :option},
      default: [],
      config_time: :compile

    @doc """
    Plugs installed on `/.well-known/`

    See also [protecting APIs](protecting-apis.html)
    """
    @type well_known_plugs :: [{module(), Keyword.t()}]
    field :well_known_plugs, {:list, :option},
      default: [],
      config_time: :compile

    @doc """
    Plugs installed on `/discovery/`

    See also [protecting APIs](protecting-apis.html)
    """
    @type discovery_plugs :: [{module(), Keyword.t()}]
    field :discovery_plugs, {:list, :option},
      default: [],
      config_time: :compile

    @doc """
    Plugs installed on browser pathes

    See also [protecting APIs](protecting-apis.html)
    """
    @type browser_plugs :: [{module(), Keyword.t()}]
    field :browser_plugs, {:list, :option},
      default: [],
      config_time: :compile

    @doc """
    List of enabled grant types

    It is used in OAuth2 APIs (such as `/token`) so as to determine support, and for metadata
    generation.
    """
    @type oauth2_grant_types_enabled :: [Asteroid.OAuth2.grant_type()]
    field :oauth2_grant_types_enabled, {:list, :atom},
      default: [:authorization_code, :refresh_token],
      config_time: :runtime

    @doc """
    List of enabled response types

    It is used in OAuth2 web authentication flows (`/authorize`) so as to determine support,
    and for metadata generation.
    """
    @type oauth2_response_types_enabled :: [Asteroid.OAuth2.response_type()]
    field :oauth2_response_types_enabled, {:list, :atom},
      default: [:code],
      config_time: :runtime

    @doc """
    Callback to verify username and password in the ROPC flow.
    """
    @typedoc """
    Callback function for the `:oauth2_flow_ropc_username_password_verify_callback` configuration
    option.

    Calls the callback `callback` with `callback.(conn, username, password)`
    """
    @type oauth2_ropc_username_password_verify_callback ::
            (Plug.Conn.t(), String.t(), String.t() ->
               {:ok, Asteroid.Subject.t()} | {:error, Exception.t()})
    field :oauth2_flow_ropc_username_password_verify_callback, :function,
      default: &Asteroid.Utils.always_nil/3,
      config_time: :runtime

    @doc """
    Verbosity level for the API's error messages

    The `:debug` level can return information useful to attackers. The `:minimal` level can
    break the specification's support.
    """
    @type api_error_response_verbosity :: :debug | :normal | :minimal
    field :api_error_response_verbosity, {:one_of_atoms, [:debug, :normal, :minimal]},
      default: :normal,
      config_time: :runtime

    @doc """
    Scope configuration for the ROPC flow
    """
    @type oauth2_flow_ropc_scope_config :: scope_config()
    field :oauth2_flow_ropc_scope_config, :term,
      default: %{},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    @doc """
    Scope configuration for the OAuth2 implicit flow
    """
    @type oauth2_flow_implicit_scope_config :: scope_config()
    field :oauth2_flow_implicit_scope_config, :term,
      default: %{},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    @doc """
    Scope configuration for the OAuth2 authorization code flow
    """
    @type oauth2_flow_authorization_code_scope_config :: scope_config()
    field :oauth2_flow_authorization_code_scope_config, :term,
      default: %{},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    @doc """
    Callback called to set scopes according to the configuration
    """
    @type oauth2_scope_callback ::
            (OAuth2Utils.Scope.Set.t(), Asteroid.Context.t() -> OAuth2Utils.Scope.Set.t())
    field :oauth2_scope_callback, :function,
      default: &Asteroid.OAuth2.Scope.grant_for_flow/2,
      config_time: :runtime,
      uses: [
        :oauth2_flow_ropc_scope_config,
        :oauth2_flow_client_credentials_scope_config,
        :oauth2_flow_device_authorization_scope_config,
        :oidc_flow_authorization_code_scope_config,
        :oidc_flow_implicit_scope_config,
        :oidc_flow_hybrid_scope_config
      ]

    @doc """
    Defines whether a refresh token should be issued when initiating an ROPC flow
    """
    @type oauth2_flow_ropc_issue_refresh_token_init :: boolean()
    field :oauth2_flow_ropc_issue_refresh_token_init, [:boolean, {:one_of_atoms, [nil]}],
      default: true,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens in the ROPC flow
    """
    @type oauth2_flow_ropc_issue_refresh_token_refresh :: boolean()
    field :oauth2_flow_ropc_issue_refresh_token_refresh, [:boolean, {:one_of_atoms, [nil]}],
      default: false,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Callback called to determine whether a refresh token should be issued

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oauth2_issue_refresh_token_callback :: (Asteroid.Context.t() -> boolean())
    field :oauth2_issue_refresh_token_callback, :function,
      default: &Asteroid.Token.RefreshToken.issue_refresh_token?/1,
      config_time: :runtime,
      uses: [
        :oauth2_issue_refresh_token_init,
        :oauth2_issue_refresh_token_refresh,
        :oauth2_flow_ropc_issue_refresh_token_init,
        :oauth2_flow_ropc_issue_refresh_token_refresh,
        :oauth2_flow_client_credentials_issue_refresh_token_init,
        :oauth2_flow_client_credentials_issue_refresh_token_refresh,
        :oauth2_flow_authorization_code_issue_refresh_token_init,
        :oauth2_flow_authorization_code_issue_refresh_token_refresh,
        :oauth2_flow_device_authorization_issue_refresh_token_init,
        :oauth2_flow_device_authorization_issue_refresh_token_refresh,
        :oidc_flow_authorization_code_issue_refresh_token_init,
        :oidc_flow_authorization_code_issue_refresh_token_refresh,
        :oidc_flow_hybrid_issue_refresh_token_init,
        :oidc_flow_hybrid_issue_refresh_token_refresh
      ]

    @doc """
    Defines the lifetime of a refresh token in the ROPC flow
    """
    @type oauth2_flow_ropc_refresh_token_lifetime :: non_neg_integer()
    field :oauth2_flow_ropc_refresh_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_refresh_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Callback called to determine the lifetime of a refresh token

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oauth2_refresh_token_lifetime_callback :: (Asteroid.Context.t() -> non_neg_integer())
    field :oauth2_refresh_token_lifetime_callback, :function,
      default: &Asteroid.Token.RefreshToken.lifetime/1,
      config_time: :runtime,
      uses: [
        :oauth2_refresh_token_lifetime,
        :oauth2_flow_ropc_refresh_token_lifetime,
        :oauth2_flow_client_credentials_refresh_token_lifetime,
        :oauth2_flow_authorization_code_refresh_token_lifetime,
        :oauth2_flow_device_authorization_refresh_token_lifetime,
        :oidc_flow_authorization_code_refresh_token_lifetime,
        :oidc_flow_hybrid_refresh_token_lifetime
      ]

    @doc """
    Defines the lifetime of an access token in the ROPC flow
    """
    @type oauth2_flow_ropc_access_token_lifetime :: non_neg_integer()
    field :oauth2_flow_ropc_access_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the serialization format of an access token in the ROPC flow
    """
    @type oauth2_flow_ropc_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oauth2_flow_ropc_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt, nil]},
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the signing key name of an access token in the ROPC flow
    """
    @type oauth2_flow_ropc_access_token_signing_key :: Crypto.Key.name()
    field :oauth2_flow_ropc_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the signing algorithm of an access token in the ROPC flow
    """
    @type oauth2_flow_ropc_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oauth2_flow_ropc_access_token_signing_alg, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    Callback called to determine the lifetime of an access token

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oauth2_access_token_lifetime_callback :: (Asteroid.Context.t() -> non_neg_integer())
    field :oauth2_access_token_lifetime_callback, :function,
    default: &Asteroid.Token.AccessToken.lifetime/1,
      config_time: :runtime,
      uses: [
        :oauth2_access_token_lifetime,
        :oauth2_flow_ropc_access_token_lifetime,
        :oauth2_flow_client_credentials_access_token_lifetime,
        :oauth2_flow_authorization_code_access_token_lifetime,
        :oauth2_flow_implicit_access_token_lifetime,
        :oauth2_flow_device_authorization_access_token_lifetime,
        :oidc_flow_authorization_code_access_token_lifetime,
        :oidc_flow_implicit_access_token_lifetime,
        :oidc_flow_hybrid_access_token_lifetime
      ]

    @doc """
    Callback called to determine the serialization format of an access token

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oauth2_access_token_serialization_format_callback ::
            (Asteroid.Context.t() -> Asteroid.Token.serialization_format())
    field :oauth2_access_token_serialization_format_callback, :function,
      default: &Asteroid.Token.AccessToken.serialization_format/1,
      config_time: :runtime,
      uses: [
        :oauth2_access_token_serialization_format,
        :oauth2_flow_ropc_access_token_serialization_format,
        :oauth2_flow_client_credentials_access_token_serialization_format,
        :oauth2_flow_authorization_code_access_token_serialization_format,
        :oauth2_flow_implicit_access_token_serialization_format,
        :oauth2_flow_device_authorization_access_token_serialization_format,
        :oidc_flow_authorization_code_access_token_serialization_format,
        :oidc_flow_implicit_access_token_serialization_format,
        :oidc_flow_hybrid_access_token_serialization_format
      ]

    @doc """
    Callback called to determine the signing key name of an access token

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oauth2_access_token_signing_key_callback ::
            (Asteroid.Context.t() -> Crypto.Key.name())
    field :oauth2_access_token_signing_key_callback, :function,
      default: &Asteroid.Token.AccessToken.signing_key/1,
      config_time: :runtime,
      uses: [
        :oauth2_access_token_signing_key,
        :oauth2_flow_ropc_access_token_signing_key,
        :oauth2_flow_client_credentials_access_token_signing_key,
        :oauth2_flow_authorization_code_access_token_signing_key,
        :oauth2_flow_implicit_access_token_signing_key,
        :oauth2_flow_device_authorization_access_token_signing_key,
        :oidc_flow_authorization_code_access_token_signing_key,
        :oidc_flow_implicit_access_token_signing_key,
        :oidc_flow_hybrid_access_token_signing_key
      ]

    @doc """
    Callback called to determine the signing algorithm of an access token

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oauth2_access_token_signing_alg_callback ::
            (Asteroid.Context.t() -> Crypto.Key.jws_alg())
    field :oauth2_access_token_signing_alg_callback, :function,
      default: &Asteroid.Token.AccessToken.signing_alg/1,
      config_time: :runtime,
      uses: [
        :oauth2_access_token_signing_alg,
        :oauth2_flow_ropc_access_token_signing_alg,
        :oauth2_flow_client_credentials_access_token_signing_alg,
        :oauth2_flow_authorization_code_access_token_signing_alg,
        :oauth2_flow_implicit_access_token_signing_alg,
        :oauth2_flow_device_authorization_access_token_signing_alg,
        :oidc_flow_authorization_code_access_token_signing_alg,
        :oidc_flow_implicit_access_token_signing_alg,
        :oidc_flow_hybrid_access_token_signing_alg
      ]

    @doc """
    Callback called to determine the lifetime of an authorization code

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oauth2_authorization_code_lifetime_callback ::
            (Asteroid.Context.t() -> non_neg_integer())
    field :oauth2_authorization_code_lifetime_callback, :function,
      default: &Asteroid.Token.AuthorizationCode.lifetime/1,
      config_time: :runtime,
      uses: [
        :oauth2_authorization_code_lifetime,
        :oauth2_flow_authorization_code_authorization_code_lifetime,
        :oidc_flow_authorization_code_authorization_code_lifetime,
        :oidc_flow_hybrid_authorization_code_lifetime
      ]

    @doc """
    Defines the lifetime of an authorization code in the code flow
    """
    @type oauth2_flow_authorization_code_authorization_code_lifetime :: non_neg_integer()
    field :oauth2_flow_authorization_code_authorization_code_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_authorization_code_lifetime_callback],
      unit: "seconds"

    @doc """
    Callback invoked on the json response when the grant_type is "password"
    """
    @type oauth2_endpoint_token_grant_type_password_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oauth2_endpoint_token_grant_type_password_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is "password"
    """
    @type oauth2_endpoint_token_grant_type_password_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_token_grant_type_password_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the json response when the grant_type is "refresh_token"
    """
    @type oauth2_endpoint_token_grant_type_refresh_token_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oauth2_endpoint_token_grant_type_refresh_token_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is "refresh_token"
    """
    @type oauth2_endpoint_token_grant_type_refresh_token_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_token_grant_type_refresh_token_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked to determine if a client is authorized to introspect tokens on the
    `"/introspect"` endpoint
    """
    @type oauth2_endpoint_introspect_client_authorized ::
            (Asteroid.Client.t() -> boolean())
    field :oauth2_endpoint_introspect_client_authorized, :function,
      default: &Asteroid.OAuth2.Client.endpoint_introspect_authorized?/1,
      config_time: :runtime

    @doc """
    Defines the default claims to be returned from the `"/introspect"` endpoint

    Note that client's configuration takes precedence over this configuration option.
    """
    @type oauth2_endpoint_introspect_claims_resp :: [String.t()]
    field :oauth2_endpoint_introspect_claims_resp, {:list, :string},
      default: [
        "scope",
        "client_id",
        "username",
        "token_type",
        "exp",
        "iat",
        "nbf",
        "sub",
        "aud",
        "iss",
        "jti"
      ],
      config_time: :runtime,
      used_by: [:oauth2_endpoint_introspect_claims_resp_callback]

    @doc """
    Callback invoked to determine the claims to be returned from the `"/introspect"` endpoint
    """
    @type oauth2_endpoint_introspect_claims_resp_callback ::
            (Asteroid.Client.t() -> [String.t()])
    field :oauth2_endpoint_introspect_claims_resp_callback, :function,
      default: &Asteroid.OAuth2.Introspect.endpoint_introspect_claims_resp/1,
      config_time: :runtime,
      uses: [:oauth2_endpoint_introspect_claims_resp]

    @doc """
    Callback invoked on the json response on the `"/introspect"` endpoint
    """
    @type oauth2_endpoint_introspect_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oauth2_endpoint_introspect_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response on the `"/introspect"` endpoint
    """
    @type oauth2_endpoint_introspect_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_introspect_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Scope configuration for the client credentials flow
    """
    @type oauth2_flow_client_credentials_scope_config :: scope_config()
    field :oauth2_flow_client_credentials_scope_config, :term,
      default: %{},
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
      [:boolean, {:one_of_atoms, [nil]}],
      default: false,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens
    """
    @type oauth2_flow_client_credentials_issue_refresh_token_refresh :: boolean()
    field :oauth2_flow_client_credentials_issue_refresh_token_refresh,
      [:boolean, {:one_of_atoms, [nil]}],
      default: false,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines the lifetime of a refresh token in the client credentials flow
    """
    @type oauth2_flow_client_credentials_refresh_token_lifetime :: non_neg_integer()
    field :oauth2_flow_client_credentials_refresh_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_refresh_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an access token in the client credentials flow
    """
    @type oauth2_flow_client_credentials_access_token_lifetime :: non_neg_integer()
    field :oauth2_flow_client_credentials_access_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the serialization format of an access token in the client credentials flow
    """
    @type oauth2_flow_client_credentials_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oauth2_flow_client_credentials_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt, nil]},
      default: :opaque,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the signing key name of an access token in the client credentials flow
    """
    @type oauth2_flow_client_credentials_access_token_signing_key :: Crypto.Key.name()
    field :oauth2_flow_client_credentials_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the signing algorithm of an access token in the client credentials flow
    """
    @type oauth2_flow_client_credentials_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oauth2_flow_client_credentials_access_token_signing_alg, :string,
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    Callback invoked on the json response when the grant_type is `"client_credentials"`
    """
    @type oauth2_endpoint_token_grant_type_client_credentials_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oauth2_endpoint_token_grant_type_client_credentials_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is
    `"client_credentials"`
    """
    @type oauth2_endpoint_token_grant_type_client_credentials_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_token_grant_type_client_credentials_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Default callback invoked on the `/authorize` endpoint to trigger the web authorization
    process flow for the OAuth2 authorization code flow

    This workflow is in charge of authenticating and authorizing (scopes...) the user in regards
    to the request. It will typically involve several step, i.e. display of web pages. It does
    returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the process,
    one of these callback shall be called:
    - `AsteroidWeb.AuthorizeController.authorization_granted/2`
    - `AsteroidWeb.AuthorizeController.authorization_denied/2`
    """
    @type oauth2_flow_authorization_code_web_authorization_callback ::
            AsteroidWeb.AuthorizeController.web_authorization_callback()
    field :oauth2_flow_authorization_code_web_authorization_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime,
      used_by: [:web_authorization_callback]

    @doc """
    Callback invoked on the `t:Asteroid.OAuth2.RedirectUri.t/0` response on the `/authorize`
    endpoint
    """
    @type oauth2_endpoint_authorize_before_send_redirect_uri_callback ::
            (Asteroid.OAuth2.RedirectUri.t(), Asteroid.Context.t() ->
               Asteroid.OAuth2.RedirectUri.t())
    field :oauth2_endpoint_authorize_before_send_redirect_uri_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response on the `/authorize` endpoint

    The connection is redirected immediatly after this callback returns.
    """
    @type oauth2_endpoint_authorize_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_authorize_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Defines whether a refresh token should be issued when submitting an authorization code
    in the authorization code flow
    """
    @type oauth2_flow_authorization_code_issue_refresh_token_init :: boolean()
    field :oauth2_flow_authorization_code_issue_refresh_token_init,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens in the authorization
    code flow
    """
    @type oauth2_flow_authorization_code_issue_refresh_token_refresh :: boolean()
    field :oauth2_flow_authorization_code_issue_refresh_token_refresh,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines the lifetime of a refresh token in the authorization code flow
    """
    @type oauth2_flow_authorization_code_refresh_token_lifetime :: non_neg_integer()
    field :oauth2_flow_authorization_code_refresh_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: 60 * 60 * 24 * 7,
      config_time: :runtime,
      used_by: [:oauth2_refresh_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an access token in the authorization code flow
    """
    @type oauth2_flow_authorization_code_access_token_lifetime :: non_neg_integer()
    field :oauth2_flow_authorization_code_access_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the serialization format of an access token in the authorization code flow
    """
    @type oauth2_flow_authorization_code_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oauth2_flow_authorization_code_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt, nil]},
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the signing key name of an access token in the authorization code flow
    """
    @type oauth2_flow_authorization_code_access_token_signing_key :: Crypto.Key.name()
    field :oauth2_flow_authorization_code_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the signing algorithm of an access token in the authorization code flow
    """
    @type oauth2_flow_authorization_code_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oauth2_flow_authorization_code_access_token_signing_alg, :string,
    default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    Callback invoked on the json response when the grant_type is "authorization_code"
    """
    @type oauth2_endpoint_token_grant_type_authorization_code_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oauth2_endpoint_token_grant_type_authorization_code_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is
    "authorization_code"
    """
    @type oauth2_endpoint_token_grant_type_authorization_code_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_token_grant_type_authorization_code_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` in the `/revoke` endpoint
    """

    @type oauth2_endpoint_revoke_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())

    field :oauth2_endpoint_revoke_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Default callback invoked on the `/authorize` endpoint to trigger the web authorization
    process flow for the OAuth2 implicit flow

    This workflow is in charge of authenticating and authorizing (scopes...) the user in regards
    to the request. It will typically involve several step, i.e. display of web pages. It does
    returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the process,
    one of these callback shall be called:
    - `AsteroidWeb.AuthorizeController.authorization_granted/2`
    - `AsteroidWeb.AuthorizeController.authorization_denied/2`
    """
    @type oauth2_flow_implicit_web_authorization_callback ::
            (Plug.Conn.t(), AsteroidWeb.AuthorizeController.Request.t() -> Plug.Conn.t())
    field :oauth2_flow_implicit_web_authorization_callback, :function,
      default: &Asteroid.Utils.always_nil/2,
      config_time: :runtime,
      used_by: [
        :web_authorization_callback
      ]

    @doc """
    Defines the lifetime of an access token in the implicit flow
    """
    @type oauth2_flow_implicit_access_token_lifetime :: non_neg_integer()
    field :oauth2_flow_implicit_access_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the serialization format of an access token in the implicit flow
    """
    @type oauth2_flow_implicit_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oauth2_flow_implicit_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt, nil]},
      default: :opaque,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the signing key name of an access token in the implicit flow
    """
    @type oauth2_flow_implicit_access_token_signing_key :: Crypto.Key.name()
    field :oauth2_flow_implicit_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the signing algorithm of an access token in the implicit flow
    """
    @type oauth2_flow_implicit_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oauth2_flow_implicit_access_token_signing_alg, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    The PKCE policy

    This configuration option can have 3 values:
    - `:disabled`: PKCE support is disabled
    - `:mandatory`: all requests using the authorization code flow must use PKCE
    - `:optional`: use of PKCE is optional, except for clients marked as forced to use it
    """
    @type oauth2_pkce_policy :: :disabled | :optional | :mandatory
    field :oauth2_pkce_policy, {:one_of_atoms, [:disabled, :optional, :mandatory]},
      default: :optional,
      config_time: :runtime

    @doc """
    Code challenge methods supported

    Supported methods are the following atoms:
    - `:plain`
    - `:S256`
    """
    @type oauth2_pkce_allowed_methods :: [atom()]
    field :oauth2_pkce_allowed_methods, {:list, :atom},
      default: [:S256],
      config_time: :runtime

    @doc """
    Returns `true` if the client has to use PKCE, `false` otherwise

    Used only when the `:oauth2_pkce_policy` configuration option is set to `:optional`
    """
    @type oauth2_pkce_must_use_callback ::
            (Client.t() -> boolean())
    field :oauth2_pkce_must_use_callback, :function,
      default: &Asteroid.OAuth2.Client.must_use_pkce?/1,
      config_time: :runtime

    @doc """
    Callback called to determine whether a client is authorized to create new clients on
    the register endpoint or not
    """
    @type oauth2_endpoint_register_authorization_callback ::
            (Plug.Conn.t(), Asteroid.Client.t() ->
               :ok | {:error, Exception.t()})
    field :oauth2_endpoint_register_authorization_callback, :function,
      default: &Asteroid.OAuth2.Register.request_authorized?/2,
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
      {:one_of_atoms, [:all, :authenticated_clients, :authorized_clients]},
      default: :authorized_clients,
      config_time: :runtime,
      used_by: [:oauth2_endpoint_register_authorization_callback]

    @doc """
    Additional fields that are saved when registering new clients

    Note that this option is overriden by client configuration, if existing.
    """
    @type oauth2_endpoint_register_additional_metadata_field :: [String.t()]
    field :oauth2_endpoint_register_additional_metadata_field, {:list, :string},
      default: [],
      config_time: :runtime

    @doc """
    Callback invoked on the json response when on the register endpoint
    """
    @type oauth2_endpoint_register_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oauth2_endpoint_register_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response on the register endpoint
    """
    @type oauth2_endpoint_register_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_register_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Asteroid.Client.t()` before it's being saved
    """
    @type oauth2_endpoint_register_client_before_save_callback ::
            (Client.t(), Asteroid.Context.t() -> Client.t())
    field :oauth2_endpoint_register_client_before_save_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked to generate the client id of a newly created client

    The callback should ensure that the client id does not already exists.
    """
    @type oauth2_endpoint_register_gen_client_id_callback ::
            (map(), Asteroid.Context.t() -> String.t())
    field :oauth2_endpoint_register_gen_client_id_callback, :function,
      default: &Asteroid.OAuth2.Register.generate_client_id/2,
      config_time: :runtime

    @doc """
    Callback invoked to generate the client *resource* id of a newly created client
    """
    @type oauth2_endpoint_register_gen_client_resource_id_callback ::
            (map(), Asteroid.Context.t() -> AttributeRepository.resource_id())
    field :oauth2_endpoint_register_gen_client_resource_id_callback, :function,
      default: &Asteroid.OAuth2.Register.generate_client_resource_id/2,
      config_time: :runtime

    @doc """
    Callback invoked to determine the client type
    """
    @type oauth2_endpoint_register_client_type_callback ::
            (Client.t() -> Asteroid.OAuth2.Client.type())
    field :oauth2_endpoint_register_client_type_callback, :function,
      default: &Asteroid.OAuth2.Register.client_type/1,
      config_time: :runtime

    @doc """
    Callback called to determine the supported authentication of the token endpoint
    """
    @type oauth2_endpoint_token_auth_methods_supported_callback ::
            (() -> [Asteroid.OAuth2.Endpoint.auth_method()])
    field :oauth2_endpoint_token_auth_methods_supported_callback, :function,
      default: &Asteroid.OAuth2.Endpoint.token_endpoint_auth_methods_supported/0,
      config_time: :runtime

    @doc """
    OAuth2 metadata service documentation URL
    """
    @type oauth2_endpoint_metadata_service_documentation :: String.t()
    field :oauth2_endpoint_metadata_service_documentation,
      [{:one_of_atoms, [nil]}, :string],
      default: nil,
      config_time: :runtime

    @doc """
    OAuth2 metadata UI locales supported
    """
    @type oauth2_endpoint_metadata_ui_locales_supported :: [String.t()]
    field :oauth2_endpoint_metadata_ui_locales_supported,
      [{:one_of_atoms, [nil]}, {:list, :string}],
      default: nil,
      config_time: :runtime

    @doc """
    OAuth2 metadata OP policy URL
    """
    @type oauth2_endpoint_metadata_op_policy_uri :: String.t()
    field :oauth2_endpoint_metadata_op_policy_uri,
      [{:one_of_atoms, [nil]}, :string],
      default: nil,
      config_time: :runtime

    @doc """
    OAuth2 metadata OP tos URL
    """
    @type oauth2_endpoint_metadata_op_tos_uri :: String.t()
    field :oauth2_endpoint_metadata_op_tos_uri,
      [{:one_of_atoms, [nil]}, :string],
      default: nil,
      config_time: :runtime

    @doc """
    Metadata fields to be signed

    The configuration option can have 3 values:
    - `:disabled`: no metadata fields are signed
    - `:all`: all fields are signed
    - `[String.t()]`: a list of fields to be included in the signed statement
    """
    @type oauth2_endpoint_metadata_signed_fields :: :disabled | :all | [String.t()]
    field :oauth2_endpoint_metadata_signed_fields,
      [{:list, :string}, {:one_of_atoms, [:disabled, :all]}],
      default: :disabled, #FIXME: :all
      config_time: :runtime

    @doc """
    Key name for the signed metadata fields
    """
    @type oauth2_endpoint_metadata_signing_key :: Crypto.Key.name()
    field :oauth2_endpoint_metadata_signing_key, :string,
      default: "",
      config_time: :runtime

    @doc """
    Key algorithm for the signed metadata fields
    """
    @type oauth2_endpoint_metadata_signing_alg :: Crypto.Key.jws_alg()
    field :oauth2_endpoint_metadata_signing_alg, :string,
      default: "",
      config_time: :runtime

    @doc """
    Callback invoked on the json response on the `/.well-known/oauth-authorization-server`
    endpoint

    Note that this callback is called before optional signature of metadata fields, so that
    added fields can be signed as well.
    """
    @type oauth2_endpoint_metadata_before_send_resp_callback :: (map() -> map())
    field :oauth2_endpoint_metadata_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id/1,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response on the
    `/.well-known/oauth-authorization-server` endpoint
    """
    @type oauth2_endpoint_metadata_before_send_conn_callback ::
            (Plug.Conn.t() -> Plug.Conn.t())
    field :oauth2_endpoint_metadata_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id/1,
      config_time: :runtime

    @doc """
    Callback invoked on the json response on the `/discovery/keys` endpoint
    """
    @type oauth2_endpoint_discovery_keys_before_send_resp_callback :: (map() -> map())
    field :oauth2_endpoint_discovery_keys_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id/1,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response on the `/discovery/keys` endpoint
    """
    @type oauth2_endpoint_discovery_keys_before_send_conn_callback ::
            (Plug.Conn.t() -> Plug.Conn.t())
    field :oauth2_endpoint_discovery_keys_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id/1,
      config_time: :runtime

    @doc """
    Cryptographic keys configuration

    Refer to `t:Asteroid.Crypto.Key.key_config/0` for more information.

    **Security consideration**: consider storing keys in a separate configuration file
    (such as `secret.exs`).
    """
    @type crypto_keys :: Crypto.Key.key_config()
    field :crypto_keys, :term,
      default: %{
        "key_auto" => {:auto_gen, [params: {:rsa, 2048}, use: :sig, advertise: false]}
      },
      config_time: :runtime

    @doc """
    Cryptographic keys cache store

    The first element is a module implementing the `Asteroid.Crypto.Key.Cache` behaviour, and
    the second element are the module's options.
    """
    @type crypto_keys_cache :: {module(), Crypto.Key.Cache.opts()}
    field :crypto_keys_cache, :option,
      default: {Asteroid.Crypto.Key.Cache.ETS, []},
      config_time: :runtime

    @doc """
    Determines whether the `"none"` JWS algorithm is supported

    It is set using the `JOSE.JWA.unsecured_signing/1` function on Asteroid startup. Defaults
    to `false`.
    """
    @type crypto_jws_none_alg_enabled :: boolean()
    field :crypto_jws_none_alg_enabled, :boolean,
      default: false,
      config_time: :runtime

    @doc """
    Scope configuration for the device authorization flow
    """
    @type oauth2_flow_device_authorization_scope_config :: scope_config()
    field :oauth2_flow_device_authorization_scope_config, :term,
      default: %{},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    @doc """
    Callback invoked on the json response when the grant_type is
    "urn:ietf:params:oauth:grant-type:device_code"
    """
    @type oauth2_endpoint_device_authorization_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oauth2_endpoint_device_authorization_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is
    "urn:ietf:params:oauth:grant-type:device_code"
    """
    @type oauth2_endpoint_device_authorization_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_device_authorization_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Defines the lifetime of a device code in the device authorization flow
    """
    @type oauth2_flow_device_authorization_device_code_lifetime :: non_neg_integer()
    field :oauth2_flow_device_authorization_device_code_lifetime, :nonnegative_integer,
      default: 60 * 15,
      config_time: :runtime,
      unit: "seconds"

    @doc """
    callback to generate the user code
    """
    @type oauth2_flow_device_authorization_user_code_callback ::
            (Asteroid.Context.t() -> String.t())
    field :oauth2_flow_device_authorization_user_code_callback, :function,
      default: &Asteroid.OAuth2.DeviceAuthorization.user_code/1,
      config_time: :runtime,
      unit: "seconds"

    @doc """
    Callback invoked on the `/device` endpoint to trigger the web authorization process flow
    for the OAuth2 device authorization flow

    This workflow is in charge of validating the user code, as well as authenticating and
    authorizing (scopes...) the request. It will typically involve several step, i.e.
    user code confirmation, authentication and optionnaly accepting scope through web pages.
    It returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the
    process, one of these callback shall be called:
    - `AsteroidWeb.DeviceController.authorization_granted/2`
    - `AsteroidWeb.DeviceController.authorization_denied/2`
    """
    @type oauth2_flow_device_authorization_web_authorization_callback ::
            (Plug.Conn.t(), AsteroidWeb.DeviceController.Request.t() -> Plug.Conn.t())
    field :oauth2_flow_device_authorization_web_authorization_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Defines whether a refresh token should be issued when initiating a device authorization
    flow
    """
    @type oauth2_flow_device_authorization_issue_refresh_token_init :: boolean()
    field :oauth2_flow_device_authorization_issue_refresh_token_init,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens in the device
    authorization flow
    """
    @type oauth2_flow_device_authorization_issue_refresh_token_refresh :: boolean()
    field :oauth2_flow_device_authorization_issue_refresh_token_refresh,
      [:boolean, {:one_of_atoms, [nil]}],
      default: false,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines the lifetime of a refresh token in the device authorization flow
    """
    @type oauth2_flow_device_authorization_refresh_token_lifetime :: non_neg_integer()
    field :oauth2_flow_device_authorization_refresh_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: 10 * 365 * 24 * 3600,
      config_time: :runtime,
      used_by: [:oauth2_refresh_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the serialization format of an access token in the device authorization flow
    """
    @type oauth2_flow_device_authorization_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oauth2_flow_device_authorization_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt, nil]},
      default: :opaque,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the signing key name of an access token in the device authorization flow
    """
    @type oauth2_flow_device_authorization_access_token_signing_key :: Crypto.Key.name()
    field :oauth2_flow_device_authorization_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the signing algorithm of an access token in the device authorization flow
    """
    @type oauth2_flow_device_authorization_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oauth2_flow_device_authorization_access_token_signing_alg, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    Defines the lifetime of an access token in the device authorization flow
    """
    @type oauth2_flow_device_authorization_access_token_lifetime :: non_neg_integer()
    field :oauth2_flow_device_authorization_access_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Callback invoked on the json response when the grant_type is
    "urn:ietf:params:oauth:grant-type:device_code"
    """
    @type oauth2_endpoint_token_grant_type_device_code_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oauth2_endpoint_token_grant_type_device_code_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response when the grant_type is
    "urn:ietf:params:oauth:grant-type:device_code"
    """
    @type oauth2_endpoint_token_grant_type_device_code_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oauth2_endpoint_token_grant_type_device_code_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Rate limiter module and options for the device authorization flow

    The module throttles the incoming requests on `/api/oauth2/token` on the device code
    parameter.
    """
    @type oauth2_flow_device_authorization_rate_limiter ::
            {module(), Asteroid.OAuth2.DeviceAuthorization.RateLimiter.opts()}
    field :oauth2_flow_device_authorization_rate_limiter, :option,
      default: {Asteroid.OAuth2.DeviceAuthorization.RateLimiter.Hammer, []},
      config_time: :runtime

    @doc """
    Interval in seconds between 2 requests on the `/api/oauth2/token` with the same device code
    in the device authorization flow
    """
    @type oauth2_flow_device_authorization_rate_limiter_interval :: non_neg_integer()
    field :oauth2_flow_device_authorization_rate_limiter_interval, :nonnegative_integer,
      default: 5,
      config_time: :runtime,
      unit: "seconds"

    @doc """
    JWT Secured Authorization Request (JAR) enabling flag

    The possible values are:
    - `:disabled`: JAR is disabled
    - `:request_only`: on ly the `"request"` parameter is enabled
    - `:request_uri_only`: only the `"request_uri"` is enabled
    - `:enabled`: both the `"request"` and `"request_uri"` parameters are enabled
    """
    @type oauth2_jar_enabled :: :disabled | :request_only | :request_uri_only | :enabled
    field :oauth2_jar_enabled,
      {:one_of_atoms, [:disabled, :request_only, :request_uri_only, :enabled]},
      default: :disabled,
      config_time: :runtime

    @doc """
    Plugs installed on `"/api/request_object"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_request_object_plugs :: [{module(), Keyword.t()}]
    field :api_request_object_plugs, {:list, :option},
      default: [
        {
          APIacAuthBasic,
          realm: "Asteroid",
          callback: &Asteroid.OAuth2.Client.get_client_secret/2,
          set_error_response: &APIacAuthBasic.send_error_response/3,
          error_response_verbosity: :debug
        }
      ],
      config_time: :compile

    @doc """
    Defines the lifetime of a request object stored internally
    """
    @type oauth2_jar_request_object_lifetime :: non_neg_integer()
    field :oauth2_jar_request_object_lifetime, :nonnegative_integer,
      default: 60,
      config_time: :runtime,
      unit: "seconds"

    @doc """
    Set the options of the HTTP request to retrieve external JAR request objects

    The options are request options of `HTTPoison.Request`
    """
    @type oauth2_jar_request_uri_get_opts :: Keyword.t()
    field :oauth2_jar_request_uri_get_opts, {:list, :option},
      default: [follow_redirect: false, max_body_length: 1024 * 20, timeout: 1000],
      config_time: :runtime

    @doc """
    List of supported signing algorithms for JAR request objects
    """
    @type oauth2_jar_request_object_signing_alg_values_supported :: [Crypto.Key.jws_alg()]
    field :oauth2_jar_request_object_signing_alg_values_supported, {:list, :string},
      default: ["RS256"],
      config_time: :runtime

    @doc """
    List of supported encryption algorithms for JAR request objects
    """
    @type oauth2_jar_request_object_encryption_alg_values_supported :: [Crypto.Key.jwe_alg()]
    field :oauth2_jar_request_object_encryption_alg_values_supported, {:list, :string},
      default: [],
      config_time: :runtime

    @doc """
    List of supported encryption encryption algorithms for JAR request objects
    """
    @type oauth2_jar_request_object_encryption_enc_values_supported :: [Crypto.Key.jwe_enc()]
    field :oauth2_jar_request_object_encryption_enc_values_supported, {:list, :string},
      default: [],
      config_time: :runtime

    @doc """
    Determines whether the audience should be checked when the request object is signed

    Checks that the audience (one one of them) is the `"issuer"` of the server, using the
    `Asteroid.OAuth2.issuer/0` function.

    Defaults to `true`. As per the specification, there's no checking when the JWT is not
    signed.
    """
    @type oauth2_jar_request_object_verify_audience :: boolean()
    field :oauth2_jar_request_object_verify_audience, :boolean,
      default: true,
      config_time: :runtime

    @doc """
    Determines whether the issuer should be checked when the request object is signed

    Defaults to `true`. As per the specification, there's no checking when the JWT is not
    signed.
    """
    @type oauth2_jar_request_object_verify_issuer :: boolean()
    field :oauth2_jar_request_object_verify_issuer, :boolean,
      default: true,
      config_time: :runtime

    @doc """
    Configuration of ACRs
    """
    @type oidc_acr_config :: OIDC.ACR.config()
    field :oidc_acr_config, :term,
      default: [],
      config_time: :runtime,
      used_by: [:web_authorization_callback]

    @doc """
    Scope configuration for the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_scope_config :: scope_config()
    field :oidc_flow_authorization_code_scope_config, :term,
      default: %{},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    @doc """
    Scope configuration for the OIDC implicit flow
    """
    @type oidc_flow_implicit_scope_config :: scope_config()
    field :oidc_flow_implicit_scope_config, :term,
      default: %{},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    @doc """
    Scope configuration for the OIDC hybrid flow
    """
    @type oidc_flow_hybrid_scope_config :: scope_config()
    field :oidc_flow_hybrid_scope_config, :term,
      default: %{},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    @doc """
    Callback invoked on the `/authorize` endpoint to trigger the web authorization process flow
    for the OAuth2 authorization code flow

    This workflow is in charge of authenticating and authorizing (scopes...) the user in regards
    to the request. It will typically involve several step, i.e. display of web pages. It does
    returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the process,
    one of these callback shall be called:
    - `AsteroidWeb.AuthorizeController.authorization_granted/2`
    - `AsteroidWeb.AuthorizeController.authorization_denied/2`
    """

    @type web_authorization_callback ::
            AsteroidWeb.AuthorizeController.web_authorization_callback()
    field :web_authorization_callback, :function,
      default: &Asteroid.WebFlow.web_authorization_callback/2,
      config_time: :runtime,
      uses: [
        :oauth2_flow_authorization_code_web_authorization_callback,
        :oauth2_flow_implicit_web_authorization_callback,
        :oidc_acr_config,
        :oidc_flow_authorization_code_web_authorization_callback,
        :oidc_flow_implicit_web_authorization_callback,
        :oidc_flow_hybrid_web_authorization_callback
      ]

    @doc """
    Callback invoked on the `/authorize` endpoint to trigger the web authorization
    process flow for the OpenID Connect authorization code flow, if the
    `:oidc_acr_config` configuration option is not used.

    This workflow is in charge of authenticating and authorizing (scopes...) the user in regards
    to the request. It will typically involve several step, i.e. display of web pages. It does
    returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the process,
    one of these callback shall be called:
    - `AsteroidWeb.AuthorizeController.authorization_granted/2`
    - `AsteroidWeb.AuthorizeController.authorization_denied/2`
    """
    @type oidc_flow_authorization_code_web_authorization_callback ::
            AsteroidWeb.AuthorizeController.web_authorization_callback()
    field :oidc_flow_authorization_code_web_authorization_callback,
      [:function, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:web_authorization_callback]

    @doc """
    Callback invoked on the `/authorize` endpoint to trigger the web authorization
    process flow for the OpenID Connect implicit flow, if the
    `:oidc_acr_config` configuration option is not used.

    This workflow is in charge of authenticating and authorizing (scopes...) the user in regards
    to the request. It will typically involve several step, i.e. display of web pages. It does
    returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the process,
    one of these callback shall be called:
    - `AsteroidWeb.AuthorizeController.authorization_granted/2`
    - `AsteroidWeb.AuthorizeController.authorization_denied/2`
    """
    @type oidc_flow_implicit_web_authorization_callback ::
            AsteroidWeb.AuthorizeController.web_authorization_callback()
    field :oidc_flow_implicit_web_authorization_callback,
      [:function, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:web_authorization_callback]

    @doc """
    Callback invoked on the `/authorize` endpoint to trigger the web authorization
    process flow for the OpenID Connect hybrid flow, if the
    `:oidc_acr_config` configuration option is not used.

    This workflow is in charge of authenticating and authorizing (scopes...) the user in regards
    to the request. It will typically involve several step, i.e. display of web pages. It does
    returns a `Plug.Conn.t()` to Phoenix but not to Asteroid directly. At the end of the process,
    one of these callback shall be called:
    - `AsteroidWeb.AuthorizeController.authorization_granted/2`
    - `AsteroidWeb.AuthorizeController.authorization_denied/2`
    """
    @type oidc_flow_hybrid_web_authorization_callback ::
            AsteroidWeb.AuthorizeController.web_authorization_callback()
    field :oidc_flow_hybrid_web_authorization_callback,
      [:function, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:web_authorization_callback]

    @doc """
    Defines whether a refresh token should be issued when submitting an authorization code
    in the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_issue_refresh_token_init :: boolean()
    field :oidc_flow_authorization_code_issue_refresh_token_init,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens in the OIDC
    authorization code flow
    """
    @type oidc_flow_authorization_code_issue_refresh_token_refresh :: boolean()
    field :oidc_flow_authorization_code_issue_refresh_token_refresh,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when submitting an authorization code
    in the OIDC hybrid flow
    """
    @type oidc_flow_hybrid_issue_refresh_token_init :: boolean()
    field :oidc_flow_hybrid_issue_refresh_token_init,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens in the OIDC
    hybrid flow
    """
    @type oidc_flow_hybrid_issue_refresh_token_refresh :: boolean()
    field :oidc_flow_hybrid_issue_refresh_token_refresh,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines the lifetime of a refresh token in the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_refresh_token_lifetime :: non_neg_integer()
    field :oidc_flow_authorization_code_refresh_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_refresh_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of a refresh token in the OIDC hybrid flow
    """
    @type oidc_flow_hybrid_refresh_token_lifetime :: non_neg_integer()
    field :oidc_flow_hybrid_refresh_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_refresh_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an access token in the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_access_token_lifetime :: non_neg_integer()
    field :oidc_flow_authorization_code_access_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an access token in the OIDC implicit flow
    """
    @type oidc_flow_implicit_access_token_lifetime :: non_neg_integer()
    field :oidc_flow_implicit_access_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an access token in the OIDC hybrid flow
    """
    @type oidc_flow_hybrid_access_token_lifetime :: non_neg_integer()
    field :oidc_flow_hybrid_access_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Callback called to determine the lifetime of an ID token

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oidc_id_token_lifetime_callback :: (Asteroid.Context.t() -> non_neg_integer())
    field :oidc_id_token_lifetime_callback, :function,
      default: &Asteroid.Token.IDToken.lifetime/1,
      config_time: :runtime,
      uses: [
        :oidc_id_token_lifetime,
        :oidc_flow_authorization_code_id_token_lifetime,
        :oidc_flow_implicit_id_token_lifetime,
        :oidc_flow_hybrid_id_token_lifetime
      ]

    @doc """
    Defines the lifetime of an ID token in the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_id_token_lifetime :: non_neg_integer()
    field :oidc_flow_authorization_code_id_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oidc_id_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an ID token in the OIDC implicit flow
    """
    @type oidc_flow_implicit_id_token_lifetime :: non_neg_integer()
    field :oidc_flow_implicit_id_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oidc_id_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an ID token in the OIDC hybrid flow
    """
    @type oidc_flow_hybrid_id_token_lifetime :: non_neg_integer()
    field :oidc_flow_hybrid_id_token_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oidc_id_token_lifetime_callback],
      unit: "seconds"

    @doc """
    List of acceptable signature `alg` algorithms to sign ID tokens
    """
    @type oidc_id_token_signing_alg_values_supported :: [Crypto.Key.jws_alg()]
    field :oidc_id_token_signing_alg_values_supported, {:list, :string},
      default: ["RS256"],
      config_time: :runtime

    @doc """
    List of acceptable encryption `alg` algorithms to encrypt ID tokens
    """
    @type oidc_id_token_encryption_alg_values_supported :: [Crypto.Key.jwe_alg()]
    field :oidc_id_token_encryption_alg_values_supported, {:list, :string},
      default: ["RSA1_5"],
      config_time: :runtime

    @doc """
    List of acceptable encryption `enc` algorithms to encrypt ID tokens
    """
    @type oidc_id_token_encryption_enc_values_supported :: [Crypto.Key.jwe_enc()]
    field :oidc_id_token_encryption_enc_values_supported, {:list, :string},
      default: ["A128GCM"],
      config_time: :runtime

    @doc """
    Callback invoked before serializing an ID token
    """
    @type token_id_token_before_serialize_callback ::
            (Asteroid.Token.IDToken.t(), Asteroid.Context.t() -> Asteroid.Token.IDToken.t())
    field :token_id_token_before_serialize_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback called to determine whether a new ID token should be issued when renewing
    tokens on `/token` with a refresh token grant type

    Note that client configuration takes precedence over configuration options. See
    `Asteroid.Client` fields.
    """
    @type oidc_issue_id_token_on_refresh_callback :: (Asteroid.Context.t() -> boolean())
    field :oidc_issue_id_token_on_refresh_callback, :function,
      default: &Asteroid.Token.IDToken.issue_id_token?/1,
      config_time: :runtime,
      uses: [
        :oidc_issue_id_token_refresh,
        :oidc_flow_authorization_code_issue_id_token_refresh,
        :oidc_flow_hybrid_issue_id_token_refresh
      ]

    @doc """
    Defines whether an ID token should be issued when refreshing tokens in the OIDC
    authorization code flow
    """
    @type oidc_flow_authorization_code_issue_id_token_refresh :: boolean()
    field :oidc_flow_authorization_code_issue_id_token_refresh,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oidc_issue_id_token_on_refresh_callback]

    @doc """
    Defines whether an ID token should be issued when refreshing tokens in the OIDC
    hybrid flow
    """
    @type oidc_flow_hybrid_issue_id_token_refresh :: boolean()
    field :oidc_flow_hybrid_issue_id_token_refresh,
      [:boolean, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oidc_issue_id_token_on_refresh_callback]

    @doc """
    Defines the lifetime of an authorization code in the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_authorization_code_lifetime :: non_neg_integer()
    field :oidc_flow_authorization_code_authorization_code_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_authorization_code_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an authorization code in the OIDC hybrid code flow
    """
    @type oidc_flow_hybrid_authorization_code_lifetime :: non_neg_integer()
    field :oidc_flow_hybrid_authorization_code_lifetime,
      [:nonnegative_integer, {:one_of_atoms, [nil]}],
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_authorization_code_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the serialization format of an access token in the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oidc_flow_authorization_code_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt, nil]},
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the serialization format of an access token in the OIDC implicit flow
    """
    @type oidc_flow_implicit_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oidc_flow_implicit_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt, nil]},
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the serialization format of an access token in the OIDC hybrid flow
    """
    @type oidc_flow_hybrid_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oidc_flow_hybrid_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt, nil]},
      default: nil,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the signing key name of an access token in the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_access_token_signing_key :: Crypto.Key.name()
    field :oidc_flow_authorization_code_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the signing key name of an access token in the OIDC implicit flow
    """
    @type oidc_flow_implicit_access_token_signing_key :: Crypto.Key.name()
    field :oidc_flow_implicit_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the signing key name of an access token in the OIDC hybrid flow
    """
    @type oidc_flow_hybrid_access_token_signing_key :: Crypto.Key.name()
    field :oidc_flow_hybrid_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the signing algorithm of an access token in the OIDC authorization code flow
    """
    @type oidc_flow_authorization_code_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oidc_flow_authorization_code_access_token_signing_alg, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    Defines the signing algorithm of an access token in the OIDC implicit flow
    """
    @type oidc_flow_implicit_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oidc_flow_implicit_access_token_signing_alg, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    Defines the signing algorithm of an access token in the OIDC hybrid flow
    """
    @type oidc_flow_hybrid_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oidc_flow_hybrid_access_token_signing_alg, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    Plugs installed on `"/api/oidc"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_oidc_plugs :: [{module(), Keyword.t()}]
    field :api_oidc_plugs, {:list, :option},
      default: [],
      config_time: :compile

    @doc """
    Plugs installed on `"/api/oidc/userinfo"`

    See also [protecting APIs](protecting-apis.html)
    """
    @type api_oidc_endpoint_userinfo_plugs :: [{module(), Keyword.t()}]
    field :api_oidc_endpoint_userinfo_plugs, {:list, :option},
      default: [
        {Corsica, [origins: "*"]},
        {APIacAuthBearer,
         realm: "Asteroid",
         bearer_validator: {Asteroid.OAuth2.APIacAuthBearer.Validator, []},
         bearer_extract_methods: [:header, :body],
         forward_bearer: true,
         error_response_verbosity: :normal}
      ],
      config_time: :compile

    @doc """
    Callback invoked on the json response on the `/userinfo` endpoint
    """
    @type oidc_endpoint_userinfo_before_send_resp_callback ::
            (map(), Asteroid.Context.t() -> map())
    field :oidc_endpoint_userinfo_before_send_resp_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    Callback invoked on the `t:Plug.Conn.t/0` response on the `/userinfo` endpoint
    """
    @type oidc_endpoint_userinfo_before_send_conn_callback ::
            (Plug.Conn.t(), Asteroid.Context.t() -> Plug.Conn.t())
    field :oidc_endpoint_userinfo_before_send_conn_callback, :function,
      default: &Asteroid.Utils.id_first_param/2,
      config_time: :runtime

    @doc """
    List of acceptable signature `alg` algorithms for the signature response on the
    `/api/oidc/userinfo` endpoint
    """
    @type oidc_endpoint_userinfo_signature_alg_values_supported :: [Crypto.Key.jws_alg()]
    field :oidc_endpoint_userinfo_signature_alg_values_supported, {:list, :string},
      default: ["RS256"],
      config_time: :runtime

    @doc """
    List of acceptable encryption `alg` algorithms for the encrypted response on the
    `/api/oidc/userinfo` endpoint
    """
    @type oidc_endpoint_userinfo_encryption_alg_values_supported :: [Crypto.Key.jwe_alg()]
    field :oidc_endpoint_userinfo_encryption_alg_values_supported, {:list, :string},
      default: [],
      config_time: :runtime

    @doc """
    List of acceptable encryption `enc` algorithms for the encrypted response on the
    `/api/oidc/userinfo` endpoint
    """
    @type oidc_endpoint_userinfo_encryption_enc_values_supported :: [Crypto.Key.jwe_enc()]
    field :oidc_endpoint_userinfo_encryption_enc_values_supported, {:list, :string},
      default: [],
      config_time: :runtime

    @doc """
    Claims supported (declarative)

    This is only used for publishing it on the discovery endpoint.
    """
    @type oidc_claims_supported :: [OIDC.claim_name()]
    field :oidc_claims_supported, {:list, :string},
      default: [
        "sub",
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "email",
        "email_verified",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "phone_number",
        "phone_number_verified",
        "address",
        "updated_at"
      ],
      config_time: :runtime

    @doc """
    Policy for response mode selection

    3 values are possible:
    - `:disabled`: the `"response_mode"` param is not processed, and the default response
    mode for the flow is choosen
    - `:oidc_only`: the `"response_mode"` param is used for OIDC flows only
    - `:enabled`: the `"response_mode"` param is used for all flows
    """
    @type oauth2_response_mode_policy :: :disabled | :oidc_only | :enabled
    field :oauth2_response_mode_policy, {:one_of_atoms, [:disabled, :oidc_only, :enabled]},
      default: :oidc_only,
      config_time: :runtime

    @doc """
    Callback invoked to calculate the `"sub"` returned in OpenID Connect ID tokens and
    on the `/userinfo` endpoint
    """
    @type oidc_subject_identifier_callback ::
            (Subject.t(), Client.t() -> String.t())
    field :oidc_subject_identifier_callback, :function,
      default: &Asteroid.OIDC.subject_identifier/2,
      config_time: :runtime

    @doc """
    Salt for the pairwise subject identifier type

    By default, a random value set at compile time, which means that the pairwise `"subs"`
    **will change** when compiling again, and **won't be stable**. To have stability, change
    this configuration option with a random value (which doesn't need to be particularly
    protected against theft), for example generating it with the following command:

    ```elixir
    $ mix phx.gen.secret
    vpEKRs4qZesc+zhKWwc/S3rku3HTRFuQ2NC2wfFOAiL9IK17/DFv1j3EyTEUI3Ry
    ```
    """
    @type oidc_subject_identifier_pairwise_salt :: String.t()
    field :oidc_subject_identifier_pairwise_salt, :string,
      default: Base.encode64(:crypto.strong_rand_bytes(24)),
      config_time: :runtime

    @doc """
    OIDC display values supported

    Voluntary information to be published on the metadata endpoint. It is not used otherwise.
    """
    @type oidc_endpoint_metadata_display_values_supported :: [String.t()]
    field :oidc_endpoint_metadata_display_values_supported, {:list, :string},
      default: [],
      config_time: :runtime

    @doc """
    Defines the lifetime of an access token
    """
    @type oauth2_access_token_lifetime :: non_neg_integer()
    field :oauth2_access_token_lifetime, :nonnegative_integer,
      default: 60 * 10,
      config_time: :runtime,
      used_by: [:oauth2_access_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the serialization format of an access token
    """
    @type oauth2_access_token_serialization_format ::
            Asteroid.Token.serialization_format()
    field :oauth2_access_token_serialization_format,
      {:one_of_atoms, [:opaque, :jwt]},
      default: :opaque,
      config_time: :runtime,
      used_by: [:oauth2_access_token_serialization_format_callback]

    @doc """
    Defines the signing algorithm of an access token
    """
    @type oauth2_access_token_signing_alg :: Crypto.Key.jws_alg()
    field :oauth2_access_token_signing_alg, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_alg_callback]

    @doc """
    Defines the signing key name of an access token
    """
    @type oauth2_access_token_signing_key :: Crypto.Key.name()
    field :oauth2_access_token_signing_key, :string,
      default: "",
      config_time: :runtime,
      used_by: [:oauth2_access_token_signing_key_callback]

    @doc """
    Defines the lifetime of an authorization code
    """
    @type oauth2_authorization_code_lifetime :: non_neg_integer()
    field :oauth2_authorization_code_lifetime, :nonnegative_integer,
      default: 60,
      config_time: :runtime,
      used_by: [:oauth2_authorization_code_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines whether a refresh token should be issued upon first request
    """
    @type oauth2_issue_refresh_token_init :: boolean()
    field :oauth2_issue_refresh_token_init, :boolean,
      default: true,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines whether a refresh token should be issued when refreshing tokens
    """
    @type oauth2_issue_refresh_token_refresh :: boolean()
    field :oauth2_issue_refresh_token_refresh, :boolean,
      default: false,
      config_time: :runtime,
      used_by: [:oauth2_issue_refresh_token_callback]

    @doc """
    Defines the lifetime of a refresh token
    """
    @type oauth2_refresh_token_lifetime :: non_neg_integer()
    field :oauth2_refresh_token_lifetime, :nonnegative_integer,
      default: 60 * 60,
      config_time: :runtime,
      used_by: [:oauth2_refresh_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines the lifetime of an ID token
    """
    @type oidc_id_token_lifetime :: non_neg_integer()
    field :oidc_id_token_lifetime, :nonnegative_integer,
      default: 60,
      config_time: :runtime,
      used_by: [:oidc_id_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Defines whether an ID token should be issued when refreshing tokens
    """
    @type oidc_issue_id_token_refresh :: boolean()
    field :oidc_issue_id_token_refresh, :boolean,
      default: true,
      config_time: :runtime,
      used_by: [:oidc_issue_id_token_on_refresh_callback]

    @doc """
    When MTLS is used, determines if the native endpoint should be started

    Possible values are:
    - `true`: the endpoint is started
    - `false`: the endpoint is not started
    - `auto`: uses the result of `Asteroid.OAuth2.MTLS.in_use?/0`. Default value
    """
    @type oauth2_mtls_start_endpoint :: boolean() | :auto
    field :oauth2_mtls_start_endpoint,
      [:boolean, {:one_of_atoms, [:auto]}],
      default: :auto,
      config_time: :runtime

    @doc """
    When MTLS is used, determines if the endpoints using MTLS should be advertised

    Defaults to `true`
    """
    @type oauth2_mtls_advertise_aliases :: boolean()
    field :oauth2_mtls_advertise_aliases, :boolean,
      default: true,
      config_time: :runtime

    @doc """
    Global OAuth2 scope configuration
    """
    @type oauth2_scope_config :: scope_config()
    field :oauth2_scope_config, :term,
      default: %{},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    @doc """
    Global scope configuration
    """
    field :scope_config, :term,
      default: %{scopes: %{"openid" => []}},
      config_time: :runtime,
      used_by: [:oauth2_scope_callback]

    ### end of configuration options
  end

  @doc """
  Loads the configuration from the configured sources and saves it on the local node
  """
  @spec load_and_save() :: {:ok, %__MODULE__{}} | {:error, Exception.t()}
  def load_and_save() do
    conf = load()

    :persistent_term.put(__MODULE__, conf)

    {:ok, conf}
  rescue
    e ->
      {:error, e}
  end

  @doc """
  Returns a configuration option. Raises if it doesn't exist

  In tests, checks first the process dictionary for the value and fall backs to the standard
  configuration, so that one can set configuration at the testing process level using:

      Process.put(:configuration_option, value)
  """
  @spec opt(atom()) :: any() | no_return()
  if Mix.env() == :test do
    def opt(configuration_option) do
      if configuration_option in Keyword.keys(Process.get()) do
        Process.get(configuration_option)
      else
        if configuration_option in __MODULE__.__specify__(:field_names),
          do: :persistent_term.get(__MODULE__) |> Map.fetch!(configuration_option),
          else: raise NotAConfigurationOptionError, opt: configuration_option
      end
    end
  else
    def opt(configuration_option) do
      if configuration_option in __MODULE__.__specify__(:field_names),
        do: :persistent_term.get(__MODULE__) |> Map.fetch!(configuration_option),
        else: raise NotAConfigurationOptionError, opt: configuration_option
    end
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
