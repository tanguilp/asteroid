defmodule Asteroid.Config do
  @moduledoc """
  Specification of configuration options and callbacks, and testouille
  """

  require Asteroid.Config.Builder

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
    Refresh token lifetime for ROPC

    Default refresh token lifetime for ROPC flow.
    """

    @type refresh_token_lifetime_ropc :: non_neg_integer()

    field :refresh_token_lifetime_ropc,
      config_time: :runtime,
      used_by: [:refresh_token_lifetime_callback],
      unit: "seconds"

    @doc """
    Refresh token lifetime callback

    Callback call to determine the lifetime of a refresh token.
    """

    @type refresh_token_lifetime_callback :: (Asteroid.Context.t() -> non_neg_integer())

    field :refresh_token_lifetime_callback,
      config_time: :runtime,
      uses: [
        :refresh_token_lifetime_ropc,
        :refresh_token_lifetime_client_credentials
      ]
  end

end
