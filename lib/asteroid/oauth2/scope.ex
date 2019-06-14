defmodule Asteroid.OAuth2.Scope do
  @moduledoc """
  Scope helper functions and default callbacks
  """

  alias OAuth2Utils.Scope
  alias Asteroid.Context
  alias Asteroid.OAuth2

  import Asteroid.Utils

  @typedoc """
  Individual scope configuration keys

  The processing rules are:
  - `:auto`: the scope will automatically be granted, even when not requested
  - `:display`: in *web flows*, display that scope to the end-user for authorization. When
  not present, shall be treated as `true`
  - `:optional`: in *web flows*, make that scope optional, so that the user can deselect it even
  when this was requested by the client. When not present, shall be treated as `false`
  - `:label`: a map of internationalised labels of the scope, that will be displayed to the
  end-user. The map keys are ISO639 tags, and the values the internationalised text of the label
  - `:acceptable_loas`: a list of LOAs for use in OIDC flows. When present, a scope shall be
  released only when the authorization process has an LOA present in this option. As a
  consequence, a scope will never be released when this option is set to an empty list
  - `:max_refresh_token_lifetime`: *when present*, restricts the lifetime of a refresh token
  released when that scope is granted. This *supersedes global*, flow or client refresh token
  lifetime configuration
  - `:max_access_token_lifetime`: *when present*, restricts the lifetime of an access token
  released when that scope is granted. This *supersedes global*, flow or client acess token
  lifetime configuration
  """

  @type scope_config_option_individual_scope_configuration ::
  {:auto, boolean()}
  | {:display, boolean()}
  | {:optional, boolean()}
  | {:label, %{required(String.t()) => String.t()}}
  | {:acceptable_loas, [Asteroid.OAuth2.LOA.t()]}
  | {:max_refresh_token_lifetime, non_neg_integer()}
  | {:max_access_token_lifetime, non_neg_integer()}

  @typedoc """
  Scope configuration option type
  """

  @type scope_config_option ::
  {:scopes, %{required(String.t()) => [scope_config_option_individual_scope_configuration()]}}

  @doc """
  Returns the merged scope configuration for a flow
  """

  @spec configuration_for_flow(OAuth2.flow()) :: scope_config_option()

  def configuration_for_flow(flow) when flow in [
    :ropc,
    :client_credentials,
    :authorization_code,
    :implicit
  ] do
    scope_config = astrenv(:scope_config)
    oauth2_scope_config = astrenv(:oauth2_scope_config)
    oauth2_flow_scope_config =
      case flow do
        :ropc ->
          astrenv(:oauth2_flow_ropc_scope_config, [])

        :client_credentials ->
          astrenv(:oauth2_flow_client_credentials_scope_config, [])

        :authorization_code ->
          astrenv(:oauth2_flow_authorization_code_scope_config, [])

        :implicit ->
          astrenv(:oauth2_flow_implicit_scope_config, [])
      end

    merged_individual_scope_config =
      Enum.reduce(
        [scope_config, oauth2_scope_config, oauth2_flow_scope_config],
        %{},
        fn
          conf, acc ->
            individual_scope_config = conf[:scopes] || %{}

            Map.merge(acc, individual_scope_config)
        end
      )

    [scopes: merged_individual_scope_config]
  end

  @doc """
  Given a set of scopes and a `t:scope_config_option/0`, returns the max refresh token lifetime
  or `nil` if not present
  """

  @spec max_refresh_token_lifetime(Scope.Set.t(), scope_config_option()) ::
  non_neg_integer()
  | nil

  def max_refresh_token_lifetime(scopes, scope_config_option) do
    Enum.reduce(
      scopes,
      [],
      fn
        scope, acc ->
          case scope_config_option[:scopes][scope][:max_refresh_token_lifetime] do
            lifetime when is_integer(lifetime) ->
              acc ++ [lifetime]

            nil ->
              acc
          end
      end
    )
    |> Enum.max(fn -> nil end)
  end

  @doc """
  Given a set of scopes and a `t:scope_config_option/0`, returns the max access token lifetime
  or `nil` if not present
  """

  @spec max_access_token_lifetime(Scope.Set.t(), scope_config_option()) ::
  non_neg_integer()
  | nil

  def max_access_token_lifetime(scopes, scope_config_option) do
    Enum.reduce(
      scopes,
      [],
      fn
        scope, acc ->
          case scope_config_option[:scopes][scope][:max_access_token_lifetime] do
            lifetime when is_integer(lifetime) ->
              acc ++ [lifetime]

            nil ->
              acc
          end
      end
    )
    |> Enum.max(fn -> nil end)
  end

  @doc """
  Returns the scopes available to a flow
  """

  @spec scopes_for_flow(OAuth2.flow()) :: Scope.Set.t()

  def scopes_for_flow(flow) when flow in [
    :ropc,
    :client_credentials,
    :authorization_code,
    :implicit
  ] do
    Enum.reduce(
      configuration_for_flow(flow)[:scopes] || %{},
      Scope.Set.new(),
      fn
        {scope, _}, acc ->
          Scope.Set.put(acc, scope)
      end
    )
  end

  @doc """
  Computes scopes to grant during requests

  Note that the list of scopes allowed for a client is directly configured in the client's
  attribute repository.

  ## ROPC

  The functions adds the scopes marked as `auto: true` in accordance to the
  #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_scope_config)}
  configuration option, only during the initial request (when the username and password
  parameters are provided).

  On further token renewal requests the released scopes are the ones requested and already
  granted during the initial request.

  ## Client credentials

  The functions adds the scopes marked as `auto: true` in accordance to the
  #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_scope_config)}
  configuration option, only during the initial request.

  On further token renewal requests the released scopes are the ones requested and already
  granted during the initial request, although you should probably not use refresh tokens
  in such a flow.
  """

  @spec grant_for_flow(Scope.Set.t(), Context.t()) :: Scope.Set.t()

  def grant_for_flow(scopes, %{flow: :ropc, grant_type: :password}) do
    Enum.reduce(
      astrenv(:oauth2_flow_ropc_scope_config) || [],
      scopes,
      fn
        {scope, scope_config}, acc ->
          if scope_config[:auto] do
            Scope.Set.put(acc, scope)
          else
            acc
          end
      end
    )
  end

  def grant_for_flow(scopes, %{flow: :client_credentials, grant_type: :client_credentials}) do
    Enum.reduce(
      astrenv(:oauth2_flow_client_credentials_scope_config) || [],
      scopes,
      fn
        {scope, scope_config}, acc ->
          if scope_config[:auto] do
            Scope.Set.put(acc, scope)
          else
            acc
          end
      end
    )
  end
end
