defmodule Asteroid.OAuth2.Scope do
  @moduledoc """
  Scope helper functions and default callbacks
  """

  alias OAuth2Utils.Scope
  alias Asteroid.Context
  alias Asteroid.OAuth2

  import Asteroid.Utils

  defmodule UnknownRequestedScopeError do
    @moduledoc """
    Error return when an unknown scope has been reuqested
    """

    defexception [:unknown_scopes]

    @type t :: %__MODULE__{
      unknown_scopes: Scope.Set.t()
    }

    def message(%{unknown_scopes: unknown_scopes}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Unknown requested scope(s)" <>
            if unknown_scopes do
              " (#{Enum.join(unknown_scopes, " ")})"
            else
              ""
            end

        :normal ->
          "Unknown requested scope(s)"

        :minimal ->
          ""
      end
    end
  end

  @typedoc """
  Individual scope configuration keys

  The processing rules are:
  - `:auto`: the scope will automatically be granted, even when not requested
  - `:advertise`: determine whether the scope is advertised on the `/.well-nown` URIs. Defaults
  to `true`. If set in a incoherent way within different flows, the behaviour is unspecified.
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
  | {:acceptable_loas, [Asteroid.OIDC.acr()]}
  | {:max_refresh_token_lifetime, non_neg_integer()}
  | {:max_access_token_lifetime, non_neg_integer()}

  @typedoc """
  Scope configuration option type
  """

  @type scope_config_option ::
  [{:scopes, %{required(String.t()) => [scope_config_option_individual_scope_configuration()]}}]

  @doc """
  Returns the merged scope configuration for a flow

  Scope configuration is merge at the key level of a individual scope configuration.
  """

  @spec configuration_for_flow(OAuth2.flow()) :: scope_config_option()

  def configuration_for_flow(flow) when flow in [
    :ropc,
    :client_credentials,
    :authorization_code,
    :implicit,
    :device_authorization,
    :oidc_authorization_code,
    :oidc_implicit,
    :oidc_hybrid
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

        :device_authorization ->
          astrenv(:oauth2_flow_device_authorization_scope_config, [])

        :oidc_authorization_code ->
          astrenv(:oidc_flow_authorization_code_scope_config, [])

        :oidc_implicit ->
          astrenv(:oidc_flow_implicit_scope_config, [])

        :oidc_hybrid ->
          astrenv(:oidc_flow_hybrid_scope_config, [])
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
    :implicit,
    :device_authorization,
    :oidc_authorization_code,
    :oidc_implicit,
    :oidc_hybrid
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
  Returns `:ok` if the scopes are enabled for the given flow, false otherwise
  """

  @spec scopes_enabled?(Scope.Set.t(), OAuth2.flow()) ::
  :ok
  | {:error, %UnknownRequestedScopeError{}}

  def scopes_enabled?(scopes, flow) do
    enabled_scopes_for_flow = scopes_for_flow(flow)

    if Scope.Set.subset?(scopes, enabled_scopes_for_flow) do
      :ok
    else
      {:error, UnknownRequestedScopeError.exception(
        unknown_scopes: Scope.Set.difference(scopes, enabled_scopes_for_flow))}
    end
  end

  @doc """
  Computes scopes to grant during requests

  Note that the list of scopes allowed for a client is directly configured in the client's
  attribute repository.

  ## ROPC flow

  The functions adds the scopes marked as `auto: true` in accordance to the
  #{Asteroid.Config.link_to_option(:oauth2_flow_ropc_scope_config)}
  configuration option, only during the initial request (when the username and password
  parameters are provided).

  On further token renewal requests the released scopes are the ones requested  and already
  granted during the initial request, or a subset of them.

  ## Client credentials flow

  The functions adds the scopes marked as `auto: true` in accordance to the
  #{Asteroid.Config.link_to_option(:oauth2_flow_client_credentials_scope_config)}
  configuration option, only during the initial request.

  On further token renewal requests the released scopes are the ones requested and already
  granted during the initial request, or a subset of them, although you should probably not
  use refresh tokens in such a flow.

  ## Authorization code flow

  The functions adds the scopes marked as `auto: true` in accordance to the
  #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_scope_config)}
  configuration option when the web flow on the `/authorize` endpoint successfully concludes.

  ## Implicit flow

  The functions adds the scopes marked as `auto: true` in accordance to the
  #{Asteroid.Config.link_to_option(:oauth2_flow_implicit_scope_config)}
  configuration option when the web flow on the `/authorize` endpoint successfully concludes.

  ## Device authorization flow
  During the initial phase of the flow, when the client requests a device code on the
  `/api/oauth2/device_authorization` endpoint, this function does not change the scopes.

  The functions adds the scopes marked as `auto: true` in accordance to the
  #{Asteroid.Config.link_to_option(:oauth2_flow_device_authorization_scope_config)}
  configuration option when the web flow on the `/device` endpoint successfully concludes.
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

  def grant_for_flow(scopes, %{endpoint: :authorize, flow: :authorization_code}) do
    Enum.reduce(
      astrenv(:oauth2_flow_authorization_code_scope_config) || [],
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

  def grant_for_flow(scopes, %{endpoint: :authorize, flow: :implicit}) do
    Enum.reduce(
      astrenv(:oauth2_flow_implicit_scope_config) || [],
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

  def grant_for_flow(scopes, %{flow: :device_authorization, endpoint: :device_authorization}) do
    scopes
  end

  def grant_for_flow(scopes, %{flow: :device_authorization, endpoint: :device}) do
    Enum.reduce(
      astrenv(:oauth2_flow_device_authorization_scope_config) || [],
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

  def grant_for_flow(scopes, %{endpoint: :authorize, flow: :oidc_authorization_code}) do
    Enum.reduce(
      astrenv(:oidc_flow_authorization_code_scope_config) || [],
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

  def grant_for_flow(scopes, %{endpoint: :authorize, flow: :oidc_implicit}) do
    Enum.reduce(
      astrenv(:oidc_flow_implicit_scope_config) || [],
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

  def grant_for_flow(scopes, %{endpoint: :authorize, flow: :oidc_hybrid}) do
    Enum.reduce(
      astrenv(:oidc_flow_hybrid_scope_config) || [],
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
