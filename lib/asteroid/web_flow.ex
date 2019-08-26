defmodule Asteroid.WebFlow do
  @moduledoc """
  Convenience functions to work with web flows
  """

  import Asteroid.Utils

  alias Asteroid.OAuth2
  alias Asteroid.OIDC
  alias AsteroidWeb.AuthorizeController.Request

  @doc """
  Callback invoked to determine which callback function to call to continue the authorization
  process after the parameters were successfully verified

  If the protocol is OAuth2, it calls:
  - #{Asteroid.Config.link_to_option(:oauth2_flow_authorization_code_web_authorization_callback)}
  if the flow is authorization code
  - #{Asteroid.Config.link_to_option(:oauth2_flow_implicit_web_authorization_callback)}
  if the flow is implicit

  If the protocol is OpenID Connect, it uses the
  #{Asteroid.Config.link_to_option(:oidc_acr_config)} configuration option to determine which
  callback to use:
  - if a preferred acr was computed, it uses its associated callback
  - otherwise, if one entry in the config is marked as `default: true`, it uses it

  If this configuration option is not used, it fall backs to:
  - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_web_authorization_callback)}
  if the flow is authorization code
  - #{Asteroid.Config.link_to_option(:oidc_flow_implicit_web_authorization_callback)}
  if the flow is implicit
  - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_web_authorization_callback)}
  if the flow is hybrid
  """

  @spec web_authorization_callback(Plug.Conn.t(), AsteroidWeb.AuthorizeController.Request.t()) ::
          {:ok, (Plug.Conn.t(), AsteroidWeb.AuthorizeController.Request.t() -> Plug.Conn.t())}
          | {:error, Exception.t()}

  def web_authorization_callback(_conn, authz_request) do
    oidc_acr_config = astrenv(:oidc_acr_config, [])

    case acceptable_acrs_for_scopes(authz_request) do
      nil ->
        default_web_authorization_callback(authz_request)

      acceptable_acrs ->
        case authz_request.claims do
          %{"id_token" => %{"acr" => %{"essential" => true, "values" => values}}} ->
            case Enum.find(values, &(&1 in acceptable_acrs)) do
              acr when is_binary(acr) ->
                {:ok, oidc_acr_config[acr][:callback]}

              nil ->
                {:error,
                 OAuth2.AccessDeniedError.exception(
                   reason: "Requested acrs could not be satisfied in regards to scopes config"
                 )}
            end

          %{"id_token" => %{"acr" => %{"essential" => true, "value" => value}}} ->
            if value in acceptable_acrs do
              {:ok, oidc_acr_config[value][:callback]}
            else
              {:error,
               OAuth2.AccessDeniedError.exception(
                 reason: "Requested acr could not be satisfied in regards to scopes config"
               )}
            end

          %{"id_token" => %{"acr" => %{"values" => values}}} ->
            case Enum.find(values, &(&1 in acceptable_acrs)) do
              acr when is_binary(acr) ->
                {:ok, oidc_acr_config[acr][:callback]}

              nil ->
                {:ok, first_acr_callback_from_config(acceptable_acrs)}
            end

          %{"id_token" => %{"acr" => %{"essential" => true, "value" => value}}} ->
            if value in acceptable_acrs do
              {:ok, oidc_acr_config[value][:callback]}
            else
              {:ok, first_acr_callback_from_config(acceptable_acrs)}
            end

          _ ->
            case authz_request.acr_values do
              acr_values when is_list(acr_values) ->
                case Enum.find(acr_values, &(&1 in acceptable_acrs)) do
                  acr when is_binary(acr) ->
                    {:ok, oidc_acr_config[acr][:callback]}

                  nil ->
                    {:ok, first_acr_callback_from_config(acceptable_acrs)}
                end

              nil ->
                default_web_authorization_callback(authz_request)
            end
        end
    end
  end

  @spec first_acr_callback_from_config(MapSet.t(OIDC.acr())) ::
          {:ok, (Plug.Conn.t(), AsteroidWeb.AuthorizeController.Request.t() -> Plug.Conn.t())}
          | {:error, Exception.t()}

  defp first_acr_callback_from_config(acceptable_acrs) do
    Enum.find(
      astrenv(:oidc_acr_config, []),
      fn
        {acr, _acr_config} ->
          acr in acceptable_acrs
      end
    )
    |> case do
      {_acr, acr_config} ->
        {:ok, acr_config[:callback]}

      _ ->
        {:error,
         OAuth2.AccessDeniedError.exception(reason: "no suitable acr found in configuration")}
    end
  end

  @spec default_web_authorization_callback(AsteroidWeb.AuthorizeController.Request.t()) ::
          {:ok, (Plug.Conn.t(), AsteroidWeb.AuthorizeController.Request.t() -> Plug.Conn.t())}
          | {:error, Exception.t()}

  defp default_web_authorization_callback(%Request{flow: :authorization_code}) do
    {:ok, astrenv(:oauth2_flow_authorization_code_web_authorization_callback)}
  end

  defp default_web_authorization_callback(%Request{flow: :implicit}) do
    {:ok, astrenv(:oauth2_flow_implicit_web_authorization_callback)}
  end

  defp default_web_authorization_callback(%Request{flow: flow} = authz_req)
       when flow in [
              :oidc_authorization_code,
              :oidc_implicit,
              :oidc_hybrid
            ] do
    oidc_acr_config = astrenv(:oidc_acr_config, [])

    maybe_preferred_acr =
      try do
        String.to_existing_atom(authz_req.preferred_acr)
      rescue
        _ ->
          nil
      end

    if oidc_acr_config[maybe_preferred_acr][:callback] do
      {:ok, oidc_acr_config[maybe_preferred_acr][:callback]}
    else
      maybe_default_callback =
        Enum.find_value(
          oidc_acr_config,
          fn
            {_acr, acr_config} ->
              if acr_config[:default] == true do
                acr_config[:callback]
              else
                nil
              end
          end
        )

      if maybe_default_callback do
        {:ok, maybe_default_callback}
      else
        case flow do
          :oidc_authorization_code ->
            {:ok, astrenv(:oidc_flow_authorization_code_web_authorization_callback)}

          :oidc_implicit ->
            {:ok, astrenv(:oidc_flow_implicit_web_authorization_callback)}

          :oidc_hybrid ->
            {:ok, astrenv(:oidc_flow_hybrid_web_authorization_callback)}
        end
      end
    end
  end

  @spec acceptable_acrs_for_scopes(Request.t()) :: MapSet.t(OIDC.acr()) | nil

  defp acceptable_acrs_for_scopes(authz_request) do
    scope_config = OAuth2.Scope.configuration_for_flow(authz_request.flow)

    # we use `nil` as the initial acc because it could be possible that one scope
    # require `acr1`, and another `acr2`. In such a case, we need to return an empty MapSet
    # (the condition cannot be satisfied). If there is no acr config at the scope level,
    # we have to return `nil` (and not an empty MapSet)

    Enum.reduce(
      authz_request.requested_scopes,
      nil,
      fn
        scope, acc ->
          case scope_config[:scopes][scope][:acceptable_acrs] do
            nil ->
              acc

            [_ | _] = acrs ->
              map_set = if acc, do: acc, else: MapSet.new()

              acrs
              |> Enum.reduce(MapSet.new(), &MapSet.put(&2, &1))
              |> MapSet.intersection(map_set)
          end
      end
    )
  end
end
