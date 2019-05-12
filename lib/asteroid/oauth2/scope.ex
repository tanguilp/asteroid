defmodule Asteroid.OAuth2.Scope do
  @moduledoc """
  Scope helper functions and default callbacks
  """

  alias OAuth2Utils.Scope
  alias Asteroid.Context

  import Asteroid.Utils

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
end
