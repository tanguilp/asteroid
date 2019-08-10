defmodule Asteroid.OIDC.AuthenticationEvent do
  @doc """
  Convenience functions to work with authentication events

  The `%Asteroid.OIDC.AuthenticationEvent{}` object has the following meaningful members in
  its `:data` field:
  - `"auth_event_name"`: the event name (`t:Asteroid.AuthenticationEvent.name/0`)
  - `"amr"`: the AMR of the event (`t:Asteroid.OIDC.amr/0`)
  - `"event_time"`: the time the authentication event occured (`non_neg_integer()`)
  - `"exp"`: expiration time (`non_neg_integer()`)
  """

  alias Asteroid.OIDC.AuthenticatedSession

  @type id :: String.t()

  @type name :: String.t()

  @enforce_keys [:id, :authenticated_session_id]

  defstruct [:id, :authenticated_session_id, :data]

  @type t :: %__MODULE__{
    id: id(),
    authenticated_session_id: AuthenticatedSession.id(),
    data: map()
  }
end
