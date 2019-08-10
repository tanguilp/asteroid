defmodule Asteroid.OIDC.AuthenticatedSession do
  @doc """
  Convenience functions to work with authenticated sessions

  The `%Asteroid.OIDC.AuthenticatedSession{}` object has the following meaningful members in
  its `:data` field:
  - `"current_acr"`: the current ACR, as calculated (`t:Asteroid.OIDC.acr/0`)
  - `"current_auth_time"`: the current authentication time, as calculated (`non_neg_integer`)
  - `"exp"`: expiration time (`non_neg_integer`)
  """

  alias Asteroid.Subject

  @type id :: String.t()

  @enforce_keys [:id, :subject_id]

  defstruct [:id, :subject_id, :data]

  @type t :: %__MODULE__{
    id: id(),
    subject_id: Subject.id(),
    data: map()
  }
end
