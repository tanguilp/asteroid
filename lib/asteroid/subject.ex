defmodule Asteroid.Subject do
  @moduledoc """
  """

  defstruct [:id, :claims]

  @type t :: %__MODULE__{
    id: binary(),
    claims: map()
  }
end
