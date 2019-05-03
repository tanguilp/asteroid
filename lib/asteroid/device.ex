defmodule Asteroid.Device do
  @moduledoc """
  """

  defstruct [:id, :claims]

  @type id :: binary()

  @type t :: %__MODULE__{
    id: id(),
    claims: map()
  }
end
