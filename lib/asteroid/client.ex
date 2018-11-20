defmodule Asteroid.Client do
  @moduledoc """
  """

  defstruct [:id, :claims]

  @type t :: %__MODULE__{
    id: binary(),
    claims: map()
  }

  @typedoc """
  """
  @type client_param :: String.t()
end
