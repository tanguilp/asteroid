defmodule Asteroid.Context do
  @moduledoc """
  """

  defstruct [:request, :client, :subject, :device]

  @type t :: %__MODULE__{
    request: map(),
    client: Asteroid.Client.t(),
    subject: Asteroid.Subject.t(),
    device: Asteroid.Device.t()
  }
end
