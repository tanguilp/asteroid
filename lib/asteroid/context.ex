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

  @doc """
  Removes data from `Client`, `Subject` and `Device` except their id

  Main use is for storage purpose
  """
  #@spec compact(t()) :: t()
  #FIXME: probably need to convert to a map at a point to allow storing
  # in Riak
end
