defmodule Asteroid.Context do
  @moduledoc """
  """

  defstruct [:request, :client, :subject, :device, :scope]

  @type t :: %__MODULE__{
    request: map(),
    client: Asteroid.Client.t(),
    subject: Asteroid.Subject.t() | nil,
    device: Asteroid.Device.t() | nil,
    scope: MapSet.t()
  }

  @doc """
  Removes data from `Client`, `Subject` and `Device` except their id

  Main use is for storage purpose
  """
  #@spec compact(t()) :: t()
  #FIXME: probably need to convert to a map at a point to allow storing
  # in Riak
end
