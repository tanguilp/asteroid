defmodule Asteroid.Device do
  use AttributeRepository.Resource, otp_app: :asteroid

  @moduledoc """
  `AttributeRepository.Resource` for devices

  A device refers to a unique machine, be it a server, a smartphone, a personal computer, an
  IOT device such as a connected toothbrush...

  ## Configuration

  This modules uses the default configuration of `AttributeRepository.Resource` (see `config/1`).
  """
end
