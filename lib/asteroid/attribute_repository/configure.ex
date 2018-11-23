defmodule Asteroid.AttributeRepository.Configure do
  @moduledoc """
  configure/?, init/? and types for attribute repositories
  """

  @callback install(Keyword.t())
    :: :ok | {:error, any()}

  @callback start(Keyword.t())
    :: :ok | {:error, any()}
end
