defmodule Asteroid.AttributeRepository.Search do
  alias Asteroid.AttributeRepository, as: AttrRep

  @moduledoc """
  Search behaviour for attribute repositories that consist in searching on full
  values of an attribute
  """

  @doc """
  Search for a value through all the entries of a repository and returns a list
  of `t:Asteroid.AttributeRepository.value()`
  """
  @callback search(AttrRep.attribute(), AttrRep.value(), AttrRep.config())
  :: {:ok, [AttrRep.id()]} |
    {:error, %Asteroid.AttributeRepository.ReadError{}}

  @doc """
  Same as `search/3`, but raises an exception instead of returning an error tuple
  """
  @callback search(AttrRep.attribute(), AttrRep.value(), AttrRep.config())
    :: [AttrRep.value()] | no_return()
end
