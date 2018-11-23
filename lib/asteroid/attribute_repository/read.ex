defmodule Asteroid.AttributeRepository.Read do
  alias Asteroid.AttributeRepository, as: AttrRep

  @moduledoc """
  Read behaviour for attribute repositories
  """

  @doc """
  Gets an attribute value in a repository

  Returns `{:ok, value}` if the value is found, `{:error, error}` otherwise.
  """
  @callback get(AttrRep.id(), AttrRep.attribute(), AttrRep.config())
  :: {:ok, AttrRep.value()} |
    {:error, %Asteroid.AttributeRepository.Read.NotFoundError{} |
             %Asteroid.AttributeRepository.ReadError{}}

  @doc """
  Same as `get/3`, but raises an exception instead of returning an error
  """
  @callback get!(AttrRep.id(), AttrRep.attribute(), AttrRep.config())
  :: AttrRep.value() | no_return()

  defmodule NotFoundError do
    defexception message: "The attribute was not found"

    @moduledoc """
    Exception returned when an requested attribute was not found
    """
  end
end
