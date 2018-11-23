defmodule Asteroid.AttributeRepository.Write do
  alias Asteroid.AttributeRepository, as: AttrRep

  @moduledoc """
  Write behaviour for attribute repositories
  """

  @doc """
  Puts an attribute value in the repository.

  Returns `{:ok, value}` on success. Note that the value can be modified by the repository,
  hence it is necessary to use the returned value.

  Repositories that can create new attributes on the fly always return a `{:ok, value}`
  tuple. Those which cannot (e.g.: LDAP repositories that require schema extension) should
  return
  """
  @callback put(AttrRep.id(), AttrRep.attribute(), AttrRep.value(), AttrRep.config())
    :: {:ok, AttrRep.value()} |
      {:error, %Asteroid.AttributeRepository.Write.NonConfiguredAttributeError{} |
               %Asteroid.AttributeRepository.WriteError{}}

  @doc """
  Same as `put/4`, but raises an exception instead of returning an error
  """
  @callback put!(AttrRep.id(), AttrRep.attribute(), AttrRep.value(), AttrRep.config())
    :: AttrRep.value() | no_return()

  @doc """
  Deletes the attribute

  Note that as `nil` is an acceptable value of an attribute, this function should not
  only delete the value but also the attribute
  """
  @callback delete(AttrRep.id(), AttrRep.attribute(), AttrRep.config())
    :: :ok |
      {:error, %Asteroid.AttributeRepository.Write.NonConfiguredAttributeError{} |
               %Asteroid.AttributeRepository.WriteError{}}

  @doc """
  Same as `delete/3`, but raises an exception instead of returning an error
  """
  @callback delete!(AttrRep.id(), AttrRep.attribute(), AttrRep.config())
    :: :ok | no_return()

  @doc """
  Returns `true` if the repository can insert new values for attributes that it does not
  know and has not been configured beforehand, `false` otherwise.
  """
  @callback on_the_fly_attribute_creation?(AttrRep.config()) :: boolean()

  defmodule NonConfiguredAttributeError do
    defexception message: "The attribute has not been configured and cannot created on the fly"

    @moduledoc """
    Exception returned when writing a new attribute that is not know to the repository and
    cannot be configured on the fly
    """
  end
end
