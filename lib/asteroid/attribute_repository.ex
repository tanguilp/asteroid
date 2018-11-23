defmodule Asteroid.AttributeRepository do
  @moduledoc """
  Types for attribute repositories

  The pair composed of a `id` and an `attribute` constitute a unique value in an
  attribute repository. It can be nonexistent or existent, but there can not be
  several values for this pair.
  """

  @typedoc """
  The **unique** and **immutable** identifier of an object of an attribute repository
  """
  @type id :: String.t()

  @typedoc """
  """
  @type attribute :: String.t()

  @typedoc """
  Value associated to an attribute
  """
  @type value :: any()

  @typedoc """
  Configuration passed to all attribute repository functions
  """
  @type config :: Keyword.t()

  defmodule ReadError do
    defexception message: "Unknown read error"

    @moduledoc """
    Error returned for technical read errors
    """
  end

  defmodule WriteError do
    defexception message: "Unknown write error"

    @moduledoc """
    Error returned for technical write errors
    """
  end

  #for behaviour <- [Configure, Read, Write, Search] do
  #  name =
  #    behaviour
  #    |> Atom.to_string()
  #    |> String.split(".")
  #    |> List.last()
  #    |> String.downcase()
  #    |> (fn str -> "supports_" <> str <> "?" end).()
  #    |> String.to_atom()

  # def unquote(name)(), do: true
  #end
end
