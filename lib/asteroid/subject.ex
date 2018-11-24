defmodule Asteroid.Subject do
  @moduledoc """
  """

  import Asteroid.Utils
  alias Asteroid.AttributeRepository, as: AttrRep

  @enforce_keys [:id]
  defstruct id: "",
            attrs: %{}

  @type t :: %__MODULE__{
    id: binary(),
    attrs: map()
  }

  @doc """
  Creates a new `Asteroid.Subject.t()` with the given id

  If the `:attrs_autoload` is set to `true` (default), the function will try to load
  the default attributes from the configuration file into the object.
  """
  @spec new_from_id(AttrRep.id(), Keyword.t()) :: t()
  def new_from_id(id, opts \\ [attrs_autoload: true]) when is_binary(id) do
    subject = %Asteroid.Subject{id: id}

    if opts[:attrs_autoload] == true do
      attribute_list = astrenv(:attribute_repositories)[:subject][:attribute_autoload]

      AttrRep.load_attributes_for_object(subject, attribute_list, :subject)
    else
      subject
    end
  end
end
