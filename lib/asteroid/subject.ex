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
  @spec new_from_id(AttrRep.id(), Keyword.t())
    :: {:ok, t()} | {:error, :client_not_found}
  def new_from_id(id, opts \\ [attrs_autoload: true]) when is_binary(id) do
    subject = %Asteroid.Subject{id: id}

    if opts[:attrs_autoload] == true do
      attribute_list = astrenv(:attribute_repositories)[:subject][:attribute_autoload]

      {:ok, AttrRep.load_attributes_for_object(subject, attribute_list, :subject)}
    else
      {:ok, subject}
    end
  end

  @spec new_from_attribute(AttrRep.attribute(), AttrRep.value(), Keyword.t())
    :: {:ok, t()} | {:error, :not_found} | {:error, :multiple_values} | {:error, Exception.t()}
  def new_from_attribute(attribute, value, opts \\ [attrs_autoload: true]) do
    module = astrenv(:attribute_repositories)[:subject][:impl]
    config = astrenv(:attribute_repositories)[:subject][:opts]

    case module.search(attribute, value, config) do
      {:ok, [id]} when is_binary(id) ->
        new_from_id(id, opts)

      {:ok, []} ->
        {:error, :not_found}

      {:ok, _} ->
        {:error, :multiple_values}

      {:error, error} ->
        {:error, error}
    end
  end
end
