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
    :: {:ok, t()} | {:error, :subject_not_found}
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

  @doc """
  Fetches an attribute if not already loaded in the subject
  """
  @spec fetch_attribute(t(), AttrRep.attribute()) :: t()
  def fetch_attribute(subject, attribute) do
    if subject.attrs[attribute] == nil do
      module = astrenv(:attribute_repositories)[:subject][:impl]
      config = astrenv(:attribute_repositories)[:subject][:opts]

      case module.get(subject.id, attribute, config) do
        {:ok, value} ->
          put_attribute(subject, attribute, value)

        {:error, _} ->
          subject
      end
    else
      subject
    end
  end

  @doc """
  Puts an attribute in the subject, overriding any existing one
  """
  @spec put_attribute(t(), AttrRep.attribute(), AttrRep.value()) :: t()
  def put_attribute(subject, attribute, value) do
    %{subject | attrs: Map.put(subject.attrs, attribute, value)}
  end

  @doc """
  Deletes an attribute from the subject
  """
  @spec delete_attribute(t(), AttrRep.attribute()) :: t()
  def delete_attribute(subject, attribute) do
    module = astrenv(:attribute_repositories)[:subject][:impl]
    config = astrenv(:attribute_repositories)[:subject][:opts]

    module.delete(subject.id, attribute, config)

    %{subject | attrs: Map.delete(subject.attrs, attribute)}
  end

  @doc """
  Persists the attributes of the subject in its repository and returns the
  unmodified subject
  """
  @spec store(t()) :: t()
  def store(subject) do
    module = astrenv(:attribute_repositories)[:subject][:impl]
    config = astrenv(:attribute_repositories)[:subject][:opts]

    for {attribute, value} <- subject.attrs do
      module.put(subject.id, attribute, value, config)
    end

    subject
  end
end
