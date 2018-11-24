defmodule Asteroid.Client do
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

  @typedoc """
  """
  @type client_param :: String.t()

  @doc """
  Creates a new `Asteroid.Client.t()` with the given id

  If the `:attrs_autoload` is set to `true` (default), the function will try to load
  the default attributes from the configuration file into the object.
  """
  @spec new_from_id(AttrRep.id(), Keyword.t()) :: t()
  def new_from_id(id, opts \\ [attrs_autoload: true]) when is_binary(id) do
    client = %Asteroid.Client{id: id}

    if opts[:attrs_autoload] == true do
      attribute_list = astrenv(:attribute_repositories)[:client][:attribute_autoload]

      AttrRep.load_attributes_for_object(client, attribute_list, :client)
    else
      client
    end
  end

  @spec new_from_attribute(AttrRep.attribute(), AttrRep.value(), Keyword.t())
    :: {:ok, t()} | {:error, :not_found} | {:error, :multiple_values} | {:error, Exception.t()}
  def new_from_attribute(attribute, value, opts \\ [attrs_autoload: true]) do
    module = astrenv(:attribute_repositories)[:client][:impl]
    config = astrenv(:attribute_repositories)[:client][:opts]

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
