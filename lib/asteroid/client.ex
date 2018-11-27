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

  @doc """
  Fetches an attribute if not already loaded in the client
  """
  @spec fetch_attribute(t(), AttrRep.attribute()) :: t()
  def fetch_attribute(client, attribute) do
    if client.attrs[attribute] == nil do
      module = astrenv(:attribute_repositories)[:client][:impl]
      config = astrenv(:attribute_repositories)[:client][:opts]

      case module.get(client.id, attribute, config) do
        {:ok, value} ->
          put_attribute(client, attribute, value)

        {:error, _} ->
          client
      end
    else
      client
    end
  end

  @doc """
  Puts an attribute in the client, overriding any existing one
  """
  @spec put_attribute(t(), AttrRep.attribute(), AttrRep.value()) :: t()
  def put_attribute(client, attribute, value) do
    %{client | attrs: Map.put(client.attrs, attribute, value)}
  end

  @doc """
  Deletes an attribute from the client
  """
  @spec delete_attribute(t(), AttrRep.attribute()) :: t()
  def delete_attribute(client, attribute) do
    module = astrenv(:attribute_repositories)[:client][:impl]
    config = astrenv(:attribute_repositories)[:client][:opts]

    module.delete(client.id, attribute, config)

    %{client | attrs: Map.delete(client.attrs, attribute)}
  end

  @doc """
  Persists the attributes of the client in its repository and returns the
  unmodified client
  """
  @spec store(t()) :: t()
  def store(client) do
    module = astrenv(:attribute_repositories)[:client][:impl]
    config = astrenv(:attribute_repositories)[:client][:opts]

    for {attribute, value} <- client.attrs do
      module.put(client.id, attribute, value, config)
    end

    client
  end
end
