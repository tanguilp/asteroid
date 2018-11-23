defmodule Asteroid.AttributeRepository.Impl.Mnesia do
  alias Asteroid.AttributeRepository
  alias Asteroid.AttributeRepository.{Configure, Read, Write}
  import Asteroid.Utils

  @behaviour Configure
  @behaviour Read
  @behaviour Write

  @impl Configure
  def install(opts) do
    # make sure Mnesia is stopped, otherwise schema can't be created
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    :mnesia.create_table(opts[:table], [
      attributes: [:key,
                   :value,
                   :metadata,
                   :created_at,
                   :created_by,
                   :last_modified_at,
                   :last_modified_by,
                   :history
      ]
    ])

    :mnesia.stop()

    :ok
  end

  @impl Configure
  def start(_opts) do
    :mnesia.start()

    :ok
  end

  @impl Read
  def get(id, attribute, opts) do
    case :mnesia.transaction(fn -> :mnesia.read(opts[:table], {id, attribute}) end) do
      {:atomic, [{
        _table,
         _key,
         value,
         _metadata,
         _created_at,
         _created_by,
         _last_modified_at,
         _last_modified_by,
         _history}]} ->
        {:ok, value}

      {:atomic, []} ->
        {:error, %Read.NotFoundError{}}

      _ ->
        {:error, %AttributeRepository.ReadError{}}
    end
  end

  @impl Read
  def get!(id, attribute, opts) do
    case get(id, attribute, opts) do
      {:ok, value} ->
        value

      {:error, error} ->
        raise(error)
    end
  end

  @impl Write
  def put(id, attribute, value, opts) do
    case :mnesia.transaction(fn -> :mnesia.read(opts[:table], {id, attribute}) end) do
      {:atomic, []} ->
        put_create(id, attribute, value, opts)

      {:atomic, [{
        _table,
         _key,
         _value,
         metadata,
         created_at,
         created_by,
         _last_modified_at,
         _last_modified_by,
         history}]} ->
        put_update(id, attribute, value, opts, [
          metadata: metadata,
          created_at: created_at,
          created_by: created_by,
          history: history])
    end
  end

  @spec put_create(AttrRep.id(), AttrRep.attribute(), AttrRep.value(), AttrRep.config())
    :: {:ok, AttrRep.value()} |
      {:error, %Asteroid.AttributeRepository.Write.NonConfiguredAttributeError{} |
               %Asteroid.AttributeRepository.WriteError{}}
  defp put_create(id, attribute, value, opts) do
    case :mnesia.transaction(fn ->
      :mnesia.write({
        opts[:table],     # table name
        {id, attribute},  # key
        value,            # value
        nil,              # metadata
        now(),            # created_at
        "Asteroid",       # created_by
        now(),            # last_update_at
        "Asteroid",       # last_update_by
        nil               # history
      })
    end) do
      {:atomic, :ok} ->
        {:ok, value}

      _ ->
        {:error, %AttributeRepository.WriteError{}}
    end
  end

  @spec put_update(AttrRep.id(), AttrRep.attribute(), AttrRep.value(), AttrRep.config(), map())
    :: {:ok, AttrRep.value()} |
      {:error, %Asteroid.AttributeRepository.Write.NonConfiguredAttributeError{} |
               %Asteroid.AttributeRepository.WriteError{}}
  defp put_update(id, attribute, value, opts, add_columns) do
    case :mnesia.transaction(fn ->
      :mnesia.write({
        opts[:table],             # table name
        {id, attribute},          # key
        value,                    # value
        add_columns[:metadata],   # metadata
        add_columns[:created_at], # created_at
        add_columns[:created_by], # created_by
        now(),                    # last_update_at
        "Asteroid",               # last_update_by
        add_columns[:history]     # history
      })
    end) do
      {:atomic, :ok} ->
        {:ok, value}

      _ ->
        {:error, %AttributeRepository.WriteError{}}
    end
  end

  @impl Write
  def put!(id, attribute, value, opts) do
    case put(id, attribute, value, opts) do
      {:ok, value} ->
        value

      {:error, error} ->
        raise(error)
    end
  end

  @impl Write
  def delete(id, attribute, opts) do
    case :mnesia.transaction(fn -> :mnesia.delete({opts[:table], {id, attribute}}) end) do
      {:atomic, :ok} ->
        :ok

      _ ->
        {:error, %AttributeRepository.WriteError{}}
    end
  end

  @impl Write
  def delete!(id, attribute, opts) do
    case delete(id, attribute, opts) do
      :ok ->
        :ok

      {:error, error} ->
        raise(error)
    end
  end

  @impl Write
  def on_the_fly_attribute_creation?(_), do: true
end
