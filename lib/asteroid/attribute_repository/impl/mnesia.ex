defmodule Asteroid.AttributeRepository.Impl.Mnesia do
  alias Asteroid.AttributeRepository
  alias Asteroid.AttributeRepository.{Configure, Read, Write, Search}
  import Asteroid.Utils

  require Logger

  @behaviour Configure
  @behaviour Read
  @behaviour Write
  @behaviour Search

  @impl Configure
  def install(conf) do
    # make sure Mnesia is stopped, otherwise schema can't be created
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    res = :mnesia.create_table(conf[:table], [
      attributes: [:key,
                   :value,
                   :metadata,
                   :created_at,
                   :created_by,
                   :last_modified_at,
                   :last_modified_by,
                   :history
      ],
      index: [:value]
    ] ++ conf[:mnesia_create_table])

    Logger.debug("#{__MODULE__}: creating table #{conf[:table]}, result: #{inspect res}")

    :mnesia.stop()

    :ok
  end

  @impl Configure
  def start(conf) do
    res = :mnesia.start()

    Logger.debug("#{__MODULE__}: starting for table #{conf[:table]}, result: #{inspect res}")

    :ok
  end

  @impl Read
  def get(id, attribute, conf) do
    case :mnesia.transaction(fn -> :mnesia.read(conf[:table], {id, attribute}) end) do
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
  def get!(id, attribute, conf) do
    case get(id, attribute, conf) do
      {:ok, value} ->
        value

      {:error, error} ->
        raise(error)
    end
  end

  @impl Write
  def put(id, attribute, value, conf, opts \\ [history: false]) do
    case :mnesia.transaction(fn -> :mnesia.read(conf[:table], {id, attribute}) end) do
      {:atomic, []} ->
        put_create(id, attribute, value, conf)

      {:atomic, [existing_record]} ->
        if opts[:history] == true do
          put_update(id, attribute, value, conf, existing_record, true)
        else
          put_update(id, attribute, value, conf, existing_record, false)
        end
    end
  end

  @spec put_create(AttrRep.id(), AttrRep.attribute(), AttrRep.value(), AttrRep.config())
    :: {:ok, AttrRep.value()} |
      {:error, %Asteroid.AttributeRepository.Write.NonConfiguredAttributeError{} |
               %Asteroid.AttributeRepository.WriteError{}}
  defp put_create(id, attribute, value, conf) do
    case :mnesia.transaction(fn ->
      :mnesia.write({
        conf[:table],     # table name
        {id, attribute},  # key
        value,            # value
        nil,              # metadata
        now(),            # created_at
        "Asteroid",       # created_by
        now(),            # last_update_at
        "Asteroid",       # last_update_by
        []               # history
      })
    end) do
      {:atomic, :ok} ->
        {:ok, value}

      _ ->
        {:error, %AttributeRepository.WriteError{}}
    end
  end

  @spec put_update(AttrRep.id(), AttrRep.attribute(), AttrRep.value(), AttrRep.config(),
                   tuple(), boolean())
    :: {:ok, AttrRep.value()} |
      {:error, %Asteroid.AttributeRepository.Write.NonConfiguredAttributeError{} |
               %Asteroid.AttributeRepository.WriteError{}}
  defp put_update(id, attribute, value, conf, existing_record, history) do
    history_record =
      if history == true do
        [
          {
            elem(existing_record, 2),
            elem(existing_record, 6),
            elem(existing_record, 7)
          } | elem(existing_record, 8)
        ]
      else
        elem(existing_record, 8)
      end

    case :mnesia.transaction(fn ->
      :mnesia.write({
        conf[:table],             # table name
        {id, attribute},          # key
        value,                    # value
        elem(existing_record, 3), # metadata
        elem(existing_record, 4), # created_at
        elem(existing_record, 5), # created_by
        now(),                    # last_update_at
        "Asteroid",               # last_update_by
        history_record            # history
      })
    end) do
      {:atomic, :ok} ->
        {:ok, value}

      _ ->
        {:error, %AttributeRepository.WriteError{}}
    end
  end

  @impl Write
  def put!(id, attribute, value, conf, opts \\ [history: false]) do
    case put(id, attribute, value, conf, opts) do
      {:ok, value} ->
        value

      {:error, error} ->
        raise(error)
    end
  end

  @impl Write
  def delete(id, attribute, conf) do
    case :mnesia.transaction(fn -> :mnesia.delete({conf[:table], {id, attribute}}) end) do
      {:atomic, :ok} ->
        :ok

      _ ->
        {:error, %AttributeRepository.WriteError{}}
    end
  end

  @impl Write
  def delete!(id, attribute, conf) do
    case delete(id, attribute, conf) do
      :ok ->
        :ok

      {:error, error} ->
        raise(error)
    end
  end

  @impl Write
  def on_the_fly_attribute_creation?(_), do: true

  @impl Search
  def search(attribute, value, conf) do
    pattern = {:subject, {:_, attribute}, value, :_, :_, :_, :_, :_, :_}

    case :mnesia.transaction(fn ->
      :mnesia.index_match_object(conf[:table], pattern, 3, :read)
    end) do
      {:atomic, tuple_list} ->
        {:ok,
          Enum.map(
            tuple_list,
            fn tuple -> elem(tuple, 1) |> elem(0) end
          )
        }

      _ ->
        {:error, %AttributeRepository.ReadError{}}
    end
  end

  @impl Search
  def search!(attribute, value, conf) do
    case search(attribute, value, conf) do
      {:ok, res} ->
        res

      {:error, error} ->
        raise(error)
    end
  end
end
