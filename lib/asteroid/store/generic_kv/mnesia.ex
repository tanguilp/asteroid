defmodule Asteroid.Store.GenericKV.Mnesia do
  @moduledoc """
  Mnesia implementation of the `Asteroid.Store.GenericKV` behaviour

  ## Options
  The options (`Asteroid.Store.GenericKV.opts()`) are:
  - `:table_name`: an `atom()` for the table name. No default, **mandatory**
  - `:tab_def`: Mnesia's table definitions of the `:mnesia.create_table/2` function. Defaults to
  the options below. User-defined `:tab_def` will be merged on a key basis, i.e. defaults will
  not be erased
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `720` (12 minutes). The purge uses the `"exp"`
  attribute of the value map as the expiration unix timestamp. If the value is not a map, it
  cannot be purged.

  ## Default Mnesia table definition
  ```elixir
  [
    attributes: [:id, :data]
  ]
  ```

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Mnesia).
  """

  require Logger

  @behaviour Asteroid.Store.GenericKV

  @impl true

  def install(opts) do
    unless is_atom(opts[:table_name]) do
      raise "Table name not specified for #{__MODULE__} store"
    end

    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    tab_def =
      [
        attributes: [:id, :data]
      ]
      |> Keyword.merge(opts[:tab_def] || [])

    case :mnesia.create_table(opts[:table_name], tab_def) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: created generiv KV store #{opts[:table_name]}")

        :ok

      {:aborted, {:already_exists, _}} ->
        Logger.info("#{__MODULE__}: generic KV store #{opts[:table_name]} already exists")
        :ok

      {:aborted, reason} ->
        Logger.error(
          "#{__MODULE__}: failed to create generic KV store #{opts[:table_name]} " <>
            "(reason: #{inspect(reason)})"
        )

        {:error, reason}
    end
  end

  @impl true

  def start_link(opts) do
    case :mnesia.start() do
      :ok ->
        opts = Keyword.merge([purge_interval: 12 * 60], opts)

        # we launch the process anyway because we need to return a process
        # but the singleton will do nothing if the value is `:no_purge`
        Singleton.start_child(__MODULE__.Purge, opts, __MODULE__)

      {:error, _} = error ->
        error
    end
  end

  @impl true

  def get(key, opts) do
    table_name = opts[:table_name] || raise "Table name not specified for #{__MODULE__} store"

    case :mnesia.dirty_read(table_name, key) do
      [] ->
        {:ok, nil}

      [{^table_name, ^key, data}] ->
        {:ok, data}

      _ ->
        {:error, "Multiple results from Mnesia"}
    end
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def put(key, value, opts) do
    table_name = opts[:table_name] || raise "Table name not specified for #{__MODULE__} store"

    :mnesia.dirty_write({table_name, key, value})

    Logger.debug(
      "#{__MODULE__}: stored object `#{inspect(key)}`, " <>
        "value: `#{inspect(value)}` in table `#{table_name}`"
    )

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def delete(key, opts) do
    table_name = opts[:table_name] || raise "Table name not specified for #{__MODULE__} store"

    :mnesia.dirty_delete(table_name, key)

    Logger.debug("#{__MODULE__}: deleted object `#{key}`")

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end
end
