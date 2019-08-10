defmodule Asteroid.Store.AuthorizationCode.Mnesia do
  @moduledoc """
  Mnesia implementation of the `Asteroid.Store.AuthorizationCode` behaviour

  ## Options
  The options (`Asteroid.Store.AuthorizationCode.opts()`) are:
  - `:table_name`: an `atom()` for the table name. Defaults to `:asteroid_authorization_code`
  - `:tab_def`: Mnesia's table definitions of the `:mnesia.create_table/2` function. Defaults to
  the options below. User-defined `:tab_def` will be merged on a key basis, i.e. defaults will
  not be erased
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `240` (3 minutes)

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

  alias Asteroid.Token.AuthorizationCode

  @behaviour Asteroid.Store.AuthorizationCode

  @impl true

  def install(opts) do
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    table_name = opts[:table_name] || :asteroid_authorization_code

    tab_def =
      [
        attributes: [:id, :data]
      ]
      |> Keyword.merge(opts[:tab_def] || [])

    case :mnesia.create_table(table_name, tab_def) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: created authorization code store #{table_name}")

        :ok

      {:aborted, {:already_exists, _}} ->
        Logger.info("#{__MODULE__}: authorization code store #{table_name} already exists")
        :ok

      {:aborted, reason} ->
        Logger.error(
          "#{__MODULE__}: failed to create authorization code store #{table_name} " <>
            "(reason: #{inspect(reason)})"
        )

        {:error, reason}
    end
  end

  @impl true

  def start_link(opts) do
    case :mnesia.start() do
      :ok ->
        opts = Keyword.merge([purge_interval: 240], opts)

        # we launch the process anyway because we need to return a process
        # but the singleton will do nothing if the value is `:no_purge`
        Singleton.start_child(__MODULE__.Purge, opts, __MODULE__)

      {:error, _} = error ->
        error
    end
  end

  @impl true

  def get(authorization_code_id, opts) do
    table_name = opts[:table_name] || :asteroid_authorization_code

    case :mnesia.dirty_read(table_name, authorization_code_id) do
      [] ->
        Logger.debug(
          "#{__MODULE__}: getting authorization code `#{authorization_code_id}`, " <> "value: `nil`"
        )

        {:ok, nil}

      [{^table_name, ^authorization_code_id, data}] ->
        authorization_code =
          AuthorizationCode.new(
            id: authorization_code_id,
            data: data
          )

        Logger.debug(
          "#{__MODULE__}: getting authorization code `#{authorization_code_id}`, " <>
            "value: `#{inspect(authorization_code)}`"
        )

        {:ok, authorization_code}

      _ ->
        {:error, "Multiple results from Mnesia"}
    end
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def put(authorization_code, opts) do
    table_name = opts[:table_name] || :asteroid_authorization_code

    record = {
      table_name,
      authorization_code.id,
      authorization_code.data
    }

    :mnesia.dirty_write(table_name, record)

    Logger.debug(
      "#{__MODULE__}: stored authorization code `#{authorization_code.id}`, " <>
        "value: `#{inspect(authorization_code)}`"
    )

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def delete(authorization_code_id, opts) do
    table_name = opts[:table_name] || :asteroid_authorization_code

    :mnesia.dirty_delete(table_name, authorization_code_id)

    Logger.debug("#{__MODULE__}: deleted authorization code `#{authorization_code_id}`")

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end
end
