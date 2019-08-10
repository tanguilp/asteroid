defmodule Asteroid.Store.DeviceCode.Mnesia do
  @moduledoc """
  Mnesia implementation of the `Asteroid.Store.DeviceCode` behaviour

  ## Options
  The options (`Asteroid.Store.DeviceCode.opts()`) are:
  - `:table_name`: an `atom()` for the table name. Defaults to `:asteroid_device_code`
  - `:tab_def`: Mnesia's table definitions of the `:mnesia.create_table/2` function. Defaults to
  the options below. User-defined `:tab_def` will be merged on a key basis, i.e. defaults will
  not be erased
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `300` (5 minutes)

  ## Default Mnesia table definition
  ```elixir
  [
    attributes: [:id, :refresh_token_id, :subject_id, :client_id, :device_id, :data],
    index: [:refresh_token_id]
  ]
  ```

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Mnesia).
  """

  require Logger

  alias Asteroid.Token.DeviceCode

  @behaviour Asteroid.Store.DeviceCode

  @impl true

  def install(opts) do
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    table_name = opts[:table_name] || :asteroid_device_code

    tab_def =
      [
        attributes: [:id, :user_code, :data],
        index: [:user_code]
      ]
      |> Keyword.merge(opts[:tab_def] || [])

    case :mnesia.create_table(table_name, tab_def) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: created device code store #{table_name}")

        :ok

      {:aborted, {:already_exists, _}} ->
        Logger.info("#{__MODULE__}: device code store #{table_name} already exists")
        :ok

      {:aborted, reason} ->
        Logger.error(
          "#{__MODULE__}: failed to create device code store #{table_name} " <>
            "(reason: #{inspect(reason)})"
        )

        {:error, reason}
    end
  end

  @impl true

  def start_link(opts) do
    case :mnesia.start() do
      :ok ->
        opts = Keyword.merge([purge_interval: 300], opts)

        # we launch the process anyway because we need to return a process
        # but the singleton will do nothing if the value is `:no_purge`
        Singleton.start_child(__MODULE__.Purge, opts, __MODULE__)

      {:error, _} = error ->
        error
    end
  end

  @impl true

  def get(device_code_id, opts) do
    table_name = opts[:table_name] || :asteroid_device_code

    case :mnesia.dirty_read(table_name, device_code_id) do
      [] ->
        Logger.debug(
          "#{__MODULE__}: getting device code `#{device_code_id}`, " <> "value: `nil`"
        )

        {:ok, nil}

      [
        {^table_name, ^device_code_id, user_code, data}
      ] ->
        device_code =
          DeviceCode.new(
            id: device_code_id,
            user_code: user_code,
            data: data
          )

        Logger.debug(
          "#{__MODULE__}: getting device code `#{device_code_id}`, " <>
            "value: `#{inspect(device_code)}`"
        )

        {:ok, device_code}

      _ ->
        {:error, "Multiple results from Mnesia"}
    end
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_user_code(user_code, opts) do
    table_name = opts[:table_name] || :asteroid_device_code

    [{_table_name, device_code_id, _user_code, _data}] = :mnesia.dirty_match_object({table_name, :_, user_code, :_})

    get(device_code_id, opts)
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def put(device_code, opts) do
    table_name = opts[:table_name] || :asteroid_device_code

    record = {
      table_name,
      device_code.id,
      device_code.user_code,
      device_code.data
    }

    :mnesia.dirty_write(table_name, record)

    Logger.debug(
      "#{__MODULE__}: stored device code `#{device_code.id}`, " <>
        "value: `#{inspect(device_code)}`"
    )

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def delete(device_code_id, opts) do
    table_name = opts[:table_name] || :asteroid_device_code

    :mnesia.dirty_delete(table_name, device_code_id)

    Logger.debug("#{__MODULE__}: deleted device code `#{device_code_id}`")

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end
end
