defmodule Asteroid.Store.AuthenticationEvent.Mnesia do
  @moduledoc """
  Mnesia implementation of the `Asteroid.Store.AuthenticationEvent` behaviour

  ## Options
  The options (`Asteroid.Store.AuthenticationEvent.opts()`) are:
  - `:table_name`: an `atom()` for the table name. Defaults to `:asteroid_authentication_event`
  - `:tab_def`: Mnesia's table definitions of the `:mnesia.create_table/2` function. Defaults to
  the options below. User-defined `:tab_def` will be merged on a key basis, i.e. defaults will
  not be erased. One can use it to add additional indexes for clients or devices, e.g.:
  `tab_def: [index: :refresh_token, :authenticated_session_id, :client_id]`
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `300` (5 minutes)

  ## Default Mnesia table definition
  ```elixir
  [
    attributes: [:id, :authenticated_session_id, :data],
    index: [:refresh_token_id]
  ]
  ```

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Mnesia).
  """

  require Logger

  alias Asteroid.OIDC.AuthenticationEvent

  @behaviour Asteroid.Store.AuthenticationEvent

  @impl true

  def install(opts) do
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    table_name = opts[:table_name] || :asteroid_authentication_event

    tab_def =
      [
        attributes: [:id, :authenticated_session_id, :data],
        index: [:refresh_token_id]
      ]
      |> Keyword.merge(opts[:tab_def] || [])

    case :mnesia.create_table(table_name, tab_def) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: created authentication event store #{table_name}")

        :ok

      {:aborted, {:already_exists, _}} ->
        Logger.info("#{__MODULE__}: authentication event store #{table_name} already exists")
        :ok

      {:aborted, reason} ->
        Logger.error(
          "#{__MODULE__}: failed to create authentication event store #{table_name} " <>
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

  def get(authentication_event_id, opts) do
    table_name = opts[:table_name] || :asteroid_authentication_event

    case :mnesia.dirty_read(table_name, authentication_event_id) do
      [] ->
        Logger.debug(
          "#{__MODULE__}: getting authentication event `#{authentication_event_id}`, " <> "value: `nil`"
        )

        {:ok, nil}

      [{^table_name, ^authentication_event_id, authenticated_session_id, data}] ->
        authentication_event =
          %AuthenticationEvent{
            id: authentication_event_id,
            authenticated_session_id: authenticated_session_id,
            data: data
          }

        Logger.debug(
          "#{__MODULE__}: getting authentication event `#{authentication_event_id}`, " <>
            "value: `#{inspect(authentication_event)}`"
        )

        {:ok, authentication_event}

      _ ->
        {:error, "Multiple results from Mnesia"}
    end
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_authenticated_session_id(authenticated_session_id, opts) do
    table_name = opts[:table_name] || :asteroid_authentication_event

    {:ok,
      for {_table_name, authentication_event_id, _authenticated_session_id, _data} <-
        :mnesia.dirty_match_object({table_name, :_, authenticated_session_id, :_}) do
        authentication_event_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def put(authentication_event, opts) do
    table_name = opts[:table_name] || :asteroid_authentication_event

    record = {
      table_name,
      authentication_event.id,
      authentication_event.authenticated_session_id,
      authentication_event.data
    }

    :mnesia.dirty_write(table_name, record)

    Logger.debug(
      "#{__MODULE__}: stored authentication event `#{authentication_event.id}`, " <>
        "value: `#{inspect(authentication_event)}`"
    )

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def delete(authentication_event_id, opts) do
    table_name = opts[:table_name] || :asteroid_authentication_event

    :mnesia.dirty_delete(table_name, authentication_event_id)

    Logger.debug("#{__MODULE__}: deleted authentication event `#{authentication_event_id}`")

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end
end
