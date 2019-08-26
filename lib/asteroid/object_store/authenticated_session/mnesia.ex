defmodule Asteroid.ObjectStore.AuthenticatedSession.Mnesia do
  @moduledoc """
  Mnesia implementation of the `Asteroid.ObjectStore.AuthenticatedSession` behaviour

  ## Options
  The options (`Asteroid.ObjectStore.AuthenticatedSession.opts()`) are:
  - `:table_name`: an `atom()` for the table name. Defaults to `:asteroid_authenticated_session`
  - `:tab_def`: Mnesia's table definitions of the `:mnesia.create_table/2` function. Defaults to
  the options below. User-defined `:tab_def` will be merged on a key basis, i.e. defaults will
  not be erased. One can use it to add additional indexes for clients or devices, e.g.:
  `tab_def: [index: :refresh_token, :subject_id, :client_id]`
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `1800` (30 minutes)

  ## Default Mnesia table definition
  ```elixir
  [
    attributes: [:id, :subject_id, :data],
    index: [:subject_id]
  ]
  ```

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Mnesia).
  """

  require Logger

  alias Asteroid.OIDC.AuthenticatedSession

  @behaviour Asteroid.ObjectStore.AuthenticatedSession

  @impl true

  def install(opts) do
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    table_name = opts[:table_name] || :asteroid_authenticated_session

    tab_def =
      [
        attributes: [:id, :subject_id, :data],
        index: [:subject_id]
      ]
      |> Keyword.merge(opts[:tab_def] || [])

    case :mnesia.create_table(table_name, tab_def) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: created authenticated session store #{table_name}")

        :ok

      {:aborted, {:already_exists, _}} ->
        Logger.info("#{__MODULE__}: authenticated session store #{table_name} already exists")
        :ok

      {:aborted, reason} ->
        Logger.error(
          "#{__MODULE__}: failed to create authenticated session store #{table_name} " <>
            "(reason: #{inspect(reason)})"
        )

        {:error, reason}
    end
  end

  @impl true

  def start_link(opts) do
    case :mnesia.start() do
      :ok ->
        opts = Keyword.merge([purge_interval: 1800], opts)

        # we launch the process anyway because we need to return a process
        # but the singleton will do nothing if the value is `:no_purge`
        Singleton.start_child(__MODULE__.Purge, opts, __MODULE__)

      {:error, _} = error ->
        error
    end
  end

  @impl true

  def get(authenticated_session_id, opts) do
    table_name = opts[:table_name] || :asteroid_authenticated_session

    case :mnesia.dirty_read(table_name, authenticated_session_id) do
      [] ->
        Logger.debug(
          "#{__MODULE__}: getting authenticated session `#{authenticated_session_id}`, " <>
            "value: `nil`"
        )

        {:ok, nil}

      [{^table_name, ^authenticated_session_id, subject_id, data}] ->
        authenticated_session = %AuthenticatedSession{
          id: authenticated_session_id,
          subject_id: subject_id,
          data: data
        }

        Logger.debug(
          "#{__MODULE__}: getting authenticated session `#{authenticated_session_id}`, " <>
            "value: `#{inspect(authenticated_session)}`"
        )

        {:ok, authenticated_session}

      _ ->
        {:error, "Multiple results from Mnesia"}
    end
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_subject_id(subject_id, opts) do
    table_name = opts[:table_name] || :asteroid_authenticated_session

    {:ok,
     for {_table_name, authenticated_session_id, _subject_id, _data} <-
           :mnesia.dirty_match_object({table_name, :_, subject_id, :_}) do
       authenticated_session_id
     end}
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def put(authenticated_session, opts) do
    table_name = opts[:table_name] || :asteroid_authenticated_session

    record = {
      table_name,
      authenticated_session.id,
      authenticated_session.subject_id,
      authenticated_session.data
    }

    :mnesia.dirty_write(table_name, record)

    Logger.debug(
      "#{__MODULE__}: stored authenticated session `#{authenticated_session.id}`, " <>
        "value: `#{inspect(authenticated_session)}`"
    )

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def delete(authenticated_session_id, opts) do
    table_name = opts[:table_name] || :asteroid_authenticated_session

    :mnesia.dirty_delete(table_name, authenticated_session_id)

    Logger.debug("#{__MODULE__}: deleted authenticated session `#{authenticated_session_id}`")

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end
end
