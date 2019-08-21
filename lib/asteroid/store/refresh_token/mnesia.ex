defmodule Asteroid.Store.RefreshToken.Mnesia do
  @moduledoc """
  Mnesia implementation of the `Asteroid.Store.RefreshToken` behaviour

  ## Options
  The options (`Asteroid.Store.RefreshToken.opts()`) are:
  - `:table_name`: an `atom()` for the table name. Defaults to `:asteroid_refresh_token`
  - `:tab_def`: Mnesia's table definitions of the `:mnesia.create_table/2` function. Defaults to
  the options below. User-defined `:tab_def` will be merged on a key basis, i.e. defaults will
  not be erased. One can use it to add additional indexes for clients or devices, e.g.:
  `tab_def: [index: :subject_id, :client_id]`
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `1200` (20 minutes)

  ## Default Mnesia table definition
  ```elixir
  [
    attributes: [:id, :subject_id, :client_id, :device_id, :authenticated_session :data],
    disc_copies: [node()]
  ]
  ```

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Mnesia).
  """

  require Logger

  alias Asteroid.Token.RefreshToken

  @behaviour Asteroid.Store.RefreshToken

  @impl true

  def install(opts) do
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    table_name = opts[:table_name] || :asteroid_refresh_token

    tab_def =
      [
        attributes: [:id, :subject_id, :client_id, :device_id, :authenticated_session, :data],
        disc_copies: [node()]
      ]
      |> Keyword.merge(opts[:tab_def] || [])

    case :mnesia.create_table(table_name, tab_def) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: created refresh token store #{table_name}")

        :ok

      {:aborted, {:already_exists, _}} ->
        Logger.info("#{__MODULE__}: refresh token store #{table_name} already exists")
        :ok

      {:aborted, reason} ->
        Logger.error(
          "#{__MODULE__}: failed to create refresh token store #{table_name} " <>
            "(reason: #{inspect(reason)})"
        )

        {:error, reason}
    end
  end

  @impl true

  def start_link(opts) do
    case :mnesia.start() do
      :ok ->
        opts = Keyword.merge([purge_interval: 1200], opts)

        # we launch the process anyway because we need to return a process
        # but the singleton will do nothing if the value is `:no_purge`
        Singleton.start_child(__MODULE__.Purge, opts, __MODULE__)

      {:error, _} = error ->
        error
    end
  end

  @impl true

  def get(refresh_token_id, opts) do
    table_name = opts[:table_name] || :asteroid_refresh_token

    case :mnesia.dirty_read(table_name, refresh_token_id) do
      [] ->
        Logger.debug(
          "#{__MODULE__}: getting refresh token `#{refresh_token_id}`, " <> "value: `nil`"
        )

        {:ok, nil}

      [{^table_name, ^refresh_token_id, _subject_id, _client_id, _device_id, _as, data}] ->
        refresh_token =
          RefreshToken.new(
            id: refresh_token_id,
            data: data
          )

        Logger.debug(
          "#{__MODULE__}: getting refresh token `#{refresh_token_id}`, " <>
            "value: `#{inspect(refresh_token)}`"
        )

        {:ok, refresh_token}

      _ ->
        {:error, "Multiple results from Mnesia"}
    end
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_subject_id(subject_id, opts) do
    table_name = opts[:table_name] || :asteroid_refresh_token

    {:ok,
      for {_table_name, refresh_token_id, _subject_id, _client_id, _device_id, _as, _data} <-
        :mnesia.dirty_match_object({table_name, :_, subject_id, :_, :_, :_, :_}) do
        refresh_token_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_client_id(client_id, opts) do
    table_name = opts[:table_name] || :asteroid_refresh_token

    {:ok,
      for {_table_name, refresh_token_id, _subject_id, _client_id, _device_id, _as, _data} <-
        :mnesia.dirty_match_object({table_name, :_, :_, client_id, :_, :_, :_}) do
        refresh_token_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_device_id(device_id, opts) do
    table_name = opts[:table_name] || :asteroid_refresh_token

    {:ok,
      for {_table_name, refresh_token_id, _subject_id, _client_id, _device_id, _as, _data} <-
        :mnesia.dirty_match_object({table_name, :_, :_, :_, device_id, :_, :_}) do
        refresh_token_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_authenticated_session_id(as_id, opts) do
    table_name = opts[:table_name] || :asteroid_refresh_token

    {:ok,
      for {_table_name, refresh_token_id, _subject_id, _client_id, _device_id, _as, _data} <-
        :mnesia.dirty_match_object({table_name, :_, :_, :_, :_, as_id, :_}) do
        refresh_token_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def put(refresh_token, opts) do
    table_name = opts[:table_name] || :asteroid_refresh_token

    record = {
      table_name,
      refresh_token.id,
      refresh_token.data["sub"],
      refresh_token.data["client_id"],
      refresh_token.data["device_id"],
      refresh_token.data["authenticated_session_id"],
      refresh_token.data
    }

    :mnesia.dirty_write(table_name, record)

    Logger.debug(
      "#{__MODULE__}: stored refresh token `#{refresh_token.id}`, " <>
        "value: `#{inspect(refresh_token)}`"
    )

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def delete(refresh_token_id, opts, {access_token_store, access_token_store_opts}) do
    table_name = opts[:table_name] || :asteroid_refresh_token

    :mnesia.dirty_delete(table_name, refresh_token_id)

    Logger.debug("#{__MODULE__}: deleted refresh token `#{refresh_token_id}`")

    access_token_store.delete_from_refresh_token_id(refresh_token_id, access_token_store_opts)
  catch
    :exit, reason ->
      {:error, reason}
  end
end
