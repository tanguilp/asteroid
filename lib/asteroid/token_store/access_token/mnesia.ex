defmodule Asteroid.TokenStore.AccessToken.Mnesia do
  @moduledoc """
  Mnesia implementation of the `Asteroid.TokenStore.AccessToken` behaviour

  ## Options
  The options (`Asteroid.TokenStore.AccessToken.opts()`) are:
  - `:table_name`: an `atom()` for the table name. Defaults to `:asteroid_access_token`
  - `:tab_def`: Mnesia's table definitions of the `:mnesia.create_table/2` function. Defaults to
  the options below. User-defined `:tab_def` will be merged on a key basis, i.e. defaults will
  not be erased. One can use it to add additional indexes for clients or devices, e.g.:
  `tab_def: [index: :refresh_token, :subject_id, :client_id]`
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

  alias Asteroid.Token.AccessToken

  @behaviour Asteroid.TokenStore.AccessToken

  @impl true

  def install(opts) do
    :mnesia.stop()

    :mnesia.create_schema([node()])

    :mnesia.start()

    table_name = opts[:table_name] || :asteroid_access_token

    tab_def =
      [
        attributes: [:id, :refresh_token_id, :subject_id, :client_id, :device_id, :data],
        index: [:refresh_token_id]
      ]
      |> Keyword.merge(opts[:tab_def] || [])

    case :mnesia.create_table(table_name, tab_def) do
      {:atomic, :ok} ->
        Logger.info("#{__MODULE__}: created access token store #{table_name}")

        :ok

      {:aborted, {:already_exists, _}} ->
        Logger.info("#{__MODULE__}: access token store #{table_name} already exists")
        :ok

      {:aborted, reason} ->
        Logger.error(
          "#{__MODULE__}: failed to create access token store #{table_name} " <>
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

  def get(access_token_id, opts) do
    table_name = opts[:table_name] || :asteroid_access_token

    case :mnesia.dirty_read(table_name, access_token_id) do
      [] ->
        Logger.debug(
          "#{__MODULE__}: getting access token `#{access_token_id}`, " <> "value: `nil`"
        )

        {:ok, nil}

      [
        {^table_name, ^access_token_id, refresh_token_id, _subject_id, _client_id, _device_id,
         data}
      ] ->
        access_token =
          AccessToken.new(
            id: access_token_id,
            refresh_token_id: refresh_token_id,
            data: data
          )

        Logger.debug(
          "#{__MODULE__}: getting access token `#{access_token_id}`, " <>
            "value: `#{inspect(access_token)}`"
        )

        {:ok, access_token}

      _ ->
        {:error, "Multiple results from Mnesia"}
    end
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_refresh_token_id(refresh_token_id, opts) do
    table_name = opts[:table_name] || :asteroid_access_token

    {:ok,

      for {_table_name, access_token_id, _refresh_token_id, _subject_id, _client_id, _device_id,
           _data} <- :mnesia.dirty_match_object({table_name, :_, refresh_token_id, :_, :_, :_, :_}) do
        access_token_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_subject_id(subject_id, opts) do
    table_name = opts[:table_name] || :asteroid_access_token

    {:ok,
      for {_table_name, access_token_id, _refresh_token_id, _subject_id, _client_id, _device_id,
           _data} <- :mnesia.dirty_match_object({table_name, :_, :_, subject_id, :_, :_, :_}) do
        access_token_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_client_id(client_id, opts) do
    table_name = opts[:table_name] || :asteroid_access_token

    {:ok,
      for {_table_name, access_token_id, _refresh_token_id, _subject_id, _client_id, _device_id,
           _data} <- :mnesia.dirty_match_object({table_name, :_, :_, :_, client_id, :_, :_}) do
        access_token_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def get_from_device_id(device_id, opts) do
    table_name = opts[:table_name] || :asteroid_access_token

    {:ok,
      for {_table_name, access_token_id, _refresh_token_id, _subject_id, _client_id, _device_id,
           _data} <- :mnesia.dirty_match_object({table_name, :_, :_, :_, :_, device_id, :_}) do
        access_token_id
      end
    }
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def put(access_token, opts) do
    table_name = opts[:table_name] || :asteroid_access_token

    record = {
      table_name,
      access_token.id,
      access_token.refresh_token_id,
      access_token.data["sub"],
      access_token.data["client_id"],
      access_token.data["device_id"],
      access_token.data
    }

    :mnesia.dirty_write(table_name, record)

    Logger.debug(
      "#{__MODULE__}: stored access token `#{access_token.id}`, " <>
        "value: `#{inspect(access_token)}`"
    )

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def delete(access_token_id, opts) do
    table_name = opts[:table_name] || :asteroid_access_token

    :mnesia.dirty_delete(table_name, access_token_id)

    Logger.debug("#{__MODULE__}: deleted access token `#{access_token_id}`")

    :ok
  catch
    :exit, reason ->
      {:error, reason}
  end

  @impl true

  def delete_from_refresh_token_id(refresh_token_id, opts) do
    res =
      for access_token_id <- get_from_refresh_token_id(refresh_token_id, opts) do
        delete(access_token_id, opts)
      end

    if Enum.any?(
         res,
         fn
           :ok ->
             true

           {:error, _} ->
             false
         end
       ) do
      :ok
    else
      {:error, "Not all tokens could be deleted in #{__MODULE__}"}
    end
  end
end
