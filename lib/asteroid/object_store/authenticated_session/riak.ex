defmodule Asteroid.ObjectStore.AuthenticatedSession.Riak do
  @moduledoc """
  Riak implementation of the `Asteroid.ObjectStore.AuthenticatedSession` behaviour

  ## Initializing a Riak bucket type

  ```console
  $ sudo riak-admin bucket-type create ephemeral_token '{"props":{"datatype":"map", "backend":"leveldb_mult"}}'
  ephemeral_token created

  $ sudo riak-admin bucket-type activate ephemeral_token
  ephemeral_token has been activated
  ```

  ## Options
  The options (`Asteroid.ObjectStore.AuthenticatedSession.opts()`) are:
  - `:bucket_type`: an `String.t()` for the bucket type that must be created beforehand in
  Riak. No defaults, **mandatory**
  - `bucket_name`: a `String.t()` for the bucket name. Defaults to `"authenticated_session"`
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `1800` (30 minutes)
  - `:rows`: the maximum number of results that a search will return. Defaults to `1_000_000`.
  Search is used by the purge process.

  ## Installation function

  The `install/1` function executes the following actions:
  - it installs a custom schema (`asteroid_object_store_authenticated_session_riak_schema`)
  - it creates a new index (`asteroid_object_store_authenticated_session_riak_index`) on the bucket
  (and not the bucket type - so as to avoid collisions)

  This is necessary to:
  1. Efficiently index expiration timestamp
  2. Disable indexing of raw authenticated session data

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Riak).
  """

  require Logger

  @behaviour Asteroid.ObjectStore.AuthenticatedSession

  @impl true

  def install(opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "authenticated_session"

    with :ok <-
           Riak.Search.Schema.create(
             schema_name(),
             (:code.priv_dir(:asteroid) ++ '/riak/object_store_authenticated_session_schema.xml')
             |> File.read!()
           ),
         :ok <- Riak.Search.Index.put(index_name(), schema_name()),
         :ok <- Riak.Search.Index.set({bucket_type, bucket_name}, index_name()) do
      Logger.info(
        "#{__MODULE__}: created authenticated session store `#{bucket_name}` " <>
          "of bucket type `#{bucket_type}`"
      )

      :ok
    else
      e ->
        "#{__MODULE__}: failed to create authenticated session store `#{bucket_name}` " <>
          "of bucket type `#{bucket_type}` (reason: #{inspect(e)})"

        {:error, "#{inspect(e)}"}
    end
  catch
    :exit, e ->
      bucket_type = opts[:bucket_type] || raise "Missing bucket type"
      bucket_name = opts[:bucket_name] || "authenticated_session"

      "#{__MODULE__}: failed to create authenticated session store `#{bucket_name}` " <>
        "of bucket type `#{bucket_type}` (reason: #{inspect(e)})"

      {:error, "#{inspect(e)}"}
  end

  @impl true

  def start_link(opts) do
    opts = Keyword.merge([purge_interval: 1800], opts)

    # we launch the process anyway because we need to return a process
    # but the singleton will do nothing if the value is `:no_purge`
    Singleton.start_child(__MODULE__.Purge, opts, __MODULE__)
  end

  @impl true

  def get(authenticated_session_id, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "authenticated_session"

    case Riak.find(bucket_type, bucket_name, authenticated_session_id) do
      res when not is_nil(res) ->
        authenticated_session =
          res
          |> Riak.CRDT.Map.get(:register, "authenticated_session_data_binary")
          |> Base.decode64!(padding: false)
          |> :erlang.binary_to_term()

        Logger.debug(
          "#{__MODULE__}: getting authenticated session `#{authenticated_session_id}`, " <>
            "value: `#{inspect(authenticated_session)}`"
        )

        {:ok, authenticated_session}

      nil ->
        Logger.debug(
          "#{__MODULE__}: getting authenticated session `#{authenticated_session_id}`, " <> "value: `nil`"
        )

        {:ok, nil}
    end
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @impl true

  def get_from_subject_id(subject_id, opts) do
    search("subject_id_register:\"#{String.replace(subject_id, "\"", "\\\"")}\"", opts)
  end

  @impl true

  def put(authenticated_session, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "authenticated_session"

    riak_map = Riak.CRDT.Map.new()

    authenticated_session_data_binary =
      authenticated_session
      |> :erlang.term_to_binary()
      |> Base.encode64(padding: false)
      |> Riak.CRDT.Register.new()

    riak_map =
      Riak.CRDT.Map.put(riak_map,
                        "authenticated_session_data_binary",
                        authenticated_session_data_binary)

    riak_map =
      if authenticated_session.subject_id != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "subject_id",
          Riak.CRDT.Register.new(authenticated_session.subject_id)
        )
      else
        riak_map
      end

    riak_map =
      if authenticated_session.data["exp"] != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "exp_int",
          Riak.CRDT.Register.new(to_string(authenticated_session.data["exp"]))
        )
      else
        Logger.warn(
          "Inserting authenticated session with no expiration: #{String.slice(authenticated_session.id, 1..5)}..."
        )

        riak_map
      end

    Riak.update(riak_map, bucket_type, bucket_name, authenticated_session.id)

    Logger.debug(
      "#{__MODULE__}: stored authenticated session `#{authenticated_session.id}`, " <>
        "value: `#{inspect(authenticated_session)}`"
    )

    :ok
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @impl true

  def delete(authenticated_session_id, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "authenticated_session"

    Riak.delete(bucket_type, bucket_name, authenticated_session_id)

    Logger.debug("#{__MODULE__}: deleted authenticated session `#{authenticated_session_id}`")

    :ok
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @doc """
  Searches in Riak-stored authenticated sessions

  This function is used internaly and made available for user convenience. authenticated sessions are
  stored in the following fields:

  |               Field name                   |  Indexed as   |
  |--------------------------------------------|:-------------:|
  | authenticated_session_data_binary_register | *not indexed* |
  | subject_id                                 | string        |
  | exp_int_register                           | int           |

  Note that you are responsible for escaping values accordingly with Solr escaping.
  """

  @spec search(String.t(), Asteroid.ObjectStore.AuthenticatedSession.opts()) ::
          {:ok, [Asteroid.OIDC.AuthenticatedSession.id()]}
          | {:error, any()}

  def search(search_query, opts) do
    case Riak.Search.query(index_name(), search_query, rows: opts[:rows] || 1_000_000) do
      {:ok, {:search_results, result_list, _, _}} ->
        {:ok,
         for {_index_name, attribute_list} <- result_list do
           :proplists.get_value("_yz_rk", attribute_list)
         end}

      {:error, _} = error ->
        error
    end
  end

  @spec schema_name() :: String.t()

  defp schema_name(), do: "asteroid_object_store_authenticated_session_riak_schema"

  @doc false

  @spec index_name() :: String.t()

  def index_name(), do: "asteroid_object_store_authenticated_session_riak_index"
end
