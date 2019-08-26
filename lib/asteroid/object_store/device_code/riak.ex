defmodule Asteroid.ObjectStore.DeviceCode.Riak do
  @moduledoc """
  Riak implementation of the `Asteroid.ObjectStore.DeviceCode` behaviour

  ## Initializing a Riak bucket type

  ```console
  $ sudo riak-admin bucket-type create ephemeral_token '{"props":{"datatype":"map", "backend":"leveldb_mult"}}'
  ephemeral_token created

  $ sudo riak-admin bucket-type activate ephemeral_token
  ephemeral_token has been activated
  ```

  ## Options
  The options (`Asteroid.ObjectStore.DeviceCode.opts()`) are:
  - `:bucket_type`: an `String.t()` for the bucket type that must be created beforehand in
  Riak. No defaults, **mandatory**
  - `bucket_name`: a `String.t()` for the bucket name. Defaults to `"device_code"`
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `300` (5 minutes)
  - `:rows`: the maximum number of results that a search will return. Defaults to `1_000_000`.
  Search is used by the purge process.

  ## Installation function

  The `install/1` function executes the following actions:
  - it installs a custom schema (`asteroid_object_store_device_code_riak_schema`)
  - it creates a new index (`asteroid_object_store_device_code_riak_index`) on the bucket
  (and not the bucket type - so as to avoid collisions)

  This is necessary to:
  1. Efficiently index expiration timestamp
  2. Disable indexing of raw device code data

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Riak).
  """

  require Logger

  @behaviour Asteroid.ObjectStore.DeviceCode

  @impl true

  def install(opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "device_code"

    with :ok <-
           Riak.Search.Schema.create(
             schema_name(),
             (:code.priv_dir(:asteroid) ++ '/riak/object_store_device_code_schema.xml')
             |> File.read!()
           ),
         :ok <- Riak.Search.Index.put(index_name(), schema_name()),
         :ok <- Riak.Search.Index.set({bucket_type, bucket_name}, index_name()) do
      Logger.info(
        "#{__MODULE__}: created device code store `#{bucket_name}` " <>
          "of bucket type `#{bucket_type}`"
      )

      :ok
    else
      e ->
        "#{__MODULE__}: failed to create device code store `#{bucket_name}` " <>
          "of bucket type `#{bucket_type}` (reason: #{inspect(e)})"

        {:error, "#{inspect(e)}"}
    end
  catch
    :exit, e ->
      bucket_type = opts[:bucket_type] || raise "Missing bucket type"
      bucket_name = opts[:bucket_name] || "device_code"

      "#{__MODULE__}: failed to create device code store `#{bucket_name}` " <>
        "of bucket type `#{bucket_type}` (reason: #{inspect(e)})"

      {:error, "#{inspect(e)}"}
  end

  @impl true

  def start_link(opts) do
    opts = Keyword.merge([purge_interval: 300], opts)

    # we launch the process anyway because we need to return a process
    # but the singleton will do nothing if the value is `:no_purge`
    Singleton.start_child(__MODULE__.Purge, opts, __MODULE__)
  end

  @impl true

  def get(device_code_id, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "device_code"

    case Riak.find(bucket_type, bucket_name, device_code_id) do
      res when not is_nil(res) ->
        device_code =
          res
          |> Riak.CRDT.Map.get(:register, "device_code_data_binary")
          |> Base.decode64!(padding: false)
          |> :erlang.binary_to_term()

        Logger.debug(
          "#{__MODULE__}: getting device code `#{device_code_id}`, " <>
            "value: `#{inspect(device_code)}`"
        )

        {:ok, device_code}

      nil ->
        Logger.debug("#{__MODULE__}: getting device code `#{device_code_id}`, " <> "value: `nil`")

        {:ok, nil}
    end
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @impl true

  def get_from_user_code(user_code, opts) do
    query = "user_code:\"#{String.replace(user_code, "\"", "\\\"")}\""

    case search(query, opts) do
      {:ok, [device_code_id]} ->
        get(device_code_id, opts)

      {:ok, [_ | _]} ->
        {:error, "Duplicate user code in the device authorization flow"}

      {:error, _} = error ->
        error
    end
  end

  @impl true

  def put(device_code, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "device_code"

    riak_map = Riak.CRDT.Map.new()

    device_code_data_binary =
      device_code
      |> :erlang.term_to_binary()
      |> Base.encode64(padding: false)
      |> Riak.CRDT.Register.new()

    riak_map = Riak.CRDT.Map.put(riak_map, "device_code_data_binary", device_code_data_binary)

    riak_map =
      Riak.CRDT.Map.put(
        riak_map,
        "user_code",
        Riak.CRDT.Register.new(device_code.user_code)
      )

    riak_map =
      if device_code.data["exp"] != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "exp_int",
          Riak.CRDT.Register.new(to_string(device_code.data["exp"]))
        )
      else
        Logger.warn(
          "Inserting device code with no expiration: #{String.slice(device_code.id, 1..5)}..."
        )

        riak_map
      end

    Riak.update(riak_map, bucket_type, bucket_name, device_code.id)

    Logger.debug(
      "#{__MODULE__}: stored device code `#{device_code.id}`, " <>
        "value: `#{inspect(device_code)}`"
    )

    :ok
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @impl true

  def delete(device_code_id, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "device_code"

    Riak.delete(bucket_type, bucket_name, device_code_id)

    Logger.debug("#{__MODULE__}: deleted device code `#{device_code_id}`")

    :ok
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @doc """
  Searches in Riak-stored device code

  This function is used internaly and made available for user convenience. Device codes are
  stored in the following fields:

  |               Field name          |  Indexed as   |
  |-----------------------------------|:-------------:|
  | device_code_data_binary_register  | *not indexed* |
  | user_code_register                | string        |
  | exp_int_register                  | int           |

  Note that you are responsible for escaping values accordingly with Solr escaping.
  """

  @spec search(String.t(), Asteroid.ObjectStore.DeviceCode.opts()) ::
          {:ok, [Asteroid.OAuth2.DeviceAuthorization.device_code()]}
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

  defp schema_name(), do: "asteroid_object_store_device_code_riak_schema"

  @doc false

  @spec index_name() :: String.t()

  def index_name(), do: "asteroid_object_store_device_code_riak_index"
end
