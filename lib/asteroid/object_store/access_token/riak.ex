defmodule Asteroid.ObjectStore.AccessToken.Riak do
  @moduledoc """
  Riak implementation of the `Asteroid.ObjectStore.AccessToken` behaviour

  ## Initializing a Riak bucket type

  ```console
  $ sudo riak-admin bucket-type create ephemeral_token '{"props":{"datatype":"map", "backend":"leveldb_mult"}}'
  ephemeral_token created

  $ sudo riak-admin bucket-type activate ephemeral_token
  ephemeral_token has been activated
  ```

  ## Options
  The options (`Asteroid.ObjectStore.AccessToken.opts()`) are:
  - `:bucket_type`: an `String.t()` for the bucket type that must be created beforehand in
  Riak. No defaults, **mandatory**
  - `bucket_name`: a `String.t()` for the bucket name. Defaults to `"access_token"`
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `300` (5 minutes)

  ## Installation function

  The `install/1` function executes the following actions:
  - it installs a custom schema (`asteroid_object_store_access_token_riak_schema`)
  - it creates a new index (`asteroid_object_store_access_token_riak_index`) on the bucket
  (and not the bucket type - so as to avoid collisions)

  This is necessary to:
  1. Efficiently index expiration timestamp
  2. Disable indexing of raw access token data

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Riak).
  """

  require Logger

  @behaviour Asteroid.ObjectStore.AccessToken

  @impl true

  def install(opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "access_token"

    with :ok <-
           Riak.Search.Schema.create(
             schema_name(),
             (:code.priv_dir(:asteroid) ++ '/riak/object_store_access_token_schema.xml')
             |> File.read!()
           ),
         :ok <- Riak.Search.Index.put(index_name(), schema_name()),
         :ok <- Riak.Search.Index.set({bucket_type, bucket_name}, index_name()) do
      Logger.info(
        "#{__MODULE__}: created access token store `#{bucket_name}` " <>
          "of bucket type `#{bucket_type}`"
      )

      :ok
    else
      e ->
        "#{__MODULE__}: failed to create access token store `#{bucket_name}` " <>
          "of bucket type `#{bucket_type}` (reason: #{inspect(e)})"

        {:error, "#{inspect(e)}"}
    end
  catch
    :exit, e ->
      bucket_type = opts[:bucket_type] || raise "Missing bucket type"
      bucket_name = opts[:bucket_name] || "access_token"

      "#{__MODULE__}: failed to create access token store `#{bucket_name}` " <>
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

  def get(access_token_id, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "access_token"

    case Riak.find(bucket_type, bucket_name, access_token_id) do
      res when not is_nil(res) ->
        access_token =
          res
          |> Riak.CRDT.Map.get(:register, "access_token_data_binary")
          |> Base.decode64!(padding: false)
          |> :erlang.binary_to_term()

        Logger.debug(
          "#{__MODULE__}: getting access token `#{access_token_id}`, " <>
            "value: `#{inspect(access_token)}`"
        )

        {:ok, access_token}

      nil ->
        Logger.debug(
          "#{__MODULE__}: getting access token `#{access_token_id}`, " <> "value: `nil`"
        )

        {:ok, nil}
    end
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @impl true

  def get_from_refresh_token_id(refresh_token_id, opts) do
    search(
      "refresh_token_id_register:\"#{String.replace(refresh_token_id, "\"", "\\\"")}\"",
      opts
    )
  end

  @impl true

  def get_from_subject_id(sub, opts) do
    search("sub_register:\"#{String.replace(sub, "\"", "\\\"")}\"", opts)
  end

  @impl true

  def get_from_client_id(client_id, opts) do
    search("client_id_register:\"#{String.replace(client_id, "\"", "\\\"")}\"", opts)
  end

  @impl true

  def get_from_device_id(device_id, opts) do
    search("device_id_register:\"#{String.replace(device_id, "\"", "\\\"")}\"", opts)
  end

  @impl true

  def put(access_token, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "access_token"

    riak_map = Riak.CRDT.Map.new()

    access_token_data_binary =
      access_token
      |> :erlang.term_to_binary()
      |> Base.encode64(padding: false)
      |> Riak.CRDT.Register.new()

    riak_map = Riak.CRDT.Map.put(riak_map, "access_token_data_binary", access_token_data_binary)

    riak_map =
      if access_token.refresh_token_id != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "refresh_token_id",
          Riak.CRDT.Register.new(access_token.refresh_token_id)
        )
      else
        riak_map
      end

    riak_map =
      if access_token.data["exp"] != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "exp_int",
          Riak.CRDT.Register.new(to_string(access_token.data["exp"]))
        )
      else
        Logger.warn(
          "Inserting access token with no expiration: #{String.slice(access_token.id, 1..5)}..."
        )

        riak_map
      end

    riak_map =
      if access_token.data["sub"] != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "sub",
          Riak.CRDT.Register.new(to_string(access_token.data["sub"]))
        )
      else
        riak_map
      end

    riak_map =
      if access_token.data["client_id"] != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "client_id",
          Riak.CRDT.Register.new(to_string(access_token.data["client_id"]))
        )
      else
        riak_map
      end

    riak_map =
      if access_token.data["device_id"] != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "device_id",
          Riak.CRDT.Register.new(to_string(access_token.data["device_id"]))
        )
      else
        riak_map
      end

    Riak.update(riak_map, bucket_type, bucket_name, access_token.id)

    Logger.debug(
      "#{__MODULE__}: stored access token `#{access_token.id}`, " <>
        "value: `#{inspect(access_token)}`"
    )

    :ok
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @impl true

  def delete(access_token_id, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "access_token"

    Riak.delete(bucket_type, bucket_name, access_token_id)

    Logger.debug("#{__MODULE__}: deleted access token `#{access_token_id}`")

    :ok
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @doc """
  Searches in Riak-stored access tokens

  This function is used internaly and made available for user convenience. Access tokens are
  stored in the following fields:

  |               Field name          |  Indexed as   |
  |-----------------------------------|:-------------:|
  | access_token_data_binary_register | *not indexed* |
  | refresh_token_id_register         | string        |
  | exp_int_register                  | int           |
  | sub_register                      | string        |
  | client_id_register                | string        |
  | device_id_register                | string        |

  Note that you are responsible for escaping values accordingly with Solr escaping.

  ## Example

  ```elixir
  iex(13)> Asteroid.ObjectStore.AccessToken.Riak.search("sub_register:j* AND exp_int_register:[0 TO #{:os.system_time(:seconds)}]", opts)
  {:ok, ["7WRQL4EAKW27C5BEFF3JDGXBTA", "WCJBCL7SC2THS7TSRXB2KZH7OQ"]}
  ```
  """

  @spec search(String.t(), Asteroid.ObjectStore.AccessToken.opts()) ::
          {:ok, [Asteroid.Token.AccessToken.id()]}
          | {:error, any()}

  def search(search_query, _opts) do
    case Riak.Search.query(index_name(), search_query) do
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

  defp schema_name(), do: "asteroid_object_store_access_token_riak_schema"

  @doc false

  @spec index_name() :: String.t()

  def index_name(), do: "asteroid_object_store_access_token_riak_index"
end
