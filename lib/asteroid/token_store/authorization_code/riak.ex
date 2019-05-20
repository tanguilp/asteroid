defmodule Asteroid.TokenStore.AuthorizationCode.Riak do
  @moduledoc """
  Riak implementation of the `Asteroid.TokenStore.AuthorizationCode` behaviour

  ## Initializing a Riak bucket type

  ```console
  $ sudo riak-admin bucket-type create ephemeral_token '{"props":{"datatype":"map", "backend":"leveldb_mult"}}'
  ephemeral_token created

  $ sudo riak-admin bucket-type activate ephemeral_token
  ephemeral_token has been activated
  ```

  ## Options
  The options (`Asteroid.TokenStore.AuthorizationCode.opts()`) are:
  - `:bucket_type`: an `String.t()` for the bucket type that must be created beforehand in
  Riak. No defaults, **mandatory**
  - `bucket_name`: a `String.t()` for the bucket name. Defaults to `"authorization_code"`
  - `:purge_interval`: the `integer()` interval in seconds the purge process will be triggered,
  or `:no_purge` to disable purge. Defaults to `240` (3 minutes)

  ## Installation function

  The `install/1` function executes the following actions:
  - it installs a custom schema (`asteroid_token_store_authorization_code_riak_schema`)
  - it creates a new index (`asteroid_token_store_authorization_code_riak_index`) on the bucket
  (and not the bucket type - so as to avoid collisions)

  This is necessary to:
  1. Efficiently index expiration timestamp
  2. Disable indexing of raw authorization code data

  ## Purge process
  The purge process uses the `Singleton` library. Therefore the purge process will be unique
  per cluster (and that's probably what you want if you use Riak).

  """

  require Logger

  @behaviour Asteroid.TokenStore.AuthorizationCode

  @impl true

  def install(opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "authorization_code"

    with :ok <-
           Riak.Search.Schema.create(
             schema_name(),
             (:code.priv_dir(:asteroid) ++ '/riak/token_store_authorization_code_schema.xml')
             |> File.read!()
           ),
         :ok <- Riak.Search.Index.put(index_name(), schema_name()),
         :ok <- Riak.Search.Index.set({bucket_type, bucket_name}, index_name()) do
      Logger.info(
        "#{__MODULE__}: created authorization code store `#{bucket_name}` " <>
          "of bucket type `#{bucket_type}`"
      )

      :ok
    else
      e ->
        "#{__MODULE__}: failed to create authorization code store `#{bucket_name}` " <>
          "of bucket type `#{bucket_type}` (reason: #{inspect(e)})"

        {:error, "#{inspect(e)}"}
    end
  catch
    :exit, e ->
      bucket_type = opts[:bucket_type] || raise "Missing bucket type"
      bucket_name = opts[:bucket_name] || "authorization_code"

      "#{__MODULE__}: failed to create authorization code store `#{bucket_name}` " <>
        "of bucket type `#{bucket_type}` (reason: #{inspect(e)})"

      {:error, "#{inspect(e)}"}
  end

  @impl true

  def start_link(opts) do
    opts = Keyword.merge([purge_interval: 240], opts)

    # we launch the process anyway because we need to return a process
    # but the singleton will do nothing if the value is `:no_purge`
    Singleton.start_child(__MODULE__.Purge, opts, __MODULE__)
  end

  @impl true

  def get(authorization_code_id, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "authorization_code"

    case Riak.find(bucket_type, bucket_name, authorization_code_id) do
      res when not is_nil(res) ->
        authorization_code =
          res
          |> Riak.CRDT.Map.get(:register, "authorization_code_data_binary")
          |> Base.decode64!(padding: false)
          |> :erlang.binary_to_term()

        Logger.debug(
          "#{__MODULE__}: getting authorization code `#{authorization_code_id}`, " <>
            "value: `#{inspect(authorization_code)}`"
        )

        {:ok, authorization_code}

      nil ->
        Logger.debug(
          "#{__MODULE__}: getting authorization code `#{authorization_code_id}`, " <> "value: `nil`"
        )

        {:ok, nil}
    end
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @impl true

  def put(authorization_code, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "authorization_code"

    riak_map = Riak.CRDT.Map.new()

    authorization_code_data_binary =
      authorization_code
      |> :erlang.term_to_binary()
      |> Base.encode64(padding: false)
      |> Riak.CRDT.Register.new()

    riak_map = Riak.CRDT.Map.put(riak_map, "authorization_code_data_binary", authorization_code_data_binary)

    riak_map =
      if authorization_code.data["exp"] != nil do
        Riak.CRDT.Map.put(
          riak_map,
          "exp_int",
          Riak.CRDT.Register.new(to_string(authorization_code.data["exp"]))
        )
      else
        Logger.warn(
          "Inserting authorization code with no expiration: #{String.slice(authorization_code.id, 1..5)}..."
        )

        riak_map
      end

    Riak.update(riak_map, bucket_type, bucket_name, authorization_code.id)

    Logger.debug(
      "#{__MODULE__}: stored authorization code `#{authorization_code.id}`, " <>
        "value: `#{inspect(authorization_code)}`"
    )

    :ok
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @impl true

  def delete(authorization_code_id, opts) do
    bucket_type = opts[:bucket_type] || raise "Missing bucket type"
    bucket_name = opts[:bucket_name] || "authorization_code"

    Riak.delete(bucket_type, bucket_name, authorization_code_id)

    Logger.debug("#{__MODULE__}: deleted authorization code `#{authorization_code_id}`")

    :ok
  catch
    :exit, e ->
      {:error, "#{inspect(e)}"}
  end

  @doc """
  Searches in Riak-stored authorization codes

  This function is used internaly and made available for user convenience. Authorization codes are
  stored in the following fields:

  |               Field name                |  Indexed as   |
  |-----------------------------------------|:-------------:|
  | authorization_code_data_binary_register | *not indexed* |
  | exp_int_register                        | int           |

  Note that you are responsible for escaping values accordingly with Solr escaping.
  """

  @spec search(String.t(), Asteroid.Token.AuthorizationCode.opts()) ::
          {:ok, [Asteroid.Token.AuthorizationCode.id()]}
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

  defp schema_name(), do: "asteroid_token_store_authorization_code_riak_schema"

  @doc false

  @spec index_name() :: String.t()

  def index_name(), do: "asteroid_token_store_authorization_code_riak_index"
end
