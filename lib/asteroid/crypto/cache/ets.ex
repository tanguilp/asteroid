defmodule Asteroid.Crypto.Key.Cache.ETS do
  @moduledoc """
  ETS cache for keys

  This cache implementation stores the keys in an ETS owned by the `#{__MODULE__}` process that
  is created by the `start_link/1` function (and is therefore supervised).

  This cache is local to an EVM instance.

  ## Security considerations

  - The ETS table is public, and can be accessed and modified by any process. Beware if you
  have some user code running
  - The ETS table is not dumped into crash dumps
  - The ETS table is in-memory - its content is never written to disk
  """

  @table_name :asteroid_jwk_cache

  use GenServer

  alias Asteroid.Crypto

  @behaviour Crypto.Key.Cache

  @impl GenServer

  def init(_) do
    :ets.new(@table_name, [:named_table, :public])

    {:ok, []}
  end

  @impl Crypto.Key.Cache

  def start_link(_opts) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__)
  end

  @impl Crypto.Key.Cache

  def get(key_name, _opts) do
    case :ets.lookup(@table_name, key_name) do
      [{_, _, key}] ->
        {:ok, key}

      _ ->
        {:error, Crypto.Key.Cache.NotFoundError.exception([])}
    end
  end

  @impl Crypto.Key.Cache

  def get_all(_opts) do
    for [key_name, key] <- :ets.match(@table_name, {:'$0', :'$1'}) do
      {key_name, key}
    end
  end

  @impl Crypto.Key.Cache

  def put(key_name, key, _opts) do
    :ets.insert(@table_name, {key_name, key})

    :ok
  rescue
    e ->
      {:error, e}
  end

  @impl Crypto.Key.Cache

  def delete(key_name, _opts) do
    :ets.delete(@table_name, key_name)

    :ok
  end
end
