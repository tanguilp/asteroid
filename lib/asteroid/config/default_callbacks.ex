defmodule Asteroid.Config.DefaultCallbacks do
  alias Asteroid.Client

  @spec issuer(Asteroid.Context.t()) :: String.t()
  def issuer(_) do
    AsteroidWeb.Endpoint.url()
  end

  @spec refresh_token_lifetime_callback(Asteroid.Context.t()) :: non_neg_integer()
  def refresh_token_lifetime_callback(%{:flow => :ropc}),
    do: Application.get_env(:asteroid, :refresh_token_lifetime_ropc)

  @spec access_token_lifetime_callback(Asteroid.Context.t()) :: non_neg_integer()
  def access_token_lifetime_callback(%{:flow => :ropc}),
    do: Application.get_env(:asteroid, :access_token_lifetime_ropc)

  @spec id(any()) :: any()
  def id(param), do: param

  @doc """
  Returns the first parameter unchanged
  """

  @spec id_first_param(any(), any()) :: any()

  def id_first_param(param, _), do: param

  # FIXME: move to Asteroid.Client ?

  @spec get_client_secret(APIac.realm(), APIac.client()) :: binary() | nil

  def get_client_secret(_realm, client_id) do
    case Client.load(client_id, attributes: ["client_secret"]) do
      {:ok, client} ->
        client.attrs["client_secret"]

      {:error, _} ->
        nil
    end
  end

  @spec conn_not_authenticated?(Plug.Conn.t()) :: boolean()
  def conn_not_authenticated?(conn), do: not APIac.authenticated?(conn)

  def put_chuck_norris_quote_on_failure(%{"active" => false} = resp) do
    chuck_norris_quote = 
      HTTPoison.get!("http://api.icndb.com/jokes/random?limitTo=[nerdy]").body
      |> Jason.decode!()
      |> get_in(["value", "joke"])

    Map.put(resp, "chuck_norris_quote", chuck_norris_quote)
  end

  def put_chuck_norris_quote_on_failure(resp), do: resp

  @spec always_nil(any(), any()) :: nil
  def always_nil(_, _ \\ nil), do: nil
end
