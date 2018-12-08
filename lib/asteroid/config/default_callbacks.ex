defmodule Asteroid.Config.DefaultCallbacks do
  alias Asteroid.{Client, Subject}

  @spec issuer(Asteroid.Context.t()) :: String.t()
  def issuer(_) do
    AsteroidWeb.Endpoint.url()
  end

  @spec test_ropc_username_password_callback(Plug.Conn.t(), String.t(), String.t())
    :: {:ok, Asteroid.Subject.t()} | {:error, atom()}
  def test_ropc_username_password_callback(_conn, _username, _password) do
    {:ok,
      %Subject{id: "11dcfa0a-80b4-4e82-9218-055f3fbcd6f0",
        attrs: %{
          :name =>"John Doe",
          :given_name => "John",
          :family_name => "Smith"
        }}}
  end

  @spec refresh_token_lifetime_callback(Asteroid.Context.t()) :: non_neg_integer()
  def refresh_token_lifetime_callback(%Asteroid.Context{request: %{:flow => :ropc}}),
    do: Application.get_env(:asteroid, :refresh_token_lifetime_ropc)

  @spec access_token_lifetime_callback(Asteroid.Context.t()) :: non_neg_integer()
  def access_token_lifetime_callback(%Asteroid.Context{request: %{:flow => :ropc}}),
    do: Application.get_env(:asteroid, :access_token_lifetime_ropc)

  @spec id(any()) :: any()
  def id(param), do: param

  @spec id_first_param(any(), any()) :: any()
  def id_first_param(param, _), do: param

  @spec get_client_secret(APISex.realm(), APISex.client()) :: binary() | nil
  def get_client_secret(_realm, client_id) do
    client =
      Client.new_from_id(client_id)
      |> elem(1)
      |> Client.fetch_attribute("client_secret")

    client.attrs["client_secret"]
  end

  @spec conn_not_authenticated?(Plug.Conn.t()) :: boolean()
  def conn_not_authenticated?(conn), do: not APISex.authenticated?(conn)

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
