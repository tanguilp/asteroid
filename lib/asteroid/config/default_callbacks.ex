defmodule Asteroid.Config.DefaultCallbacks do
  import Asteroid.Utils
  alias Asteroid.{Client, Subject, Context}

  @spec issuer(Asteroid.Context.t()) :: String.t()
  def issuer(_) do
    AsteroidWeb.Endpoint.url()
  end

  @spec test_ropc_username_password_callback(Plug.Conn.t(), String.t(), String.t())
    :: {:ok, Asteroid.Subject.t()} | {:error, atom()}
  def test_ropc_username_password_callback(_conn, username, password) do
    case Subject.new_from_id(username) do
      {:ok, sub} ->
        sub = Subject.fetch_attribute(sub, "password")

        if sub.attrs["password"] == password do
          {:ok, sub}
        else
          {:error, :invalid_password}
        end

      {:error, reason} ->
        {:error, reason}
    end
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

  @spec get_client_secret(APIac.realm(), APIac.client()) :: binary() | nil
  def get_client_secret(_realm, client_id) do
    client =
      Client.new_from_id(client_id)
      |> elem(1)
      |> Client.fetch_attribute("client_secret")

    client.attrs["client_secret"]
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

  @doc """
  Returns `:ok` is the client is authorized to introspect tokens on the /introspect
  endpoint, `{:error, reason}` otherwise

  An authorized client is a client that has a map `permissions` attribute containing
  a `"introspect"` key that has the `true` value
  """
  @spec introspect_endpoint_authorized?(Client.t()) :: :ok | {:error, :unauthorized}
  def introspect_endpoint_authorized?(client) do
    client = Client.fetch_attribute(client, "permissions")

    if client.attrs["permissions"]["introspect"] == true do
      :ok
    else
      {:error, :unauthorized}
    end
  end

  @doc """
  Returns `true` if a refresh token shall be issued, `false` otherwise

  Conditions for releasing a refresh token are:
  - the flow allows it (e.g ROPC does but implicit does not)
  - the flow option is configured to `true`:
    - `ropc_issue_refresh_token`
    - `client_credentials_issue_refresh_token`
  - the client's `"grant_types"` attribute contains the `"refresh_token"` value
  """
  @spec issue_refresh_token_callback(Context.t()) :: boolean
  def issue_refresh_token_callback(%Context{request: %{flow: flow}, client: client}) do
    if astrenv(String.to_atom(Atom.to_string(flow) <> "_" <> "issue_refresh_token"), false) do
      client = Client.fetch_attribute(client, "grant_types")

      if "refresh_token" in client.attrs["grant_types"] do
        true
      else
        false
      end
    else
      false
    end
    Application.get_env(:asteroid, :ropc_issue_refresh_token, false)
  end
end
