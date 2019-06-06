defmodule Asteroid.OAuth2.Register do
  @moduledoc """
  Utils fnuction related to client registration
  """

  import Asteroid.Utils

  alias Asteroid.Client
  alias OAuth2Utils.Scope

  defmodule UnauthorizedClientError do
    @moduledoc """
    Exception returned when the client is not authorized to register new clients on the client
    registration endpoint
    """

    defexception [:client_id, :reason]

    @impl true

    def message(%{client_id: client_id, reason: reason}) do
      "Client `#{client_id}` is not authorized to register new clients (reason: #{reason})"
    end
  end

  @doc """
  Returns `:ok` if the client is authorized to register new clients,
  `{:error, %Asteroid.OAuth2.Register.UnauthorizedClientError{}}` otherwise
  """

  @spec client_authorized?(Plug.Conn.t(), Client.t()) :: 
  :ok
  | {:error, %Asteroid.OAuth2.Register.UnauthorizedClientError{}}

  def client_authorized?(conn, client) do
    case astrenv(:oauth2_endpoint_register_client_authorization_policy) do
      :all ->
        :ok

      :authenticated_clients ->
        if APIac.authenticated?(conn) do
          :ok
        else
          client = Client.fetch_attributes(client, ["client_id"])

          {:error, Asteroid.OAuth2.Register.UnauthorizedClientError.exception(
            client_id: client.attrs["client_id"],
            reason: "Client authentication is required"
          )}
        end

      :authorized_clients ->
        if APIac.metadata(conn)["scope"] != nil and
          "asteroid.register" in Scope.Set.from_scope_param!(APIac.metadata(conn)["scope"])
        do
          :ok
        else
          client = Client.fetch_attributes(client, ["client_id", "scope"])

          if "asteroid.register" in client.data["scope"] do
            :ok
          else
            {:error, Asteroid.OAuth2.Register.UnauthorizedClientError.exception(
              client_id: client.attrs["client_id"],
              reason: "Client authentication is required"
            )}
          end
        end
    end
  end
end
