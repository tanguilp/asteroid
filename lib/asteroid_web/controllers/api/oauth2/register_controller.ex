defmodule AsteroidWeb.API.OAuth2.RegisterController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Config, only: [opt: 1]

  alias OAuth2Utils.Scope
  alias Asteroid.{Client, OAuth2}

  defmodule InvalidClientMetadataFieldError do
    @moduledoc """
    Error returned when client metadata is invalid
    """

    defexception [:field, :reason]

    @impl true

    def message(%{field: field, reason: reason}) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          case field do
            "token_endpoint_auth_method" ->
              "Invalid field `#{field}` (reason: #{reason}, supported methods:)" <>
                "#{inspect(opt(:oauth2_endpoint_token_auth_methods_supported_callback).())})"

            _ ->
              "Invalid field `#{field}` (reason: #{reason})"
          end

        :normal ->
          "Invalid field `#{field}`"

        :minimal ->
          ""
      end
    end
  end

  defmodule UnauthorizedRequestedScopesError do
    @moduledoc """
    Error returned when returning scopes are not allowed according to the policy (either the
    client's configuration or the scopes existing in the configuration options).
    """

    defexception [:scopes]

    @impl true

    def message(%{scopes: scopes}) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          "The following requested scopes are not allowed under the current policy: " <>
            Enum.join(scopes, " ")

        :normal ->
          "The requested scopes are not allowed under the current policy"

        :minimal ->
          ""
      end
    end
  end

  defmodule InvalidRedirectURIError do
    @moduledoc """
    Error raised when the one or more redirect URIs are invalid
    """

    defexception [:redirect_uri]

    @type t :: %__MODULE__{
            redirect_uri: String.t()
          }

    @impl true

    def message(%{redirect_uri: redirect_uri}) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          "Invalid redirect URI `#{redirect_uri}`"

        :normal ->
          "Invalid redirect URI `#{redirect_uri}`"

        :minimal ->
          ""
      end
    end
  end

  def handle(conn, req_metadata) do
    maybe_client =
      case OAuth2.Client.get_authenticated_client(conn) do
        {:ok, client} ->
          client

        {:error, _} ->
          nil
      end

    ctx =
      %{}
      |> Map.put(:endpoint, :register)
      |> Map.put(:conn, conn)
      |> Map.put(:client, maybe_client)
      |> Enum.filter(fn {_k, v} -> v != nil end)
      |> Enum.into(%{})

    with :ok <- request_authorized?(conn, maybe_client),
         {:ok, metadata} <- OAuth2.ClientRegistration.register(req_metadata, maybe_client) do
      metadata = opt(:oauth2_endpoint_register_before_send_resp_callback).(metadata, ctx)

      conn
      |> put_status(201)
      |> opt(:oauth2_endpoint_register_before_send_conn_callback).(ctx)
      |> json(metadata)

    else
      {:error, %_{} = e} ->
        AsteroidWeb.Error.respond_api(conn, e)
    end
  end

  @spec request_authorized?(Plug.Conn.t(), Client.t() | nil) ::
          :ok
          | {:error, %OAuth2.Client.AuthenticationError{}}
          | {:error, %OAuth2.Client.AuthorizationError{}}
  def request_authorized?(conn, maybe_client) do
    case opt(:oauth2_endpoint_register_authorization_policy) do
      :all ->
        :ok

      :authenticated_clients ->
        if APIac.authenticated?(conn) do
          :ok
        else
          {:error, %OAuth2.Client.AuthenticationError{reason: :client_authentication_required}}
        end

      :authorized_clients ->
        if APIac.metadata(conn)["scope"] != nil and
             "asteroid.register" in Scope.Set.from_scope_param!(APIac.metadata(conn)["scope"]) do
          :ok
        else
          if maybe_client do
            client = Client.fetch_attributes(maybe_client, ["client_id", "scope"])

            if "asteroid.register" in client.attrs["scope"] do
              :ok
            else
              {:error, %OAuth2.Client.AuthorizationError{reason: :unauthorized_client}}
            end
          else
            {:error, %OAuth2.Client.AuthenticationError{reason: :client_authentication_required}}
          end
        end
    end
  end
end
