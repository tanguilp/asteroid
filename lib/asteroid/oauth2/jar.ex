defmodule Asteroid.OAuth2.JAR do
  @moduledoc """
  Functions to work with JWT Secured Authorization Request (JAR)
  """

  import Asteroid.Utils

  defmodule RequestNotSupported do
    @moduledoc """
    Error returned when requesting with a JAR request object is not supported
    """

    defexception []

    @impl true

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "use of JAR request objects is disabled"
          <> " (current config: #{inspect astrenv(:oauth2_jar_enabled)})"

        :normal ->
          "use of JAR request objects is disabled"

        :minimal ->
          ""
      end
    end
  end

  defmodule RequestURINotSupported do
    @moduledoc """
    Error returned when requesting with a JAR request object URI is not supported
    """

    defexception []

    @impl true

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "use of JAR request object URIs is disabled"
          <> " (current config: #{inspect astrenv(:oauth2_jar_enabled)})"

        :normal ->
          "use of JAR request object URIs is disabled"

        :minimal ->
          ""
      end
    end
  end

  @doc """
  Parses and verifies a request object
  """

  @spec parse_and_verify(String.t()) :: map()

  def parse_and_verify(_request_object_str) do
    %{}
  end

  @doc """
  Retrieves a request object from a URI
  """

  @spec retrieve_object(String.t()) :: String.t()

  def retrieve_object(uri) do
    uri
  end

  @doc """
  Retrieves an object from Asteroid's request object store
  """

  @spec get_stored_request_object(String.t()) :: {:ok, String.t()} | {:error, any()}

  def get_stored_request_object(key) do
    module = astrenv(:token_store_request_object)[:module]
    opts = astrenv(:token_store_request_object)[:opts] || []

    req_obj_lifetime = astrenv(:oauth2_jar_request_object_lifetime, 0)

    now = now()

    case module.get(key, opts) do
      {:ok, %{"exp" => exp}} when now + req_obj_lifetime < exp ->
        {:error, :expired_object_request}

      {:ok, %{"request_object" => request_object}} ->
        {:ok, request_object}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Saves an object to Asteroid's request object store
  """

  @spec put_request_object(String.t(), String.t()) :: :ok | {:error, any()}

  def put_request_object(key, value) do
    module = astrenv(:token_store_request_object)[:module]
    opts = astrenv(:token_store_request_object)[:opts] || []

    module.put(key, value, opts)
  end
end
