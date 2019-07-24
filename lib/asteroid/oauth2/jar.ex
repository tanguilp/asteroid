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
end
