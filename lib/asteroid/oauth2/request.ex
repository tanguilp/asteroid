defmodule Asteroid.OAuth2.Request do
  import Asteroid.Utils

  defmodule InvalidRequestError do
    @moduledoc """
    Error returned when an OAuth2 request is invalid

    Parameter is used internally to differentiate errors
    """

    @enforce_keys [:reason]

    defexception [:reason, :parameter]

    @type t :: %__MODULE__{
      reason: String.t(),
      parameter: String.t()
    }

    @impl true

    def message(%{reason: reason, parameter: parameter}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "invalid parameter `#{parameter}`, reason: #{reason}"

        :normal ->
          "invalid parameter `#{parameter}`"

        :minimal ->
          ""
      end
    end
  end

  defmodule MalformedParamError do
    @moduledoc """
    Error raised when an OAuth2 request param is malformed
    """

    defexception [:name, :value]

    @type t :: %__MODULE__{
      name: String.t(),
      value: String.t()
    }

    @impl true

    def message(%{name: name, value: value}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Malformed parameter `#{name}` with value `#{value}`"

        :normal ->
          "Malformed parameter `#{name}`"

        :minimal ->
          ""
      end
    end
  end
end
