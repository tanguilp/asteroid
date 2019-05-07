defmodule Asteroid.OAuth2.Request do
  import Asteroid.Utils

  defmodule MalformedParamError do
    @moduledoc """
    Error raised when an OAuth2 request param is malformed
    """

    defexception parameter_name: nil, parameter_value: nil

    def message(exception) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Malformed parameter `#{exception.parameter_name}` "
          <> "with value `#{exception.parameter_value}`"

        :normal ->
          "Malformed parameter `#{exception.parameter_name}` "
          <> "with value `#{exception.parameter_value}`"

        :minimal ->
          ""
      end
    end
  end

  @spec error_response(Plug.Conn.t(), Exception.t()) :: Plug.Conn.t()
  def error_response(conn, %__MODULE__.MalformedParamError{parameter_name: parameter_name} = error) do
    conn
    |> Plug.Conn.put_status(400)
    |> Phoenix.Controller.json(%{
      "error" =>
        if parameter_name == "scope" do
          "invalid_scope"
        else
          "invalid_request"
        end,
      "error_description" => Exception.message(error)
    })
  end
end
