defmodule Asteroid.OAuth2.RedirectUri do
  @moduledoc """
  Helper functions to deal with redirect URIs
  """

  @type t :: String.t()

  @doc """
  Returns `true` if a redirect uri is valid, `false` otherwise
  """

  @spec valid?(String.t()) ::
  :ok
  | {:error, %__MODULE__.MalformedError{}}

  def valid?(redirect_uri) when is_binary(redirect_uri) do
    parsed_uri = URI.parse(redirect_uri)

    if parsed_uri.scheme != nil and parsed_uri.fragment == nil do
      :ok
    else
      {:error, __MODULE__.MalformedError.exception(redirect_uri: redirect_uri)}
    end
  end

  def valid?(_) do
    false
  end

  defmodule MalformedError do
    @moduledoc """
    Exception returned when a redirect URI is malformed
    """

    defexception [:redirect_uri]

    @impl true

    def message(%{redirect_uri: redirect_uri}) do
      "Malformed redirect_uri `#{redirect_uri}`"
    end
  end
end
