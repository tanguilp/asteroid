defmodule Asteroid.OAuth2.RedirectUri do
  @moduledoc """
  Helper functions to deal with redirect URIs
  """

  @type t :: String.t()

  @doc """
  Returns `true` if a redirect uri is valid, `false` otherwise
  """

  @spec valid?(String.t()) :: boolean()

  def valid?(redirect_uri) when is_binary(redirect_uri) do
    parsed_uri = URI.parse(redirect_uri)

    if parsed_uri.scheme != nil and parsed_uri.fragment == nil do
      true
    else
      false
    end
  end

  def valid?(_) do
    false
  end

  @doc """
  Add params to a request URI

  A request URI can already contain params, and new params shall be added to it
  without erasing the others. This is what this function does.
  """

  @spec add_params(String.t(), %{required(String.t()) => String.t()}) :: String.t()

  def add_params(redirect_uri, params) do
    case URI.parse(redirect_uri) do
      %URI{query: query} = parsed_uri when is_binary(query) ->
        parsed_uri
        |> Map.put(:query, URI.encode_query(URI.decode_query(query, params)))

      %URI{query: nil} = parsed_uri ->
        parsed_uri
        |> Map.put(:query, URI.encode_query(params))

    end
    |> URI.to_string()
  end
end
