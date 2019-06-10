defmodule Asteroid.OAuth2.APIacAuthBearer.Validator do
  @moduledoc """
  Implementation of `APIacAuthBearer.Validator` for Asteroid

  This implementation checks the access token against Asteroid's own access token store and can
  be used on Asteroid endpoints on which clients can authenticate using the HTTP `Bearer`
  scheme, such as `/introspect` and `/register`.

  There are no options.
  """

  alias Asteroid.Token.AccessToken

  @behaviour APIacAuthBearer.Validator

  @impl true

  def validate(access_token_param, _) do
    case AccessToken.get(access_token_param) do
      {:ok, access_token} ->
        {:ok, access_token.data}

      {:error, _} = error ->
        error
    end
  end
end
