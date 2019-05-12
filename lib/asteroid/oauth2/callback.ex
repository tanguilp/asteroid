defmodule Asteroid.OAuth2.Callback do
  alias Asteroid.Context
  alias Asteroid.Client

  import Asteroid.Utils

  @doc """
  Callback invoked to determine which claims to return from the `"/introspect"` endpoint

  ## Processing rules
  - If the `"__asteroid_endpoint_introspect_claims_resp"` attribute of the client is set to
  a list of `String.t()` claims, returns it
  - Otherwise, if the `:oauth2_endpoint_introspect_claims_resp` is set to a list of `String.t()`
  clains, returns it
  - Otherwise returns an empty list `[]`
  """

  @spec endpoint_introspect_claims_resp(Context.t()) :: [String.t()]

  def endpoint_introspect_claims_resp(%{client: client}) do
    client = Client.fetch_attributes(client, ["__asteroid_endpoint_introspect_claims_resp"])

    if is_list(client.attrs["__asteroid_endpoint_introspect_claims_resp"]) do
      client.attrs["__asteroid_endpoint_introspect_claims_resp"]
    else
      endpoint_introspect_claims_resp(%{})
    end
  end

  def endpoint_introspect_claims_resp(_) do
    astrenv(:oauth2_endpoint_introspect_claims_resp, [])
  end
end
