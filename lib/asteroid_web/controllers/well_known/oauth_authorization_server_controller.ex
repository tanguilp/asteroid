defmodule AsteroidWeb.WellKnown.OauthAuthorizationServerController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Config, only: [opt: 1]

  alias Asteroid.{Crypto, OAuth2}

  def handle(conn, _params) do
    metadata =
      OAuth2.Metadata.get()
      |> opt(:oauth2_endpoint_metadata_before_send_resp_callback).()
      |> sign()

    conn
    |> opt(:oauth2_endpoint_metadata_before_send_conn_callback).()
    |> json(metadata)
  end

  @spec sign(map()) :: map()
  defp sign(metadata) do
    case opt(:oauth2_endpoint_metadata_signed_fields) do
      :disabled ->
        metadata

      :all ->
        Map.put(metadata, "signed_metadata", signed_statement(metadata))

      fields when is_list(fields) ->
        fields_to_be_signed = Map.take(metadata, ["issuer" | fields])

        Map.put(metadata, "signed_metadata", signed_statement(fields_to_be_signed))
    end
  end

  @spec signed_statement(map()) :: String.t()
  defp signed_statement(to_be_signed) do
    signing_key_selector =
      Keyword.merge([use: "sig"], opt(:oauth2_endpoint_metadata_signing_key_selector))

    {:ok, {signed, _}} = Crypto.JOSE.sign(to_be_signed, nil, signing_key_selector)

    signed
  end
end
