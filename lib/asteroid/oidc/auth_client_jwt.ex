defmodule Asteroid.OIDC.AuthClientJWT do
  @moduledoc """
  Helper functions and callbacks for integration with `APIacAuthClientJWT`

  ## Example

      {
      APIacAuthClientJWT,
      client_callback: &Asteroid.OIDC.AuthClientJWT.client_callback/1,
      jti_register: JTIRegister.ETS,
      server_metadata_callback: &Asteroid.OIDC.AuthClientJWT.server_metadata_callback/0,
      set_error_response: &APIacAuthClientJWT.save_authentication_failure_response/3
      }
  """

  import Asteroid.Config, only: [opt: 1]

  alias Asteroid.{Client, OAuth2}

  @doc """
  Returns the list of accepted signature algorithms for use with the `"private_key_jwt"` or
  `"client_secret_jwt"` client auithentication scheme
  """
  @spec signing_alg_values_supported() :: [JOSEUtils.JWA.sig_alg()]
  def signing_alg_values_supported() do
    case opt(:oidc_endpoint_token_auth_signing_alg_values_supported) do
      :auto ->
        Asteroid.Crypto.JOSE.public_keys()
        |> Enum.flat_map(&JOSEUtils.JWK.sig_algs_supported/1)
        |> Enum.uniq()

      sig_algs ->
        sig_algs
    end
  end

  @doc """
  Client callback for `APIacAuthClientJWT`
  """
  @spec client_callback(String.t()) :: APIacAuthClientJWT.client_config()
  def client_callback(client_id) do
    case Client.load_from_unique_attribute("client_id", client_id) do
      {:ok, client} ->
        client.attrs

      {:error, e} ->
        raise e
    end
  end

  @doc """
  Server metadata callback for `APIacAuthClientJWT`
  """
  @spec server_metadata_callback() :: APIacAuthClientJWT.server_metadata()
  def server_metadata_callback(), do: OAuth2.Metadata.get()
end
