defmodule Asteroid.OIDC.Userinfo do
  @moduledoc """
  Convenience function to work with the `/api/oidc/userinfo` endpoint
  """

  import Asteroid.Utils

  alias Asteroid.Client

  @doc """
  Returns `true` if the response shall be signed, `false` otherwise

  Depending on the `:oidc_endpoint_userinfo_sign_response_policy` configuration option:
  - `:disabled`: returns `false`
  - `:client_configuration`: returns `true if the
  `"__asteroid_oidc_endpoint_userinfo_sign_response"` client attribute is set to `true`, `false`
  otherwise
  - `:always`: returns `true`
  """

  @spec sign_response?(Asteroid.Context.t()) :: boolean()

  def sign_response?(%{client: client}) do
    case astrenv(:oidc_endpoint_userinfo_sign_response_policy, :disabled) do
      :disabled ->
        false

      :always ->
        true

      :client_configuration ->
        client =
          Client.fetch_attributes(client, ["__asteroid_oidc_endpoint_userinfo_sign_response"])

        client.attrs["__asteroid_oidc_endpoint_userinfo_sign_response"] == true
    end
  end

  @doc """
  Returns `true` if the response shall be encrypted, `false` otherwise

  Depending on the `:oidc_endpoint_userinfo_encrypt_response_policy` configuration option:
  - `:disabled`: returns `false`
  - `:client_configuration`: returns `true if the
  `"__asteroid_oidc_endpoint_userinfo_encrypt_response"` client attribute is set to `true`,
  `false` otherwise
  - `:always`: returns `true`
  """

  @spec encrypt_response?(Asteroid.Context.t()) :: boolean()

  def encrypt_response?(%{client: client}) do
    case astrenv(:oidc_endpoint_userinfo_encrypt_response_policy, :disabled) do
      :disabled ->
        false

      :always ->
        true

      :client_configuration ->
        client =
          Client.fetch_attributes(client, ["__asteroid_oidc_endpoint_userinfo_encrypt_response"])

        client.attrs["__asteroid_oidc_endpoint_userinfo_encrypt_response"] == true
    end
  end
end
