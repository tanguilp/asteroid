defmodule Asteroid.OIDC.Userinfo do
  @moduledoc """
  Convenience functions to work with the `/userinfo` endpoint
  """

  import Asteroid.Config, only: [opt: 1]

  @doc """
  Returns the list of supported signing algorithms for the userinfo endpoint

  See
  #{Asteroid.Config.link_to_option(:oidc_endpoint_userinfo_signature_alg_values_supported)}
  """
  @spec signing_alg_values_supported() :: [JOSEUtils.JWA.sig_alg()]
  def signing_alg_values_supported() do
    case opt(:oidc_endpoint_userinfo_signature_alg_values_supported) do
      :auto ->
        Asteroid.Crypto.JOSE.public_keys()
        |> Enum.flat_map(&JOSEUtils.JWK.sig_algs_supported/1)
        |> Enum.uniq()

      sig_algs ->
        sig_algs
    end
  end

  @doc """
  Returns the list of supported encryption key derivation algorithms for the userinfo endpoint

  See
  #{Asteroid.Config.link_to_option(:oidc_endpoint_userinfo_encryption_alg_values_supported)}
  """
  @spec encryption_alg_values_supported() :: [JOSEUtils.JWA.enc_alg()]
  def encryption_alg_values_supported() do
    case opt(:oidc_endpoint_userinfo_encryption_alg_values_supported) do
      :auto ->
        Asteroid.Crypto.JOSE.public_keys()
        |> Enum.flat_map(&JOSEUtils.JWK.enc_algs_supported/1)
        |> Enum.uniq()

      enc_algs ->
        enc_algs
    end
  end

  @doc """
  Returns the list of supported content encryption algorithms for the userinfo endpoint

  See
  #{Asteroid.Config.link_to_option(:oidc_endpoint_userinfo_encryption_enc_values_supported)}
  """
  @spec encryption_enc_values_supported() :: [JOSEUtils.JWA.enc_enc()]
  def encryption_enc_values_supported(),
    do: opt(:oidc_endpoint_userinfo_encryption_enc_values_supported)



  @doc """
  Returns the mapping between the `"email"`, `"profile"`, `"phone"` and `"address"` scope
  and their corresponding claims

  ```elixir
  %{
    "profile" => [
      "name",
      "family_name",
      "given_name",
      "middle_name",
      "nickname",
      "preferred_username",
      "profile",
      "picture",
      "website",
      "gender",
      "birthdate",
      "zoneinfo",
      "locale",
      "updated_at"
    ],
    "email" => ["email", "email_verified"],
    "address" => ["address"],
    "phone" => ["phone_number","phone_number_verified"]
  }
  ```
  """

  @spec scope_claims_mapping() :: %{required(String.t()) => [String.t()]}

  def scope_claims_mapping() do
    %{
      "profile" => [
        "name",
        "family_name",
        "given_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at"
      ],
      "email" => ["email", "email_verified"],
      "address" => ["address"],
      "phone" => ["phone_number", "phone_number_verified"]
    }
  end
end
