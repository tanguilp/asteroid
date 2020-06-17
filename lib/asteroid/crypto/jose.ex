defmodule Asteroid.Crypto.JOSE do
  @moduledoc """
  """

  alias Asteroid.Client

  @mac_algs ["HS256", "HS384", "HS512"]
  @enc_sym_algs [
    "A128KW",
    "A192KW",
    "A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW"
  ]
  @enc_dh_algs [
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW"
  ]

  defmodule NoSuitableKeyFoundError do
    defexception message: "no suitable key found in JOSEVirtualHSM or client JWKs"
  end

  @spec sign(
    payload :: any(),
    sig_alg :: JOSEUtils.JWA.sig_alg(),
    client :: Client.t()
  ) :: {:ok, {JOSEUtils.JWS.serialized(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  def sign(payload, sig_alg, client) when sig_alg in @mac_algs do
    with {:ok, jwks} <- Client.get_jwks(client) do
      eligible_keys =
        jwks
        |> JOSEUtils.JWKS.signature_keys()
        |> JOSEUtils.JWKS.filter(sig_alg: sig_alg)

      case eligible_keys do
        [jwk | _] ->
          case JOSEUtils.JWS.sign(payload, jwk, sig_alg) do
            {:ok, signed_payload} ->
              {:ok, {signed_payload, jwk}}

            {:error, _} = error ->
              error
          end

        [] ->
          {:error, %NoSuitableKeyFoundError{}}
      end
    end
  end

  def sign(payload, sig_alg, _client) do
    JOSEVirtualHSM.sign(payload, alg: sig_alg)
  end

  @spec encrypt(
    payload :: any(),
    enc_alg :: JOSE.JWA.enc_alg(),
    enc_enc :: JOSE.JWA.enc_enc(),
    client :: Client.t()
  ) :: {:ok, {JOSEUtils.JWE.serialized(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  def encrypt(payload, enc_alg, enc_enc, client) when enc_alg in @enc_sym_algs do
    with {:ok, jwks} <- Client.get_jwks(client) do
      eligible_keys =
        jwks
        |> JOSEUtils.JWKS.encryption_keys()
        |> JOSEUtils.JWKS.filter(enc_alg: enc_alg, enc_enc: enc_enc)

      case eligible_keys do
        [jwk | _] ->
          case JOSEUtils.JWE.encrypt(payload, jwk, enc_alg, enc_enc) do
            {:ok, encrypted_payload} ->
              {:ok, {encrypted_payload, jwk}}

            {:error, _} = error ->
              error
          end

        [] ->
          {:error, %NoSuitableKeyFoundError{}}
      end
    end
  end

  def encrypt(payload, enc_alg, enc_enc, client) when enc_alg in @enc_dh_algs do
    with {:ok, jwks} <- Client.get_jwks(client) do
      eligible_keys =
        jwks
        |> JOSEUtils.JWKS.encryption_keys()
        |> JOSEUtils.JWKS.filter(enc_alg: enc_alg, enc_enc: enc_enc)

      case eligible_keys do
        [jwk_pub_key | _] ->
          JOSEVirtualHSM.encrypt(payload, jwk_pub_key, enc_alg: enc_alg, enc_enc: enc_enc)

        [] ->
          {:error, %NoSuitableKeyFoundError{}}
      end
    end
  end

  def encrypt(payload, enc_alg, enc_enc, _client) do
    JOSEVirtualHSM.encrypt(payload, enc_alg: enc_alg, enc_enc: enc_enc)
  end

  @doc """
  Returns the list of public keys managed by the server
  """
  @spec public_keys() :: [JOSEUtils.JWK.t()]
  def public_keys(), do: JOSEVirtualHSM.public_keys()
end
