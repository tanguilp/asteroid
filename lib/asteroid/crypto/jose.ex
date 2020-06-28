defmodule Asteroid.Crypto.JOSE do
  @moduledoc """
  """

  alias Asteroid.Client

  @mac_algs ["HS256", "HS384", "HS512"]

  @enc_dh_algs [
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW"
  ]

  @symmetric_enc_algs [
    "A128KW",
    "A192KW",
    "A256KW",
    "dir",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW"
  ]

  defmodule NoSuitableKeyFoundError do
    defexception message: "no suitable key found in JOSEVirtualHSM or client JWKs"
  end

  defmodule InvalidJWSError do
    defexception message: "the input JWS is invalid"
  end

  defmodule InvalidJWEError do
    defexception message: "the input JWE is invalid"
  end

  defmodule SignatureVerificationError do
    defexception message: "signature verification failed (no key verified the signature)"
  end

  defmodule MissingAlgParameterError do
    defexception message: "algorithm parameter is missing for crypto operation"
  end

  defmodule EncryptionError do
    defexception message: "the payload could not be encrypted (no valid key / alg pair?)"
  end

  @doc """
  Signs a payload with one of Asteroid's private keys and returned the corresponding
  JWS

  The payload can be any erlang term:
  - strings are signed as-is
  - other Erlang terms are serialized to JSON

  Both MACing and asymmetric cryptography are supported.
  """
  @spec sign(
    payload :: any(),
    client :: Client.t() | nil,
    key_selector :: JOSEUtils.JWK.key_selector()
  ) :: {:ok, {JOSEUtils.JWS.serialized(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  def sign(payload, client \\ nil, key_selector \\ [])

  def sign(payload, client, key_selector) do
    case key_selector[:alg] do
      <<_::binary>> = alg when alg in @mac_algs ->
        mac(payload, client, key_selector)

      algs when is_list(algs) ->
        if Enum.all?(algs, fn alg -> alg in @mac_algs end) do
          mac(payload, client, key_selector)
        else
          JOSEVirtualHSM.sign(payload, key_selector)
        end

      nil ->
        JOSEVirtualHSM.sign(payload, key_selector)
    end
  end

  defp mac(payload, client, key_selector) when client != nil do
    with {:ok, jwks} <- Client.get_jwks(client) do
      eligible_keys =
        jwks
        |> JOSEUtils.JWKS.signature_keys()
        |> JOSEUtils.JWKS.filter(key_selector)

      case eligible_keys do
        [jwk | _] ->
          [alg | _] = JOSEUtils.JWK.sig_algs_supported(jwk)

          case JOSEUtils.JWS.sign(payload, jwk, alg) do
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

  @doc """
  Verifies a signed JWS payload signed by a client and returns the verified content

  Note that the key selector `:alg` shall be set, otherwise an error is returned.
  """
  @spec verify(
    jws :: JOSEUtils.JWS.serialized(),
    client :: Client.t(),
    key_selector :: JOSEUtils.JWK.key_selector()
  ) :: {:ok, {verified_content :: String.t(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  def verify(jws, client, key_selector \\ []) when not is_nil(client) do
    with true <- JOSEUtils.is_jws?(jws),
         {:ok, jwks} <- Client.get_jwks(client) do
      jwks = JOSEUtils.JWKS.filter(jwks, key_selector)
      algs = algs(key_selector)

      case JOSEUtils.JWS.verify(jws, jwks, algs) do
        {:ok, _} = result ->
          result

        :error ->
          {:error, %SignatureVerificationError{}}
      end
    else
      false ->
        {:error, %InvalidJWSError{}}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Encrypts a message to a client, using one of the client's keys
  """
  @spec encrypt(
    payload :: any(),
    alg :: JOSE.JWA.enc_alg(),
    enc :: JOSE.JWA.enc_enc(),
    client :: Client.t(),
    key_selector :: JOSEUtils.JWK.key_selector()
  ) :: {:ok, {JOSEUtils.JWE.serialized(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  def encrypt(payload, enc_alg, enc_enc, client, key_selector \\ []) do
    with {:ok, jwks} <- Client.get_jwks(client) do
      eligible_keys =
        jwks
        |> JOSEUtils.JWKS.encryption_keys()
        |> JOSEUtils.JWKS.filter(key_selector)
        |> JOSEUtils.JWKS.filter(alg: enc_alg, enc: enc_enc)

      case eligible_keys do
        [jwk | _] ->
          do_encrypt(payload, jwk, enc_alg, enc_enc)

        [] ->
          {:error, %NoSuitableKeyFoundError{}}
      end
    end
  end

  defp do_encrypt(payload, jwk_pub, enc_alg, enc_enc) when enc_alg in @enc_dh_algs do
    case JOSEVirtualHSM.encrypt_ecdh(payload, jwk_pub, enc_alg, enc_enc) do
      {:ok, encrypted_payload} ->
        {:ok, {encrypted_payload, jwk_pub}}

      {:error, _} = error ->
        error
    end
  end

  defp do_encrypt(payload, jwk, enc_alg, enc_enc) do
    case JOSEUtils.JWE.encrypt(payload, jwk, enc_alg, enc_enc) do
      {:ok, encrypted_payload} ->
        {:ok, {encrypted_payload, jwk}}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Decrypts a JWE encrypted with one of Asteroid's key

  Key selector `:alg` and `:enc` are mandatory for decryption of symmetric or assymetric
  with DH JWEs.
  """
  @spec decrypt(
    jwe :: JOSEUtils.JWE.serialized(),
    client :: Client.t(),
    key_selector :: JOSEUtils.JWK.key_selector()
  ) :: {:ok, {decrypted_content :: String.t(), JOSEUtils.JWK.t()}} | {:error, Exception.t()}
  def decrypt(jwe, client, key_selector \\ []) when client != nil do
    if JOSEUtils.is_jwe?(jwe) do
      case JOSEUtils.JWE.peek_header(jwe) do
        %{"alg" => alg} when alg in @symmetric_enc_algs ->
          decrypt_symmetric(jwe, client, key_selector)

        _ ->
          JOSEVirtualHSM.decrypt(jwe, key_selector)
      end
    else
      {:error, %InvalidJWEError{}}
    end
  end

  defp decrypt_symmetric(jwe, client, key_selector) do
    with {:ok, jwks} <- Client.get_jwks(client) do
      jwks =
        jwks
        |> JOSEUtils.JWKS.decryption_keys()
        |> JOSEUtils.JWKS.filter(key_selector)

      JOSEUtils.JWE.decrypt(jwe, jwks, key_selector[:alg] || [], key_selector[:enc] || [])
    end
  end

  @doc """
  Returns the list of public keys managed by the server
  """
  @spec public_keys() :: [JOSEUtils.JWK.t()]
  def public_keys(), do: JOSEVirtualHSM.public_keys()

  defp algs(key_selector) do
    case key_selector[:alg] do
      algs when is_list(algs) -> algs
      <<_::binary>> = alg -> [alg]
      nil -> []
    end
  end
end
