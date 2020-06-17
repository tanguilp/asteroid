defmodule Asteroid.Token.IDToken do
  import Asteroid.Config, only: [opt: 1]

  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias Asteroid.OIDC
  alias Asteroid.Subject

  @moduledoc """
  OpenID Connect's ID token structure
  """

  @client_id_token_crypto_fields [
    "id_token_signed_response_alg",
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc"
  ]

  @enforce_keys [:iss, :sub, :aud, :exp, :iat, :client]

  defstruct [
    :iss,
    :sub,
    :aud,
    :exp,
    :iat,
    :auth_time,
    :nonce,
    :acr,
    :amr,
    :azp,
    :client,
    :associated_access_token_serialized,
    :associated_authorization_code_serialized,
    data: %{}
  ]

  @typedoc """
  Structure for the ID token, before it is serialized

  The data in the `"data"` field are added to the serialized (signed) ID token.
  """

  @type t :: %__MODULE__{
          iss: OAuth2.issuer(),
          sub: OAuth2.subject(),
          aud: OAuth2.audience(),
          exp: non_neg_integer(),
          iat: non_neg_integer(),
          auth_time: non_neg_integer() | nil,
          nonce: OIDC.nonce() | nil,
          acr: OIDC.acr() | nil,
          amr: OIDC.amr() | nil,
          azp: String.t() | nil,
          client: Client.t(),
          associated_access_token_serialized: String.t() | nil,
          associated_authorization_code_serialized: String.t() | nil,
          data: map()
        }

  @type id :: String.t()

  @doc """
  Puts a value into the `data` field of an ID token

  If the value is `nil`, the ID token is not changed and the filed is not added.
  """

  @spec put_value(t(), any(), any()) :: t()

  def put_value(id_token, _key, nil), do: id_token

  def put_value(id_token, key, val) do
    %{id_token | data: Map.put(id_token.data, key, val)}
  end

  @doc """
  Removes a value from the `data` field of an ID token

  If the value does not exist, does nothing.
  """

  @spec delete_value(t(), any()) :: t()

  def delete_value(id_token, key) do
    %{id_token | data: Map.delete(id_token.data, key)}
  end

  @doc """
  Serializes the ID token

  If the signing algorithm was set, it uses this algorithm, otherwise it uses the default
  signer of `JOSE.JWT.sign/2`
  """

  @spec serialize(%__MODULE__{}) :: String.t()

  def serialize(id_token) do
    client = Client.fetch_attributes(id_token.client, @client_id_token_crypto_fields)

    (id_token.data || %{})
    |> Map.put("iss", id_token.iss)
    |> Map.put("sub", id_token.sub)
    |> Map.put("aud", id_token.aud)
    |> Map.put("exp", id_token.exp)
    |> Map.put("iat", id_token.iat)
    |> Map.put("auth_time", id_token.auth_time)
    |> Map.put("nonce", id_token.nonce)
    |> Map.put("acr", id_token.acr)
    |> Map.put("amr", id_token.amr)
    |> Map.put("azp", id_token.azp)
    |> maybe_put_token_hash("at_hash", id_token.associated_access_token_serialized, client)
    |> maybe_put_token_hash("c_hash", id_token.associated_authorization_code_serialized, client)
    |> Enum.reject(fn {_k, v} -> v == nil end)
    |> Enum.into(%{})
    |> sign(client)
    |> maybe_encrypt(client)
  end

  @spec maybe_put_token_hash(map(), String.t(), String.t() | nil, Client.t()) :: String.t()
  defp maybe_put_token_hash(id_token_claims, _, nil, _) do
    id_token_claims
  end

  defp maybe_put_token_hash(id_token_claims, token_hash_name, token, client) do
    {hash_alg, kid_or_nil} = hash_alg(client.attrs["id_token_signed_response_alg"] || "RS256")

    digest = :crypto.hash(hash_alg, token)

    digest_final =
      digest
      |> :binary.part({0, div(byte_size(digest), 2)})
      |> Base.url_encode64(padding: false)

    id_token_claims
    |> Map.put(token_hash_name, digest_final)
    |> Map.put(:selected_kid, kid_or_nil)
  end

  @spec hash_alg(String.t()) :: {:crypto.hash_algorithm(), kid :: String.t() | nil}
  defp hash_alg("ES256"), do: {:sha256, nil}
  defp hash_alg("ES384"), do: {:sha384, nil}
  defp hash_alg("ES512"), do: {:sha512, nil}
  defp hash_alg("HS256"), do: {:sha256, nil}
  defp hash_alg("HS384"), do: {:sha384, nil}
  defp hash_alg("HS512"), do: {:sha512, nil}
  defp hash_alg("PS256"), do: {:sha256, nil}
  defp hash_alg("PS384"), do: {:sha384, nil}
  defp hash_alg("PS512"), do: {:sha512, nil}
  defp hash_alg("RS256"), do: {:sha256, nil}
  defp hash_alg("RS384"), do: {:sha384, nil}
  defp hash_alg("RS512"), do: {:sha512, nil}
  defp hash_alg("EdDSA") do
    # alg is no sufficient to determine the hash alg for the EdDSA alg: we need the curve as
    # well, which is why we have to select a key manually
    Crypto.JOSE.public_keys()
    |> JOSEUtils.JWKS.signature_keys()
    |> JOSEUtils.JWKS.filter(alg: "EdDSA")
    |> case do
      [%{"crv" => "Ed25519", "kid" => kid} | _] ->
        {:sha256, kid}

      [%{"crv" => "Ed448", "kid" => kid} | _] ->
        {:sha3_256, kid}

      _ ->
        raise Crypto.JOSE.NoSuitableKeyFoundError
    end
  end

  @spec sign(map(), Client.t()) :: String.t()
  defp sign(claims, client) do
    signing_alg = client.attrs["id_token_signed_response_alg"] || "RS256"

    if claims[:selected_kid] do
      Crypto.JOSE.sign(claims, signing_alg, client, kid: claims[:selected_kid])
    else
      Crypto.JOSE.sign(claims, signing_alg, client)
    end
    |> case do
      {:ok, {signed_payload, _jwk}} ->
        signed_payload

      {:error, e} ->
        raise e
    end
  end

  @spec maybe_encrypt(String.t(), Client.t()) :: String.t()
  defp maybe_encrypt(id_token_serialized, client) do
    enc_alg = client.attrs["id_token_encrypted_response_alg"]

    if enc_alg do
      enc_enc = client.attrs["id_token_encrypted_response_enc"] || "A128CBC-HS256"

      case Crypto.JOSE.encrypt(id_token_serialized, enc_alg, enc_enc, client) do
        {:ok, {encrypted_payload, _jwk}} ->
          encrypted_payload

        {:error, e} ->
          raise e
      end
    else
      id_token_serialized
    end
  end

  @doc """
  Returns the ID token lifetime

  ## Processing rules
  - If the client has the following field set to an integer value for the corresponding flow
  returns that value:
    - `"__asteroid_oidc_flow_authorization_code_id_token_lifetime"`
    - `"__asteroid_oidc_flow_implicit_id_token_lifetime"`
    - `"__asteroid_oidc_flow_hybrid_id_token_lifetime"`
  - Otherwise, if the following configuration option is set to an integer for the corresponding
  flow, returns its value:
    - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_id_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_implicit_id_token_lifetime)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_id_token_lifetime)}
  - Otherwise uses the
  #{Asteroid.Config.link_to_option(:oidc_id_token_lifetime)} configuration option
  - Otherwise returns `0`
  """

  @spec lifetime(Context.t()) :: non_neg_integer()

  def lifetime(%{flow: flow, client: client}) do
    attr =
      case flow do
        :oidc_authorization_code ->
          "__asteroid_oidc_flow_authorization_code_id_token_lifetime"

        :oidc_implicit ->
          "__asteroid_oidc_flow_implicit_id_token_lifetime"

        :oidc_hybrid ->
          "__asteroid_oidc_flow_hybrid_id_token_lifetime"
      end

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        conf_opt =
          case flow do
            :oidc_authorization_code ->
              :oidc_flow_authorization_code_id_token_lifetime

            :oidc_implicit ->
              :oidc_flow_implicit_id_token_lifetime

            :oidc_hybrid ->
              :oidc_flow_hybrid_id_token_lifetime
          end

        opt(conf_opt) || opt(:oidc_id_token_lifetime)
    end
  end

  @doc """
  Returns `true` if an ID token is to be issued on token renewal, `false` otherwise

  An ID token is always issued on initial request, hence that function deals only with renewal.

  ## Processing rules
  - If the client has the following field set to `true` for the corresponding flow and
  grant type, returns `true`:
    - `"__asteroid_oidc_flow_authorization_code_issue_id_token_refresh"`
    - `"__asteroid_oidc_flow_hybrid_issue_id_token_refresh"`
  - Otherwise, if the following configuration option is set to `true` for the corresponding flow
  and grant type, returns `true`:
    - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_issue_id_token_refresh)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_issue_id_token_refresh)}
  - Otherwise uses the
  #{Asteroid.Config.link_to_option(:oidc_issue_id_token_refresh)} configuration option
  - Otherwise returns `false`
  """

  @spec issue_id_token?(Context.t()) :: boolean()

  def issue_id_token?(%{flow: flow, grant_type: :refresh_token, client: client}) do
    attr =
      case flow do
        :oidc_authorization_code ->
          "__asteroid_oidc_flow_authorization_code_issue_id_token_refresh"

        :oidc_hybrid ->
          "__asteroid_oidc_flow_hybrid_issue_id_token_refresh"
      end

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      conf_opt =
        case flow do
          :oidc_authorization_code ->
            :oidc_flow_authorization_code_issue_id_token_refresh

          :oidc_hybrid ->
            :oidc_flow_hybrid_issue_id_token_refresh
        end

      opt(conf_opt) || opt(:oidc_issue_id_token_refresh)
    end
  end

  def issue_id_token?(_) do
    false
  end

  @doc """
  Add subject claims from a list of claims
  """

  @spec add_sub_claims(t(), [String.t()], Subject.t()) :: t()

  def add_sub_claims(id_token, [], _subject) do
    id_token
  end

  def add_sub_claims(id_token, claims, subject) do
    claims_to_exclude = [
      "iss",
      "sub",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "acr",
      "amr",
      "azp"
    ]

    claims_to_load = Enum.filter(claims, &(&1 not in claims_to_exclude))

    subject = Subject.fetch_attributes(subject, claims_to_load)

    Enum.reduce(claims_to_load, id_token, &put_value(&2, &1, subject.attrs[&1]))
  end
end
