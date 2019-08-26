defmodule Asteroid.Token.IDToken do
  import Asteroid.Utils

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

    jwt =
      (id_token.data || %{})
      |> Map.put("iss", id_token.iss)
      |> Map.put("sub", id_token.sub)
      |> Map.put("aud", id_token.aud)
      |> Map.put("exp", id_token.exp)
      |> Map.put("iat", id_token.iat)
      |> put_if_not_nil("auth_time", id_token.auth_time)
      |> put_if_not_nil("nonce", id_token.nonce)
      |> put_if_not_nil("acr", id_token.acr)
      |> put_if_not_nil("amr", id_token.amr)
      |> put_if_not_nil("azp", id_token.azp)
      |> put_if_not_nil(
        "at_hash",
        token_hash(id_token, id_token.associated_access_token_serialized)
      )
      |> put_if_not_nil(
        "c_hash",
        token_hash(id_token, id_token.associated_authorization_code_serialized)
      )

    signing_alg = client.attrs["id_token_signed_response_alg"] || "RS256"

    eligible_jwks =
      Crypto.Key.get_all()
      |> Enum.filter(fn
        %JOSE.JWK{fields: fields} ->
          fields["use"] == "sig" and
            (fields["key_ops"] in ["sign"] or fields["key_ops"] == nil) and
            (fields["alg"] == signing_alg or fields["alg"] == nil)
      end)

    case eligible_jwks do
      [jwk | _] ->
        serialized_jws =
          JOSE.JWT.sign(jwk, JOSE.JWS.from_map(%{"alg" => signing_alg}), jwt)
          |> JOSE.JWS.compact()
          |> elem(1)

        encryption_alg = client.attrs["id_token_encrypted_response_alg"]

        if encryption_alg do
          case Client.get_jwks(client) do
            {:ok, keys} ->
              eligible_jwks =
                keys
                |> Enum.map(&JOSE.JWK.from/1)
                |> Enum.filter(fn
                  %JOSE.JWK{fields: fields} ->
                    (fields["use"] == "enc" or fields["use"] == nil) and
                      (fields["key_ops"] == "encrypt" or fields["key_ops"] == nil) and
                      (fields["alg"] == encryption_alg or fields["alg"] == nil)
                end)

              case eligible_jwks do
                [jwk | _] ->
                  encryption_enc =
                    client.attrs["id_token_encrypted_response_enc"] || "A128CBC-HS256"

                  JOSE.JWE.block_encrypt(
                    jwk,
                    serialized_jws,
                    %{"alg" => encryption_alg, "enc" => encryption_enc}
                  )
                  |> JOSE.JWE.compact()
                  |> elem(1)

                [] ->
                  raise Crypto.Key.NoSuitableKeyError
              end

            {:error, _} ->
              raise Crypto.Key.NoSuitableKeyError
          end
        else
          serialized_jws
        end

      [] ->
        raise Crypto.Key.NoSuitableKeyError
    end
  end

  @spec token_hash(t(), token :: String.t() | nil) :: String.t()

  defp token_hash(_, nil) do
    nil
  end

  defp token_hash(%__MODULE__{client: client}, token) do
    client = Client.fetch_attributes(client, ["id_token_signed_response_alg"])

    hash_alg =
      cond do
        client.attrs["id_token_signed_response_alg"] in ["ES256", "HS256", "PS256", "RS256"] ->
          :sha256

        client.attrs["id_token_signed_response_alg"] in ["ES384", "HS384", "PS384", "RS384"] ->
          :sha384

        client.attrs["id_token_signed_response_alg"] in ["ES512", "HS512", "PS512", "RS512"] ->
          :sha512

        true ->
          nil
      end

    if hash_alg do
      digest = :crypto.hash(hash_alg, token)

      digest
      |> :binary.part({0, div(byte_size(digest), 2)})
      |> Base.url_encode64(padding: false)
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

        astrenv(conf_opt, astrenv(:oidc_id_token_lifetime, 0))
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

      astrenv(conf_opt, astrenv(:oidc_issue_id_token_refresh, false))
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
