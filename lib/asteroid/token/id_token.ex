defmodule Asteroid.Token.IDToken do
  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias Asteroid.OIDC

  @moduledoc """
  OpenID Connect's ID token structure
  """

  @enforce_keys [:iss, :sub, :aud, :exp, :iat, :signing_key, :signing_alg]

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
    :signing_key,
    :signing_alg,
    :associated_access_token_serialized,
    :associated_authorization_code_serialized,
    :data
  ]

  @type id :: String.t()

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
    signing_key: Asteroid.Crypto.Key.name() | nil,
    signing_alg: Asteroid.Crypto.Key.jws_alg() | nil,
    associated_access_token_serialized: String.t() | nil,
    associated_authorization_code_serialized: String.t() | nil,
    data: map()
  }

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

  @spec serialize(t()) :: String.t()

  def serialize(id_token) do
    jwt =
      id_token.data || %{}
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
      |> put_if_not_nil("at_hash",
                        token_hash(id_token, id_token.associated_access_token_serialized))
      |> put_if_not_nil("c_hash",
                        token_hash(id_token, id_token.associated_authorization_code_serialized))

    {:ok, jwk} = Crypto.Key.get(id_token.signing_key)

    if id_token.signing_alg do
      jws = JOSE.JWS.from_map(%{"alg" => id_token.signing_alg})

      JOSE.JWT.sign(jwk, jws, jwt)
      |> JOSE.JWS.compact
      |> elem(1)
    else
      JOSE.JWT.sign(jwk, jwt)
      |> JOSE.JWS.compact
      |> elem(1)
    end
  end

  @spec token_hash(t(), token :: String.t() | nil) :: String.t()

  defp token_hash(_, nil) do
    nil
  end

  defp token_hash(%__MODULE__{signing_alg: signing_alg}, token) when signing_alg in [
    "ES256", "ES384", "ES512", "HS256", "HS384", "HS512", "PS256", "PS384", "PS512",
    "RS256", "RS384", "RS512"
  ] do
    hash_alg =
      cond do
        signing_alg in ["ES256", "HS256", "PS256", "RS256"] ->
          :sha256

        signing_alg in ["ES384", "HS384", "PS384", "RS384"] ->
          :sha384

        signing_alg in ["ES512", "HS512", "PS512", "RS512"] ->
          :sha512
      end

    digest = :crypto.hash(hash_alg, token)

    digest
    |> :binary.part({0, div(byte_size(digest), 2)})
    |> Base.url_encode64(padding: false)
  end

  defp token_hash(_, _) do
    nil
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
  - Otherwise returns `0`
  """

  @spec lifetime(Context.t()) :: non_neg_integer()

  def lifetime(%{flow: :oidc_authorization_code, client: client}) do
    attr = "__asteroid_oidc_flow_authorization_code_id_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oidc_flow_authorization_code_id_token_lifetime, 0)
    end
  end

  def lifetime(%{flow: :oidc_implicit, client: client}) do
    attr = "__asteroid_oidc_flow_implicit_id_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oidc_flow_implicit_id_token_lifetime, 0)
    end
  end

  def lifetime(%{flow: :oidc_hybrid, client: client}) do
    attr = "__asteroid_oidc_flow_hybrid_id_token_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        astrenv(:oidc_flow_hybrid_id_token_lifetime, 0)
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
  - Otherwise returns `false`
  """

  @spec issue_id_token?(Context.t()) :: boolean()

  def issue_id_token?(%{
    flow: :oidc_authorization_code,
    grant_type: :refresh_token,
    client: client})
  do
    attr = "__asteroid_oidc_flow_authorization_code_issue_id_token_refresh"

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      astrenv(:oidc_flow_authorization_code_issue_id_token_refresh, false)
    end
  end

  def issue_id_token?(%{
    flow: :oidc_hybrid,
    grant_type: :refresh_token,
    client: client})
  do
    attr = "__asteroid_oidc_flow_hybrid_issue_id_token_refresh"

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] == true do
      true
    else
      astrenv(:oidc_flow_hybrid_issue_id_token_refresh, false)
    end
  end

  def issue_id_token?(_) do
    false
  end

  @doc """
  Returns the signing key name for an ID token

  - If the client has the following field set to an integer value for the corresponding flow
  returns that value:
    - `"__asteroid_oidc_flow_authorization_code_id_token_signing_key"`
    - `"__asteroid_oidc_flow_implicit_id_token_signing_key"`
    - `"__asteroid_oidc_flow_hybrid_id_token_signing_key"`
  - Otherwise, if the following configuration option is set to an integer for the corresponding
  flow, returns its value:
    - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_id_token_signing_key)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_implicit_id_token_signing_key)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_id_token_signing_key)}
  - otherwise, returns `nil`
  """

  @spec signing_key(Context.t()) :: Asteroid.Crypto.Key.name()

  def signing_key(%{flow: flow, client: client}) do
    attr =
      case flow do
        :oidc_authorization_code ->
          "__asteroid_oidc_flow_authorization_code_id_token_signing_key"

        :oidc_implicit ->
          "__asteroid_oidc_flow_implicit_id_token_signing_key"

        :oidc_hybrid ->
          "__asteroid_oidc_flow_hybrid_id_token_signing_key"
      end

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] != nil do
      client.attrs[attr]
    else
      conf_opt =
        case flow do
          :oidc_authorization_code ->
            :oidc_flow_authorization_code_id_token_signing_key

          :oidc_implicit ->
            :oidc_flow_implicit_id_token_signing_key

          :oidc_hybrid ->
            :oidc_flow_hybrid_id_token_signing_key
        end

      astrenv(conf_opt, nil)
    end
  end

  def signing_key(_) do
    nil
  end

  @doc """
  Returns the signing key algorithm for an ID token

  - If the client has the following field set to an integer value for the corresponding flow
  returns that value:
    - `"__asteroid_oidc_flow_authorization_code_id_token_signing_alg"`
    - `"__asteroid_oidc_flow_implicit_id_token_signing_alg"`
    - `"__asteroid_oidc_flow_hybrid_id_token_signing_alg"`
  - Otherwise, if the following configuration option is set to an integer for the corresponding
  flow, returns its value:
    - #{Asteroid.Config.link_to_option(:oidc_flow_authorization_code_id_token_signing_alg)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_implicit_id_token_signing_alg)}
    - #{Asteroid.Config.link_to_option(:oidc_flow_hybrid_id_token_signing_alg)}
  - otherwise, returns `nil`
  """

  @spec signing_alg(Context.t()) :: Asteroid.Crypto.Key.jws_alg()

  def signing_alg(%{flow: flow, client: client}) do
    attr =
      case flow do
        :oidc_authorization_code ->
          "__asteroid_oidc_flow_authorization_code_id_token_signing_alg"

        :oidc_implicit ->
          "__asteroid_oidc_flow_implicit_id_token_signing_alg"

        :oidc_hybrid ->
          "__asteroid_oidc_flow_hybrid_id_token_signing_alg"
      end

    client = Client.fetch_attributes(client, [attr])

    if client.attrs[attr] != nil do
      client.attrs[attr]
    else
      conf_opt =
        case flow do
          :oidc_authorization_code ->
            :oidc_flow_authorization_code_id_token_signing_alg

          :oidc_implicit ->
            :oidc_flow_implicit_id_token_signing_alg

          :oidc_hybrid ->
            :oidc_flow_hybrid_id_token_signing_alg
        end

      astrenv(conf_opt, nil)
    end
  end
end
