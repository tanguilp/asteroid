defmodule AsteroidWeb.API.OIDC.UserinfoController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.Context
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias Asteroid.OIDC
  alias Asteroid.Subject
  alias Asteroid.Token.AccessToken

  @scope_claims_mapping %{
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

  def show(conn, _params) do
    with {:ok, access_token} <- AccessToken.get(APIac.metadata(conn)["bearer"]),
         claims <- claims_for_access_token(access_token),
         {:ok, client} <-
           Client.load_from_unique_attribute("client_id", access_token.data["client_id"]),
         {:ok, subject} <-
           Subject.load_from_unique_attribute("sub", access_token.data["sub"], attributes: claims)
    do
      ctx =
        %{}
        |> Map.put(:endpoint, :userinfo)
        |> Map.put(:client, client)
        |> Map.put(:subject, subject)
        |> Map.put(:access_token, access_token)

      result_claims =
        Enum.reduce(
          claims,
          %{},
          fn
            claim, acc ->
              put_if_not_nil(acc, claim, subject.attrs[claim])
          end
        )
        |> put_iss_aud_if_signed(ctx)
        |> astrenv(:oidc_endpoint_userinfo_before_send_resp_callback).(ctx)
        |> maybe_sign(ctx)
        |> maybe_encrypt(ctx)

      case result_claims do
        %{} ->
          conn
          |> put_status(200)
          |> put_resp_content_type("application/json")
          |> astrenv(:oidc_endpoint_userinfo_before_send_conn_callback).(ctx)
          |> json(result_claims)

        _ ->
          conn
          |> put_status(200)
          |> put_resp_content_type("application/jwt")
          |> astrenv(:oidc_endpoint_userinfo_before_send_conn_callback).(ctx)
          |> text(result_claims)
      end
    else
      {:error, err} ->
        AsteroidWeb.Error.respond_api(conn, OAuth2.ServerError.exception(reason: inspect(err)))
    end
  rescue
    e ->
      conn
      |> put_status(500)
      |> text(Exception.message(e))
  end

  @spec claims_for_access_token(AccessToken.t()) :: [String.t()]

  defp claims_for_access_token(access_token) do
    Enum.reduce(
      access_token.data["scope"] || [],
      ["sub"], # The sub (subject) Claim MUST always be returned in the UserInfo Response.
      fn
        scope, acc when scope in unquote(Map.keys(@scope_claims_mapping)) ->
          @scope_claims_mapping[scope] ++ acc

        _, acc ->
          acc
      end
    )
  end

  @spec put_iss_aud_if_signed(map(), Context.t()) :: map()

  defp put_iss_aud_if_signed(claims, %{client: client} = ctx) do
    if OIDC.Userinfo.sign_response?(ctx) do
      client = Client.fetch_attributes(client, ["client_id"])

      claims
      |> Map.put("iss", OAuth2.issuer())
      |> Map.put("aud", client.attrs["client_id"])
    else
      claims
    end
  end

  @spec maybe_sign(map(), Context.t()) :: String.t() | map()

  defp maybe_sign(claims, ctx) do
    if OIDC.Userinfo.sign_response?(ctx) do
      signing_key = astrenv(:oidc_endpoint_userinfo_signing_key)
      signing_alg = astrenv(:oidc_endpoint_userinfo_signing_alg)

      {:ok, jwk} = Crypto.Key.get(signing_key)

      if signing_alg do
        jws = JOSE.JWS.from_map(%{"alg" => signing_alg})

        JOSE.JWT.sign(jwk, jws, claims)
        |> JOSE.JWS.compact
        |> elem(1)
      else
        JOSE.JWT.sign(jwk, claims)
        |> JOSE.JWS.compact
        |> elem(1)
      end
    else
      claims
    end
  end

  @spec maybe_encrypt(map() | String.t(), Context.t()) :: String.t() | map()

  defp maybe_encrypt(claims_or_jws, %{client: client} = ctx) do
    if OIDC.Userinfo.encrypt_response?(ctx) do
      case Client.get_jwks(client) do
        {:ok, keys} ->
          jwe_alg_supported =
            astrenv(:oidc_endpoint_userinfo_encryption_alg_values_supported) || []
          jwe_enc_supported =
            astrenv(:oidc_endpoint_userinfo_encryption_enc_values_supported) || []

          eligible_jwks =
            keys
            |> Enum.map(&JOSE.JWK.from/1)
            |> Enum.filter(
              fn
                %JOSE.JWK{fields: fields} ->
                  (fields["use"] == "enc" or fields["use"] == nil) and
                  (fields["key_ops"] == "encrypt" or fields["key_ops"] == nil) and
                  (fields["alg"] in jwe_alg_supported or fields["alg"] == nil)
              end
            )

          case eligible_jwks do
            [key | _] ->
              payload =
                case claims_or_jws do
                  %{} ->
                    Jason.encode!(claims_or_jws)
                  
                  _ ->
                    claims_or_jws
                end

              #FIXME: determine how to select alg and enc for encryption
              alg = key.fields["alg"] || List.first(jwe_alg_supported)
              enc = List.first(jwe_enc_supported)

              JOSE.JWE.block_encrypt(key, payload, %{"alg" => alg, "enc" => enc})
              |> JOSE.JWE.compact()
              |> elem(1)

              [] ->
                raise Crypto.Key.NoSuitableKeyError
          end

        {:error, _} ->
          raise Crypto.Key.NoSuitableKeyError
      end
    else
      claims_or_jws
    end
  end
end
