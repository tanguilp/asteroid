defmodule AsteroidWeb.API.OIDC.UserinfoController do
  @moduledoc false

  use AsteroidWeb, :controller

  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias Asteroid.OIDC
  alias Asteroid.Subject
  alias Asteroid.Token.AccessToken

  @client_userinfo_crypto_fields [
    "userinfo_signed_response_alg",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc"
  ]

  def show(conn, _params) do
    with {:ok, access_token} <- AccessToken.get(APIac.metadata(conn)["bearer"]),
         claims <- claims_for_access_token(access_token),
         {:ok, client} <-
           Client.load_from_unique_attribute("client_id", access_token.data["client_id"]),
         {:ok, subject} <-
           Subject.load_from_unique_attribute("sub", access_token.data["sub"], attributes: claims)
    do
      client = Client.fetch_attributes(client, @client_userinfo_crypto_fields)

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
        |> Map.put("sub", astrenv(:oidc_subject_identifier_callback).(subject, client))
        |> put_iss_aud_if_signed(client)
        |> astrenv(:oidc_endpoint_userinfo_before_send_resp_callback).(ctx)
        |> maybe_sign(client)
        |> maybe_encrypt(client)

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
      "azp",
    ]

    claims_from_param =
      (access_token.data["__asteroid_oidc_claims"]["userinfo"] || %{})
      |> Map.keys()
      |> Enum.filter(&(&1 not in claims_to_exclude))

    Enum.reduce(
      access_token.data["scope"] || [],
      claims_from_param,
      fn
        scope, acc when scope in unquote(Map.keys(OIDC.Userinfo.scope_claims_mapping())) ->
          OIDC.Userinfo.scope_claims_mapping()[scope] ++ acc

        _, acc ->
          acc
      end
    )
  end

  @spec put_iss_aud_if_signed(map(), Client.t()) :: map()

  defp put_iss_aud_if_signed(claims, client) do
    if client.attrs["userinfo_signed_response_alg"] do

      claims
      |> Map.put("iss", OAuth2.issuer())
      |> Map.put("aud", client.attrs["client_id"])
    else
      claims
    end
  end

  @spec maybe_sign(map(), Client.t()) :: String.t() | map()

  defp maybe_sign(claims, client) do
    signing_alg = client.attrs["userinfo_signed_response_alg"]

    if signing_alg do
      eligible_jwks =
        Crypto.Key.get_all()
        |> Enum.filter(
          fn
            %JOSE.JWK{fields: fields} ->
              fields["use"] == "sig" and
              (fields["key_ops"] in ["sign"] or fields["key_ops"] == nil) and
              (fields["alg"] == signing_alg or fields["alg"] == nil)
          end
        )

      case eligible_jwks do
        [jwk | _] ->
          JOSE.JWT.sign(jwk, JOSE.JWS.from_map(%{"alg" => signing_alg}), claims)
          |> JOSE.JWS.compact
          |> elem(1)

        [] ->
          raise Crypto.Key.NoSuitableKeyError
      end
    else
      claims
    end
  end

  @spec maybe_encrypt(map() | String.t(), Client.t()) :: String.t() | map()

  defp maybe_encrypt(claims_or_jws, client) do
    encryption_alg = client.attrs["userinfo_encrypted_response_alg"]

    if encryption_alg do
      case Client.get_jwks(client) do
        {:ok, keys} ->
          eligible_jwks =
            keys
            |> Enum.map(&JOSE.JWK.from/1)
            |> Enum.filter(
              fn
                %JOSE.JWK{fields: fields} ->
                  (fields["use"] == "enc" or fields["use"] == nil) and
                  (fields["key_ops"] == "encrypt" or fields["key_ops"] == nil) and
                  (fields["alg"] == encryption_alg or fields["alg"] == nil)
              end
            )

          case eligible_jwks do
            [jwk | _] ->
              payload =
                case claims_or_jws do
                  %{} ->
                    Jason.encode!(claims_or_jws)

                  _ ->
                    claims_or_jws
                end

              encryption_enc = client.attrs["userinfo_encrypted_response_enc"] || "A128CBC-HS256"

              JOSE.JWE.block_encrypt(
                jwk,
                payload,
                %{"alg" => encryption_alg, "enc" => encryption_enc})
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
