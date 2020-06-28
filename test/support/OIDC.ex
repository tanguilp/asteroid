defmodule TestOIDCHelpers do
  def token_hash(signing_alg, token) do
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
end
