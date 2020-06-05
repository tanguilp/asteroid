defmodule Asteroid.Crypto.Key do
  @moduledoc """
  Convenience module to work with cryptographic keys
  """

  import Asteroid.Utils

  alias JOSE.JWK

  defmodule InvalidUseError do
    @moduledoc """
    Error returned when a `t:key_config_entry/0` is invalid because its `:use` is invalid

    `:use` must be one atom specified in `t:key_use`.
    """

    defexception []

    @impl true

    def message(_), do: "Invalid `:use` option (must be one of: [:sign, :enc])"
  end

  defmodule NoSuitableKeyError do
    @moduledoc """
    Error returned when no suitable key was found

    This can be returned, for instance, when trying to find an encryption key for a client that
    has published only signing keys.
    """

    defexception []

    @impl true

    def message(_), do: "no suitable key was found"
  end

  @typedoc """
  A JSON web key in its raw map format

  ## Example

  ```elixir
  %{
    "d" => "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97I\n           jlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0\n           BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn\n           439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYT\n           CBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLh\n           BOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
    "dp" => "BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3Q\n           CLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb\n           34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
    "dq" => "h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa\n           7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-ky\n           NlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
    "e" => "AQAB",
    "kty" => "RSA",
    "n" => "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx\n           HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs\n           D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH\n           SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV\n           MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8\n           NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
    "p" => "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdi\n           YrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPG\n           BY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
    "q" => "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxa\n           ewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA\n           -njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
    "qi" => "IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2o\n           y26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLU\n           W0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
  }
  ```
  """

  @type t :: map()

  @type name :: String.t()

  @typedoc """
  Key config options

  A key config entry can have the following values:
  - `{:pem_file, Keyword.t()}` to load a PEM file stored in the disc, and that includes
  a private key. The options of the `Keyword.t()` are:
    - `:path`: the path to the file. **Mandatory**
    - `:password`: the password of the file to decrypt it, if any
    - `:use`: a `t:key_use/0`. **Mandatory**
    - `:advertise`: a boolean to determine whether the key should be advertised on the
    jwk URI endpoint or not. Defaults to `true`
  - `{:map, Keyword.t()}`: a `JOSE.JWK` converted to a map (using for instance
  `JOSE.JWK.to_map/1`). The options of the `Keyword.t()` are:
    - `:key`: a key as returned by `JOSE.JWK.to_map/1`, for instance:
    `{%{kty: :jose_jwk_kty_oct},
    %{"k" => "P9dGnU_We5thJOOigUGtl00WmubLVAAr1kYsAUP80Sc", "kty" => "oct"}}`. **Mandatory**
    - `:use`: a `t:key_use/0`. **Mandatory**
    - `:advertise`: a boolean to determine whether the key should be advertised on the
    jwk URI endpoint or not. Defaults to `true`
  - `{:auto_gen, any()}`: configuration to automatically generated a key on startup.
  The options of the `Keyword.t()` are:
    - `params`: the parameters that will be passed to `JOSE.JWK.generate_key/1`. **Mandatory**
    - `:use`: a `t:key_use/0`. **Mandatory**
    - `:advertise`: a boolean to determine whether the key should be advertised on the
    jwk URI endpoint or not. Defaults to `true`
  """

  @type key_config_entry ::
          {:pem_file, Keyword.t()}
          | {:map, Keyword.t()}
          | {:auto_gen, Keyword.t()}

  @typedoc """
  Key config entry

  Each key requires a name and its associated config. Keys are referred and used by their
  names.
  """

  @type key_config :: %{required(name()) => key_config_entry()}

  @type key_use :: :sig | :enc

  @typedoc """
  JOSE JWS signature algorithm

  Example of output of `JOSE.JWA.supports/0`:

  ```elixir
  iex> JOSE.JWA.supports() |> Enum.find(fn {:jws, _} -> true; _ -> false end) |> elem(1)
  {:alg,
   ["ES256", "ES384", "ES512", "HS256", "HS384", "HS512", "PS256", "PS384",
    "PS512", "RS256", "RS384", "RS512"]}
  ```
  """

  @jws_alg [
    "ES256",
    "ES384",
    "ES512",
    "Ed25519",
    "Ed25519ph",
    "Ed448",
    "Ed448ph",
    "HS256",
    "HS384",
    "HS512",
    "PS256",
    "PS384",
    "PS512",
    "Poly1305",
    "RS256",
    "RS384",
    "RS512"
  ]

  @type jws_alg :: String.t()

  @typedoc """
  JOSE JWE algorithm

  Example of output of `JOSE.JWA.supports/0`:

  ```elixir
  iex> JOSE.JWA.supports() |> Enum.find(fn {:jwe, _, _, _} -> true; _ -> false end) |> elem(1)
  {:alg,
   ["A128GCMKW", "A128KW", "A192GCMKW", "A192KW", "A256GCMKW", "A256KW",
    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
    "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "RSA1_5",
    "dir"]}
  ```
  """

  @jwe_alg [
    "A128GCMKW",
    "A128KW",
    "A192GCMKW",
    "A192KW",
    "A256GCMKW",
    "A256KW",
    "ECDH-ES",
    "ECDH-ES+A128KW",
    "ECDH-ES+A192KW",
    "ECDH-ES+A256KW",
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW",
    "RSA-OAEP",
    "RSA-OAEP-256",
    "RSA1_5",
    "dir"
  ]

  @type jwe_alg :: String.t()

  @typedoc """
  JOSE JWE encryption algorithm

  Example of output of `JOSE.JWA.supports/0`:

  ```elixir
  iex> JOSE.JWA.supports() |> Enum.find(fn {:jwe, _, _, _} -> true; _ -> false end) |> elem(2)
  {:enc,
   ["A128CBC-HS256", "A128GCM", "A192CBC-HS384", "A192GCM", "A256CBC-HS512",
    "A256GCM"]}
  ```
  """

  @jwe_enc [
    "A128CBC-HS256",
    "A128GCM",
    "A192CBC-HS384",
    "A192GCM",
    "A256CBC-HS512",
    "A256GCM",
    "ChaCha20/Poly1305"
  ]

  @type jwe_enc :: String.t()

  @spec load_from_config!() :: :ok

  def load_from_config!() do
    {cache_module, cache_opts} = astrenv(:crypto_keys_cache)

    if function_exported?(cache_module, :start_link, 1) do
      cache_module.start_link(cache_opts)
    else
      if function_exported?(cache_module, :start, 1) do
        cache_module.start(cache_opts)
      end
    end

    existing_keys =
      for {key_name, _key} <- cache_module.get_all(cache_opts) do
        key_name
      end

    inserted_keys =
      for {key_name, key_config} <- astrenv(:crypto_keys, []) do
        jwk = prepare!(key_config)

        :ok = cache_module.put(key_name, jwk, cache_opts)

        key_name
      end

    for key_to_delete <- existing_keys -- inserted_keys do
      cache_module.delete(key_to_delete, cache_opts)
    end

    :ok
  end

  @spec prepare!(key_config_entry()) :: %JOSE.JWK{}

  def prepare!({:pem_file, params}) do
    if params[:use] == nil do
      raise InvalidUseError
    end

    if params[:password] do
      JWK.from_pem_file(params[:password], params[:path])
      |> set_key_use(params[:use])
      |> set_key_id()
      |> set_advertised(params[:advertise])
    else
      JWK.from_pem_file(params[:path])
      |> set_key_use(params[:use])
      |> set_key_id()
      |> set_advertised(params[:advertise])
    end
  end

  def prepare!({:map, params}) do
    if params[:use] == nil do
      raise InvalidUseError
    end

    JWK.from_map(params[:key])
    |> set_key_use(params[:use])
    |> set_key_id()
    |> set_advertised(params[:advertise])
  end

  def prepare!({:auto_gen, params}) do
    if params[:use] == nil do
      raise InvalidUseError
    end

    JWK.generate_key(params[:params])
    |> set_key_use(params[:use])
    |> set_key_id()
    |> set_advertised(params[:advertise])
  end

  @spec get(name()) :: {:ok, %JOSE.JWK{}} | {:error, Exception.t()}

  def get(key_name) do
    {cache_module, cache_opts} = astrenv(:crypto_keys_cache)

    cache_module.get(key_name, cache_opts)
  end

  @doc """
  Returns all the keys

  Note that it returns the private keys
  """

  @spec get_all() :: [%JOSE.JWK{}]

  def get_all() do
    {cache_module, cache_opts} = astrenv(:crypto_keys_cache)

    for {_key_name, jwk} <- cache_module.get_all(cache_opts) do
      JOSE.JWK.from(jwk)
    end
  end

  @doc """
  Returns all the public keys
  """

  @spec get_all_public() :: [%JOSE.JWK{}]

  def get_all_public() do
    {cache_module, cache_opts} = astrenv(:crypto_keys_cache)

    for {_key_name, jwk} <- cache_module.get_all(cache_opts) do
      JOSE.JWK.to_public(jwk)
    end
  end

  @spec set_key_use(%JOSE.JWK{}, key_use()) :: %JOSE.JWK{}

  def set_key_use(%JOSE.JWK{} = jwk, key_use) when key_use in [:sig, :enc] do
    %{jwk | fields: Map.put(jwk.fields, "use", Atom.to_string(key_use))}
  end

  @spec set_key_ops(%JOSE.JWK{}, [String.t()]) :: %JOSE.JWK{}

  def set_key_ops(%JOSE.JWK{} = jwk, key_ops) when is_list(key_ops) do
    %{jwk | fields: Map.put(jwk.fields, "key_ops", key_ops)}
  end

  @spec set_key_id(%JOSE.JWK{}) :: %JOSE.JWK{}

  def set_key_id(jwk) do
    %{jwk | fields: Map.put(jwk.fields, "kid", JOSE.JWK.thumbprint(jwk))}
  end

  @spec set_key_sig_alg(%JOSE.JWK{}, jws_alg()) :: %JOSE.JWK{}

  def set_key_sig_alg(jwk, jws_alg) when jws_alg in @jws_alg do
    %{jwk | fields: Map.put(jwk.fields, "alg", jws_alg)}
  end

  @spec set_key_enc_alg(%JOSE.JWK{}, jwe_alg()) :: %JOSE.JWK{}

  def set_key_enc_alg(jwk, jwe_alg) when jwe_alg in @jwe_alg do
    %{jwk | fields: Map.put(jwk.fields, "alg", jwe_alg)}
  end

  @spec set_key_enc_enc(%JOSE.JWK{}, jwe_enc()) :: %JOSE.JWK{}

  def set_key_enc_enc(jwk, jwe_enc) when jwe_enc in @jwe_enc do
    %{jwk | fields: Map.put(jwk.fields, "enc", jwe_enc)}
  end

  @spec set_advertised(%JOSE.JWK{}, boolean() | nil) :: %JOSE.JWK{}

  defp set_advertised(jwk, false) do
    %{jwk | fields: Map.put(jwk.fields, "advertise", false)}
  end

  defp set_advertised(jwk, _) do
    %{jwk | fields: Map.put(jwk.fields, "advertise", true)}
  end
end
