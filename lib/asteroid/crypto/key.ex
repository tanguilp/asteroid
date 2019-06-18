defmodule Asteroid.Crypto.Key do
  @moduledoc """
  Convenience module to work with cryptographic keys
  """

  import Asteroid.Utils

  alias JOSE.JWK

  defmodule InvalidUseError do
    @moduledoc """
    Error returned when a `t:key_config_entry/0` is invalid because its `:use` is ivnalid

    `:use` must be one atom speicified in `t:key_use`.
    """

    defexception []

    @impl true

    def message(_), do: "Invalid `:use` option (must be one of: [:sign, :enc])"
  end

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
  JOSE encryption or signature algorithm

  Example of output of `JOSE.JWA.supports/0`:

  ```elixir
  iex> JOSE.JWA.supports()      
  [
    {:jwe,
     {:alg,
      ["A128GCMKW", "A128KW", "A192GCMKW", "A192KW", "A256GCMKW", "A256KW",
       "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
       "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "RSA1_5",
       "dir"]},
     {:enc,
      ["A128CBC-HS256", "A128GCM", "A192CBC-HS384", "A192GCM", "A256CBC-HS512",
       "A256GCM"]}, {:zip, ["DEF"]}},
    {:jwk, {:kty, ["EC", "OKP", "RSA", "oct"]}, {:kty_OKP_crv, []}},
    {:jws,
     {:alg,
      ["ES256", "ES384", "ES512", "HS256", "HS384", "HS512", "PS256", "PS384",
       "PS512", "RS256", "RS384", "RS512"]}}
  ]
  ```
  """

  @type alg :: String.t()

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

  @spec get_all_public() :: [%JOSE.JWK{}]

  def get_all_public() do
    {cache_module, cache_opts} = astrenv(:crypto_keys_cache)

    for {_key_name, jwk} <- cache_module.get_all(cache_opts) do
      JOSE.JWK.to_public(jwk)
    end
  end

  @spec set_key_use(%JOSE.JWK{}, key_use()) :: %JOSE.JWK{}

  defp set_key_use(%JOSE.JWK{} = jwk, key_use) when key_use in [:sig, :enc] do
    %{jwk | fields: Map.put(jwk.fields, "use", Atom.to_string(key_use))}
  end

  @spec set_key_id(%JOSE.JWK{}) :: %JOSE.JWK{}

  defp set_key_id(jwk) do
    %{jwk | fields: Map.put(jwk.fields, "kid", JOSE.JWK.thumbprint(jwk))}
  end

  @spec set_advertised(%JOSE.JWK{}, boolean() | nil) :: %JOSE.JWK{}

  defp set_advertised(jwk, false) do
    %{jwk | fields: Map.put(jwk.fields, "advertise", false)}
  end

  defp set_advertised(jwk, _) do
    %{jwk | fields: Map.put(jwk.fields, "advertise", true)}
  end
end
