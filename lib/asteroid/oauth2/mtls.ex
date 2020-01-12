defmodule Asteroid.OAuth2.MTLS do
  @moduledoc """
  Utils functions to work with MTLS
  """

  alias Asteroid.Client

  import Asteroid.Utils

  @typedoc """
  The parameter to be used to check against a certificate when using PKI mutual-TLS method
  """

  @type pki_auth_param ::
  :tls_client_auth_subject_dn
  | :tls_client_auth_san_dns
  | :tls_client_auth_san_uri
  | :tls_client_auth_san_ip
  | :tls_client_auth_san_email

  @mtls_possible_endpoint_config_opts [
    :api_oauth2_plugs,
    :api_oauth2_endpoint_token_plugs,
    :api_oauth2_endpoint_introspect_plugs,
    :api_oauth2_endpoint_revoke_plugs,
    :api_oauth2_endpoint_register_plugs,
    :api_oauth2_endpoint_device_authorization_plugs,
    :api_request_object_plugs
  ]

  @doc false
  @spec start_mtls_aliases_endpoint?() :: boolean()
  def start_mtls_aliases_endpoint?() do
    case astrenv(:oauth2_mtls_start_endpoint, :auto) do
      true ->
        true

      false ->
        false

      :auto ->
        in_use?(native: true)
    end
  end

  @doc """
  Determines if MTLS is in use

  It scans the following configuration options looking for the use of at least one
  `APIacAuthMTLS` plug:

  ```elixir
  #{inspect(@mtls_possible_endpoint_config_opts, pretty: true)}
  ```

  It accepts the following options:
  - `:native`: if set to `true`, returns `true` only if one `APIacAuthMTLS` uses direct Asteroid
  TLS client peer information (and not a header), which means Asteroi is the TLS termination
  endpoint. Defaults to `false`
  """
  @spec in_use?(Keyword.t()) :: boolean()
  def in_use?(opts \\ []) do
    Enum.any?(@mtls_possible_endpoint_config_opts, &uses?(&1, opts))
  end

  @doc """
  Returns `true` if an endpoint supports MTLS, `false` otherwise

  It accepts the following options:
  - `:native`: if set to `true`, returns `true` only if the `APIacAuthMTLS` uses direct Asteroid
  TLS client peer information (and not a header), which means Asteroi is the TLS termination
  endpoint. Defaults to `false`

  Takes a configuration option of an endpoint's plugs as a parameter.

      iex> Asteroid.OAuth2.MTLS.uses?(:api_oauth2_endpoint_token_plugs)
      true
      iex> Asteroid.OAuth2.MTLS.uses?(:api_oauth2_endpoint_introspect_plugs)
      false

  Does not inspect parent configuration options.
  """
  @spec uses?(atom(), Keyword.t()) :: boolean()
  def uses?(config_option, opts \\ []) do
    Enum.any?(
      astrenv(config_option, []),
      fn
        {APIacAuthMTLS, apiac_opts} ->
          if opts[:native] do
            apiac_opts[:cert_data_origin] in [:native, nil]
          else
            true
          end

        {_, _} ->
          false
      end
    )
  end

  @doc """
  Callback implementation of PKI mutual-TLS method for APIacAuthMTLS
  """
  @spec pki_mutual_tls_method(String.t()) :: {pki_auth_param(), String.t()} | nil
  def pki_mutual_tls_method(client_id) do
    attrs = [
      "tls_client_auth_subject_dn",
      "tls_client_auth_san_dns",
      "tls_client_auth_san_uri",
      "tls_client_auth_san_ip",
      "tls_client_auth_san_email"
    ]

    Client.load_from_unique_attribute(
      "client_id",
      client_id,
      ["token_endpoint_auth_method"] ++ attrs
    )
    |> case do
      {:ok, client} ->
        if client.attrs["token_endpoint_auth_method"] == "tls_client_auth" do
          Enum.find_value(
            client.attrs,
            fn {k, v} -> if k in attrs, do: {String.to_atom(k), v} end
          )
        end

      {:error, _} ->
        nil
    end
  end

  @doc """
  Callback implementation of self-signed certificate mutual-TLS method for APIacAuthMTLS

  This functions only uses certificates in the `"x5c"` attribute (and not the JWK key) and
  only returns the certificates whose JWK key `"use"` attribute is `nil` or `"sign"`.
  """
  @spec self_signed_mutual_tls_method(String.t()) :: [binary()]
  def self_signed_mutual_tls_method(client_id) do
    case Client.load_from_unique_attribute("client_id", client_id, []) do
      {:ok, client} ->
        client
        |> Client.get_jwks()
        |> Enum.filter(fn jwk -> jwk["x5c"] end)
        |> Enum.filter(fn jwk -> jwk["use"] in ["sig", nil] end)
        |> Enum.map(fn jwk -> jwk["x5c"] end)
        |> Enum.map(fn cert_chain -> List.first(cert_chain) end)
        |> Enum.map(&Base.decode64!/1)

      {:error, _} ->
        []
    end
  end
end
