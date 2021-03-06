defmodule Asteroid.OAuth2.Endpoint do
  @moduledoc """
  Util functions to work with OAuth2 endpoints
  """

  import Asteroid.Utils

  @type auth_method :: :none | :client_secret_basic | :tls_client_auth

  @typedoc """
  String representation of an endpoint client authentication method

  Must be the strict conversion of a `t:auth_method/0` atom
  """

  @type auth_method_str :: String.t()

  @doc """
  Returns the authentication methods supported by the token endpoint

  It scans the following configuration options and tries to find known `APIac.Authenticator`
  modules to determine autyhentication method support:
  - `:api_oauth2_plugs`
  - `:api_oauth2_endpoint_token_plugs`

  It also adds `:none` to the list since public client are authorized to access the token
  endpoint without authentication.
  """

  @spec token_endpoint_auth_methods_supported() :: [auth_method()]

  def token_endpoint_auth_methods_supported() do
    Enum.reduce(
      astrenv(:api_oauth2_plugs, []) ++ astrenv(:api_oauth2_endpoint_token_plugs, []),
      MapSet.new([:none]),
      fn
        {module, _options}, acc ->
          case apiac_authenticator_to_auth_method(module) do
            nil ->
              acc

            apiac_authenticator ->
              MapSet.put(acc, apiac_authenticator)
          end
      end
    )
    |> MapSet.to_list()
  end

  @doc """
  Returns the authentication methods supported by the revocation endpoint

  It scans the following configuration options and tries to find known `APIac.Authenticator`
  modules to determine autyhentication method support:
  - `:api_oauth2_plugs`
  - `:api_oauth2_endpoint_revoke_plugs`
  """

  @spec revoke_endpoint_auth_methods_supported() :: [auth_method()]

  def revoke_endpoint_auth_methods_supported() do
    Enum.reduce(
      astrenv(:api_oauth2_plugs, []) ++ astrenv(:api_oauth2_endpoint_revoke_plugs, []),
      MapSet.new(),
      fn
        {module, _options}, acc ->
          case apiac_authenticator_to_auth_method(module) do
            nil ->
              acc

            apiac_authenticator ->
              MapSet.put(acc, apiac_authenticator)
          end
      end
    )
    |> MapSet.to_list()
  end

  @doc """
  Returns the authentication methods supported by the introspection endpoint

  It scans the following configuration options and tries to find known `APIac.Authenticator`
  modules to determine autyhentication method support:
  - `:api_oauth2_plugs`
  - `:api_oauth2_endpoint_introspect_plugs`
  """

  @spec introspect_endpoint_auth_methods_supported() :: [auth_method()]

  def introspect_endpoint_auth_methods_supported() do
    Enum.reduce(
      astrenv(:api_oauth2_plugs, []) ++ astrenv(:api_oauth2_endpoint_introspect_plugs, []),
      MapSet.new(),
      fn
        {module, _options}, acc ->
          case apiac_authenticator_to_auth_method(module) do
            nil ->
              acc

            apiac_authenticator ->
              MapSet.put(acc, apiac_authenticator)
          end
      end
    )
    |> MapSet.to_list()
  end

  @doc """
  Returns the `t:auth_method/0` of an `APIac.Authenticator` or `nil` if it is not recognized

  The mapping is as follows:
  - `APIacAuthBasic`: `:client_secret_basic`
  - `APIacAuthMTLS`: `:tls_client_auth`
  """

  @spec apiac_authenticator_to_auth_method(module()) :: auth_method | nil

  def apiac_authenticator_to_auth_method(APIacAuthBasic), do: :client_secret_basic
  def apiac_authenticator_to_auth_method(APIacAuthClientSecretPost), do: :client_secret_post
  def apiac_authenticator_to_auth_method(APIacAuthMTLS), do: :tls_client_auth
  def apiac_authenticator_to_auth_method(_), do: nil
end
