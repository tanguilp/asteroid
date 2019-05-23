defmodule Asteroid.OAuth2 do
  @moduledoc """
  Types and helper functions for OAuth2
  """

  import Asteroid.Utils

  @typedoc """
  OAuth2 grant types
  """

  @type grant_type ::
  :authorization_code
  | :password
  | :client_credentials
  | :refresh_token

  @typedoc """
  String representation of `t:grant_type/0`

  Must be the string conversion of its corresponding `t:grant_type/0` atom.
  """

  @type grant_type_str :: String.t()

  @type flow :: :ropc | :client_credentials | :authorization_code | :implicit

  @typedoc """
  String representation of a `t:flow()/0`

  Must be the string conversion of its corresponding `t:flow/0` atom.
  """

  @type flow_str :: String.t()

  @type response_type :: :code | :token

  @typedoc """
  String representation of a `t:response_type/0`

  Must be the string conversion of its corresponding `t:response_type/0`
  """

  @type response_type_str :: String.t()

  @type endpoint :: :authorize | :token | :introspect | :revoke

  @doc """
  Returns `:ok` if the grant type is enabled, `{:error, :grant_type_disabled}` otherwise

  Uses the #{Asteroid.Config.link_to_option(:oauth2_grant_types_enabled)} configuration
  option's value.
  """

  @spec grant_type_enabled?(grant_type()) :: :ok | {:error, :grant_type_disabled}

  def grant_type_enabled?(grant_type) do
    if grant_type in astrenv(:oauth2_grant_types_enabled, []) do
      :ok
    else
      {:error, :grant_type_disabled}
    end
  end

  @doc """
  Returns `:ok` if the grant type is enabled, `{:error, :response_type_disabled}` otherwise

  Uses the #{Asteroid.Config.link_to_option(:oauth2_response_types_enabled)} configuration
  option's value.
  """

  @spec response_type_enabled?(response_type()) :: :ok | {:error, :response_type_disabled}

  def response_type_enabled?(response_type) do
    if response_type in astrenv(:oauth2_response_types_enabled, []) do
      :ok
    else
      {:error, :response_type_disabled}
    end
  end

  @doc """
  Converts a `t:flow_str/0` to a `t:flow/0`
  """

  @spec to_flow(String.t()) :: flow()

  def to_flow("ropc"), do: :ropc
  def to_flow("client_credentials"), do: :client_credentials
  def to_flow("authorization_code"), do: :authorization_code

  @doc """
  Returns the issuer

  The issuer is the concatenation of the url and the base path (in case there is one, for
  instance when using Asteroid behing a reverse proxy).
  """

  @spec issuer() :: String.t()

  def issuer() do
    AsteroidWeb.Endpoint.url() <> to_string(astrenv(AsteroidWeb.Endpoint)[:url][:path])
  end
end
