defmodule Asteroid.OIDC do
  @moduledoc """
  Types and helper functions for OpenID Connect
  """

  import Asteroid.Config, only: [opt: 1]

  alias Asteroid.{Client, Crypto, OAuth2, Subject}

  defmodule InteractionRequiredError do
    @moduledoc """
    Error returned when an interaction is required

    This error can happen when using the parameter `"prompt"` with the value `"none"`, if user
    interaction is required to retrieve new tokens
    """

    defexception []

    @type t :: %__MODULE__{}

    @impl true

    def message(_) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          "interaction required"

        :normal ->
          "interaction required"

        :minimal ->
          ""
      end
    end
  end

  defmodule LoginRequiredError do
    @moduledoc """
    Error returned when a loging interaction is required

    This error can happen when using the parameter `"prompt"` with the value `"none"`,
    if new loging is required to retrieve tokens.
    """

    defexception []

    @type t :: %__MODULE__{}

    @impl true

    def message(_) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          "login required"

        :normal ->
          "login required"

        :minimal ->
          ""
      end
    end
  end

  defmodule AccountSelectionRequiredError do
    @moduledoc """
    Error returned when account selection is required

    This error can happen when using the parameter `"prompt"` with the value `"none"`, if user
    account selection is required to retrieve new tokens
    """

    defexception []

    @type t :: %__MODULE__{}

    @impl true

    def message(_) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          "account selection required"

        :normal ->
          "account selection required"

        :minimal ->
          ""
      end
    end
  end

  defmodule ConsentRequiredError do
    @moduledoc """
    Error returned when user consent is required

    This error can happen when using the parameter `"prompt"` with the value `"none"`, if user
    consent is required to retrieve new tokens.
    """

    defexception []

    @type t :: %__MODULE__{}

    @impl true

    def message(_) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          "account selection required"

        :normal ->
          "account selection required"

        :minimal ->
          ""
      end
    end
  end

  defmodule IncorrectConfigError do
    @moduledoc """
    Error returned when OpenID Connect is misconfigured
    """

    @enforce_keys [:reason]

    defexception [:reason]

    @type t :: %__MODULE__{
      reason: String.t()
    }

    @impl true
    def message(%{reason: reason}) do
      "incorrect OpenID Connect configuration: " <> reason
    end
  end

  @typedoc """
  Atoms describing the endpoints

  The values refer to:
  - `:userinfo`: `/api/oidc/userinfo`
  """

  @type endpoint :: :userinfo

  @typedoc """
  Nonce
  """

  @type nonce :: String.t()

  @typedoc """
  Claim name, such as `"phone_number"`
  """

  @type claim_name :: String.t()

  @typedoc """
  Authentication Class Reference
  """

  @type acr :: String.t()

  @typedoc """
  Authentication Method Reference
  """

  @type amr :: String.t()

  @doc """
  Returns `true` if OpenID Connect is enabled, `false` otherwise

  OpenID Connect is considered enabled if the `"openid"` scope is configured for one of the
  OpenID Connect flows (authorization code, implicit, or hybrid). For instance, one can
  activate OpenID Connect setting this scope on the root configuration scope:

  ```elixir
  config :asteroid, :scope_config, [scopes: %{"openid" => []}]
  ```
  """

  @spec enabled?() :: boolean()

  def enabled?() do
    "openid" in OAuth2.Scope.scopes_for_flow(:oidc_authorization_code) or
    "openid" in OAuth2.Scope.scopes_for_flow(:oidc_implicit) or
    "openid" in OAuth2.Scope.scopes_for_flow(:oidc_hybrid)
  end

  @doc """
  Verifies that the configuration is correct for OpenID Connect

  It verifies that there is at least one RSA signing key available.

  Checks are performed only if OpenID Connect is enabled (see `enabled?/0`).
  """
  @spec verify_config() :: :ok | {:error, Exception.t()}
  def verify_config() do
    if enabled?() do
      if signing_rsa_key_available?() do
        :ok
      else
        {:error, %IncorrectConfigError{reason:
          "no RSA key configured for signing, which is mandatory per 'OpenID Connect" <>
          "Discovery 1.0 incorporating errata set 1' specification"}}
      end
    else
      :ok
    end
  end

  defp signing_rsa_key_available?() do
    not (
      Crypto.JOSE.public_keys()
      |> JOSEUtils.JWKS.signature_keys()
      |> JOSEUtils.JWKS.filter(kty: "RSA")
      |> Enum.empty?()
    )
  end

  @doc """
  Returns the subject identifier, taking into account the subject type

  If the subject type is `"pairwise"`, it returns the hash of the concatenation of:
  - the hashed sector identifier's host component, or if missing the hasshed host component of
  the unique registered redirect URI for this client
  - the hashed subject id (and not the `"sub"`)
  - the salt configured by the `:oidc_subject_identifier_pairwise_salt` configuration option

  It uses sha256 as the hash function.
  """

  @spec subject_identifier(Subject.t(), Client.t()) :: String.t()

  def subject_identifier(subject, client) do
    subject = Subject.fetch_attributes(subject, ["sub"])

    client =
      Client.fetch_attributes(client, ["subject_type", "sector_identifier_uri", "redirect_uris"])

    if client.attrs["subject_type"] == "pairwise" do
      host_component =
        if client.attrs["sector_identifier_uri"] do
          URI.parse(client.attrs["sector_identifier_uri"]).host
        else
          # in this case all the redirect URIs should have the same host per the
          # OIDC dynamic client registration specification
          [redirect_uri | _] = client.attrs["redirect_uris"]

          URI.parse(redirect_uri).host
        end

      salt = opt(:oidc_subject_identifier_pairwise_salt)

      # we don't follow the OIDC specification here because hashing
      # sha256(a <> b) can result in same hash by carefully choosing a and b,
      # for instance the following pairs will have the same hash:
      # - a = "www.example.com", b = "alcom"
      # - a = "www.example.co", b = "malcom"

      hashed_subject_id = :crypto.hash(:sha256, subject.id)
      hashed_host_component = :crypto.hash(:sha256, host_component)

      :crypto.hash(:sha256, hashed_host_component <> hashed_subject_id <> salt)
      |> Base.url_encode64(padding: false)
    else
      subject.attrs["sub"]
    end
  end
end
