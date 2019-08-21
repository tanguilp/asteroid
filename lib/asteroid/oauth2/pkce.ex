defmodule Asteroid.OAuth2.PKCE do
  @moduledoc false

  alias Asteroid.OAuth2

  @type code_challenge :: String.t()

  @type code_challenge_method :: :plain | :S256

  @typedoc """
  Must be the string representation of `t:code_challenge_method/0`
  """

  @type code_challenge_method_str :: String.t()

  @type code_verifier :: String.t()

  defmodule MalformedCodeChallengeError do
    @moduledoc """
    Exception returned when a code challenge is malformed

    Note that the length is restricted: from 43 to 128 characters.
    """

    defexception [:code_challenge]

    @impl true

    def message(%{code_challenge: code_challenge}) when byte_size(code_challenge) < 43 do
      "Code challenge must be at least 43 characters"
    end

    def message(%{code_challenge: code_challenge}) when byte_size(code_challenge) > 128 do
      "Code challenge must be no more than 128 characters"
    end

    def message(%{code_challenge: code_challenge}) do
      "Invalid character in code challenge `#{code_challenge}`"
    end
  end


  defmodule UnsupportedCodeChallengeMethodError do
    @moduledoc """
    Exception returned when a code challenge method is not supported

    Supported methods are those of `t:code_challenge_method/0` and are activated with the
    #{Asteroid.Config.link_to_option(:oauth2_pkce_allowed_methods)}
    configuration option.
    """

    defexception [:code_challenge_method_str]

    @impl true

    def message(%{code_challenge_method_str: code_challenge_method_str}) do
      "Invalid code challenge `#{code_challenge_method_str}`"
    end
  end

  @doc """
  Returns `:ok` if the code challenge is valid,
  `{:error, %Asteroid.OAuth2.PKCE.InvalidCodeChallengeError{}}` otherwise
  """

  @spec code_challenge_valid?(code_challenge()) :: boolean()

  def code_challenge_valid?(code_challenge) do
    Regex.run(~r<^[\x41-\x5A\x61-\x7A\x30-\x39._~-]{43,128}$>, code_challenge) != nil
  end

  @doc """
  Returns `t:code_challenge_method/0` if the parameter is a valid code challenge method,
  `nil` otherwise
  """

  @spec code_challenge_method_from_string(String.t()) :: atom() | nil

  def code_challenge_method_from_string("plain"), do: :plain
  def code_challenge_method_from_string("S256"), do: :S256
  def code_challenge_method_from_string(_), do: nil

  @doc """
  Returns `:ok` if the code verifier is validated against the code challenge,
  `{:error, %Asteroid.OAuth2.PKCE.InvalidCodeVerifierError{}}` otherwise
  """

  @spec verify_code_verifier(code_verifier(), code_challenge(), code_challenge_method()) ::
  :ok
  | {:error, %OAuth2.InvalidGrantError{}}

  def verify_code_verifier(code_verifier, code_challenge, :plain) do
    if code_verifier == code_challenge do
      :ok
    else
      {:error, OAuth2.InvalidGrantError.exception(
        grant: "code_verifier",
        reason: "invalid code verifier",
        debug_details: "code_verifier: `#{code_verifier}, code_challenge_method: `:plain`)}")}
    end
  end

  def verify_code_verifier(code_verifier, code_challenge, :S256) do
    if Base.url_encode64(:crypto.hash(:sha256, code_verifier), padding: false) == code_challenge 
    do
      :ok
    else
      {:error, OAuth2.InvalidGrantError.exception(
        grant: "code_verifier",
        reason: "invalid code verifier",
        debug_details: "code_verifier: `#{code_verifier}, code_challenge_method: `:S256`)}")}
    end
  end
end
