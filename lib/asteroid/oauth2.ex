defmodule Asteroid.OAuth2 do
  @moduledoc """
  Types and helper functions for OAuth2
  """

  import Asteroid.Utils

  defmodule UnsupportedGrantTypeError do
    @moduledoc """
    Error returned when the grant type is unsupported or unknown
    """

    defexception [:grant_type]

    @type t :: %__MODULE__{
      grant_type: String.t()
    }

    @impl true

    def message(%{grant_type: grant_type}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Unsupported grant type `#{grant_type}` (enabled grant types are: " <>
          "#{inspect astrenv(:oauth2_grant_types_enabled, [])})"

        :normal ->
          "Unsupported grant type `#{grant_type}`"

        :minimal ->
          ""
      end
    end
  end

  defmodule UnsupportedResponseTypeError do
    @moduledoc """
    Error returned when the grant type is unsupported or unknown
    """

    defexception [:response_type]

    @type t :: %__MODULE__{
      response_type: String.t()
    }

    @impl true

    def message(%{response_type: response_type}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Unsupported response type `#{response_type} (enabled grant types are: " <>
          "#{inspect astrenv(:oauth2_response_types_enabled, [])})"

        :normal ->
          "Unsupported response type `#{response_type}`"

        :minimal ->
          ""
      end
    end
  end

  defmodule InvalidGrantError do
    @moduledoc """
    Error returned for invalid grants (refresh token, password, authorization code,
    PKCE code verifier...)
    """

    @enforce_keys [:grant, :reason]

    defexception [:grant, :reason, :debug_details]

    @type t :: %__MODULE__{
      grant: String.t(),
      reason: String.t(),
      debug_details: String.t()
    }

    @impl true

    def message(%{grant: grant, reason: reason, debug_details: debug_details}) do
      case astrenv(:api_error_response_verbosity) do
        :debug when not is_nil(debug_details) ->
          "Invalid grant `#{grant}`: #{reason} (#{debug_details})"

        :debug when is_nil(debug_details) ->
          "Invalid grant `#{grant}`: #{reason}"

        :normal ->
          "Invalid grant `#{grant}`: #{reason}"

        :minimal ->
          ""
      end
    end
  end

  defmodule AccessDeniedError do
    @moduledoc """
    Error returned when the access was denied either because of the user not consenting or
    the server's policy inadequation with the request (eg. scopes)
    """

    @enforce_keys [:reason]

    defexception [:reason]

    @type t :: %__MODULE__{
      reason: String.t()
    }

    @impl true

    def message(%{reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Access denied: " <> reason

        :normal ->
          "Access denied: " <> reason

        :minimal ->
          ""
      end
    end
  end

  defmodule ServerError do
    @moduledoc """
    Error returned in case of undetermined server error
    """

    @enforce_keys [:reason]

    defexception [:reason, :stacktrace]

    @type t :: %__MODULE__{
      reason: String.t(),
      stacktrace: Exception.stacktrace()
    }

    @impl true

    def message(%{reason: reason} = e) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Server error: #{reason} (stacktrace: #{inspect e.stacktrace})"

        :normal ->
          "Server error: " <> reason

        :minimal ->
          ""
      end
    end
  end

  defmodule TemporarilyUnavailableError do
    @moduledoc """
    Error returned when the server is unavailable
    """

    @enforce_keys [:reason]

    defexception [:reason]

    @type t :: %__MODULE__{
      reason: String.t()
    }

    @impl true

    def message(%{reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "Temporary unavailable: " <> reason

        :normal ->
          "Temporary unavailable: " <> reason

        :minimal ->
          ""
      end
    end
  end

  @typedoc """
  OAuth2 grant types
  """

  @type grant_type ::
  :authorization_code
  | :implicit
  | :password
  | :client_credentials
  | :refresh_token
  | :"urn:ietf:params:oauth:grant-type:device_code"

  @typedoc """
  String representation of `t:grant_type/0`

  Must be the string conversion of its corresponding `t:grant_type/0` atom.
  """

  @type grant_type_str :: String.t()

  @type flow ::
  :ropc
  | :client_credentials
  | :authorization_code
  | :implicit
  | :device_authorization

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

  @typedoc """
  Atoms describing the endpoints

  The values refer to:
  - `:authorize`: `/authorize`
  - `:device`: `/device`
  - `:token`: `/api/oauth2/token`
  - `:introspect`: `/api/oauth2/introspect`
  - `:revoke`: `/api/oauth2/revoke`
  - `:register`: `/api/oauth2/register`
  - `:device_authorization`: `/api/oauth2/device_authorization`
  """

  @type endpoint ::
  :authorize                  # web flow for the authorization code or implicit flow
  | :device                   # web flow for the device authorization flow
  | :token
  | :introspect
  | :revoke
  | :register
  | :device_authorization

  @doc """
  Converts a `t:grant_type_str/0` to a `t:grant_type/0`

  Returns `{:ok, grant_type()}` if the grant type is supported,
  `{:error, %Asteroid.OAuth2.UnsupportedGrantTypeError{}}` otherwise.
  """

  @spec to_grant_type(String.t()) ::
  {:ok, grant_type()}
  | {:error, %__MODULE__.UnsupportedGrantTypeError{}}

  def to_grant_type("authorization_code"), do: {:ok, :authorization_code}
  def to_grant_type("implicit"), do: {:ok, :implicit}
  def to_grant_type("password"), do: {:ok, :password}
  def to_grant_type("client_credentials"), do: {:ok, :client_credentials}
  def to_grant_type("refresh_token"), do: {:ok, :refresh_token}
  def to_grant_type(param), do: {:error, __MODULE__.UnsupportedGrantTypeError.exception(grant_type: param)}

  @doc """
  Converts a `t:grant_type_str/0` to a `t:grant_type/0`

  Returns `t:grant_type/0` if it exists or raises a
  `%Asteroid.OAuth2.UnsupportedGrantTypeError{}` otherwise.
  """

  @spec to_grant_type!(String.t()) :: grant_type()

  def to_grant_type!(grant_type_str) do
    case to_grant_type(grant_type_str) do
      {:ok, grant_type} ->
        grant_type

      {:error, e} ->
        raise e
    end
  end

  @doc """
  Returns the flow associated to a grant type, or `nil`

  The conversion is performed in conformance to the following table:

  |      Grant type        |       Flow            |
  |:----------------------:|:---------------------:|
  | `:authorization_code`  | `:authorization_code` |
  | `:implicit`            | `:implicit`           |
  | `:password`            | `:ropc`               |
  | `:client_credentials`  | `:client_credentials` |

  """

  @spec grant_type_to_flow(grant_type()) :: flow() | nil

  def grant_type_to_flow(:authorization_code), do: :authorization_code
  def grant_type_to_flow(:implicit), do: :implicit
  def grant_type_to_flow(:password), do: :ropc
  def grant_type_to_flow(:client_credentials), do: :client_credentials
  def grant_type_to_flow(_), do: nil

  @doc """
  Converts a `t:response_type_str/0` to a `t:response_type/0`

  Returns `{:ok, response_type()}` if the response type is supported,
  `{:error, %Asteroid.OAuth2.UnsupportedResponseTypeError{}}` otherwise.
  """

  @spec to_response_type(String.t()) ::
  {:ok, response_type()}
  | {:error, %UnsupportedResponseTypeError{}}

  def to_response_type("code"), do: {:ok, :code}
  def to_response_type("token"), do: {:ok, :token}
  def to_response_type(val), do: {:error, UnsupportedResponseTypeError.exception(response_type: val)}

  @doc """
  Converts a `t:response_type_str/0` to a `t:response_type/0`

  Returns `t:response_type/0` if it exists or raises a
  `%Asteroid.OAuth2.UnsupportedResponseTypeError{}` otherwise.
  """

  @spec to_response_type!(String.t()) :: response_type()

  def to_response_type!(response_type_str) do
    case to_response_type(response_type_str) do
      {:ok, response_type} ->
        response_type

      {:error, e} ->
        raise e
    end
  end

  @doc """
  Returns `:ok` if the grant type is enabled,
  `{:error, %Asteroid.OAuth2.UnsupportedGrantTypeError{}}` otherwise

  Uses the #{Asteroid.Config.link_to_option(:oauth2_grant_types_enabled)} configuration
  option's value.
  """

  @spec grant_type_enabled?(grant_type()) ::
  :ok
  | {:error, %UnsupportedGrantTypeError{}}

  def grant_type_enabled?(grant_type) do
    if grant_type in astrenv(:oauth2_grant_types_enabled, []) do
      :ok
    else
      {:error, UnsupportedGrantTypeError.exception(grant_type: Atom.to_string(grant_type))}
    end
  end

  @doc """
  Returns `:ok` if the grant type is enabled,
  `{:error, %Asteroid.OAuth2.UnsupportedResponseTypeError}` otherwise

  Uses the #{Asteroid.Config.link_to_option(:oauth2_response_types_enabled)} configuration
  option's value.
  """

  @spec response_type_enabled?(response_type()) ::
  :ok
  | {:error, %UnsupportedResponseTypeError{}}

  def response_type_enabled?(response_type) do
    if response_type in astrenv(:oauth2_response_types_enabled, []) do
      :ok
    else
      {:error,
        UnsupportedResponseTypeError.exception(response_type: Atom.to_string(response_type))}
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
    AsteroidWeb.Router.Helpers.url(AsteroidWeb.Endpoint)
  end
end
