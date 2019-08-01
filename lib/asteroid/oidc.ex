defmodule Asteroid.OIDC do
  @moduledoc """
  Types and helper functions for OpenID Connect
  """

  import Asteroid.Utils

  defmodule InteractionRequiredError do
    @moduledoc """
    Error returned when an interaction is required

    This error can happen when using the parameter `"prompt"` with the value `"none"`, if user
    interaction is required to retrieve new tokens
    """

    defexception []

    @type t :: %__MODULE__{
    }

    @impl true

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
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

    @type t :: %__MODULE__{
    }

    @impl true

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
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

    @type t :: %__MODULE__{
    }

    @impl true

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
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

    @type t :: %__MODULE__{
    }

    @impl true

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "account selection required"

        :normal ->
          "account selection required"

        :minimal ->
          ""
      end
    end
  end

  @typedoc """
  Nonce
  """

  @type nonce :: String.t()

  @typedoc """
  Authentication Class Reference
  """

  @type acr :: String.t()

  @typedoc """
  Authentication Method Reference
  """

  @type amr :: String.t()
end
