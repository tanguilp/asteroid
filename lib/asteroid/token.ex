defmodule Asteroid.Token do
  require Logger
  import Asteroid.Utils

  @moduledoc """
  """

  @token_types [:access_token, :refresh_token]

  @typedoc """
  The different formats a token may have once serialized
  """
  @type serialization_format ::
    :opaque
    | :jwt
    | :saml1
    | :saml2

  @spec auto_install_from_config() :: :ok
  def auto_install_from_config() do
    for token_type <- @token_types do
      config_key = String.to_atom("store_" <> Atom.to_string(token_type))

      case astrenv(config_key, nil) do
        nil ->
          Logger.warn("No configuration for `#{token_type}` store")

        conf ->
          if conf[:autostart] == true do
            conf[:impl].install()
          end
      end
    end
  end

  @spec auto_start_from_config() :: :ok
  def auto_start_from_config() do
    for token_type <- @token_types do
      config_key = String.to_atom("store_" <> Atom.to_string(token_type))

      case astrenv(config_key, nil) do
        nil ->
          Logger.warn("No configuration for `#{token_type}` store")

        conf ->
          if conf[:autostart] == true do
            conf[:impl].start()
          end
      end
    end
  end

end
