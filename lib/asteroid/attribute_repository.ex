defmodule Asteroid.AttributeRepository do
  @moduledoc """
  Types for attribute repositories

  The pair composed of a `id` and an `attribute` constitute a unique value in an
  attribute repository. It can be nonexistent or existent, but there can not be
  several values for this pair.
  """

  @typedoc """
  The **unique** and **immutable** identifier of an object of an attribute repository
  """
  @type id :: String.t()

  @typedoc """
  """
  @type attribute :: String.t()

  @typedoc """
  Value associated to an attribute
  """
  @type value :: any()

  @typedoc """
  Configuration passed to all attribute repository functions
  """
  @type config :: Keyword.t()

  defmodule ReadError do
    defexception message: "Unknown read error"

    @moduledoc """
    Error returned for technical read errors
    """
  end

  defmodule WriteError do
    defexception message: "Unknown write error"

    @moduledoc """
    Error returned for technical write errors
    """
  end

  #for behaviour <- [Configure, Read, Write, Search] do
  #  name =
  #    behaviour
  #    |> Atom.to_string()
  #    |> String.split(".")
  #    |> List.last()
  #    |> String.downcase()
  #    |> (fn str -> "supports_" <> str <> "?" end).()
  #    |> String.to_atom()

  # def unquote(name)(), do: true
  #end

  @doc """
  Auto install all attribute repositories from the configuration file for
  repositories that have the `:autoinstall` key set to `true`

  Example configuration:
  ```elixir
  config :asteroid, :attribute_repositories,
  [
    [
      impl: Asteroid.AttributeRepository.Impl.Mnesia,
      autoinstall: true,
      autostart: true,
      opts:
      [
        table: :client,
        mnesia_create_table:
        [
          disc_copies: [node()]
        ]
      ]
    ],
    [
      impl: Asteroid.AttributeRepository.Impl.Mnesia,
      autoinstall: true,
      autostart: true,
      opts:
      [
        table: :subject,
        mnesia_create_table:
        [
          disc_copies: [node()]
        ]
      ]
    ]
  ]
  ```
  """

  @spec auto_install_from_config() :: :ok
  def auto_install_from_config() do
    configs = Application.get_env(:asteroid, :attribute_repositories)

    if is_list(configs) do
      Enum.map(
        configs,
        fn config ->
          if config[:autoinstall] == true do
            config[:impl].install(config[:opts])
          end
        end
      )

      :ok
    else
      :ok
    end
  end

  @doc """
  Autostarts all attribute repositories from the configuration file for
  repositories that have the `:autostart` key set to `true`

  Example configuration:
  ```elixir
  config :asteroid, :attribute_repositories,
  [
    [
      impl: Asteroid.AttributeRepository.Impl.Mnesia,
      autoinstall: true,
      autostart: true,
      opts:
      [
        table: :client,
        mnesia_create_table:
        [
          disc_copies: [node()]
        ]
      ]
    ],
    [
      impl: Asteroid.AttributeRepository.Impl.Mnesia,
      autoinstall: true,
      autostart: true,
      opts:
      [
        table: :subject,
        mnesia_create_table:
        [
          disc_copies: [node()]
        ]
      ]
    ]
  ]
  ```
  """

  @spec auto_start_from_config() :: :ok
  def auto_start_from_config() do
    configs = Application.get_env(:asteroid, :attribute_repositories)

    if is_list(configs) do
      Enum.map(
        configs,
        fn config ->
          if config[:autostart] == true do
            config[:impl].start(config[:opts])
          end
        end
      )

      :ok
    else
      :ok
    end
  end
end
