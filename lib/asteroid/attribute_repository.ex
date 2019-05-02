defmodule Asteroid.AttributeRepository do
  @moduledoc """
  Types for attribute repositories

  The pair composed of a `id` and an `attribute` constitute a unique value in an
  attribute repository. It can be nonexistent or existent, but there can not be
  several values for this pair.
  """

  import Asteroid.Utils

  require Logger

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

  @typedoc """
  Configuration name as registered in config file
  """
  @type config_name :: atom()

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

  @spec auto_install_from_config() :: :ok | {:error, any()}

  def auto_install_from_config() do
    conf_list = Application.get_env(:asteroid, :attribute_repositories)
    
    do_auto_install_from_config(conf_list)
  end

  @spec do_auto_install_from_config([Keyword.t()]) :: :ok | {:error, any()}

  defp do_auto_install_from_config([{rep, conf} | t]) do
    if conf[:auto_install] != false do
      Logger.info("#{__MODULE__}: configuring attribute repository `#{rep}`")

      case conf[:module].install(conf[:run_opts] || [], conf[:init_opts] || []) do
        :ok ->
          do_auto_install_from_config(t)

        {:error, _} = error ->
          error
      end
    else
      do_auto_install_from_config(t)
    end
  end

  defp do_auto_install_from_config([]) do
    :ok
  end

  @spec auto_start_from_config() :: :ok | {:error, any()}

  def auto_start_from_config() do
    conf_list = Application.get_env(:asteroid, :attribute_repositories)
    
    do_auto_start_from_config(conf_list)
  end

  @spec do_auto_start_from_config([Keyword.t()]) :: :ok | {:error, any()}

  defp do_auto_start_from_config([{rep, conf} | t]) do
    if conf[:auto_start] != false do
      Logger.info("#{__MODULE__}: starting attribute repository `#{rep}`")

      impl = conf[:module]
      if {:start_link, 1} in impl.__info__(:functions) do
        case impl.start_link(conf[:init_opts] || []) do
          {:ok, _pid} ->
            do_auto_start_from_config(t)

          {:error, _} = error ->
            error
        end
      else
        case impl.start(conf[:init_opts] || []) do
          :ok ->
            do_auto_start_from_config(t)

          {:error, _} = error ->
            error
        end
      end
    else
      do_auto_start_from_config(t)
    end
  end

  defp do_auto_start_from_config([]) do
    :ok
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

  @spec load_attributes_for_object(struct(), [attribute()], config_name()) :: struct()
  def load_attributes_for_object(obj, nil, _config_name), do: obj

  def load_attributes_for_object(%_{id: id, attrs: %{}} = obj, attribute_list, config_name) do
    module = astrenv(:attribute_repositories)[config_name][:impl]
    opts = astrenv(:attribute_repositories)[config_name][:opts]

    Enum.reduce(
      attribute_list,
      obj,
      fn attribute, obj ->
        case module.get(id, attribute, opts) do
          {:ok, value} ->
            %{obj | attrs: Map.put(obj.attrs, attribute, value)}

          {:error, _} ->
            obj
        end
      end
    )
  end
end
