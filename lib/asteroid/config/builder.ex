defmodule Asteroid.Config.Builder do
  defmodule Schema do
    defmacro field(name, options \\ []) do
      quote do
        field_documentation = Module.delete_attribute(__MODULE__, :doc)

        field_documentation =
          case field_documentation do
            {_line, val} ->
              val

            nil ->
              IO.warn(
                "Missing documentation for configuration field `#{unquote(name)}`. Please add it by adding `@doc \"field documentation here\"` above the line where you define it."
              )

              ""
          end

        Module.put_attribute(
          __MODULE__,
          :config_fields,
          %{
            module: __MODULE__,
            name: unquote(name),
            documentation: field_documentation,
            options: unquote(options)
          }
        )
      end
    end
  end

  defmacro defconfig(_options \\ [], do: block) do
    quote do
      import Asteroid.Config.Builder.Schema

      Module.register_attribute(__MODULE__, :config_fields, accumulate: true)

      try do
        unquote(block)
      after
        config_fields =
          Module.get_attribute(__MODULE__, :config_fields)
          |> Enum.reverse()

        {line_number, existing_moduledoc} =
          Module.delete_attribute(__MODULE__, :moduledoc) || {0, ""}

        Module.put_attribute(
          __MODULE__,
          :moduledoc,
          {line_number, existing_moduledoc <>
            Asteroid.Config.Builder.__config_doc__(config_fields)})

          # FIXME: dynamically generate types
          # See: https://elixirforum.com/t/dynamically-generate-typespecs-from-module-attribute-list/7078/2
          #
          #Enum.each(
          #  config_fields,
          #  fn
          #    %{options: options, name: name} ->
          #      if options[:type] do
          #        @type unquote(:name) :: non_neg_integer()
          #      end
          #  end
          #)
      end
    end
  end

  def __config_doc__(config_fields) do
    current_env = Mix.env()

    Mix.env(:dev)
    {conf_dev, _imported_paths} = Mix.Config.eval!("config/config.exs")

    Mix.env(:test)
    {conf_test, _imported_path} = Mix.Config.eval!("config/config.exs")

    Mix.env(:prod)
    {conf_prod, _imported_path} = Mix.Config.eval!("config/config.exs")

    Mix.env(current_env)

    field_list =
      config_fields
      |> Enum.sort_by(
        fn %{name: name} -> name end,
        &</2
      )
      |> Enum.reduce(
        "Options:\n",
        fn
          %{name: name}, acc ->
            acc <> "- [`:#{name}`](#module-#{to_string(name)})\n"
        end
      )

    acc =
      Enum.reduce(
        config_fields,
        field_list,
        fn
          %{name: name, documentation: documentation, options: options}, acc ->
            config_time =
              case options[:config_time] do
                :runtime ->
                  "runtime"

                :compile ->
                  "compile-time"

                _ ->
                  "*Unknown*"
              end

            doc = """
            ## `:#{name}`

            ### Properties

            |         Property          |         Value                       |
            |--------------------------:|-------------------------------------|
            | Configuration time:       | #{config_time}                      |
            | Type:                     | `t:#{name}/0`                       |
            | Default value (dev):      | #{default_value(conf_dev, name)}    |
            | Default value (test):     | #{default_value(conf_test, name)}   |
            | Default value (prod):     | #{default_value(conf_prod, name)}   |
            """

            doc =
              if options[:uses] do
                uses =
                  options[:uses]
                  |> Enum.map(&to_string/1)
                  |> Enum.map(fn str -> "[`:" <> str <> "`](#module-" <> str <> ")" end)
                  |> Enum.join("<br/>")

                doc <> "| Uses: | #{uses} |\n"
              else
                doc
              end

            doc =
              if options[:used_by] do
                used_by =
                  options[:used_by]
                  |> Enum.map(&to_string/1)
                  |> Enum.map(fn str -> "[`:" <> str <> "`](#module-" <> str <> ")" end)
                  |> Enum.join("<br/>")

                doc <> "| Used by:| #{used_by}|\n"
              else
                doc
              end

            doc =
              if options[:unit] do
                doc <> "| Unit:| #{options[:unit]}|\n"
              else
                doc
              end

            acc <> doc <>
            """
            ### Documentation

            #{documentation || "*No documentation*"}
            
            ***

            """

        end
      )

    """
    ***

    #{acc}
    """
  end

  @spec default_value(Keyword.t(), atom()) :: String.t()
  defp default_value(conf, key) do
    case conf[:asteroid][key] do
      f when is_function(f) ->
        case inspect(f) do
          "&" <> function_name ->
            "`" <> function_name <>"`"

          val ->
            "`" <> val <> "`"
        end

      val ->
        "`#{inspect val}`"
    end
  end
end
