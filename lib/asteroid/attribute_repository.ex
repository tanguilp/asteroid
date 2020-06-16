defmodule Asteroid.AttributeRepository do
  import Asteroid.Config, only: [opt: 1]

  require Logger

  @spec auto_install_from_config() :: :ok | {:error, any()}

  def auto_install_from_config() do
    conf_list = opt(:attribute_repositories)

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
    conf_list = opt(:attribute_repositories)

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
end
