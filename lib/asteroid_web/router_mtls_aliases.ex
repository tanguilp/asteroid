defmodule AsteroidWeb.RouterMTLSAliases do
  @moduledoc false

  use AsteroidWeb, :router
  use Plug.ErrorHandler

  import Asteroid.Config, only: [opt: 1]

  alias Asteroid.OAuth2
  alias Asteroid.OAuth2.MTLS

  Asteroid.Config.load_and_save()

  pipeline :api_urlencoded do
    plug :accepts, ["json"]
    plug Plug.Parsers, parsers: [:urlencoded]
  end

  pipeline :api_json do
    plug :accepts, ["json"]
    plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  end

  pipeline :request_object do
    for {plug_module, plug_options} <- opt(:api_request_object_plugs) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2 do
    for {plug_module, plug_options} <- opt(:api_oauth2_plugs) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_token do
    for {plug_module, plug_options} <- opt(:api_oauth2_endpoint_token_plugs) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_introspect do
    for {plug_module, plug_options} <- opt(:api_oauth2_endpoint_introspect_plugs) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_revoke do
    for {plug_module, plug_options} <- opt(:api_oauth2_endpoint_revoke_plugs) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_register do
    for {plug_module, plug_options} <- opt(:api_oauth2_endpoint_register_plugs) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_device_authorization do
    for {plug_module, plug_options} <- opt(:api_oauth2_endpoint_device_authorization_plugs) do
      plug plug_module, plug_options
    end
  end

  if MTLS.uses?(:api_request_object_plugs) do
    scope "/api", AsteroidWeb.API do
      scope "/request_object" do
        pipe_through :request_object

        get "/:id", RequestObjectController, :show
        post "/", RequestObjectController, :create
      end
    end
  end

  scope "/api/oauth2", AsteroidWeb.API.OAuth2 do
    pipe_through :oauth2

    if MTLS.uses?(:api_oauth2_plugs) or MTLS.uses?(:api_oauth2_endpoint_token_plugs) do
      scope "/token" do
        pipe_through :api_urlencoded
        pipe_through :oauth2_endpoint_token

        post "/", TokenController, :handle
      end
    end

    if MTLS.uses?(:api_oauth2_plugs) or MTLS.uses?(:api_oauth2_endpoint_introspect_plugs) do
      scope "/introspect" do
        pipe_through :api_urlencoded
        pipe_through :oauth2_endpoint_introspect

        post "/", IntrospectController, :handle
      end
    end

    if MTLS.uses?(:api_oauth2_plugs) or MTLS.uses?(:api_oauth2_endpoint_revoke_plugs) do
      scope "/revoke" do
        pipe_through :api_urlencoded
        pipe_through :oauth2_endpoint_revoke

        post "/", RevokeController, :handle
      end
    end

    if MTLS.uses?(:api_oauth2_plugs) or MTLS.uses?(:api_oauth2_endpoint_register_plugs) do
      scope "/register" do
        pipe_through :api_json
        pipe_through :oauth2_endpoint_register

        post "/", RegisterController, :handle
      end
    end

    if MTLS.uses?(:api_oauth2_plugs) or MTLS.uses?(:api_oauth2_endpoint_device_authorization_plugs)
    do
      scope "/device_authorization" do
        pipe_through :api_json
        pipe_through :oauth2_endpoint_device_authorization

        post "/", DeviceAuthorizationController, :handle
      end
    end
  end

  def handle_errors(conn, %{kind: _kind, reason: reason, stack: stack}) do
    conn
    |> AsteroidWeb.Error.respond_api(
      OAuth2.ServerError.exception(
        reason: inspect(reason),
        stacktrace: stack
      )
    )
  end
end
