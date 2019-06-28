defmodule AsteroidWeb.RouterAPI do
  @moduledoc false

  use AsteroidWeb, :router
  use Plug.ErrorHandler

  import Asteroid.Utils

  alias Asteroid.OAuth2

  pipeline :api_urlencoded do
    plug :accepts, ["json"]
    plug Plug.Parsers, parsers: [:urlencoded]
  end

  pipeline :api_json do
    plug :accepts, ["json"]
    plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  end

  pipeline :oauth2 do
    for {plug_module, plug_options} <- astrenv(:api_oauth2_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_token do
    for {plug_module, plug_options} <- astrenv(:api_oauth2_endpoint_token_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_introspect do
    for {plug_module, plug_options} <- astrenv(:api_oauth2_endpoint_introspect_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_revoke do
    for {plug_module, plug_options} <- astrenv(:api_oauth2_endpoint_revoke_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_register do
    for {plug_module, plug_options} <- astrenv(:api_oauth2_endpoint_register_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :oauth2_endpoint_device_authorization do
    for {plug_module, plug_options} <- astrenv(:api_oauth2_endpoint_device_authorization_plugs, []) do
      plug plug_module, plug_options
    end
  end

  scope "/api/oauth2", AsteroidWeb.API.OAuth2 do
    pipe_through :oauth2

    scope "/token" do
      pipe_through :api_urlencoded
      pipe_through :oauth2_endpoint_token

      post "/", TokenEndpoint, :handle
    end

    scope "/introspect" do
      pipe_through :api_urlencoded
      pipe_through :oauth2_endpoint_introspect

      post "/", IntrospectEndpoint, :handle
    end

    scope "/revoke" do
      pipe_through :api_urlencoded
      pipe_through :oauth2_endpoint_revoke

      post "/", RevokeEndpoint, :handle
    end

    scope "/register" do
      pipe_through :api_json
      pipe_through :oauth2_endpoint_register

      post "/", RegisterEndpoint, :handle
    end

    scope "/device_authorization" do
      pipe_through :api_json
      pipe_through :oauth2_endpoint_device_authorization

      post "/", DeviceAuthorizationEndpoint, :handle
    end
  end

  def handle_errors(conn, %{kind: _kind, reason: reason, stack: stack}) do
    conn
    |> AsteroidWeb.Error.respond_api(OAuth2.ServerError.exception(reason: inspect(reason),
                                                                  stacktrace: stack))
  end
end