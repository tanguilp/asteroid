defmodule AsteroidWeb.Router do
  @moduledoc false

  use AsteroidWeb, :router
  use Plug.ErrorHandler

  import Asteroid.Utils

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug Plug.Parsers, parsers: [:urlencoded]
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

  scope "/", AsteroidWeb do
    pipe_through :browser

    get "/", PageController, :index
  end

  scope "/api/oauth2", AsteroidWeb.API.OAuth2 do
    pipe_through :api
    pipe_through :oauth2

    scope "/token" do
      pipe_through :oauth2_endpoint_token

      post "/", TokenEndpoint, :handle
    end

    scope "/introspect" do
      pipe_through :oauth2_endpoint_introspect

      post "/", IntrospectEndpoint, :handle
    end
  end

  def handle_errors(conn, %{kind: _kind, reason: reason, stack: _stack} = error) do
    conn
    |> put_status(400)
    |> json(%{
      "error" => "invalid_request",
      "error_description" => Exception.message(reason)
    })
  end
end
