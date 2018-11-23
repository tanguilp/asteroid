defmodule AsteroidWeb.Router do
  use AsteroidWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug APISexAuthBasic, realm: "Asteroid"
    plug Plug.Parsers, parsers: [:urlencoded]
  end

  scope "/", AsteroidWeb do
    pipe_through :browser

    get "/", PageController, :index
  end

  scope "/api/oauth2", AsteroidWeb.API.OAuth2 do
    pipe_through :api

    post "/token", TokenEndpoint, :handle
  end
end
