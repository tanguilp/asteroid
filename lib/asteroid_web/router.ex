defmodule AsteroidWeb.Router do
  @moduledoc false

  use AsteroidWeb, :router
  use Plug.ErrorHandler

  import Asteroid.Utils

  alias Asteroid.OAuth2

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    for {plug_module, plug_options} <- astrenv(:browser_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :well_known do
    for {plug_module, plug_options} <- astrenv(:well_known_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :discovery do
    for {plug_module, plug_options} <- astrenv(:discovery_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :api_urlencoded do
    plug :accepts, ["json"]
    plug Plug.Parsers, parsers: [:urlencoded]
  end

  pipeline :api_json do
    plug :accepts, ["json"]
    plug Plug.Parsers, parsers: [:json], json_decoder: Jason
  end

  pipeline :request_object do
    for {plug_module, plug_options} <- astrenv(:api_request_object_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :oidc do
    for {plug_module, plug_options} <- astrenv(:api_oidc_plugs, []) do
      plug plug_module, plug_options
    end
  end

  pipeline :oidc_endpoint_userinfo do
    for {plug_module, plug_options} <- astrenv(:api_oidc_endpoint_userinfo_plugs, []) do
      plug plug_module, plug_options
    end
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

  scope "/", AsteroidWeb do
    pipe_through :browser

    get "/authorize", AuthorizeController, :pre_authorize
    get "/device", DeviceController, :pre_authorize
  end

  scope "/api", AsteroidWeb.API do
    scope "/request_object" do
      pipe_through :request_object

      get "/:id", RequestObjectController, :show
      post "/", RequestObjectController, :create
    end
  end

  scope "/api/oidc", AsteroidWeb.API.OIDC do
    pipe_through :oidc

    scope "/userinfo" do
      pipe_through :api_urlencoded
      pipe_through :oidc_endpoint_userinfo

      get "/", UserinfoController, :show
      post "/", UserinfoController, :show
    end
  end

  scope "/api/oauth2", AsteroidWeb.API.OAuth2 do
    pipe_through :oauth2

    scope "/token" do
      pipe_through :api_urlencoded
      pipe_through :oauth2_endpoint_token

      post "/", TokenController, :handle
    end

    scope "/introspect" do
      pipe_through :api_urlencoded
      pipe_through :oauth2_endpoint_introspect

      post "/", IntrospectController, :handle
    end

    scope "/revoke" do
      pipe_through :api_urlencoded
      pipe_through :oauth2_endpoint_revoke

      post "/", RevokeController, :handle
    end

    scope "/register" do
      pipe_through :api_json
      pipe_through :oauth2_endpoint_register

      post "/", RegisterController, :handle
    end

    scope "/device_authorization" do
      pipe_through :api_json
      pipe_through :oauth2_endpoint_device_authorization

      post "/", DeviceAuthorizationController, :handle
    end
  end

  scope "/.well-known", AsteroidWeb.WellKnown do
    pipe_through :well_known

    get "/oauth-authorization-server", OauthAuthorizationServerController, :handle
    get "/openid-configuration", OauthAuthorizationServerController, :handle
  end

  scope "/discovery", AsteroidWeb.Discovery do
    pipe_through :discovery

    get "/keys", KeysController, :handle
  end

  def handle_errors(conn, %{kind: _kind, reason: reason, stack: stack}) do
    conn
    |> AsteroidWeb.Error.respond_api(OAuth2.ServerError.exception(reason: inspect(reason),
                                                                  stacktrace: stack))
  end
end
