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

  scope "/", AsteroidWeb do
    pipe_through :browser

    get "/authorize", AuthorizeController, :pre_authorize
    get "/device", DeviceController, :pre_authorize
    get "/account_select", AccountSelectController, :index
    get "/username", UsernameController, :index
    post "/username", UsernameController, :put
    get "/password", PasswordController, :index
    post "/password", PasswordController, :put
    get "/register_webauthn_key", RegisterWebauthnKeyController, :index
    post "/register_webauthn_key", RegisterWebauthnKeyController, :validate
    get "/webauthn_login", WebauthnLoginController, :index
    post "/webauthn_login", WebauthnLoginController, :validate
    get "/authorize_scopes", AuthorizeScopesController, :index
    post "/authorize_scopes", AuthorizeScopesController, :validate
  end

  scope "/.well-known", AsteroidWeb.WellKnown do
    pipe_through :well_known

    get "/oauth-authorization-server", OauthAuthorizationServerEndpoint, :handle
  end

  scope "/discovery", AsteroidWeb.Discovery do
    pipe_through :discovery

    get "/keys", KeysEndpoint, :handle
  end

  def handle_errors(conn, %{kind: _kind, reason: reason, stack: stack}) do
    conn
    |> AsteroidWeb.Error.respond_api(OAuth2.ServerError.exception(reason: inspect(reason),
                                                                  stacktrace: stack))
  end
end
