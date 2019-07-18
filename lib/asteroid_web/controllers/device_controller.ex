defmodule AsteroidWeb.DeviceController do
  use AsteroidWeb, :controller

  require Logger

  import Asteroid.Utils

  alias OAuth2Utils.Scope
  alias Asteroid.OAuth2
  alias Asteroid.Subject
  alias Asteroid.Token.DeviceCode

  defmodule Request do
    @moduledoc """
    Struct with the necessary information to process an web authorization request for the device
    authorization flow
    """

    defstruct [
      :params
    ]

    @type t :: %__MODULE__{
      params: map()
    }
  end

  @doc false

  @spec pre_authorize(Plug.Conn.t(), map()) :: Plug.Conn.t()

  def pre_authorize(conn, params) do
    authz_request = %Request{params: params}

    astrenv(:oauth2_flow_authorization_code_web_authorization_callback).(conn, authz_request)
  end

  @doc """
  Callback to be called when the authorization is granted, typically after user code verification,
  authentication and authorization (approving scopes) process

  The `opts` parameter is a `map()` whose keys are (all **mandatory**):
  - `:authz_request`: the initial `Request.t()` authorization request
  - `:user_code`: the user code (`t:Asteroid.OAuth2.DeviceAuthorization.user_code/0`) that has
  ben inputed by the user and optionnaly verified within the web flow
  - `:sjid`: the `t:Asteroid.Subject.id/0` of the user having approved the request
  - `:granted_scopes`: a `MapSet.t()` for the granted scope. If none was granted (because none
  were requested, or because user did not authorize them), a empty `t:Scope.Set.t/0` must be
  set
  """

  @spec authorization_granted(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()

  def authorization_granted(conn, opts) do
    case DeviceCode.get_from_user_code(opts[:user_code]) do
      {:ok, device_code} ->
        Logger.debug("#{__MODULE__}: authorization granted with params: `#{inspect opts}`")

        {:ok, subject} = Subject.load(opts[:sjid])

        ctx =
          %{}
          |> Map.put(:endpoint, :device)
          |> Map.put(:flow, :device_authorization)
          |> Map.put(:requested_scopes, Scope.Set.new(device_code.data["requested_scopes"] || []))
          |> Map.put(:granted_scopes, opts[:granted_scopes])
          |> Map.put(:subject, subject)
          |> Map.put(:flow_result, opts)

        granted_scopes = astrenv(:oauth2_scope_callback).(opts[:granted_scopes], ctx)

        device_code
        |> DeviceCode.put_value("sjid", opts[:sjid])
        |> DeviceCode.put_value("granted_scopes", Scope.Set.to_list(granted_scopes))
        |> DeviceCode.put_value("status", "granted")
        |> DeviceCode.store(ctx)

        conn
        |> put_flash(:info, "Pairing successful")
        |> put_status(200)
        |> render("device_authorization_granted.html")

      {:error, e} ->
        conn
        |> assign(:exception, e)
        |> assign(:authz_request, opts[:authz_request])
        |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
        |> put_status(400)
        |> render("device_authorization_error.html")
    end
  end

  @doc """
  Callback to be called when the authorization is denied, either by the user or by the
  server

  The options are a `map()` with the following keys (all **mandatory**):
  - `:authz_request`: the initial `t:AsteroidWeb.AuthorizeController.Request.t/0` authorization
  request
  - `:user_code`: the user code, if any was validated or entered by the user, to be marked
  as denied or `nil` if it was not verified
  - `:error`: one of the following exceptions:
    - `t:Asteroid.OAuth2.AccessDeniedError.t/0` when the request was denied either because of
    server policy or because of the user refusal
    - `t:Asteroid.OAuth2.ServerError.t/0` in case of server error
    - `t:Asteroid.OAuth2.TemporarilyUnavailableError.t/0` when the service is temporarily
    unavailable. Can be useful for maintenance mode
  """

  @spec authorization_denied(Plug.Conn.t(), Plug.opts()) :: Plug.Conn.t()

  def authorization_denied(conn, %{error: %OAuth2.AccessDeniedError{}, user_code: nil} = opts)
  do
    Logger.debug("#{__MODULE__}: authorization denied (#{inspect opts[:authz_request]}) with "
    <> "reason: `#{Exception.message(opts[:error])}`")

    conn
    |> assign(:exception, opts[:error])
    |> assign(:authz_request, opts[:authz_request])
    |> put_status(200)
    |> render("device_authorization_denied.html")
  end

  def authorization_denied(conn, %{error: %OAuth2.AccessDeniedError{},
                                   user_code: user_code} = opts)
  do
    Logger.debug("#{__MODULE__}: authorization denied (#{inspect opts[:authz_request]}) with "
    <> "reason: `#{Exception.message(opts[:error])}` and user code `#{user_code}`")

    case DeviceCode.get_from_user_code(user_code) do
      {:ok, device_code} ->
        ctx =
          %{}
          |> Map.put(:endpoint, :device)
          |> Map.put(:flow, :device_authorization)
          |> Map.put(:requested_scopes, Scope.Set.new(device_code.data["scope"] || []))
          |> Map.put(:flow_result, opts[:error])

        device_code
        |> DeviceCode.put_value("status", "denied")
        |> DeviceCode.store(ctx)

        conn
        |> assign(:exception, opts[:error])
        |> assign(:authz_request, opts[:authz_request])
        |> put_status(200)
        |> render("device_authorization_denied.html")

      {:error, e} ->
        conn
        |> assign(:exception, e)
        |> assign(:authz_request, opts[:authz_request])
        |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
        |> put_status(400)
        |> render("device_authorization_error.html")
    end
  end

  def authorization_denied(conn, opts) do
    Logger.debug("#{__MODULE__}: authorization denied (#{inspect opts[:authz_request]}) with "
    <> "reason: `#{Exception.message(opts[:error])}`")

    conn
    |> assign(:exception, opts[:error])
    |> assign(:authz_request, opts[:authz_request])
    |> put_flash(:error, "An error has occured (#{Exception.message(opts[:error])})")
    |> put_status(400)
    |> render("device_authorization_error.html")
  end
end
