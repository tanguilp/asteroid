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

  The `res` parameter is a `map()` whose keys are:
  - `:user_code`: the user code (`t:Asteroid.OAuth2.DeviceAuthorization.user_code/0`) that has
  ben inputed by the user and optionnaly verified within the web flow
  - `:sjid`: the `t:Asteroid.Subject.id/0` of the user having approved the request
  - `:granted_scopes`: a `MapSet.t()` for the granted scope. If none was granted (because none
  were requested, or because user did not authorize them), a empty `t:Scope.Set.t/0` must be
  set
  """

  @spec authorization_granted(Plug.Conn.t(), Request.t(), map()) :: Plug.Conn.t()

  def authorization_granted(conn, authz_request, res) do
    case DeviceCode.get_from_user_code(res[:user_code]) do
      {:ok, device_code} ->
        Logger.debug("#{__MODULE__}: authorization granted (#{inspect(authz_request)}) with "
        <> "params: `#{inspect res}`")

        {:ok, subject} = Subject.load(res[:sjid])

        ctx =
          %{}
          |> Map.put(:endpoint, :device)
          |> Map.put(:flow, :device_authorization)
          |> Map.put(:requested_scopes, Scope.Set.new(device_code.data["requested_scopes"] || []))
          |> Map.put(:granted_scopes, res[:granted_scopes])
          |> Map.put(:subject, subject)
          |> Map.put(:flow_result, res)

        device_code
        |> DeviceCode.put_value("sjid", res[:sjid])
        |> DeviceCode.put_value("granted_scopes", Scope.Set.to_list(res[:granted_scopes]))
        |> DeviceCode.put_value("status", "granted")
        |> DeviceCode.store(ctx)

        conn
        |> put_flash(:info, "Pairing successful")
        |> put_status(200)
        |> render("device_authorization_granted.html")

      {:error, e} ->
        conn
        |> assign(:exception, e)
        |> assign(:authz_request, authz_request)
        |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
        |> put_status(403)
        |> render("device_authorization_error.html")
    end
  end

  @doc """
  Callback to be called when the authorization is denied, either by the user or by the
  server

  It must be called with one of the following exception:
  - `t:Asteroid.OAuth2.AccessDeniedError.t/0` when the request was denied either because of server
  policy or because of the user refusal
  - `t:Asteroid.OAuth2.ServerError.t/0` in case of server error
  - `t:Asteroid.OAuth2.TemporarilyUnavailableError.t/0` when the service is temporarily
  unavailable. Can be useful for maintenance mode

  The last argument is the user code, if any was validated or entered by the user, to be marked
  as denied.
  """

  @spec authorization_denied(Plug.Conn.t(), Request.t(),
  OAuth2.AccessDeniedError.t() | OAuth2.ServerError.t() | OAuth2.TemporarilyUnavailableError.t(),
  OAuth2.DeviceAuthorization.user_code() | nil)
  :: Plug.Conn.t()

  def authorization_denied(conn, authz_request, e, user_code \\ nil)

  def authorization_denied(conn, authz_request, %OAuth2.AccessDeniedError{} = e, nil)
  do
    Logger.debug("#{__MODULE__}: authorization denied (#{inspect authz_request}) with "
    <> "reason: `#{Exception.message(e)}`")

    conn
    |> assign(:exception, e)
    |> assign(:authz_request, authz_request)
    |> put_status(403)
    |> render("device_authorization_denied.html")
  end

  def authorization_denied(conn, authz_request, %OAuth2.AccessDeniedError{} = e, user_code)
  do
    Logger.debug("#{__MODULE__}: authorization denied (#{inspect authz_request}) with "
    <> "reason: `#{Exception.message(e)}` and user code `#{inspect user_code}`")

    case DeviceCode.get_from_user_code(user_code) do
      {:ok, device_code} ->
        ctx =
          %{}
          |> Map.put(:endpoint, :device)
          |> Map.put(:flow, :device_authorization)
          |> Map.put(:requested_scopes, Scope.Set.new(device_code.data["scope"] || []))
          |> Map.put(:flow_result, e)

        device_code
        |> DeviceCode.put_value("status", "denied")
        |> DeviceCode.store(ctx)

        conn
        |> assign(:exception, e)
        |> assign(:authz_request, authz_request)
        |> put_status(403)
        |> render("device_authorization_denied.html")

      {:error, e} ->
        conn
        |> assign(:exception, e)
        |> assign(:authz_request, authz_request)
        |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
        |> put_status(403)
        |> render("device_authorization_error.html")
    end
  end

  def authorization_denied(conn, authz_request, e, _user_code)
  do
    Logger.debug("#{__MODULE__}: authorization denied (#{inspect(authz_request)}) with "
    <> "reason: `#{Exception.message(e)}`")

    conn
    |> assign(:exception, e)
    |> assign(:authz_request, authz_request)
    |> put_flash(:error, "An error has occured (#{Exception.message(e)})")
    |> put_status(403)
    |> render("device_authorization_error.html")
  end
end
