defmodule AsteroidWeb.OIDCAuthorizeScopesController do
  use AsteroidWeb, :controller

  alias Asteroid.Client
  alias Asteroid.OAuth2
  alias Asteroid.OIDC
  alias Asteroid.Subject
  alias AsteroidWeb.AuthorizeController.Request
  alias OAuth2Utils.Scope

  def index(conn, _params) do
    authz_request = get_session(conn, :authz_request)

    if consent_scopes?(conn, authz_request) do
      if "none" in authz_request.prompt do
        AsteroidWeb.AuthorizeController.authorization_denied(
          conn,
          %{
            authz_request: get_session(conn, :authz_request),
            error: OIDC.LoginRequiredError.exception(reason: "Login required")})
      else
        {:ok, client} =
          Client.load_from_unique_attribute("client_id",
                                            authz_request.client_id,
                                            attributes: ["client_name", "client_id"])

        requested_scopes_config = requested_scopes_config(conn)

        conn
        |> put_status(200)
        |> put_secure_browser_headers()
        |> put_resp_header("cache-control", "no-cache, no-store, must-revalidate")
        |> render("scope_selector.html", scopes: requested_scopes_config, client: client)
      end
    else
      AsteroidWeb.AuthorizeController.authorization_granted(
        conn,
        %{
          authz_request: get_session(conn, :authz_request),
          subject: get_session(conn, :subject),
          granted_scopes: Scope.Set.new(authz_request.requested_scopes),
          authenticated_session_id: get_session(conn, :authenticated_session_id)
        })
    end
  end

  def validate(conn, %{"submit_grant" => _, "scopes" => submitted_scopes}) do
    authz_request = get_session(conn, :authz_request)

    requested_scopes_config = requested_scopes_config(conn)

    valid_submitted_scopes =
      Enum.all?(
        requested_scopes_config,
        fn
          %{name: name, optional: false} ->
            submitted_scopes[name] == "true"

          # a scope already granted cannot be ungranted
          %{name: name, already_authorized: true} ->
            submitted_scopes[name] == "true"

          _ ->
            true
        end
      )

    if valid_submitted_scopes do
      granted_scopes =
        Enum.reduce(
          submitted_scopes,
          Scope.Set.new(),
          fn
            {scope, "true"}, acc ->
              Scope.Set.put(acc, scope)

            {_scope, _}, acc ->
              acc
          end
        )

      subject =
        conn
        |> get_session(:subject)
        |> Subject.fetch_attributes(["consented_scopes"])

      consented_scopes =
        (subject.attrs["consented_scopes"] || %{})
        |> Map.put(authz_request.client_id, Scope.Set.to_scope_param(granted_scopes))

      subject
      |> Subject.add("consented_scopes", consented_scopes)
      |> Subject.store()

      AsteroidWeb.AuthorizeController.authorization_granted(
        conn,
        %{
          authz_request: get_session(conn, :authz_request),
          subject: get_session(conn, :subject),
          granted_scopes: Scope.Set.new(granted_scopes),
          authenticated_session_id: get_session(conn, :authenticated_session_id)
        }
      )
    else
      conn
      |> put_flash(:error, "Required scope has not been granted")
      |> index(%{})
    end
  end

  def validate(conn, %{"submit_deny" => _}) do
    AsteroidWeb.AuthorizeController.authorization_denied(
      conn,
      %{
        authz_request: get_session(conn, :authz_request),
        error: Asteroid.OAuth2.AccessDeniedError.exception(reason: "User denied authorization")
      }
    )
  end

  @spec consent_scopes?(Plug.Conn.t(), Request.t()) :: boolean()

  defp consent_scopes?(conn, authz_request) do
    if "consent" in authz_request.prompt do
      true
    else
      subject = get_session(conn, :subject)

      consented_scopes = consented_scopes(subject, authz_request.client_id)

      if Scope.Set.subset?(authz_request.requested_scopes, consented_scopes) do
        false
      else
        true
      end
    end
  end

  defp requested_scopes_config(conn) do
    subject =
      get_session(conn, :subject)
      |> Subject.fetch_attributes(["consented_scopes"])

    authz_request = get_session(conn, :authz_request)

    scope_config = OAuth2.Scope.configuration_for_flow(authz_request.flow)

    consented_scopes = consented_scopes(subject, authz_request.client_id)

    Enum.reduce(
      scope_config[:scopes],
      Scope.Set.new(),
      fn
        {k, v}, acc ->
          if k in authz_request.requested_scopes do
            scope =
              %{
                name: k,
                label: v[:label]["en"],
                optional: v[:optional] || false,
                already_authorized: k in consented_scopes,
                display: (if v[:display] == false, do: false, else: true)
              }

            Scope.Set.put(acc, scope)
          else
            acc
          end
      end
    )
  end

  @spec consented_scopes(Subject.t(), String.t()) :: Scope.Set.t()

  defp consented_scopes(subject, client_id) do
    subject = Subject.fetch_attributes(subject, ["consented_scopes"])

    Enum.find_value(
      subject.attrs["consented_scopes"] || %{},
      fn
        {^client_id, scope} ->
          Scope.Set.from_scope_param!(scope)

        _ ->
          false
      end
    ) || Scope.Set.new()
  end
end
