defmodule AsteroidWeb.AuthorizeScopesController do
  use AsteroidWeb, :controller

  alias Asteroid.OAuth2
  alias Asteroid.Client
  alias Asteroid.Subject
  alias OAuth2Utils.Scope

  def index(conn, _params) do
    check_authenticated(conn)

    authz_request = get_session(conn, :authz_request)

    {:ok, client} = Client.load_from_unique_attribute("client_id",
                                                      authz_request.client_id,
                                                      attributes: ["client_name"])

    requested_scopes_config = requested_scopes_config(conn)

    conn
    |> put_status(200)
    |> render("scope_selector.html", scopes: requested_scopes_config, client: client)
  end

  def validate(conn, %{"submit_grant" => _, "scopes" => submitted_scopes}) do
    check_authenticated(conn)

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
          [],
          fn
            {scope, "true"}, acc ->
              [scope | acc]

            {_scope, _}, acc ->
              acc
          end
        )

      get_session(conn, :subject)
      |> Subject.add("authorized_scopes", granted_scopes)
      |> Subject.store()

      AsteroidWeb.AuthorizeController.authorization_granted(
        conn,
        %{
          authz_request: get_session(conn, :authz_request),
          subject: get_session(conn, :subject),
          granted_scopes: Scope.Set.new(granted_scopes)
        }
      )
    else
      conn
      |> put_flash(:error, "Required scope has not been granted")
      |> index(%{})
    end
  end

  # case when no scopes where submitted

  def validate(conn, %{"submit_grant" => _}) do
    check_authenticated(conn)

    AsteroidWeb.AuthorizeController.authorization_granted(
      conn,
      %{
        authz_request: get_session(conn, :authz_request),
        subject: get_session(conn, :subject),
        granted_scopes: Scope.Set.new()
      }
    )
  end

  def validate(conn, %{"submit_deny" => _}) do
    check_authenticated(conn)

    AsteroidWeb.AuthorizeController.authorization_denied(
      conn,
      %{
        authz_request: get_session(conn, :authz_request),
        error: Asteroid.OAuth2.AccessDeniedError.exception(reason: "User denied authorization")
      }
    )
  end

  defp check_authenticated(conn) do
    unless get_session(conn, :authenticated) == true do
      raise "User shall be authneticated at this point"
      # better error may be implemented, such as redirecting to /account_select
    end
  end

  defp requested_scopes_config(conn) do
    subject =
      get_session(conn, :subject)
      |> Subject.fetch_attributes(["authorized_scopes"])

    scope_config = OAuth2.Scope.configuration_for_flow(:authorization_code)

    authz_request = get_session(conn, :authz_request) |> IO.inspect()

    Enum.reduce(
      scope_config[:scopes],
      [],
      fn {k, v}, acc ->
        if k in authz_request.requested_scopes do
          scope =
            %{
              name: k,
              label: v[:label]["en"],
              optional: v[:optional] || false,
              already_authorized: k in (subject.attrs["authorized_scopes"] || [])
            }

          [scope | acc]
        else
          acc
        end
      end
    )
  end
end
