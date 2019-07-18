defmodule AsteroidWeb.AuthorizeScopesController do
  use AsteroidWeb, :controller

  alias Asteroid.OAuth2
  alias Asteroid.Subject

  @requested_scopes ["read_balance", "read_account_information", "interbank_transfer"]

  def index(conn, _params) do
    #FIXME: authenticated ?
    IO.inspect(get_session(conn, :authz_request))

    requested_scopes_config = requested_scopes_config(conn)

    conn
    |> put_status(200)
    |> render("scope_selector.html", scopes: requested_scopes_config)
  end

  def validate(conn, %{"scopes" => submitted_scopes}) do
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
      conn
      |> put_status(200)
      |> text("Youpi lol !")
    else
      conn
      |> put_flash(:error, "Required scope has not been granted")
      |> index(%{})
    end
  end

  defp requested_scopes_config(conn) do
    subject =
      get_session(conn, :subject)
      |> Subject.fetch_attributes(["authorized_scopes"])

    scope_config = OAuth2.Scope.configuration_for_flow(:authorization_code)

    Enum.reduce(
      scope_config[:scopes],
      [],
      fn {k, v}, acc ->
        if k in @requested_scopes do
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
