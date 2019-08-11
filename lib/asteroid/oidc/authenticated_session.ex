defmodule Asteroid.OIDC.AuthenticatedSession do
  @moduledoc """
  Convenience functions to work with authenticated sessions

  The `%Asteroid.OIDC.AuthenticatedSession{}` object has the following meaningful members in
  its `:data` field:
  - `"current_acr"`: the current ACR, as calculated (`t:Asteroid.OIDC.acr/0`)
  - `"current_auth_time"`: the current authentication time, as calculated (`non_neg_integer`)
  - `"exp"`: expiration time (`non_neg_integer()`)
  """

  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.OIDC
  alias Asteroid.OIDC.AuthenticationEvent
  alias Asteroid.Subject
  alias Asteroid.Token
  alias Asteroid.Token.RefreshToken

  @type id :: String.t()

  @enforce_keys [:id, :subject_id]

  defstruct [:id, :subject_id, :data]

  @type t :: %__MODULE__{
    id: id(),
    subject_id: Subject.id(),
    data: map()
  }

  @doc """
  Generates a new authenticated session
  """

  @spec gen_new(Subject.id()) :: t()

  def gen_new(subject_id) do
    %__MODULE__{
      id: secure_random_b64(),
      subject_id: subject_id,
      data: %{},
    }
  end

  @doc """
  Gets an authenticated session from the store
  """

  @spec get(id(), Keyword.t()) :: {:ok, t()} | {:error, Exception.t()}

  def get(authenticated_session_id, _opts \\ []) do
    token_store_module = astrenv(:token_store_authenticated_session)[:module]
    token_store_opts = astrenv(:token_store_authenticated_session)[:opts] || []

    case token_store_module.get(authenticated_session_id, token_store_opts) do
      {:ok, authenticated_session} when not is_nil(authenticated_session) ->
        {:ok, authenticated_session}

      {:ok, nil} ->
        {:error, Token.InvalidTokenError.exception(
          sort: "authenticated session",
          reason: "not found in the store",
          id: authenticated_session_id)}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Stores an authenticated session
  """

  @spec store(t(), Context.t()) :: {:ok, t()} | {:error, any()}

  def store(authenticated_session, ctx \\ %{})

  def store(authenticated_session, ctx) do
    token_store_module = astrenv(:token_store_authenticated_session)[:module]
    token_store_opts = astrenv(:token_store_authenticated_session)[:opts] || []

    authenticated_session =
      astrenv(:token_store_authenticated_session_before_store_callback).(authenticated_session,
                                                                         ctx)

    case token_store_module.put(authenticated_session, token_store_opts) do
      :ok ->
        {:ok, authenticated_session}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Deletes an authenticated session
  """

  @spec delete(t() | id()) :: :ok | {:error, any()}

  def delete(%__MODULE__{id: id}) do
    delete(id)
  end

  def delete(authenticated_session_id) do
    token_store_module = astrenv(:token_store_authenticated_session)[:module]
    token_store_opts = astrenv(:token_store_authenticated_session)[:opts] || []

    token_store_module.delete(authenticated_session_id, token_store_opts)

    token_store_rt_module = astrenv(:token_store_refresh_token)[:module]
    token_store_rt_opts = astrenv(:token_store_refresh_token)[:opts] || []

    {:ok, refresh_token_ids} =
      token_store_rt_module.get_from_authenticated_session_id(authenticated_session_id,
                                                              token_store_rt_opts)

    for refresh_token_id <- refresh_token_ids do
      {:ok, refresh_token} = RefreshToken.get(refresh_token_id, check_active: false)

      rt_scopes = refresh_token.data["scope"] || []

      if "openid" in rt_scopes and "offline_access" not in rt_scopes do
        RefreshToken.delete(refresh_token_id)
      end
    end

    :ok
  end

  @doc """
  Puts a value into the `data` field of authenticated session

  If the value is `nil`, the authenticated session is not changed and the filed is not added.
  """

  @spec put_value(t(), any(), any()) :: t()

  def put_value(authenticated_session, _key, nil), do: authenticated_session

  def put_value(authenticated_session, key, val) do
    %{authenticated_session | data: Map.put(authenticated_session.data, key, val)}
  end

  @doc """
  Removes a value from the `data` field of a authenticated session

  If the value does not exist, does nothing.
  """

  @spec delete_value(t(), any()) :: t()

  def delete_value(authenticated_session, key) do
    %{authenticated_session | data: Map.delete(authenticated_session.data, key)}
  end

  @doc """
  Computes the current ACR of an authenticated session
  """

  @spec compute_current_acr(%__MODULE__{} | id()) :: OIDC.acr() | nil

  def compute_current_acr(%__MODULE__{id: id}) do
    compute_current_acr(id)
  end

  def compute_current_acr(authenticated_session_id) when is_binary(authenticated_session_id) do
    ae_store_module = astrenv(:token_store_authentication_event)[:module]
    ae_store_opts = astrenv(:token_store_authentication_event)[:opts] || []

    case ae_store_module.get_from_authenticated_session_id(authenticated_session_id,
                                                           ae_store_opts)
    do
      {:ok, auth_event_ids} ->
        auth_events =
          auth_event_ids
          |> Enum.map(fn
            auth_event_id ->
              {:ok, auth_event} = AuthenticationEvent.get(auth_event_id)

              auth_event
          end)
          |> Enum.reduce(MapSet.new(), &(MapSet.put(&2, &1.data["name"])))

        acr_config =
          Enum.find(
            astrenv(:oidc_acr_config, []),
            fn
              {_acr, acr_conf} ->
                Enum.find(
                  acr_conf[:auth_events] || [],
                  fn
                    acr_auth_events when is_list(acr_auth_events) ->
                      acr_auth_events = MapSet.new(acr_auth_events)

                      MapSet.subset?(acr_auth_events, auth_events)
                  end
                )
            end
          )

        case acr_config do
          {acr, _} ->
            Atom.to_string(acr)

          nil ->
            nil
        end

      _ ->
        nil
    end
  end

  @doc """
  Updates the current acr of an authenticated session and stores it
  """

  @spec update_acr(%__MODULE__{} | id()) :: {:ok, %__MODULE__{}} | {:error, any()}

  def update_acr(%__MODULE__{id: id}) do
    update_acr(id)
  end

  def update_acr(authenticated_session_id) when is_binary(authenticated_session_id) do
    {:ok, auth_session} = get(authenticated_session_id)

    case compute_current_acr(authenticated_session_id) do
      nil ->
        delete(authenticated_session_id)

      acr when is_binary(acr) ->
        auth_session
        |> put_value("current_acr", acr)
        |> store()
    end
  end
end
