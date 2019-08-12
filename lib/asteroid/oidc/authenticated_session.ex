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
                  acr_conf[:auth_event_set] || [],
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

  @doc """
  Returns the authentication time and the AMRs of an authenticated session for a given ACR

  It returns:
  - `:acr`: the acr
  - `:auth_time`: the timestamp of the most recent authentication event
  - `:amr`: the list of ARMs of these authentication events

  Returns `nil` if no match was found.

  ## Example
  ```elixir
  iex> Asteroid.Utils.astrenv(:oidc_acr_config)
  [
    "3-factor": [
      callback: &AsteroidWeb.LOA3_webflow.start_webflow/2,
      auth_event_set: [["password", "otp", "webauthn"]]
    ],
    "2-factor": [
      callback: &AsteroidWeb.LOA2_webflow.start_webflow/2,
      auth_event_set: [
        ["password", "otp"],
        ["password", "webauthn"],
        ["webauthn", "otp"]
      ]
    ],
    "1-factor": [
      callback: &AsteroidWeb.LOA1_webflow.start_webflow/2,
      auth_event_set: [["password"], ["webauthn"]],
      default: true
    ]
  ]
  iex> alias Asteroid.OIDC.AuthenticationEvent, as: AE
  Asteroid.OIDC.AuthenticationEvent
  iex> alias Asteroid.OIDC.AuthenticatedSession, as: AS
  Asteroid.OIDC.AuthenticatedSession
  iex> {:ok, as} = AS.gen_new("user_1") |> AS.store()
  {:ok,
   %Asteroid.OIDC.AuthenticatedSession{
     data: %{},
     id: "gvycEhbeig9RjwUu36UEGTxO1MNRE3qQ9WHisfpk0Zk",
     subject_id: "user_1"
   }}
  iex> AE.gen_new(as.id) |> AE.put_value("name", "password") |> AE.put_value("amr", "pwd") |> AE.put_value("time", 100000) |> AE.store()
  {:ok,
   %Asteroid.OIDC.AuthenticationEvent{
     authenticated_session_id: "gvycEhbeig9RjwUu36UEGTxO1MNRE3qQ9WHisfpk0Zk",
     data: %{"amr" => "pwd", "name" => "password", "time" => 100000},
     id: "WxQ6AHMRthQlk9cqsGUMVWsFNZ3EeNjyFfNCRYkiF20"
   }}
  iex> AE.gen_new(as.id) |> AE.put_value("name", "otp") |> AE.put_value("amr", "otp") |> AE.put_value("time", 200000)|> AE.store()
  {:ok,
   %Asteroid.OIDC.AuthenticationEvent{
     authenticated_session_id: "gvycEhbeig9RjwUu36UEGTxO1MNRE3qQ9WHisfpk0Zk",
     data: %{"amr" => "otp", "name" => "otp", "time" => 200000},
     id: "QnZZE82I4St41JieLpLg8z3HG_T8l6yutlt3dPo_Yx8"
   }}
  iex> AE.gen_new(as.id) |> AE.put_value("name", "webauthn") |> AE.put_value("amr", "phr") |> AE.put_value("time", 300000)|> AE.store()
  {:ok,
   %Asteroid.OIDC.AuthenticationEvent{
     authenticated_session_id: "gvycEhbeig9RjwUu36UEGTxO1MNRE3qQ9WHisfpk0Zk",
     data: %{"amr" => "phr", "name" => "webauthn", "time" => 300000},
     id: "N_V4i9lz5obd-3C0XZagZGtOFuDMZo0ywXSBjoum0KY"
   }}
  iex> AS.info(as.id)            
  %{acr: "3-factor", amr: ["otp", "phr", "pwd"], auth_time: 300000}
  iex> AS.info(as.id, "1-factor")
  %{acr: "1-factor", amr: ["pwd"], auth_time: 100000}
  iex> AS.info(as.id, "2-factor")
  %{acr: "2-factor", amr: ["otp", "pwd"], auth_time: 200000}
  iex> AS.info(as.id, "3-factor")
  %{acr: "3-factor", amr: ["otp", "phr", "pwd"], auth_time: 300000}
  ```
  """

  @spec info(%__MODULE__{} | id(), Asteroid.OIDC.acr() | nil) ::
  %{
    required(:acr) => Asteroid.OIDC.acr() | nil,
    required(:auth_time) => non_neg_integer() | nil,
    required(:amr) => [Asteroid.OIDC.amr(), ...]
  }
  | nil

  def info(auth_session_id, acr \\ nil)

  def info(auth_session_id, acr) when is_binary(auth_session_id) do
    case get(auth_session_id) do
      {:ok, auth_session} ->
        info(auth_session, acr)

      {:error, _} ->
        nil
    end
  end

  def info(authenticated_session, acr) do
    acr =
      if acr do
        acr
      else
        authenticated_session.data["current_acr"]
      end

    if acr do
      auth_events =
        AuthenticationEvent.get_from_authenticated_session_id(authenticated_session.id)

      case find_matching_auth_event_set(auth_events, acr) do
        auth_event_set when is_list(auth_event_set) ->
          amr =
            Enum.reduce(
              auth_events,
              MapSet.new(),
              fn
                %AuthenticationEvent{data: %{"name" => name, "amr" => amr}}, acc ->
                  if name in auth_event_set do
                    MapSet.put(acc, amr)
                  else
                    acc
                  end

                _, acc ->
                  acc
              end)
            |> MapSet.to_list()

          auth_time =
            Enum.reduce(
              auth_events,
              nil,
              fn
                %AuthenticationEvent{data: %{"name" => name, "time" => auth_time}}, acc ->
                  if name in auth_event_set do
                    if acc == nil do
                      auth_time
                    else
                      max(acc, auth_time)
                    end
                  else
                    acc
                  end

                _, acc ->
                  acc
              end)

          %{acr: acr, amr: amr, auth_time: auth_time}

        nil ->
          %{acr: acr, amr: nil, auth_time: nil}
      end
    else
      %{acr: nil, amr: nil, auth_time: nil}
    end
  end

  @doc """
  Find matching authentication event set (`t:Asteroid.OIDC.ACR.auth_event_set/0`) for a given
  ACR from a set of authentication events, or `nil` if none could be found

  ## Example

  ```elixir
  iex> Asteroid.Utils.astrenv(:oidc_acr_config)
  [
    loa2: [
      callback: &AsteroidWeb.LOA2_webflow.start_webflow/2,
      auth_event_set: [
        ["password", "otp"],
        ["password", "webauthn"],
        ["webauthn", "otp"]
      ]
    ],
    loa1: [
      callback: &AsteroidWeb.LOA1_webflow.start_webflow/2,
      auth_event_set: [["password"], ["webauthn"]],
      default: true
    ]
  ]
  iex> alias Asteroid.OIDC.AuthenticationEvent
  Asteroid.OIDC.AuthenticationEvent
  iex> alias Asteroid.OIDC.AuthenticatedSession
  Asteroid.OIDC.AuthenticatedSession
  iex> {:ok, as} = AuthenticatedSession.gen_new("user_1") |> AuthenticatedSession.store()
  {:ok,
   %Asteroid.OIDC.AuthenticatedSession{
     data: %{},
     id: "jcKc4uwqDYN7c84B7gzfzgVBkpLMUBNusTRMG6NdOTg",
     subject_id: "user_1"
   }}
  iex> {:ok, ae1} = AuthenticationEvent.gen_new(as.id) |> AuthenticationEvent.put_value("name", "password") |> AuthenticationEvent.store()
  {:ok,
   %Asteroid.OIDC.AuthenticationEvent{
     authenticated_session_id: "jcKc4uwqDYN7c84B7gzfzgVBkpLMUBNusTRMG6NdOTg",
     data: %{"name" => "password"},
     id: "zwhSZ4HPs6JuFpeoTCNNV1wCzFBnnrKAU5bv1FCxLDg"
   }}
  iex> {:ok, ae2} = AuthenticationEvent.gen_new(as.id) |> AuthenticationEvent.put_value("name", "otp") |> AuthenticationEvent.store()
  {:ok,
   %Asteroid.OIDC.AuthenticationEvent{
     authenticated_session_id: "jcKc4uwqDYN7c84B7gzfzgVBkpLMUBNusTRMG6NdOTg",
     data: %{"name" => "otp"},
     id: "cvYtgORDaZfzjxxpUnpS0mf3M1d2lLt74tm6KXifyYg"
   }}
  iex> AuthenticatedSession.find_matching_auth_event_set(AuthenticationEvent.get_from_authenticated_session_id(as.id), "loa1")
  ["password"]
  iex> AuthenticatedSession.find_matching_auth_event_set(AuthenticationEvent.get_from_authenticated_session_id(as.id), "loa2")
  ["password", "otp"]
  iex> AuthenticatedSession.find_matching_auth_event_set(AuthenticationEvent.get_from_authenticated_session_id(as.id), "loa3")
  nil
  ```
  """

  @spec find_matching_auth_event_set([AuthenticationEvent.t()], OIDC.acr()) ::
  OIDC.ACR.auth_event_set()
  | nil

  def find_matching_auth_event_set(auth_events, acr) do
    acr = String.to_existing_atom(acr)

    searched_auth_events_set =
      Enum.reduce(auth_events, MapSet.new(), &(MapSet.put(&2, &1.data["name"])))

    Enum.find(
      astrenv(:oidc_acr_config)[acr][:auth_event_set] || [],
      fn
        conf_auth_event_set ->
          conf_auth_event_set = MapSet.new(conf_auth_event_set)

        MapSet.subset?(conf_auth_event_set, searched_auth_events_set)
      end
    )
  rescue
    _ ->
      nil
  end
end
