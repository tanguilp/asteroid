defmodule Asteroid.OIDC.AuthenticationEvent do
  @moduledoc """
  Convenience functions to work with authentication events

  The `%Asteroid.OIDC.AuthenticationEvent{}` object has the following meaningful members in
  its `:data` field:
  - `"name"`: the event name (`t:Asteroid.AuthenticationEvent.name/0`)
  - `"amr"`: the AMR of the event (`t:Asteroid.OIDC.amr/0`)
  - `"time"`: the time the authentication event occured (`non_neg_integer()`)
  - `"exp"`: expiration time (`non_neg_integer()`)
  """

  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.OIDC.AuthenticatedSession
  alias Asteroid.Token

  @type id :: String.t()

  @type name :: String.t()

  @enforce_keys [:id, :authenticated_session_id]

  defstruct [:id, :authenticated_session_id, :data]

  @type t :: %__MODULE__{
    id: id(),
    authenticated_session_id: AuthenticatedSession.id(),
    data: map()
  }

  @doc """
  Generates a new authentication event
  """

  @spec gen_new(AuthenticatedSession.id()) :: t()

  def gen_new(authenticated_session_id) do
    %__MODULE__{
      id: secure_random_b64(),
      authenticated_session_id: authenticated_session_id,
      data: %{},
    }
  end

  @doc """
  Gets an authentication event from the store
  """

  @spec get(id(), Keyword.t()) :: {:ok, t()} | {:error, Exception.t()}

  def get(authentication_event_id, _opts \\ []) do
    token_store_module = astrenv(:token_store_authentication_event)[:module]
    token_store_opts = astrenv(:token_store_authentication_event)[:opts] || []

    case token_store_module.get(authentication_event_id, token_store_opts) do
      {:ok, authentication_event} when not is_nil(authentication_event) ->
        {:ok, authentication_event}

      {:ok, nil} ->
        {:error, Token.InvalidTokenError.exception(
          sort: "authentication event",
          reason: "not found in the store",
          id: authentication_event_id)}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Returns all authentication events associated to an authenticated session
  """

  @spec get_from_authenticated_session_id(AuthenticatedSession.id()) :: [%__MODULE__{}]

  def get_from_authenticated_session_id(auth_session_id) do
    ae_store_module = astrenv(:token_store_authentication_event)[:module]
    ae_store_opts = astrenv(:token_store_authentication_event)[:opts] || []

    case ae_store_module.get_from_authenticated_session_id(auth_session_id, ae_store_opts) do
      {:ok, auth_event_ids} ->
        Enum.reduce(auth_event_ids,
                    [],
                    fn
                      auth_event_id, acc ->
                        case get(auth_event_id) do
                          {:ok, auth_event} ->
                            [auth_event | acc]

                          {:error, _} ->
                            acc
                        end
                    end)

      _ ->
        []
    end
  end

  @doc """
  Stores an authentication event
  """

  @spec store(t(), Context.t()) :: {:ok, t()} | {:error, any()}

  def store(authentication_event, ctx \\ %{})

  def store(authentication_event, ctx) do
    token_store_module = astrenv(:token_store_authentication_event)[:module]
    token_store_opts = astrenv(:token_store_authentication_event)[:opts] || []

    authentication_event =
      astrenv(:token_store_authentication_event_before_store_callback).(authentication_event,
                                                                         ctx)

    case token_store_module.put(authentication_event, token_store_opts) do
      :ok ->
        AuthenticatedSession.update_acr(authentication_event.authenticated_session_id)

        {:ok, authentication_event}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Deletes an authentication event
  """

  @spec delete(t() | id()) :: :ok | {:error, any()}

  def delete(%__MODULE__{id: id, authenticated_session_id: authenticated_session_id}) do
    token_store_as_module = astrenv(:token_store_authentication_event)[:module]
    token_store_as_opts = astrenv(:token_store_authentication_event)[:opts] || []

    res = token_store_as_module.delete(id, token_store_as_opts)

    AuthenticatedSession.update_acr(authenticated_session_id)

    res
  end

  def delete(authentication_event_id) when is_binary(authentication_event_id) do
    {:ok, authentication_event} = get(authentication_event_id)

    delete(authentication_event)
  end

  @doc """
  Puts a value into the `data` field of authentication event

  If the value is `nil`, the authentication event is not changed and the filed is not added.
  """

  @spec put_value(t(), any(), any()) :: t()

  def put_value(authentication_event, _key, nil), do: authentication_event

  def put_value(authentication_event, key, val) do
    %{authentication_event | data: Map.put(authentication_event.data, key, val)}
  end

  @doc """
  Removes a value from the `data` field of a authentication event

  If the value does not exist, does nothing.
  """

  @spec delete_value(t(), any()) :: t()

  def delete_value(authentication_event, key) do
    %{authentication_event | data: Map.delete(authentication_event.data, key)}
  end
end
