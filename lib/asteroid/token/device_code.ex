defmodule Asteroid.Token.DeviceCode do
  import Asteroid.Config, only: [opt: 1]
  import Asteroid.Utils

  alias Asteroid.Context
  alias Asteroid.Client
  alias Asteroid.OAuth2
  alias Asteroid.Token

  @moduledoc """
  Device code structure

  Note that this token is searched using 2 keys:
  - the device code (when polling)
  - the user code, to mark this token as `"granted"` or `"denied"` upon completion of
  the user web flow
  Thus, even though the primary key is the device code id, the user code should probably be
  indexed as well.

  ## Field naming
  The `data` field holds the token data. The following field names are standard and are used
  by Asteroid:
  - `"exp"`: the expiration unix timestamp of the device code
  - `"clid"`: the `t:Asteroid.Client.id()` of the device code
  - `"sjid"`: the `t:Asteroid.Subject.id()` of the user that has accepted the request,
  after entering the user code in the web flow
  - `"requested_scopes"`: a list of `OAuth2Utils.Scope.scope()` requested scopes
  - `"granted_scopes"`: a list of `OAuth2Utils.Scope.scope()` granted scopes
  - `"status"`: a `String.t()` for the status of the device code. Mandatory, one of:
    - `"authorization_pending"`: the user has not yet granted or denied the request (the default
    value upon the token's creation)
    - `"granted"`: the user has granted the request
    - `"denied"`: the user has denied the request
  """

  @enforce_keys [:id, :user_code, :serialization_format, :data]

  defstruct [:id, :user_code, :serialization_format, :data]

  @type t :: %__MODULE__{
          id: OAuth2.DeviceAuthorization.device_code(),
          user_code: binary() | nil,
          serialization_format: Asteroid.Token.serialization_format(),
          data: map()
        }

  @doc ~s"""
  Creates a new device code

  ## Options
  - `:id`: `String.t()` id, **mandatory**
  - `:user_code`: the `t:Asteroid.OAuth2.DeviceAuthorization.user_code/0` associated to the
  device code. **Mandatory**
  - `:data`: a data `map()`
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  """

  @spec new(Keyword.t()) :: t()

  def new(opts) do
    %__MODULE__{
      id: opts[:id] || raise("Missing device code"),
      user_code: opts[:user_code] || raise("Missing user code"),
      data: opts[:data] || %{},
      serialization_format: opts[:serialization_format] || :opaque
    }
  end

  @doc """
  Generates a new device code

  ## Options
  - `:user_code`: the user code to be presented to the user. **Mandatory**
  - `:serialization_format`: an `t:Asteroid.Token.serialization_format/0` atom, defaults to
  `:opaque`
  """

  @spec gen_new(Keyword.t()) :: t()
  def gen_new(opts \\ []) do
    %__MODULE__{
      id: secure_random_b64(),
      user_code: opts[:user_code] || raise("Missing user code"),
      data: %{},
      serialization_format:
        if(opts[:serialization_format], do: opts[:serialization_format], else: :opaque)
    }
  end

  @doc """
  Gets a device code from the device code store

  ## Options
  - `:check_active`: determines whether the validity of the device code should be checked.
  Defaults to `true`. For validity checking details, see `active?/1`
  """

  @spec get(OAuth2.DeviceAuthorization.device_code(), Keyword.t()) ::
          {:ok, t()}
          | {:error, Exception.t()}

  def get(device_code_id, opts \\ [check_active: true]) do
    code_store_module = opt(:object_store_device_code)[:module]
    code_store_opts = opt(:object_store_device_code)[:opts] || []

    case code_store_module.get(device_code_id, code_store_opts) do
      {:ok, device_code} when not is_nil(device_code) ->
        if opts[:check_active] != true or active?(device_code) do
          {:ok, device_code}
        else
          {:error,
           Token.InvalidTokenError.exception(
             sort: "device code",
             reason: "expired code",
             id: device_code_id
           )}
        end

      {:ok, nil} ->
        {:error,
         Token.InvalidTokenError.exception(
           sort: "device code",
           reason: "not found in the token store",
           id: device_code_id
         )}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Gets a device code from the device code store from its associated user code

  ## Options
  - `:check_active`: determines whether the validity of the device code should be checked.
  Defaults to `true`. For validity checking details, see `active?/1`
  """

  @spec get_from_user_code(OAuth2.DeviceAuthorization.user_code(), Keyword.t()) ::
          {:ok, t()}
          | {:error, Exception.t()}

  def get_from_user_code(user_code, opts \\ [check_active: true]) do
    code_store_module = opt(:object_store_device_code)[:module]
    code_store_opts = opt(:object_store_device_code)[:opts] || []

    case code_store_module.get_from_user_code(user_code, code_store_opts) do
      {:ok, device_code} when not is_nil(device_code) ->
        if opts[:check_active] != true or active?(device_code) do
          {:ok, device_code}
        else
          {:error,
           Token.InvalidTokenError.exception(
             sort: "device code",
             reason: "inactive token",
             id: device_code.id
           )}
        end

      {:ok, nil} ->
        {:error,
         Token.InvalidTokenError.exception(
           sort: "device code",
           reason: "invalid user code",
           id: user_code
         )}

      {:error, error} ->
        {:error, error}
    end
  end

  @doc """
  Stores a device code
  """

  @spec store(t(), Context.t()) :: {:ok, t()} | {:error, any()}

  def store(device_code, ctx) do
    code_store_module = opt(:object_store_device_code)[:module]
    code_store_opts = opt(:object_store_device_code)[:opts] || []

    device_code = opt(:object_store_device_code_before_store_callback).(device_code, ctx)

    case code_store_module.put(device_code, code_store_opts) do
      :ok ->
        {:ok, device_code}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Deletes a device code
  """

  @spec delete(t() | OAuth2.DeviceAuthorization.device_code()) :: :ok | {:error, any()}

  def delete(%__MODULE__{id: id}) do
    delete(id)
  end

  def delete(device_code_id) do
    code_store_module = opt(:object_store_device_code)[:module]
    code_store_opts = opt(:object_store_device_code)[:opts] || []

    code_store_module.delete(device_code_id, code_store_opts)
  end

  @doc """
  Puts a value into the `data` field of a device code

  If the value is `nil`, the device code is not changed and the filed is not added.
  """

  @spec put_value(t(), any(), any()) :: t()

  def put_value(device_code, _key, nil), do: device_code

  def put_value(device_code, key, val) do
    %{device_code | data: Map.put(device_code.data, key, val)}
  end

  @doc """
  Removes a value from the `data` field of a device code

  If the value does not exist, does nothing.
  """

  @spec delete_value(t(), any()) :: t()

  def delete_value(device_code, key) do
    %{device_code | data: Map.delete(device_code.data, key)}
  end

  @doc """
  Serializes the device code, using its inner `t:Asteroid.Token.serialization_format/0`
  information

  Supports serialization to `:opaque`.
  """

  @spec serialize(t()) :: String.t()

  def serialize(%__MODULE__{id: id, serialization_format: :opaque}) do
    id
  end

  @doc """
  Returns `true` if the token is active, `false` otherwise

  The following data, *when set*, are used to determine that a token is active:
  - `"exp"`: must be higher than current time
  """

  @spec active?(t()) :: boolean()
  def active?(device_code) do
    is_nil(device_code.data["exp"]) or device_code.data["exp"] > now()
  end

  @doc """
  Returns the device code lifetime

  ## Processing rules
  - If the client has the
  `"__asteroid_oauth2_flow_device_authorization_device_code_lifetime"` set to an integer,
  returns this value
  - Otherwise, if the
  #{Asteroid.Config.link_to_option(:oauth2_flow_device_authorization_device_code_lifetime)}
  #configuration option is set, return this value
  - Otherwise returns `0`
  """

  @spec lifetime(Context.t()) :: non_neg_integer()

  def lifetime(%{client: client}) do
    attr = "__asteroid_oauth2_flow_device_authorization_device_code_lifetime"

    client = Client.fetch_attributes(client, [attr])

    case client.attrs[attr] do
      lifetime when is_integer(lifetime) ->
        lifetime

      _ ->
        opt(:oauth2_flow_device_authorization_device_code_lifetime)
    end
  end
end
