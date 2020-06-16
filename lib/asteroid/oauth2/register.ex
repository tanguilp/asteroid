defmodule Asteroid.OAuth2.Register do
  @moduledoc """
  Utils fnuction related to client registration
  """

  import Asteroid.Config, only: [opt: 1]
  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.OAuth2
  alias OAuth2Utils.Scope

  @doc """
  Returns `:ok` if the request is authorized to register new clients,
  `{:error, Exception.t()}` otherwise

  Unauthenticated requests are authorized only if the
  #{Asteroid.Config.link_to_option(:oauth2_endpoint_register_authorization_policy)} is set
  to `:all`.

  A client passed as a parameter shall be authenticated.

  When using the HTTP `Bearer` scheme, it is not required that the client exists in Asteroid.
  """

  @spec request_authorized?(Plug.Conn.t(), Client.t() | nil) ::
          :ok
          | {:error, %OAuth2.Client.AuthenticationError{}}
          | {:error, %OAuth2.Client.AuthorizationError{}}

  def request_authorized?(conn, maybe_authenticated_client) do
    case opt(:oauth2_endpoint_register_authorization_policy) do
      :all ->
        :ok

      :authenticated_clients ->
        if APIac.authenticated?(conn) do
          :ok
        else
          if maybe_authenticated_client do
            {:error,
             Asteroid.OAuth2.Client.AuthenticationError.exception(
               reason: :client_authentication_required
             )}
          else
            {:error,
             Asteroid.OAuth2.Client.AuthenticationError.exception(
               reason: :client_authentication_required
             )}
          end
        end

      :authorized_clients ->
        if APIac.metadata(conn)["scope"] != nil and
             "asteroid.register" in Scope.Set.from_scope_param!(APIac.metadata(conn)["scope"]) do
          :ok
        else
          if maybe_authenticated_client do
            client = Client.fetch_attributes(maybe_authenticated_client, ["client_id", "scope"])

            if "asteroid.register" in client.attrs["scope"] do
              :ok
            else
              {:error,
               Asteroid.OAuth2.Client.AuthorizationError.exception(reason: :unauthorized_client)}
            end
          else
            {:error,
             Asteroid.OAuth2.Client.AuthenticationError.exception(
               reason: :client_authentication_required
             )}
          end
        end
    end
  end

  @doc """
  Returns `:ok` if the grant types and the responses types are consistent,
  `{:error, String.t()}` otherwise.

  The error response's string contains a human-readable explanation of the reason it is not
  consistent.

  The following table is used for consistency check:


  | grant_types value includes:                   | response_types      |
  |-----------------------------------------------|---------------------|
  | authorization_code                            | code                |
  | implicit                                      | token               |
  | implicit                                      | id_token            |
  | implicit                                      | token id_token      |
  | authorization_code, implicit                  | code id_token       |
  | authorization_code, implicit                  | code token          |
  | authorization_code, implicit                  | code id_token token |
  | password                                      | (none)              |
  | client_credentials                            | (none)              |
  | refresh_token                                 | (none)              |
  | urn:ietf:params:oauth:grant-type:jwt-bearer   | (none)              |
  | urn:ietf:params:oauth:grant-type:saml2-bearer | (none)              |

  """

  @spec grant_response_types_consistent?(
          [OAuth2.grant_type_str()],
          [OAuth2.response_type_str()]
        ) ::
          :ok
          | {:error, String.t()}

  def grant_response_types_consistent?(grant_types, response_types) do
    mapping = %{
      "code" => ["authorization_code"],
      "token" => ["implicit"],
      "id_token" => ["implicit"],
      "token id_token" => ["implicit"],
      "code id_token" => ["authorization_code", "implicit"],
      "code token" => ["authorization_code", "implicit"],
      "code id_token token" => ["authorization_code", "implicit"]
    }

    Enum.reduce_while(
      response_types,
      :ok,
      fn
        response_type, _acc ->
          mandatory_grant_types = mapping[response_type]

          if Enum.all?(mandatory_grant_types, &(&1 in grant_types)) do
            {:cont, :ok}
          else
            {:halt,
             {:error, "response_type `#{response_type}` have missing mandatory grant type"}}
          end
      end
    )
  end

  @doc """
  Generates a new id for the client attribute repository

  This function simply returns the client id passed in the processed metadata
  """

  @spec generate_client_resource_id(processed_metadata :: map(), Asteroid.Context.t()) ::
          AttributeRepository.resource_id()

  def generate_client_resource_id(%{"client_id" => client_id}, _ctx), do: client_id

  @doc """
  Generates a new OAuth2 client id

  It takes into parameter the map of the parsed and controlled client metadata ready to be
  returned to the initiating client.

  This function generates a new `client_id` given the following rules:
  - If the map value of `"client_name"` is a string:
    - Strips the parameters from invalid characters (not in the range \x20-\x7E)
    - Lowercase this string
    - Replace spaces by underscores
    - If the resulting string is not the empty string:
      - Returns it if no client as already the same `client_id`
      - Otherwise, append `"_1"`, `"_2"`, `"_3"`, `"_4"`... to `"_99"` until there's no client
      with that `client_id` already in the base
      - If all these client exists, returns a 20 bytes random string
    - Otherwise returns a 20 bytes random string
  - Otherwise returns a 20 bytes random string
  """

  @spec generate_client_id(map(), Asteroid.Context.t()) :: String.t()

  def generate_client_id(%{"client_name" => client_name}, _ctx) when is_binary(client_name) do
    client_name_sanitized =
      client_name
      |> String.replace(~r/[^\x20-\x7E]/, "")
      |> String.downcase(:ascii)
      |> String.replace(" ", "_")

    gen_new_client_id_from_client_name(client_name_sanitized, 0)
  end

  def generate_client_id(_, _ctx) do
    secure_random_b64(20)
  end

  @spec gen_new_client_id_from_client_name(String.t(), non_neg_integer()) :: String.t()

  defp gen_new_client_id_from_client_name(_client_name, n) when n >= 100 do
    secure_random_b64(20)
  end

  # client is only composed of special chars - no interest to use client name here

  defp gen_new_client_id_from_client_name("", _) do
    secure_random_b64(20)
  end

  defp gen_new_client_id_from_client_name(client_name, n) do
    client_name_suffixed =
      case n do
        0 ->
          client_name

        _ ->
          client_name <> "_" <> Integer.to_string(n)
      end

    case Client.load_from_unique_attribute("client_id", client_name_suffixed, attributes: []) do
      {:error, %AttributeRepository.Read.NotFoundError{}} ->
        # the client doesn't exist
        client_name_suffixed

      {:ok, _} ->
        gen_new_client_id_from_client_name(client_name, n + 1)
    end
  end

  @doc """
  Returns the computed client's type

  Returns `:public` if the client `"token_endpoint_auth_method"` is set to `"none"`,
  `:confidential` otherwise.
  """

  @spec client_type(Client.t()) :: OAuth2.Client.type()

  def client_type(client) do
    client = Client.fetch_attributes(client, ["token_endpoint_auth_method"])

    if client.attrs["token_endpoint_auth_method"] == "none" do
      :public
    else
      :confidential
    end
  end
end
