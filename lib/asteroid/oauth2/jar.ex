defmodule Asteroid.OAuth2.JAR do
  @moduledoc """
  Functions to work with JWT Secured Authorization Request (JAR)
  """

  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.Crypto
  alias AsteroidWeb.Router.Helpers, as: Routes

  defmodule RequestNotSupportedError do
    @moduledoc """
    Error returned when requesting with a JAR request object is not supported
    """

    defexception []

    @impl true

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "use of JAR request objects is disabled"
          <> " (current config: #{inspect astrenv(:oauth2_jar_enabled)})"

        :normal ->
          "use of JAR request objects is disabled"

        :minimal ->
          ""
      end
    end
  end

  defmodule RequestURINotSupportedError do
    @moduledoc """
    Error returned when requesting with a JAR request object URI is not supported
    """

    defexception []

    @impl true

    def message(_) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          "use of JAR request object URIs is disabled"
          <> " (current config: #{inspect astrenv(:oauth2_jar_enabled)})"

        :normal ->
          "use of JAR request object URIs is disabled"

        :minimal ->
          ""
      end
    end
  end

  defmodule InvalidRequestURIError do
    @moduledoc """
    Error returned when requesting with a JAR request object URI fails
    """

    defexception [:reason]

    @type t :: %__MODULE__{
      reason: String.t()
    }

    @impl true

    def message(%{reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          reason

        :normal ->
          reason

        :minimal ->
          ""
      end
    end
  end

  defmodule InvalidRequestObjectError do
    @moduledoc """
    Error returned when parsing and validatin a JAR object request fails
    """

    defexception [:reason]

    @type t :: %__MODULE__{
      reason: String.t()
    }

    @impl true

    def message(%{reason: reason}) do
      case astrenv(:api_error_response_verbosity) do
        :debug ->
          reason

        :normal ->
          reason

        :minimal ->
          ""
      end
    end
  end

  @doc """
  Parses and verifies a request object
  """

  @spec verify_and_parse(String.t()) :: {:ok, map()} | {:error, Exception.t()}

  def verify_and_parse(request_object_str) do
    if is_binary(decode_jwe_header(request_object_str)["enc"]) do
      case decrypt_jwe(request_object_str) do
        {:ok, jws} ->
          verify_and_parse_jws(jws)

        {:error, _} = error ->
          error
      end
    else
      verify_and_parse_jws(request_object_str)
    end
  rescue
    e ->
      {:error, e}
  end

  @spec decode_jwe_header(String.t()) :: map()

  defp decode_jwe_header(request_object_str) do
    request_object_str
    |> String.split(".")
    |> List.first()
    |> Base.url_decode64!(padding: false)
    |> Jason.decode!()
  rescue
    _ ->
      raise InvalidRequestObjectError, reason: "Invalid JWE header"
  end

  @spec decrypt_jwe(String.t()) :: {:ok, String.t()} | {:error, Exception.t()}

  defp decrypt_jwe(jwe) do
    jwe_alg_supported = astrenv(:oauth2_jar_request_object_encryption_alg_values_supported) || []
    jwe_enc_supported = astrenv(:oauth2_jar_request_object_encryption_enc_values_supported) || []

    eligible_jwks =
      Crypto.Key.get_all()
      |> Enum.filter(
        fn
          %JOSE.JWK{fields: fields} ->
            (fields["use"] == "enc" or fields["use"] == nil) and
            (fields["key_ops"] in ["encrypt", "deriveKey"] or fields["key_ops"] == nil) and
            (fields["alg"] in jwe_alg_supported or fields["alg"] == nil)
        end
      )
      # as per https://mailarchive.ietf.org/arch/msg/oauth/pNMHnuBeBgF5zlea0RkA4bcmhz0

    jwe_header = decode_jwe_header(jwe)

    if jwe_header["alg"] in jwe_alg_supported and jwe_header["enc"] in jwe_enc_supported do
      maybe_payload =
        Enum.find_value(
          eligible_jwks,
          :decryption_failure,
          fn
            jwk ->
              try do
                {message, %JOSE.JWE{}} = JOSE.JWE.block_decrypt(jwk, jwe)
                # FIXME: verify that result alg and enc in whitelist?

                message
              rescue
                _ ->
                  false
              end
          end
        )

      case maybe_payload do
        payload when is_binary(payload) ->
          {:ok, payload}

        :decryption_failure ->
          {:error, InvalidRequestObjectError.exception(reason: "JWE decryption failed")}
      end
    else
      {:error, InvalidRequestObjectError.exception(reason: "Unsupported JWE `alg` or `enc`")}
    end
  end

  @spec verify_and_parse_jws(String.t()) :: {:ok, map()} | {:error, Exception.t()}

  defp verify_and_parse_jws(jws) do
    case Jason.decode(JOSE.JWS.peek_payload(jws)) do
      {:ok, unverified_params} ->
        case unverified_params do
          %{"client_id" => client_id} ->
            jws_alg_supported =
              astrenv(:oauth2_jar_request_object_signing_alg_values_supported) || []

            {:ok, client} =  Client.load_from_unique_attribute("client_id",
                                                               client_id,
                                                               attributes: ["jwks", "jwks_uri"])

            jws_alg = Jason.decode!(JOSE.JWS.peek_protected(jws))["alg"]

            if jws_alg == "none" and "none" in jws_alg_supported do
              case JOSE.JWS.verify_strict(%JOSE.JWK{}, ["none"], jws) do
                {true, payload, %JOSE.JWS{alg: {:jose_jws_alg_none, :none}}}->
                  case Jason.decode!(payload) do
                    {:ok, jwt} ->
                      {:ok, jwt}

                    {:error, _} ->
                      {:error, InvalidRequestObjectError.exception(
                        reason: "JWT parsing error")}
                  end

                _ ->
                  {:error, InvalidRequestObjectError.exception(
                    reason: "JWS signature verification failed")}
              end
            else
              case Client.get_jwks(client) do
                {:ok, keys} ->
                  eligible_jwks =
                    keys
                    |> Enum.map(&JOSE.JWK.from/1)
                    |> Enum.filter(
                      fn
                        %JOSE.JWK{fields: fields} ->
                          (fields["use"] == "sig" or fields["use"] == nil) and
                          (fields["key_ops"] == "sign" or fields["key_ops"] == nil) and
                          (fields["alg"] in jws_alg_supported or fields["alg"] == nil)
                      end
                    )

                  maybe_payload =
                    Enum.find_value(
                      eligible_jwks,
                      :signature_verification_failure,
                      fn
                        jwk ->
                          case JOSE.JWS.verify_strict(jwk, jws_alg_supported, jws) do
                            {true, message, %JOSE.JWS{}} ->
                              message

                            _ ->
                              false
                          end
                      end
                    )

                  case maybe_payload do
                    payload when is_binary(payload) ->
                      case Jason.decode!(payload) do
                        {:ok, jwt} ->
                          {:ok, jwt}

                        {:error, _} ->
                          {:error, InvalidRequestObjectError.exception(
                            reason: "JWT parsing error")}
                      end

                    :signature_verification_failure ->
                      {:error, InvalidRequestObjectError.exception(
                        reason: "JWS signature verification failed")}
                  end

                {:error, error} ->
                  {:error, InvalidRequestObjectError.exception(
                    reason: "client keys could not be retrieved (#{inspect(error)})")}
              end
            end

          _ ->
            {:error, InvalidRequestObjectError.exception(
              reason: "missing `client_id` in object request")}
        end

      {:error, _} ->
        {:error, InvalidRequestObjectError.exception(reason: "invalid object request data")}
    end
  rescue
    # raised by JOSE.JWS.peek/1
    _ ->
      {:error, InvalidRequestObjectError.exception(reason: "invalid JWS format")}
  end

  @doc """
  Retrieves a request object from a URI
  """

  @spec retrieve_object(String.t()) :: {:ok, String.t()} | {:error, Exception.t()}

  def retrieve_object(uri) do
    asteroid_request_object_store_prefix =
      Routes.request_object_url(AsteroidWeb.Endpoint, :create) <> "/"

    if String.starts_with?(uri, asteroid_request_object_store_prefix) do
      uri
      |> String.replace_prefix(asteroid_request_object_store_prefix, "")
      |> do_retrieve_object_internal()
    else
      do_retrieve_object_external(uri)
    end
  end

  @spec do_retrieve_object_internal(String.t()) :: {:ok, String.t()} | {:error, Exception.t()}

  defp do_retrieve_object_internal(object_id) do
    case get_stored_request_object(object_id) do
      {:ok, request_object_serialized} ->
        {:ok, request_object_serialized}

      {:error, :expired_request_object} ->
        InvalidRequestURIError.exception(reason: "request object has expired")

      {:error, reason} ->
        InvalidRequestURIError.exception(reason: inspect(reason))
    end
  end

  @spec do_retrieve_object_external(String.t()) :: {:ok, String.t()} | {:error, Exception.t()}

  defp do_retrieve_object_external(uri) do
    parsed_uri = URI.parse(uri)

    if parsed_uri.scheme == "https" do
      jar_request_uri_get_opts = astrenv(:oauth2_jar_request_uri_get_opts, [])

      case HTTPoison.get(uri, [], jar_request_uri_get_opts) do
        {:ok, response} ->
          {:ok, response.body}

        {:error, e} ->
          {:error, InvalidRequestURIError.exception(reason: Exception.message(e))}
      end
    else
      InvalidRequestURIError.exception(reason: "request URI must be HTTPS")
    end
  end

  @doc """
  Retrieves an object from Asteroid's request object store
  """

  @spec get_stored_request_object(Asteroid.TokenStore.GenericKV.key()) ::
  {:ok, String.t()}
  | {:error, any()}

  def get_stored_request_object(key) do
    module = astrenv(:token_store_request_object)[:module]
    opts = astrenv(:token_store_request_object)[:opts] || []

    req_obj_lifetime = astrenv(:oauth2_jar_request_object_lifetime, 0)

    now = now()

    case module.get(key, opts) do
      {:ok, %{"exp" => exp}} when now + req_obj_lifetime < exp ->
        {:error, :expired_request_object}

      {:ok, %{"request_object" => request_object}} ->
        {:ok, request_object}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Saves an object to Asteroid's request object store
  """

  @spec put_request_object(Asteroid.TokenStore.GenericKV.key(),
                           Asteroid.TokenStore.GenericKV.value()) ::
  :ok
  | {:error, any()}

  def put_request_object(key, value) do
    module = astrenv(:token_store_request_object)[:module]
    opts = astrenv(:token_store_request_object)[:opts] || []

    module.put(key, value, opts)
  end
end