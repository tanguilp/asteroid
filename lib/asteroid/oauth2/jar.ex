defmodule Asteroid.OAuth2.JAR do
  @moduledoc """
  Functions to work with JWT Secured Authorization Request (JAR)
  """

  import Asteroid.Config, only: [opt: 1]
  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias AsteroidWeb.Router.Helpers, as: Routes

  defmodule RequestNotSupportedError do
    @moduledoc """
    Error returned when requesting with a JAR request object is not supported
    """

    @enforce_keys [:request_object]

    defexception [:request_object]

    @type t :: %__MODULE__{
            request_object: String.t()
          }

    @impl true

    def message(_) do
      case opt(:api_error_response_verbosity) do
        :debug ->
          "use of JAR request objects is disabled" <>
            " (current config: #{inspect(opt(:oauth2_jar_enabled))})"

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
      case opt(:api_error_response_verbosity) do
        :debug ->
          "use of JAR request URIs is disabled" <>
            " (current config: #{inspect(opt(:oauth2_jar_enabled))})"

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
      case opt(:api_error_response_verbosity) do
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

    @enforce_keys [:reason]

    defexception [:reason]

    @type t :: %__MODULE__{
            reason: String.t()
          }

    @impl true
    def message(%{reason: reason}) do
      case opt(:api_error_response_verbosity) do
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
  Returns the list of supported signing algorithms for request objects

  See
  #{Asteroid.Config.link_to_option(:oauth2_jar_request_object_signing_alg_values_supported)}
  """
  @spec signing_alg_values_supported() :: [JOSEUtils.JWA.sig_alg()]
  def signing_alg_values_supported() do
    case opt(:oauth2_jar_request_object_signing_alg_values_supported) do
      :auto ->
        Asteroid.Crypto.JOSE.public_keys()
        |> Enum.flat_map(&JOSEUtils.JWK.sig_algs_supported/1)
        |> Enum.uniq()

      l ->
        l
    end
  end

  @doc """
  Returns the list of supported encryption key derivation algorithms for request objects

  See
  #{Asteroid.Config.link_to_option(:oauth2_jar_request_object_encryption_alg_values_supported)}
  """
  @spec encryption_alg_values_supported() :: [JOSEUtils.JWA.enc_alg()]
  def encryption_alg_values_supported() do
    case opt(:oauth2_jar_request_object_encryption_alg_values_supported) do
      :auto ->
        Asteroid.Crypto.JOSE.public_keys()
        |> Enum.flat_map(&JOSEUtils.JWK.enc_algs_supported/1)
        |> Enum.uniq()

      l ->
        l
    end
  end

  @doc """
  Returns the list of supported content encryption algorithms for request objects

  See
  #{Asteroid.Config.link_to_option(:oauth2_jar_request_object_encryption_enc_values_supported)}
  """
  @spec encryption_enc_values_supported() :: [JOSEUtils.JWA.enc_enc()]
  def encryption_enc_values_supported(),
    do: opt(:oauth2_jar_request_object_encryption_enc_values_supported)

  @doc """
  Parses and verifies a request object
  """
  @spec verify_and_parse(String.t(), Client.t()) :: {:ok, map()} | {:error, Exception.t()}
  def verify_and_parse(request_object_str, client) do
    with {:ok, jws} <- maybe_decrypt(request_object_str, client),
         {:ok, req_object_str} <- verify(jws, client),
         {:ok, req_object} <- Jason.decode(req_object_str),
         :ok <- request_object_issuer_valid?(req_object, client),
         :ok <- request_object_audience_valid?(req_object) do
      {:ok, req_object}
    end
  end

  @spec maybe_decrypt(String.t(), Client.t()) :: {:ok, String.t()} | {:error, Exception.t()}
  defp maybe_decrypt(maybe_jwe, client) do
    if JOSEUtils.is_jwe?(maybe_jwe),
      do: do_decrypt(maybe_jwe, client),
      else: {:ok, maybe_jwe}
  end

  defp do_decrypt(jwe, client) do
    client = Client.fetch_attributes(
      client,
      ["request_object_encryption_alg", "request_object_encryption_enc", "jwks", "jwks_uri"]
    )

    enc_alg = client.attrs["request_object_encryption_alg"] || encryption_alg_values_supported()
    enc_enc = client.attrs["request_object_encryption_enc"] || encryption_enc_values_supported()

    case Crypto.JOSE.decrypt(jwe, client, alg: enc_alg, enc: enc_enc) do
      {:ok, {decrypted_content, _jwk}} ->
        {:ok, decrypted_content}

      {:error, e} ->
        {:error, %InvalidRequestObjectError{reason: Exception.message(e)}}
    end
  end

  @spec verify(String.t(), Client.t()) :: {:ok, map()} | {:error, Exception.t()}
  defp verify(jws, client) do
    if JOSEUtils.is_jws?(jws),
      do: do_verify(jws, client),
      else: {:error, %InvalidRequestObjectError{reason: "invalid jws"}}
  end

  defp do_verify(jws, client) do
    client = Client.fetch_attributes(client, ["request_object_signing_alg"])

    case client.attrs["request_object_signing_alg"] do
      <<_::binary>> = alg ->
        case Crypto.JOSE.verify(jws, client, alg: alg) do
          {:ok, {verified_content, _jwk}} ->
            {:ok, verified_content}

          {:error, e} ->
            {:error, %InvalidRequestObjectError{reason: Exception.message(e)}}
        end

      nil ->
        {:error, %InvalidRequestObjectError{
          reason: "missing `request_object_signing_alg` client configuration"}}
    end

  end

  @spec request_object_issuer_valid?(map(), Client.t()) :: :ok | {:error, Exception.t()}
  defp request_object_issuer_valid?(request_object, client) do
    if opt(:oauth2_jar_request_object_verify_issuer) do
      client = Client.fetch_attributes(client, ["client_id"])

      if request_object["iss"] == client.attrs["client_id"],
        do: :ok,
        else: {:error, %InvalidRequestObjectError{reason: "invalid issuer"}}
    else
      :ok
    end
  end

  @spec request_object_audience_valid?(map()) :: :ok | {:error, Exception.t()}
  defp request_object_audience_valid?(request_object) do
    if opt(:oauth2_jar_request_object_verify_audience) do
      aud = request_object["aud"]

      if (is_list(aud) and OAuth2.issuer() in aud) or OAuth2.issuer() == aud,
        do: :ok,
        else: {:error, %InvalidRequestObjectError{reason: "invalid audience"}}
    else
      :ok
    end
  end

  @doc """
  Retrieves a request object from a URI
  """

  @spec retrieve_object(String.t()) :: {:ok, String.t()} | {:error, Exception.t()}

  # as per the specification:
  #    The entire Request URI MUST NOT exceed 512 ASCII characters.  There
  #    are three reasons for this restriction.

  def retrieve_object(uri) when byte_size(uri) > 512 do
    {:error, InvalidRequestURIError.exception(reason: "`request_uri` too long")}
  end

  def retrieve_object(uri) do
    asteroid_request_object_store_prefix =
      Routes.request_object_url(AsteroidWeb.Endpoint, :create) <> "/"

    if String.starts_with?(uri, asteroid_request_object_store_prefix) do
      uri
      |> String.replace_prefix(asteroid_request_object_store_prefix, "")
      |> get_stored_request_object()
    else
      do_retrieve_object_external(uri)
    end
  end

  @spec do_retrieve_object_external(String.t()) :: {:ok, String.t()} | {:error, Exception.t()}

  defp do_retrieve_object_external(uri) do
    parsed_uri = URI.parse(uri)

    if parsed_uri.scheme == "https" do
      jar_request_uri_get_opts = opt(:oauth2_jar_request_uri_get_opts)

      case HTTPoison.get(uri, [], jar_request_uri_get_opts) do
        {:ok, %HTTPoison.Response{status_code: 200, headers: headers, body: body}} ->
          if headers_contain_content_type?(headers, "application", "jwt") do
            {:ok, body}
          else
            {:error,
             InvalidRequestURIError.exception(
               reason: "requesting the request uri resulted in incorrect `content-type`"
             )}
          end

        {:ok, %HTTPoison.Response{status_code: status_code}} ->
          {:error,
           InvalidRequestURIError.exception(
             reason: "requesting the request uri resulted in HTTP code #{status_code}"
           )}

        {:error, e} ->
          {:error, InvalidRequestURIError.exception(reason: Exception.message(e))}
      end
    else
      {:error, InvalidRequestURIError.exception(reason: "request URI must be HTTPS")}
    end
  end

  @doc """
  Retrieves an object from Asteroid's request object store
  """

  @spec get_stored_request_object(Asteroid.ObjectStore.GenericKV.key()) ::
          {:ok, String.t()}
          | {:error, Exception.t()}

  def get_stored_request_object(key) do
    module = opt(:object_store_request_object)[:module]
    opts = opt(:object_store_request_object)[:opts] || []

    req_obj_lifetime = opt(:oauth2_jar_request_object_lifetime)

    now = now()

    case module.get(key, opts) do
      {:ok, %{"exp" => exp}} when now + req_obj_lifetime < exp ->
        {:error, InvalidRequestURIError.exception(reason: "object has expired")}

      {:ok, %{"request_object" => request_object}} ->
        {:ok, request_object}

      {:ok, nil} ->
        {:error, InvalidRequestURIError.exception(reason: "object could not be found")}

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Saves an object to Asteroid's request object store
  """

  @spec put_request_object(
          Asteroid.ObjectStore.GenericKV.key(),
          Asteroid.ObjectStore.GenericKV.value()
        ) ::
          :ok
          | {:error, any()}

  def put_request_object(key, value) do
    module = opt(:object_store_request_object)[:module]
    opts = opt(:object_store_request_object)[:opts] || []

    module.put(key, value, opts)
  end
end
