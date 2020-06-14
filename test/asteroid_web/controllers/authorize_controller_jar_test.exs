defmodule AsteroidWeb.AuthorizeControllerJARTest do
  use AsteroidWeb.ConnCase, async: true

  import Asteroid.Config, only: [opt: 1]
  import Asteroid.Utils

  alias Asteroid.Client
  alias Asteroid.Crypto
  alias Asteroid.OAuth2
  alias AsteroidWeb.Router.Helpers, as: Routes
  alias OAuth2Utils.Scope

  @base_params %{
    "response_type" => "code",
    "client_id" => "client_confidential_1",
    "redirect_uri" => "https://www.example.com",
    "scope" => "openid"
  }

  setup_all do
    Process.put(:scope_config, scopes: %{"openid" => []})

    rsa_sig_alg_all =
      JOSE.JWK.generate_key({:rsa, 1024})
      |> Crypto.Key.set_key_use(:sig)

    rsa_sig_alg_all_key_ops_verify =
      JOSE.JWK.generate_key({:rsa, 1024})
      |> Crypto.Key.set_key_ops(["verify"])

    rsa_sig_alg_PS384 =
      JOSE.JWK.generate_key({:rsa, 1024})
      |> Crypto.Key.set_key_use(:sig)
      |> Crypto.Key.set_key_sig_alg("PS384")

    rsa_enc_alg_all =
      JOSE.JWK.generate_key({:rsa, 1024})
      |> Crypto.Key.set_key_use(:enc)

    rsa_enc_alg_key_ops_decrypt =
      JOSE.JWK.generate_key({:rsa, 1024})
      |> Crypto.Key.set_key_use(:enc)
      |> Crypto.Key.set_key_ops(["decrypt"])

    rsa_enc_alg_rsaoaep =
      JOSE.JWK.generate_key({:rsa, 1024})
      |> Crypto.Key.set_key_use(:enc)
      |> Crypto.Key.set_key_enc_alg("RSA-OAEP")

    {cache_module, cache_opts} = opt(:crypto_keys_cache)

    :ok = cache_module.put("rsa_enc_alg_all", rsa_enc_alg_all, cache_opts)
    :ok = cache_module.put("rsa_enc_alg_key_ops_decrypt", rsa_enc_alg_key_ops_decrypt, cache_opts)
    :ok = cache_module.put("rsa_enc_alg_rsaoaep", rsa_enc_alg_rsaoaep, cache_opts)
    # here we had client keys for testing purpose only (wront key use...)
    :ok = cache_module.put("rsa_sig_alg_all", rsa_sig_alg_all, cache_opts)

    Client.load("client_confidential_1")
    |> elem(1)
    |> Client.add("jwks", [
      rsa_sig_alg_all |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1),
      rsa_sig_alg_all_key_ops_verify |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1),
      rsa_sig_alg_PS384 |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1),
      # here we had the server's enc keys just for testing purpose (signing with encryption key...
      rsa_enc_alg_all |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1),
      rsa_enc_alg_key_ops_decrypt |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1),
      rsa_enc_alg_rsaoaep |> JOSE.JWK.to_public() |> JOSE.JWK.to_map() |> elem(1)
    ])
    |> Client.store()

    %{
      "rsa_sig_alg_all" => rsa_sig_alg_all,
      "rsa_sig_alg_all_key_ops_verify" => rsa_sig_alg_all_key_ops_verify,
      "rsa_sig_alg_PS384" => rsa_sig_alg_PS384,
      "rsa_enc_alg_all" => rsa_enc_alg_all,
      "rsa_enc_alg_key_ops_decrypt" => rsa_enc_alg_key_ops_decrypt,
      "rsa_enc_alg_rsaoaep" => rsa_enc_alg_rsaoaep
    }
  end

  # success cases

  test "Success case - req obj - sig only", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    conn
    |> get("/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")
    |> json_response(200)
  end

  test "Success case - req obj - sig + enc", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_encryption_alg_values_supported, ["RSA1_5"])
    Process.put(:oauth2_jar_request_object_encryption_enc_values_supported, ["A128GCM"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")
      |> encrypt_request_object("rsa_enc_alg_all", "RSA1_5", "A128GCM")

    conn
    |> get("/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")
    |> json_response(200)
  end

  test "Success case - req obj - sig only with alg \"none\"", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["none", "RS256"])
    JOSE.JWA.unsecured_signing(true)

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "none")

    conn
    |> get("/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")
    |> json_response(200)

    JOSE.JWA.unsecured_signing(false)
  end

  test "Success case - req uri local - sig only", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_uri_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    key = secure_random_b64()

    OAuth2.JAR.put_request_object(key, %{"request_object" => req_obj, "exp" => now() + 10})

    req_uri = Routes.request_object_url(AsteroidWeb.Endpoint, :show, key)

    conn
    |> get("/authorize?#{URI.encode_query(Map.put(@base_params, "request_uri", req_uri))}")
    |> json_response(200)
  end

  # error cases

  test "Error case - req obj - not supported with valid client_id / redirect_uri",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :disabled)

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "request_not_supported"
    assert params["error_description"] =~ "use of JAR request objects is disabled"
  end

  test "Error case - req obj - not supported with invalid client_id",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :disabled)

    query_params = Map.put(@base_params, "client_id", "nonexistent_client_id")

    req_obj =
      query_params
      |> Map.put("iss", "nonexistent_client_id")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(query_params, "request", req_obj))}")

    assert html_response(conn, 400) =~ "use of JAR request objects is disabled"
  end

  test "Error case - req obj - not supported with no client_id & redirect_uri",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :disabled)

    query_params =
      @base_params
      |> Map.delete("client_id")
      |> Map.delete("redirect_uri")

    req_obj =
      query_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(query_params, "request", req_obj))}")

    assert html_response(conn, 400) =~ "missing parameter"
  end

  test "Error case - req obj - oidc: missing response_type query parameter",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)

    query_params =
      @base_params
      |> Map.delete("response_type")

    req_obj =
      query_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(query_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request"
    assert params["error_description"] =~ "missing parameter"
  end

  test "Error case - req uri - not supported with valid client_id / redirect_uri",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :disabled)

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    key = secure_random_b64()

    OAuth2.JAR.put_request_object(key, %{"request_object" => req_obj, "exp" => now() + 10})

    req_uri = Routes.request_object_url(AsteroidWeb.Endpoint, :show, key)

    conn =
      get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request_uri", req_uri))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "request_uri_not_supported"
    assert params["error_description"] =~ "use of JAR request URIs is disabled"
  end

  test "Error case - req uri - not supported with invalid client_id", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :disabled)

    query_params = Map.put(@base_params, "client_id", "nonexistent_client_id")

    req_obj =
      query_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    key = secure_random_b64()

    OAuth2.JAR.put_request_object(key, %{"request_object" => req_obj, "exp" => now() + 10})

    req_uri = Routes.request_object_url(AsteroidWeb.Endpoint, :show, key)

    conn =
      get(conn, "/authorize?#{URI.encode_query(Map.put(query_params, "request_uri", req_uri))}")

    assert html_response(conn, 400) =~ "use of JAR request URIs is disabled"
  end

  test "Error case - req uri - not supported with no redirect_uri & client_id",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :disabled)

    query_params =
      @base_params
      |> Map.delete("client_id")
      |> Map.delete("redirect_uri")

    req_obj =
      query_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    key = secure_random_b64()

    OAuth2.JAR.put_request_object(key, %{"request_object" => req_obj, "exp" => now() + 10})

    req_uri = Routes.request_object_url(AsteroidWeb.Endpoint, :show, key)

    conn =
      get(conn, "/authorize?#{URI.encode_query(Map.put(query_params, "request_uri", req_uri))}")

    assert html_response(conn, 400) =~ "missing parameter"
  end

  test "Error case - req uri - oidc missing response_type query parameter",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_uri_only)

    query_params =
      @base_params
      |> Map.delete("response_type")

    req_obj =
      query_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    key = secure_random_b64()

    OAuth2.JAR.put_request_object(key, %{"request_object" => req_obj, "exp" => now() + 10})

    req_uri = Routes.request_object_url(AsteroidWeb.Endpoint, :show, key)

    conn =
      get(conn, "/authorize?#{URI.encode_query(Map.put(query_params, "request_uri", req_uri))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request"
    assert params["error_description"] =~ "missing parameter"
  end

  test "Error case - req obj - invalid audience", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_verify_audience, true)

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", "https://example.com/invalid_audience")
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "invalid `aud` or `iss` JWT field"
  end

  test "Error case - req obj - invalid issuer", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_verify_audience, true)

    req_obj =
      @base_params
      |> Map.put("iss", "invalid_issuer")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "invalid `aud` or `iss` JWT field"
  end

  test "Error case - req obj - client_id differs between query param and req obj",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> Map.put("client_id", "client_confidential_1")
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    params = Map.put(@base_params, "client_id", "client_confidential_2")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"

    assert params["error_description"] =~
             "Request and request object `response_type` or `client_id` don't match"
  end

  test "Error case - req obj - response_type differs between query param and req obj",
       %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> Map.put("client_id", "client_confidential_1")
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    params = Map.put(@base_params, "response_type", "token")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"

    assert params["error_description"] =~
             "Request and request object `response_type` or `client_id` don't match"
  end

  test "Error case - req obj - invalid signature", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    [header, payload, sig] = String.split(req_obj, ".")

    # should be enough to make the sig invalid /s
    sig = String.reverse(sig)

    req_obj = Enum.join([header, payload, sig], ".")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWS signature verification failed"
  end

  test "Error case - req obj - sig alg not allowed", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS512")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWS signature verification failed"
  end

  test "Error case - req obj - sig alg \"none\" not allowed", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    JOSE.JWA.unsecured_signing(true)

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "none")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    JOSE.JWA.unsecured_signing(false)

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWS signature verification failed"
  end

  test "Error case - req obj - sig key invalid use", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_enc_alg_all"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWS signature verification failed"
  end

  test "Error case - req obj - sig key invalid key_ops", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all_key_ops_verify"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWS signature verification failed"
  end

  test "Error case - req obj - sig key invalid key alg", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_PS384"], "RS256")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWS signature verification failed"
  end

  # the JWS header can lie:
  # https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

  test "Error case - req obj - sig valid but different alg than the one declared in JWS header",
       %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS384")

    [_header, payload, sig] = String.split(req_obj, ".")

    malicious_header = Base.encode64("{\"alg\":\"RS256\"}", padding: false)

    req_obj = Enum.join([malicious_header, payload, sig], ".")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWS signature verification failed"
  end

  test "Error case - req obj - encryption invalid", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_encryption_alg_values_supported, ["RSA1_5"])
    Process.put(:oauth2_jar_request_object_encryption_enc_values_supported, ["A128GCM"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")
      |> encrypt_request_object("rsa_enc_alg_all", "RSA1_5", "A128GCM")

    [header, cek, iv, ciphertext, auth_tag] = String.split(req_obj, ".")

    ciphertext = String.reverse(ciphertext)

    req_obj = Enum.join([header, cek, iv, ciphertext, auth_tag], ".")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWE decryption failure"
  end

  test "Error case - req obj - enc invalid key use", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_encryption_alg_values_supported, ["RSA1_5"])
    Process.put(:oauth2_jar_request_object_encryption_enc_values_supported, ["A128GCM"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")
      |> encrypt_request_object("rsa_sig_alg_all", "RSA1_5", "A128GCM")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWE decryption failure"
  end

  test "Error case - req obj - enc invalid key ops", %{conn: conn} = params do
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_encryption_alg_values_supported, ["RSA1_5"])
    Process.put(:oauth2_jar_request_object_encryption_enc_values_supported, ["A128GCM"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")
      |> encrypt_request_object("rsa_enc_alg_key_ops_decrypt", "RSA1_5", "A128GCM")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWE decryption failure"
  end

  test "Error case - req obj - enc invalid alg for key", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_encryption_alg_values_supported, ["RSA1_5"])
    Process.put(:oauth2_jar_request_object_encryption_enc_values_supported, ["A128GCM"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")
      |> encrypt_request_object("rsa_enc_alg_rsaoaep", "RSA1_5", "A128GCM")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWE decryption failure"
  end

  # relevance of the 2 following tests is questionnable, see:
  # https://security.stackexchange.com/questions/214185/json-web-encryption-jwe-should-one-verify-the-alg-and-enc-similarly-to-jws-al

  test "Error case - req obj - enc valid but different alg than the one declared in JWE header",
       %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_encryption_alg_values_supported, ["RSA1_5"])
    Process.put(:oauth2_jar_request_object_encryption_enc_values_supported, ["A128GCM"])

    # needed for OAEP
    JOSE.JWA.crypto_fallback(true)

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")
      |> encrypt_request_object("rsa_enc_alg_all", "RSA-OAEP", "A128GCM")

    JOSE.JWA.crypto_fallback(false)

    [_header, cek, iv, ciphertext, auth_tag] = String.split(req_obj, ".")

    malicious_header = Base.encode64("{\"alg\":\"RSA1_5\",\"enc\":\"A128GCM\"}", padding: false)

    req_obj = Enum.join([malicious_header, cek, iv, ciphertext, auth_tag], ".")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWE decryption failure"
  end

  test "Error case - req obj - enc valid but different enc than the one declared in JWE header",
       %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])
    Process.put(:oauth2_jar_request_object_encryption_alg_values_supported, ["RSA1_5"])
    Process.put(:oauth2_jar_request_object_encryption_enc_values_supported, ["A128GCM"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")
      |> encrypt_request_object("rsa_enc_alg_all", "RSA1_5", "A192GCM")

    [_header, cek, iv, ciphertext, auth_tag] = String.split(req_obj, ".")

    malicious_header = Base.encode64("{\"alg\":\"RSA1_5\",\"enc\":\"A128GCM\"}", padding: false)

    req_obj = Enum.join([malicious_header, cek, iv, ciphertext, auth_tag], ".")

    conn = get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request", req_obj))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_object"
    assert params["error_description"] =~ "JWE decryption failure"
  end

  test "Error case - req uri local - URI too long", %{conn: conn} = params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_uri_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    req_obj =
      @base_params
      |> Map.put("iss", "client_confidential_1")
      |> Map.put("aud", OAuth2.issuer())
      |> build_signed_request_object(params["rsa_sig_alg_all"], "RS256")

    key = String.duplicate("x", 513)

    OAuth2.JAR.put_request_object(key, %{"request_object" => req_obj, "exp" => now() + 10})

    req_uri = Routes.request_object_url(AsteroidWeb.Endpoint, :show, key)

    conn =
      get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request_uri", req_uri))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_uri"
    assert params["error_description"] =~ "`request_uri` too long"
  end

  test "Error case - req uri local - req obj doesn't exist", %{conn: conn} = _params do
    Process.put(:oidc_flow_authorization_code_web_authorization_callback, &print_json_result/2)
    Process.put(:oauth2_jar_enabled, :request_uri_only)
    Process.put(:oauth2_jar_request_object_signing_alg_values_supported, ["RS256"])

    key = secure_random_b64()

    req_uri = Routes.request_object_url(AsteroidWeb.Endpoint, :show, key)

    conn =
      get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request_uri", req_uri))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_uri"
    assert params["error_description"] =~ "object could not be found"
  end

  test "Error case - req uri local - URI not https", %{conn: conn} = _params do
    Process.put(:oauth2_jar_enabled, :request_uri_only)

    req_uri = "http://www.example.com/object/afekxgasmfyskgzfxga"

    conn =
      get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request_uri", req_uri))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_uri"
    assert params["error_description"] =~ "request URI must be HTTPS"
  end

  test "Error case - req uri local - req uri not reachable", %{conn: conn} = _params do
    Process.put(:oauth2_jar_enabled, :request_uri_only)

    req_uri = "https://www.somedomain.nonexistenttld/object/dsxfhjiwaso"

    conn =
      get(conn, "/authorize?#{URI.encode_query(Map.put(@base_params, "request_uri", req_uri))}")

    assert redirected_to(conn) =~ "https://www.example.com"

    params = URI.decode_query(URI.parse(redirected_to(conn)).query)

    assert params["error"] == "invalid_request_uri"
  end

  # helper functions

  defp print_json_result(conn, request) do
    request_map =
      Map.from_struct(request)
      |> Map.put(:client_id, request.client_id)
      |> Map.put(:requested_scopes, Scope.Set.to_list(request.requested_scopes))

    conn
    |> put_status(200)
    |> Phoenix.Controller.json(request_map)
  end

  defp build_signed_request_object(params, key, alg) do
    JOSE.JWS.sign(
      key,
      Jason.encode!(params),
      %{"alg" => alg}
    )
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp encrypt_request_object(message, key_name, alg, enc) do
    {:ok, jwk} = Crypto.Key.get(key_name)

    JOSE.JWE.block_encrypt(jwk, message, %{"alg" => alg, "enc" => enc})
    |> JOSE.JWE.compact()
    |> elem(1)
  end
end
