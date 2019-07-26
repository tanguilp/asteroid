# JWT Secured Authorization Request (JAR)

Asteroid implements the draft RFC JWT Secured Authorization Request (JAR)
([draft-ietf-oauth-jwsreq-19](https://tools.ietf.org/html/draft-ietf-oauth-jwsreq-19)).

## Signing and encryption keys

A request object can be either:
- signed then encrypted
- signed

Let's examine how Asteroid figures out which keys and algorithms to use.

### JAR signature

A client shall sign the request object. It uses one of its private keys to do so. It can
communicate the list of its signing key by:
- publishing it on a JWK URI. Asteroid uses the client's `"jwks_uri"` to retrieve those keys
(using the `JWKSURIUpdater` library). This is the preferred method, suited for servers
- including it in the `Asteroid.Client` `"jwks"` attribute. This is suited for mobile or javascript
applications that cannot publish keys at an endpoint

Asteroid comes with a configured list of acceptable signing algorithms with the
[`:oauth2_jar_request_object_signing_alg_values_supported`](file:///home/tangui/coding/asteroid/doc/Asteroid.Config.html#module-oauth2_jar_request_object_signing_alg_values_supported)
configuration option (which is also published in the metadata under the
`"request_object_signing_alg_values_supported"` key).

Asteroid will try all the eligible keys. An eligible key is one that fulfills **all** of the
following conditions:
- the `"use"` field is `"sig"` or is not set
- the `"key_ops"` field is `"sign"` or is not set
- the `"alg"` field is one of the those configured by
[`:oauth2_jar_request_object_signing_alg_values_supported`](Asteroid.Config.html#module-oauth2_jar_request_object_signing_alg_values_supported)
or is not set
  - note that even is the key has no `"alg"` set, only algorithms listed by the option above
  will be allowed

### JAR encryption

A client can optionally encrypt the request object. To do so, it needs to retrieve one public
encryption key from Asteroid. It can do so by picking one on the
`/discovery/keys` endpoint.

It then encrypts the JWS request object and sends it in a request.
Asteroid comes with a configured list of acceptable encryption algorithms with the
[`:oauth2_jar_request_object_encryption_alg_values_supported`](Asteroid.Config.html#module-oauth2_jar_request_object_encryption_alg_values_supported)
and
[`:oauth2_jar_request_object_encryption_enc_values_supported`](Asteroid.Config.html#module-oauth2_jar_request_object_encryption_enc_values_supported)
configuration options (which are also published in the metadata under the
`"request_object_encryption_alg_values_supported"` and
`"request_object_encryption_enc_values_supported"` keys).

Asteroid will select from its own crypto key store the keys that fulfill all of these conditions:
- the `"use"` field is `"enc"` or is not set
- the `"key_ops"` field is `"encrypt"` or `"deriveKey"`, or is not set
- the `"alg"` field is one of the those configured by
[`:oauth2_jar_request_object_encryption_alg_values_supported`](Asteroid.Config.html#module-oauth2_jar_request_object_encryption_alg_values_supported)
or is not set
  - note that even is the key has no `"alg"` set, only algorithms listed by the option above

## Request object store

Asteroid ships with a convenience request object store that can be reached on the
`/api/request` API.

It is enabled as soon as the
[`:token_store_request_object`](Asteroid.Config.html#module-token_store_request_object)
configuration option is set.

### API

This API supports 2 HTTP verbs: `GET` and `POST`.

Saving a request object to the server requires to request the API using `POST` with the
`application/x-www-form-urlencoded` content-type. The request object is the value of the
`"request_object"` key:

```bash
$ curl -v -d "request_object=yJhbGciOiJSUzI1NiI..." https://example.com/api/request_object
* TCP_NODELAY set
* Connected to localhost (127.0.0.1) port 4000 (#0)
> POST /api/request_object HTTP/1.1
> Host: localhost:4000
> User-Agent: curl/7.61.0
> Accept: */*
> Content-Length: 24
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 24 out of 24 bytes
< HTTP/1.1 201 Created
< cache-control: max-age=0, private, must-revalidate
< content-length: 0
< date: Wed, 24 Jul 2019 21:57:06 GMT
< location: http://localhost:4000/api/request_object/yld6TOlhjdoGtG3ZRJ-J6ZcqjBR0dpK4p_6Nxt4H7o0
< server: Cowboy
< x-request-id: FbR2pl-O3iwjLm4AAEzC
< 
* Connection #0 to host localhost left intact
```

In case of success, it returns a `201` code along with the URL of the object in the `Location`
header.

In case of failure, it returns a `500` HTTP error code.

The get interface is here for convenience, although it should be of no use when using this
protocol in production.

### Use in the flows

When using Asteroid's request object store and such an object's URL in an
OAuth2 or OpenID Connect web flow, Asteroid automatically detects that it refers to one of its
stored objects (using URL matching) and retrieves it internally without an HTTP request.

### Expiration

Lifetime of stored objects can be set using the
[`:oauth2_jar_request_object_lifetime`](Asteroid.Config.html#module-oauth2_jar_request_object_lifetime)
configuration option.

### API protection

It is highly recommended to set rate limiting or authentication using the
[`:api_request_object_plugs`](Asteroid.Config.html#module-api_request_object_plugs)
configuration option.

Should you want to allow both confidential and public clients to access this API, it is
possible to throttle accesses for public client only using `APIacFilterThrottler`
configuration options.
