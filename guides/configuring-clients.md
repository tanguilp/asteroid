# Configuring clients

## Asteroid scopes

Specific permissions can be granted to clients using scopes. Scopes are stored in the
`"scope"` attribute of a client as a list of `String.t()`. These scopes are prefixed with
`"asteroid."` and are:
- `"asteroid.introspect"`: allows a client to introspect tokens on the `"/introspect"` endpoint.
Note that the client can introspect *all* tokens, not only those issued to it
