defmodule Asteroid.Context do
  @moduledoc """
  OAuth2 and connection context passed to callback functions

  This is basically a map containing:
  - the current endpoint
  - the current flow
  - the used grant type
  - the requested scopes
  - the scopes released after calling the relevant callbacks
  - the client object
  - the subject object
  - the device object
  - and any other useful information

  Note that for pattern matching convenience, the define fields cannot be `nil`. For example,
  there will never be a `:subject` field in client credentials flow.
  """

  alias OAuth2Utils.Scope

  @type t :: %{
          optional(:endpoint) => Asteroid.OAuth2.endpoint() | Asteroid.OIDC.endpoint(),
          optional(:flow) => Asteroid.OAuth2.flow(),
          optional(:grant_type) => Asteroid.OAuth2.grant_type(),
          optional(:response_type) => Asteroid.OAuth2.response_type(),
          optional(:requested_scopes) => Scope.Set.t(),
          optional(:granted_scopes) => Scope.Set.t(),
          optional(:client) => Asteroid.Client.t(),
          optional(:subject) => Asteroid.Subject.t(),
          optional(:device) => Asteroid.Device.t(),
          optional(:conn) => Plug.Conn.t(),
          optional(any()) => any()
        }
end
