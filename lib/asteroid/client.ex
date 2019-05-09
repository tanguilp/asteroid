defmodule Asteroid.Client do
  use AttributeRepository.Resource, otp_app: :asteroid

  @moduledoc """
  `AttributeRepository.Resource` for clients

  Client refers to an OAuth2 client, that is a **application** (and not a machine). There are 2
  types of clients:
  - those who can keep a secret secret: *confidential clients* (such as a server). Usually there
  is one instance of this application running (even though it has several servers running), so in
  this case 1 client = 1 machine
  - those who can't: *public clients* (mobile applications, SPAs...). In this case there are
  multiple instances of the same client running, used by different subjects

  ## Field naming
  The following fields have standardised meaning:
  - `"client_id"`: the client identifier (as in OAuth2) (`String.t()`)
  - `"client_secret"`: the client secret (`String.t()`)
  - `"client_type"`: `"public"` or `"confidential"`, depending on the client's type
  - `"grant_types"`: the list of grant types (`t:Asteroid.OAuth2.grant_type_str/0`) that the
  client is allowed to use
  - `"redirect_uris"`: the list of OAuth2 / OpenID Connect redirect URIs (`[String.t()]`)
  - `"scope"`: a list of OAuth2 scopes that the client can use when requesting tokens
  - `"__asteroid_oauth2_flow_ropc_issue_refresh_token_init"`: a `boolean()` set to true if a
  refresh token is to be issued at the first request of the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_issue_refresh_token_refresh"`: a `boolean()` set to true if a
  refresh token is to be issued when refresh tokens in the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_refresh_token_lifetime"`: a `non_neg_integer()` set to the
  lifetime duration of a refresh token in the ROPC flow
  - `"__asteroid_oauth2_flow_ropc_access_token_lifetime"`: a `non_neg_integer()` set to the
  lifetime duration of an access token in the ROPC flow

  ## Configuration

  This modules uses the default configuration of `AttributeRepository.Resource` (see `config/1`).

  ## Security considerations

  - When using client secrets, make sure to 1) generate their secrets randomly and 2) store them
  in an appropriate manner. See the [expwd](https://github.com/tanguilp/expwd) library.
  """
end
