# Managing scopes

Asteroid comes with a fine-grained systems to manage scopes. This systems allows configuring
scopes a the global or flow level, and configuring each scope independently.

The configuration options for managing scopes are as follows:

```elixir
global configuration………………………………………………………………………… :scope_config
│
╰─ oauth2……………………………………………………………………………………………………… :oauth2_scope_config
   │
   ├ authorization code flow…………………………………………………… :oauth2_flow_authorization_code_scope_config
   ├ implicit flow……………………………………………………………………………… :oauth2_flow_implicit_scope_config
   ├ client credentials flow…………………………………………………… :oauth2_flow_client_credentials_scope_config
   ╰ ROPC flow………………………………………………………………………………………… :oauth2_flow_ropc_scope_config
```

When using scopes in flows, configuration options of each scope to that flow are merge in a
manner that values of a deeper configuration option takes precedence over values of higher
configuration options.

Values of these configuration options are described in
`t:Asteroid.OAuth2.Scope.scope_config_option/0`. In particular, each scope can be individually
configured with the following options:
- `:auto`: the scope will automatically be granted, even when not requested
- `:advertise`: determine whether the scope is advertised on the `/.well-nown` URIs. Defaults
to `true`. If set in a incoherent way within different flows, the behaviour is unspecified.
- `:display`: in *web flows*, display that scope to the end-user for authorization. When
not present, shall be treated as `true`
- `:optional`: in *web flows*, make that scope optional, so that the user can deselect it even
when this was requested by the client. When not present, shall be treated as `false`
- `:label`: a map of internationalised labels of the scope, that will be displayed to the
end-user. The map keys are ISO639 tags, and the values the internationalised text of the label
- `:acceptable_loas`: a list of LOAs for use in OIDC flows. When present, a scope shall be
released only when the authorization process has an LOA present in this option. As a
consequence, a scope will never be released when this option is set to an empty list
- `:max_refresh_token_lifetime`: *when present*, restricts the lifetime of a refresh token
released when that scope is granted. This *supersedes global*, flow or client refresh token
lifetime configuration
- `:max_access_token_lifetime`: *when present*, restricts the lifetime of an access token
released when that scope is granted. This *supersedes global*, flow or client acess token
lifetime configuration

Merging happens at this level (but values are not merged, simply erased).

As an example, let's look at the following configuration:
```elixir
config :asteroid, :scope_config,
[
  scopes: %{
    "api.access" => [auto: true]
  }
]

config :asteroid, :oauth2_scope_config,
[
  scopes: %{
    "read_balance" => [
      label: %{
        "en" => "Read my account balance",
        "fr" => "Lire mes soldes de compte",
        "ru" => "Читать баланс счета"
      }
    ],
    "read_account_information" => [
      optional: true,
      label: %{
        "en" => "Read my account transactions",
        "fr" => "Consulter la liste de mes transactions bancaires",
        "ru" => "Читать транзакции по счету"
      }
    ]
  }
]

config :asteroid, :oauth2_flow_authorization_code_scope_config,
[
  scopes: %{
    "interbank_transfer" => [
      max_refresh_token_lifetime: 3600 * 24 * 30 * 3,
      label: %{
        "en" => "Make bank transfers",
        "fr" => "Réaliser des virements",
        "ru" => "Делать банковские переводы"
      }
    ]
  }
]
```

The resulting merged configuration can be accessed via the
`Asteroid.OAuth2.Scope.configuration_for_flow/1` function:

```elixir
iex> Asteroid.OAuth2.Scope.configuration_for_flow(:implicit)
[
  scopes: %{
    "api.access" => [auto: true],
    "read_account_information" => [
      optional: true,
      label: %{
        "en" => "Read my account transactions",
        "fr" => "Consulter la liste de mes transactions bancaires",
        "ru" => "Читать транзакции по счету"
      }
    ],
    "read_balance" => [
      label: %{
        "en" => "Read my account balance",
        "fr" => "Lire mes soldes de compte",
        "ru" => "Читать баланс счета"
      }
    ]
  }
]
iex> Asteroid.OAuth2.Scope.configuration_for_flow(:authorization_code)
[
  scopes: %{
    "api.access" => [auto: true],
    "interbank_transfer" => [
      max_refresh_token_lifetime: 7776000,
      label: %{
        "en" => "Make bank transfers",
        "fr" => "Réaliser des virements",
        "ru" => "Делать банковские переводы"
      }
    ],
    "read_account_information" => [
      optional: true,
      label: %{
        "en" => "Read my account transactions",
        "fr" => "Consulter la liste de mes transactions bancaires",
        "ru" => "Читать транзакции по счету"
      }
    ],
    "read_balance" => [
      label: %{
        "en" => "Read my account balance",
        "fr" => "Lire mes soldes de compte",
        "ru" => "Читать баланс счета"
      }
    ]
  }
]
```
