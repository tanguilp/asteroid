# Configuring Riak

## Globally

You need to configure the pooler in the configuration file by uncommenting the
following lines:


```elixir
config :pooler,
  pools: [
    [
      name: :riak,
      group: :riak,
      max_count: 10,
      init_count: 5,
      start_mfa: {Riak.Connection, :start_link, ['127.0.0.1', 8087]}
    ]
  ]
```

and setting the pool options as needed.

Asteroid and associated libraries do only use pooled Riak connections.

## As an attribute repository

Uncomment the following line in `mix.exs` and then run `mix deps.get`:

```elixir
{:attribute_repository_riak, github: "tanguilp/attribute_repository_riak"},
```
