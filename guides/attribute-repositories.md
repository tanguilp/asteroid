# Attribute repositories

Attribute repositories are backend systems in charge of storing resource data. By default
Asteroid requires attribute repositories for:
- Subjects
- Clients
- Devices

The `AttributeRepository` repository can be found here:
[https://github.com/tanguilp/attribute_repository](https://github.com/tanguilp/attribute_repository)

## Configuration

Attribute repositories are configure under the `:attribute_repositories` key that contains
a key-value list of instance names and configuration options for each attribute repository.
The key is the instance name which will be further use to interact with a given attribute
repository. The values are the following key-value configuration options:
- `:module`: the name of the module implementing the `AttributeRepository` behaviours. No
default
- `:init_opts`: initialisation options that will be passed to the install function as described
in `t:AttributeRepository.init_opts/1`. Defaults to `[]`
- `:run_opts`: run options that will be passed to the all `AttributeRepository` functions (
`t:AttributeRepository.run_opts/1`). Defaults to `[]`
- `:auto_install`: `boolean()` indicating whether the `AttributeRepositoryModule.install/2`
function should be called at Asteroid startup. Defaults to `true`
- `:auto_start`: `boolean()` indicating whether the `AttributeRepositoryModule.start_link/1` or
the `AttributeRepositoryModule.start/1` function should be called at Asteroid startup.
Defaults to `true`

### Example

```elixir
config :asteroid, :attribute_repositories,
[
  user: [
    module: AttributeRepositoryLdap,
    init_opts: [
      name: :slapd,
      max_overflow: 10,
      ldap_args: [hosts: ['localhost'], base: 'ou=people,dc=example,dc=org']
    ],
    run_opts: [instance: :slapd, base_dn: 'ou=people,dc=example,dc=org'],
    auto_install: false # AttributeRepositoryLdap has no install callback implemented
  ],
  client: [
    module: AttributeRepositoryMnesia,
    init_opts: [mnesia_config: [disc_copies: [node()]]],
    run_opts: [instance: :client]
  ],
  device: [
    module: AttributeRepositoryRiak,
    run_opts: [instance: :device, bucket_type: "device"],
    auto_start: false
  ]
]
```

When starting the following logs will be shown:
```bash
[info] Elixir.Asteroid.AttributeRepository: configuring attribute repository `client`
[info] Application mnesia exited: :stopped
[debug] Elixir.AttributeRepositoryMnesia: created table of instance client
[info] Elixir.Asteroid.AttributeRepository: configuring attribute repository `device`
[info] Elixir.Asteroid.AttributeRepository: starting attribute repository `user`
[info] Elixir.Asteroid.AttributeRepository: starting attribute repository `client`
```

Note that the names given to these repositories are arbitrary and these repositories
are accessed by callback functions. Even though it would be the norm to have 3 repositories
for these 3 types of resources, it is absolutely possible:
- to have more than one repository for a resource type (e.g. 2 ldap servers for users)
- to have 2 or more resource types in the same repository (though this is probably a
bad idea)
- to have additional declared repositories (e.g. for storing adresses) for use in
custom code

## Startup

At startup, Asteroid reads the configuration file and executes the following actions for each
attribute repository module:
1. calling the `AttributeRepositoryModule.install/2` callback of the module (except if the
`auto_install` option is set to `false`)
2. trying to start the attribute repository by (and except if the `auto_start` option is set
to `false`):
    - calling the `AttributeRepositoryModule.start_link/1` if it exists, so as to create a
    supervised process
    - otherwise calling the `AttributeRepositoryModule.start/1`
Should any function fail, Asteroid will immediately stop.
