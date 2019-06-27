# Getting started

Asteroid is an OAuth2 compliant server. Its name stands for
"Authorization Server on sTEROIDs", "Authorization server on STEROIDs" or again
"AuthoriSation server on sTEROIDs" (as a friendly gesture to our fellows in the UK).

## Compatibility

OTP21+

Elixir 17+

Mix 1.9 (for releases)

## Downloading and starting Asteroid in development mode

After installing elixir and mix, launch the command:

```bash
$ git clone https://github.com/tanguilp/asteroid.git

$ cd asteroid/

$ mix deps.get

$ iex -S mix phx.server
```

Dialyzer is included in the dependencies, and you can check type correctness launching:

```bash
$ mix dialyzer
```

## Running tests

Launch the following command:

```bash
$ MIX_ENV=test mix test
```

## Release for production environment

Launch the following command:

```bash
$ MIX_ENV=prod mix release
```

The released binary is generated in `_build/prod/rel/prod/bin/prod`

## Generating documentation

```bash
$ mix docs
```

## Dependencies

### Disabling

Asteroid lists all the dependencies that can be useful (such as all `APIac.Authenticator` and
all `APIac.Filter`) in the `mix.exs` file. Some are also used in tests.

Before releasing, make sure to remove or disable (using the `:only` option) those not needed.

For instance, the `APIacAuthMTLS` dependency is listed as:

```elixir
{:apiac_auth_mtls, github: "tanguilp/apiac_auth_mtls"},
```

and can be either deleted or disabled in production environment by writing:

```elixir
{:apiac_auth_mtls, github: "tanguilp/apiac_auth_mtls", only: [:dev, :test]},
```

### Security considerations

The default package manager hex is widely used in the Elixir and Erlang ecosystem. However, it
does not guarantee the integrity of the downloaded packages.

The typical flow to publish packages on that platform is:

    Github -> package developer's working environment -> hex.pm -> end-user of the package (developer)

In environments with demanding security requirements or high risks, consider using the Github
repository directly so as to minimize trust by removing a trusted third-party (hex.pm):

    Github -> end-user of the package (developer)

The downside is to lose the package management features of mix.
