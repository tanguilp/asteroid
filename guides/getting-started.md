# Getting started

Asteroid is an OAuth2 compliant server. Its name stands for "Authorization Server on sTEROIDs".

## Compatibility

OTP21+

Elixir 17+

Mix 1.9

## Downloading and starting Asteroid in development mode

After installing elixir and mix, launch the command:

```bash
$ git clone https://github.com/tanguilp/asteroid.git

$ cd asteroid/

$ mix deps.get

$ iex -S mix phx.server
```

Dialyzer is included in the dependencies, and you can check type correctness running:

```bash
$ mix dialyzer
```

## Running tests

Launch the following command:

```bash
$ MIX_ENV=test mix test
```

## Releases for production environment

To enable extensibility, Asteroid uses a lot of callbacks functions which are set in configuration
files. Due to a [bug](https://bugs.erlang.org/browse/ERL-1009) in Erlang's standard library,
Asteroid **cannot be compiled** to a release with tools like Distillery or `mix release`
(this has been tested). Should the bug be corrected in the next OTP version, it will become
possible to use this tools to create Asteroid releases.

Until then, only Mix can be used to make Asteroid in production.

## Generating documentation

```bash
$ mix docs
```

## Dependencies

### Disabling

Asteroid lists all the dependencies that can be useful (such as all `APIac.Authenticator` and
all `APIac.Filter`) in the `mix.exs` file. Some are also used in tests.

Before releasing, make sure to remove or disable (using the `:only` option) those not needed.

For instance, the `APIacAuthClientSecretPost` dependency is listed as:

```elixir
{:apiac_auth_client_secret_post, github: "tanguilp/apiac_auth_client_secret_post"},
```

and can be either deleted or disabled in production environment by writing:

```elixir
{:apiac_auth_client_secret_post, github: "tanguilp/apiac_auth_client_secret_post", only: [:dev, :test]},
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
