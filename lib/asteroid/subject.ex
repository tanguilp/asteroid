defmodule Asteroid.Subject do
  use AttributeRepository.Resource, otp_app: :asteroid

  @moduledoc """
  `AttributeRepository.Resource` for subjects

  Subject resource are real-world physical persons, such as the reader of this documentation. It
  refers to the OAuth2 definition of a subject.

  ## Field naming
  The following fields have standardised meaning:
  - `"sub"`: the subject identifier (`"sub"` in OAuth2) (`String.t()`)
  - `"consented_scopes"`: a map whose keys are the `client_id`s and the values the string
  representation of the already consented scopes (such as `"email profile address"`). Note that
  although this is the format used in the demo application, other ways to store consented scopes
  are also possible (but it still has to remain per client)

  ## Configuration

  This modules uses the default configuration of `AttributeRepository.Resource` (see `config/1`).

  ## Security considerations

  - When storing subject passwords, you shall take into account the specifics of such password
  (reuse, non-randomness...) and use the relevant algorithms. If you don't know about this
  topic, you should probably not try to implement it by yourself.

  ## Example

  ```elixir
  iex(13)> alias Asteroid.Subject
  Asteroid.Subject

  iex> {:ok, s} = Subject.load("uid=john,ou=People,dc=example,dc=org")
  {:ok,
   %Asteroid.Subject{
     attrs: %{
       "cn" => ["John Doe"],
       "displayName" => "John Doe",
       "givenName" => ["John"],
       "mail" => ["john.doe@example.com"],
       "manager" => ["uid=toto,ou=People,dc=example,dc=org"],
       "sn" => ["Doe"]
     },
     id: "uid=john,ou=People,dc=example,dc=org",
     modifications: [],
     newly_created: false
   }}
  iex> s = s
  ...> |> Subject.add("initials", "JD")
  ...> |> Subject.add("mail", "john.doe@example.org")
  ...> |> Subject.remove("manager")
  %Asteroid.Subject{
    attrs: %{
      "cn" => ["John Doe"],
      "displayName" => "John Doe",
      "givenName" => ["John"],
      "initials" => "JD",
      "mail" => ["john.doe@example.org", "john.doe@example.com"],
      "sn" => ["Doe"]
    },
    id: "uid=john,ou=People,dc=example,dc=org",
    modifications: [
      {:add, "initials", "JD"},
      {:add, "mail", "john.doe@example.org"},
      {:delete, "manager"}
    ],
    newly_created: false
  }
  iex> Subject.store(s)
  :ok
  ```
  """

  def gen_new_id(opts) do
    "sub-" <> super(opts)
  end
end
