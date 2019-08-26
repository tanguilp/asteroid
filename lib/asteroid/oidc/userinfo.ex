defmodule Asteroid.OIDC.Userinfo do
  @moduledoc """
  Convenience functions to work with the `/userinfo` endpoint
  """

  @doc """
  Returns the mapping between the `"email"`, `"profile"`, `"phone"` and `"address"` scope
  and their corresponding claims

  ```elixir
  %{
    "profile" => [
      "name",
      "family_name",
      "given_name",
      "middle_name",
      "nickname",
      "preferred_username",
      "profile",
      "picture",
      "website",
      "gender",
      "birthdate",
      "zoneinfo",
      "locale",
      "updated_at"
    ],
    "email" => ["email", "email_verified"],
    "address" => ["address"],
    "phone" => ["phone_number","phone_number_verified"]
  }
  ```
  """

  @spec scope_claims_mapping() :: %{required(String.t()) => [String.t()]}

  def scope_claims_mapping() do
    %{
      "profile" => [
        "name",
        "family_name",
        "given_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at"
      ],
      "email" => ["email", "email_verified"],
      "address" => ["address"],
      "phone" => ["phone_number", "phone_number_verified"]
    }
  end
end
