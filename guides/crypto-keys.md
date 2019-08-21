# Using cryptographic keys

Cryptographic keys are loaded at startup from the configuration file.

The related configuration options are:
- [`:crypto_keys`](Asteroid.Config.html#module-crypto_keys)
- [`:crypto_keys_cache`](Asteroid.Config.html#module-crypto_keys_cache)

## Key loading and key cache

Since signing can be frequent and is CPU-intensive, Asteroid loads all keys at startup and
store them in a key cache. The associated behaviour is `Asteroid.Crypto.Key.Cache`. It is
essential that the key cache returns the keys quickly. Also, read carefully the security
considerations of the modules implementing the key cache behaviour since such caches store
the **private keys** of these keys. You might want to consider:
- What happens in case of the EVM crash: are the private keys dumped to the crash dump?
- Are the keys stored at some point on the file system? If the file system encrypted?
- Which processes can access the keys on the EVM, if the cache runs on the EVM? Or who can
access the keys if it's stored in an external system?
- Can the keys be updated and modified during runtime?

Asteroid ships with the local key cache `Asteroid.Crypto.Key.Cache.ETS` which make some tradeoffs
between simplicity and security.

Note that you can reload the keys at runtime using `Asteroid.Crypto.Key.load_from_config!/0`:
it will load new keys from the configuration file and remove those no longer present.

This interface may changed in the future and be replaced by a signer interface, along with a
virtual HSM implementation.

## Options to load keys

There are 3 options to load private keys as described in
`t:Asteroid.Crypto.Key.key_config_entry/0`:
- loading keys from files (encrypted or unencrypted)
- loading keys from configuration file
- generate new keys on the fly

When loading keys from the configuration files, make sure to set keys in a separate configuration
file that is not versionned or widely shared (use of `secret.exs`).

Generating new keys on the fly can be useful for some types of tokens, such as access tokens: in
case of server reboot, the signing keys will indeed change but the target resource servers can
update the new keys from the JWKs URI. However, the `Asteroid.Crypto.Key.Cache.ETS` implementation is
local and this solution doesn't work in a multi-server deployment scenario.

Example of configured keys:

```elixir
config :asteroid, :crypto_keys, %{
  "key_from_file_1" => {:pem_file, [path: "priv/keys/ec-secp256r1.pem", use: :sig]},
  "key_from_file_2" => {:pem_file, [path: "priv/keys/ec-secp521r1.pem", use: :sig]},
  "key_from_map" => {:map, [key: {%{kty: :jose_jwk_kty_oct}, %{"k" => "P9dGnU_We5thJOOigUGtl00WmubLVAAr1kYsAUP80Sc", "kty" => "oct"}}, use: :sig]},
  "key_auto" => {:auto_gen, [params: {:rsa, 4096}, use: :sig]}
}

config :asteroid, :crypto_keys_cache, {Asteroid.Crypto.Key.Cache.ETS, []}
```

## JWK URI

Keys are published on the `/discovery/keys` endpoint, unless marked as not advertised in the
configuration file.

Keys of type `"oct"` (symmetric keys) are never published.

A `"kid"` field is automatically generated for each key, based on constant key parameters. The
generated `"kid"` will remain unchanged for a key.

The previous configuration example will output the following JWKs:

```elixir
[
   {
      "crv":"P-256",
      "kid":"_heSWDZvRaALUVVp66bvHAt4IvebygU1HbECbvyTPaQ",
      "kty":"EC",
      "use":"sig",
      "x":"QiHRAuLJuI4alEUEJH9fjIaXBqYIyjn4ofSXmrJL_kQ",
      "y":"SHWYJ9iYWh-EgeQZorHOl-cBZkZK9rW1FFgv6RlVB20"
   },
   {
      "crv":"P-521",
      "kid":"sKICOK5W-juwHVRLBN-UGnFZ0bl8KCE1D7-ByZ8hAgc",
      "kty":"EC",
      "use":"sig",
      "x":"AB25hyb0l5nMEDWQPkDNfKc-qAm_mTYQa1v4qUBQbOeKm40tiPupmgts4AJ02AwAtesa14RC8SqLTdqbp6OxId2f",
      "y":"AGMeI_7eyhti1jN9W6Rkkv142BZ370NXqLwHfqxEVowrIbX12cHIh5nUWBcwu-LIpQARWasT6-7bTdqKn6S8MOsR"
   },
   {
      "e":"AQAB",
      "kid":"3nTYFtfRnEiW4ISV2Wj_i_CXAI7kZAOFlI6MwQ2ImBQ",
      "kty":"RSA",
      "n":"1Lh-W5EkoCAspB5cvtzVtLq19PQZCPO4gDYQu8K3fktUgk8rocS6eteMScrRvcJxoYyuohybmyeaVJdaEayW8XowUm7oBo3WHIi1bMTHE6qVTTBHD7J-_SDQ87_F0mH-r_P04sva-LbmUuxq7GQd5f7mIC7y4yJPJJl757dCgm-lPbhHiXGmVK3ZzYND45mSEzp0TRI5zdWQogaYJf0NXUtxzZW7UY0D-bTKnX8zhY5TEPGAxjrX0_e1s__xiH3mN4Sw_WFIAaLskS1MWstzPJVN_4TQ6PN5D5up63ABlafgtE-ywyRLHBqKMVIsP3jhJgcu4aOuUK-92dA2I8v5rNcEkxlE76uTmIszLpRzYXWm0v7Wjg_qizPOagJh3-Fecwj0rF7tADgZidL6uc70OkwZENhx3qtjTnXVK0rJDnTFknS8d44TFP4_QmVl7ftf0P0C5u1r2SGAo3Butld8A2ZC4obPcCZWWVXAyGLzhjcUKluj84aqRbqmKj7uL16NGFT61LgqXXOenoZXHZ3gKjTgzwymkDr3vjeaRP5Vsimpibcvpr5CCzq5QRwPTPq6irXjb5BeSDdrQHjxG6tUQgg_3nLCUP5ZMjzHN4tTVY1kmV3eiY-anMYIIW6_aQM3hbUC-xuEcRJ8_rn1CUeZzh5VPitO6CZxzdKpWEZBw0U",
      "use":"sig"
   }
]
```

## JWS "none" algorithm

Asteroid relies on the JOSE library to deal with JWS' and JWEs. This library by default disables
the use of the "none" JWS algorithm.

To activate it, refer to the
[`:crypto_jws_none_alg_enabled`](Asteroid.Config.html#module-crypto_jws_none_alg_enabled)
configuration option. **Assess carefully** when activating such a feature.
