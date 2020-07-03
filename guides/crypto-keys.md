# Using cryptographic keys

Cryptographic keys are managed with the `JOSEVirtualHSM` library. They are loaded at startup
and stored in memory in a secure and protected way in the `JOSEVirtualHSM` processes.

This library handles distribution automatically, which means Asteroid "shares" keys between
instances as soon as they are connected through Erlang distribution. (They are actually not
shared because it would require copying them; instead `JOSEVirtualHSM` instances communicate
to perform signing and decryption operations.)

It also allows generating keys randomly at startup. It is particularly well suited for an
authorization server because clients do not require long-lived certificates but instead
use keys published on the `jwks_uri`. At startup, an Asteroid server using auto-generated keys
will generate such keys and start advertising the (and the keys of the other members of the
cluster) on the `jwks_uri`.

Refer to `JOSEVirtualHSM` documentation for more information.

The asymmetric keys managed by `JOSEVirtualHSM` are by default used to determine automatically
which algorithms are supported. This behaviour can be overridden in the options.

The related configuration options are:
- [`:jose_virtual_hsm_keys_config`](Asteroid.Config.html#module-jose_virtual_hsm_keys_config)
- [`:jose_virtual_hsm_crypto_fallback`](Asteroid.Config.html#module-jose_virtual_hsm_crypto_fallback)
- [`:oauth2_jar_request_object_signing_alg_values_supported`](Asteroid.Config.html#module-oauth2_jar_request_object_signing_alg_values_supported)
- [`:oauth2_jar_request_object_encryption_alg_values_supported`](Asteroid.Config.html#module-oauth2_jar_request_object_encryption_alg_values_supported)
- [`:oauth2_jar_request_object_encryption_enc_values_supported`](Asteroid.Config.html#module-oauth2_jar_request_object_encryption_enc_values_supported)
- [`:oidc_id_token_signing_alg_values_supported`](Asteroid.Config.html#module-oidc_id_token_signing_alg_values_supported)
- [`:oidc_id_token_encryption_alg_values_supported`](Asteroid.Config.html#module-oidc_id_token_encryption_alg_values_supported)
- [`:oidc_id_token_encryption_enc_values_supported`](Asteroid.Config.html#module-oidc_id_token_encryption_enc_values_supported)
- [`:oidc_endpoint_userinfo_signing_alg_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_signing_alg_values_supported)
- [`:oidc_endpoint_userinfo_encryption_alg_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encryption_alg_values_supported)
- [`:oidc_endpoint_userinfo_encryption_enc_values_supported`](Asteroid.Config.html#module-oidc_endpoint_userinfo_encryption_enc_values_supported)

## JWK URI

Keys are published on the `/discovery/keys` endpoint.

Keys of type `"oct"` (symmetric keys) are never published.

A `"kid"` field is automatically generated for each key, based on constant key parameters. The
generated `"kid"` will remain unchanged for a key.


Using the following configuration:

```elixir
config :asteroid, :jose_virtual_hsm_keys_config,  [
  {:auto_gen, {:rsa, 2048}, %{"use" => "sig"}},
  {:auto_gen, {:ec, "P-256"}, %{"use" => "sig"}},
  {:auto_gen, {:okp, :Ed25519}, %{"use" => "sig"}},
  {:auto_gen, {:rsa, 2048}, %{"use" => "enc"}},
  {:auto_gen, {:ec, "P-256"}, %{"use" => "enc"}},
  {:auto_gen, {:okp, :X25519}, %{"use" => "enc"}}
]

config :asteroid, :jose_virtual_hsm_crypto_fallback, true
```

the following keys are advertised on the `jwks_uri`:

```elixir
{
  "keys": [
    {
      "crv": "P-256",
      "kid": "O_C4DKTei6Vm72V79YD-_BO2_6bYGNugzeSdymPt2cI",
      "kty": "EC",
      "use": "sig",
      "x": "Bn0v42AUy9NnkfJCoIcsMEEaaFvL0UmX6k8oQtSfRXo",
      "y": "sikN5ZGz_Ld6gOCEdj9Pqu1CXUyq30WYe504_4PXl84"
    },
    {
      "crv": "X25519",
      "kid": "KaOY2pylfW2MuRcp74O8XgmSnWenC2BZMfbyrpiXA5s",
      "kty": "OKP",
      "use": "enc",
      "x": "H3pdUWRBRdyZx_pdwP_W-7C7T_nUlQ_LZiKB8qjL5RQ"
    },
    {
      "crv": "Ed25519",
      "kid": "Puwf64Cd8ooGue3vb7ghI8quggrEARN1Hj5yUwXE1v4",
      "kty": "OKP",
      "use": "sig",
      "x": "C0ulZcGlfSkk5selFENR21KDuDGqvE2JlLDfKxcgD94"
    },
    {
      "e": "AQAB",
      "kid": "mKbunlceWaYh6MK4Af6VHuxXClddHmXuMZ4zsXVaOtc",
      "kty": "RSA",
      "n": "qeLGYsbgSM_zHprIUKaOGzecKpHffCJz0NF_2B8scCd9DVtSIF1q4bYWLXrc2upX2rWtsLfILcC1xu9EfJYncHHxAmFY6QRHm_X2R0BMRrmRNqRk8LpyaS7o74LZ27FF9c5LPFxxS3j4ka97OP9gtwOJepkkaa9COSXMu97-Bf3RgZgFGcyqvZbH_YlB_mEBh-U2lVboyWUTLtktN-MD7EO7J3CPXwuarRm8Vvfyl9pbAfpwJAPzOODqR1S7onJN_42nw1XExOBqsiCsM3k18XT6kbew5Tvh53c3-fMMqv-ixMzoY8KAF4YeBhUZpxxBiKTscMoHnCfEH2R9uWO3ww",
      "use": "enc"
    },
    {
      "e": "AQAB",
      "kid": "G7kJOtSFPkOxuJ85fQJV73aiMk9caIejFcKHlw_GaY4",
      "kty": "RSA",
      "n": "zaoG3cnMkugSksoxRpk9rslZ_6zHEBct-92Fn8RMLKuWA2cc3ukwJh311K6tm9ytT34sbhKo8DP7eXk--qlV0-92U8_oNx8sMoW5Hq03RFUBdMPxsNlb4k1fFaL6Mx2EiermePN1cz2p1DxAlPwd6VKrwWshz29qek4HaqRvSNyUNKxgIvmngXIjhnPjAeKeXFtxIo_qyUism_b0VMZT4rVzJStktEbMs410oOdNVeHf8KPpkSrUZhycCdrvSHTsnr0YN-6QBL7rwEjvUrztBLLd8fYH7l89zE964YZCvnv9uVQpc1YHyb7fZG3N24bllvlM-wO-rwA43JyNrWd8dQ",
      "use": "sig"
    },
    {
      "crv": "P-256",
      "kid": "pzuXXpypwN_7vyIDJsbFSldFX3dOWfe4ok33Bb_pqH8",
      "kty": "EC",
      "use": "enc",
      "x": "BCZJtGDmSC_vhMUyX8LMhAYXluhNCznez5jsZ2EU58U",
      "y": "-N8DnjRsuaJ4aptkV6rF-cWOy5JdZ5JYNF_O-vgZYfU"
    }
  ]
}
```

## JWS `"none"` algorithm

The JWS `"none"` algorithm is not available because it weakens the security if used
carelessly.
