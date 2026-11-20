# Policy FIPS test fixtures

Keys for the Policy FIPS integration tests
(`tests/integration/tests/suite/examples/policy_jwt_fips.rs`). Test-only:
nothing outside those tests may trust or sign with them. Access tokens and
DPoP proofs are not stored here; the tests sign them with these keys at run
time, with the real request URL, the current `iat` and a fresh `jti`.

| File | What it is |
|---|---|
| `rsa2048-key.pem` | RSA-2048 (e = 65537) private key; signs RS256 access tokens |
| `p256-key.pem`, `p256-pub.pem` | P-256 key pair; signs and verifies ES256 access tokens |
| `dpop-p256-key.pem` | P-256 client key that signs DPoP proofs |
| `jwks.json` | The RSA and P-256 public keys, plus an HMAC (`oct`) and an Ed25519 key a FIPS build must skip |
| `jwt-policy.yaml` | Policy document with RS256 (JWKS), ES256 (PEM) and DPoP issuers |

Generated with OpenSSL 3.6:

```console
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048-key.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out p256-key.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out dpop-p256-key.pem
openssl pkey -in p256-key.pem -pubout -out p256-pub.pem
```

`jwks.json` holds the RSA modulus and the P-256 coordinates of those keys
(base64url, RFC 7518 section 6), a fixed `oct` key and the public half of a
throwaway Ed25519 key that was not kept. The PEM files start with a line naming
them test-only, which OpenSSL skips.
