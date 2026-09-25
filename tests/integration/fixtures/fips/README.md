# FIPS test fixtures

Certificates the FIPS behavior tests (`tests/integration/tests/suite/fips.rs`)
present to praxis to prove what a FIPS deployment refuses. They are
deliberately weak; nothing outside those tests should use them.

| File | What it is | Why |
|---|---|---|
| `ca-cert.pem` | A P-256 CA, self-signed with SHA-256, 100-year validity | Signs the two leaves below, so a client can trust them through an otherwise unobjectionable chain. |
| `rsa1536-cert.pem`, `rsa1536-key.pem` | A `localhost` leaf with a 1536-bit RSA key, signed by the CA with SHA-256 | Below the 2048-bit minimum of FIPS 186-5 for signature generation: the validated module refuses to sign with it, so a listener carrying it cannot serve in approved mode. Large enough for RSA-PSS with SHA-512, the scheme the provider prefers, so outside approved mode it serves; a 1024-bit key would fail everywhere for that unrelated reason. |
| `sha1-cert.pem`, `sha1-key.pem` | A `localhost` leaf with a P-256 key, signed by the CA with SHA-1 | A legacy signature algorithm, rejected by rustls in every build. |

Generated on 2026-09-24 with OpenSSL 3.5.8:

```console
openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -sha256 -days 36500 -subj '/CN=Praxis FIPS Test CA' \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' -out ca-cert.pem
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > leaf.ext

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1536 -out rsa1536-key.pem
openssl req -new -key rsa1536-key.pem -subj '/CN=localhost' -out rsa1536.csr
openssl x509 -req -in rsa1536.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -sha256 -days 36500 \
    -extfile leaf.ext -out rsa1536-cert.pem

openssl ecparam -name prime256v1 -genkey -noout -out sha1-key.pem
openssl req -new -key sha1-key.pem -subj '/CN=localhost' -out sha1.csr
# Red Hat's OpenSSL refuses SHA-1 signatures unless told otherwise.
printf 'openssl_conf = openssl_init\n[openssl_init]\nalg_section = evp_properties\n[evp_properties]\nrh-allow-sha1-signatures = yes\n' > sha1.cnf
OPENSSL_CONF=sha1.cnf openssl x509 -req -in sha1.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -sha1 \
    -days 36500 -extfile leaf.ext -out sha1-cert.pem
```

The CA key is not kept: nothing needs to sign with it again.
