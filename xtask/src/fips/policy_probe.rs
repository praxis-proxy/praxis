// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Policy traffic through a FIPS image built with a Policy profile.
//!
//! The image is started again under `PRAXIS_REQUIRE_FIPS=1` with a plain-HTTP
//! listener whose `policy` filter needs the profile's identity plugin. The
//! probe then sends real requests from outside: for API key, a known key is
//! admitted and an unknown one refused; for JWT, an ES256 token is admitted,
//! an expired one refused, a DPoP-bound token with a fresh proof admitted and
//! the same proof replayed refused. Tokens and proofs are signed here, through
//! this host's OpenSSL, with keys generated for the run and the real request
//! URL, the current `iat` and a fresh `jti`.

use std::{
    io::{Read as _, Write as _},
    net::TcpStream,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, PointConversionForm},
    ecdsa::EcdsaSig,
    hash::{MessageDigest, hash},
    nid::Nid,
    pkey::{PKey, Private},
    sign::Signer,
};
use serde_json::{Value, json};

use super::runtime_probe::{Container, PROBE_MOUNT, free_port, set_mode};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The Policy listener's port inside the container.
const POLICY_PORT: u16 = 8_080;

/// How long the Policy listener gets to come up.
const STARTUP_DEADLINE: Duration = Duration::from_secs(30);

/// The API key the probe's key directory admits.
const API_KEY: &str = "sk-probe-alice";

/// The JWT issuer the probe signs for.
const ISSUER: &str = "https://idp.probe.test";

/// The DPoP-bound issuer the probe signs for.
const DPOP_ISSUER: &str = "https://dpop.probe.test";

/// The audience both issuers expect.
const AUDIENCE: &str = "praxis-fips-probe";

/// The URL `DPoP` proofs name, `dpop.external_base_url` in the policy.
const EXTERNAL_BASE_URL: &str = "https://api.probe.test";

// -----------------------------------------------------------------------------
// Profile
// -----------------------------------------------------------------------------

/// The Policy profile the image was built with, as `FIPS_POLICY_PROFILE`
/// names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Profile {
    /// No Policy: nothing to probe.
    None,
    /// The engine alone: a plugin-free policy loads.
    Engine,
    /// The API-key plugin.
    ApiKey,
    /// The JWT plugin.
    Jwt,
    /// Both plugins.
    Both,
}

impl Profile {
    /// Whether the image carries the API-key plugin.
    const fn api_key(self) -> bool {
        matches!(self, Self::ApiKey | Self::Both)
    }

    /// Whether the image carries the JWT plugin.
    const fn jwt(self) -> bool {
        matches!(self, Self::Jwt | Self::Both)
    }
}

// -----------------------------------------------------------------------------
// Entry Point
// -----------------------------------------------------------------------------

/// Start the image with the profile's policy and drive traffic through it.
pub(crate) fn run(image: &str, work: &Path, profile: Profile) -> Result<(), String> {
    if profile == Profile::None {
        return Ok(());
    }
    let keys = Keys::generate()?;
    write_policy_files(work, profile, &keys)?;
    let port = free_port()?;
    let container = Container::start(image, work, port, POLICY_PORT, "policy-config.yaml")?;
    wait_until_serving(&container, port)?;
    let checks = exchanges(profile, &keys)?;
    for (what, request, expected) in &checks {
        let status = status_of(port, request)?;
        if status != *expected {
            return Err(format!(
                "policy probe: {what} returned {status}, expected {expected}. The image's log:\n{}",
                container.logs()?
            ));
        }
        println!("fips-runtime-probe: ok: policy {what}: {status}");
    }
    println!(
        "fips-runtime-probe: ok: {} Policy exchanges ({profile:?}) passed against the image",
        checks.len()
    );
    Ok(())
}

/// One request, what it shows, and the status it must get.
type Exchange = (&'static str, String, u16);

/// The requests to send for `profile`.
fn exchanges(profile: Profile, keys: &Keys) -> Result<Vec<Exchange>, String> {
    let mut checks = Vec::new();
    if profile == Profile::Engine {
        checks.push(("plugin-free policy admits", request("/probe", None, None), 200));
    }
    if profile.api_key() {
        checks.push((
            "known API key",
            request("/probe", Some(&format!("Bearer {API_KEY}")), None),
            200,
        ));
        checks.push((
            "unknown API key",
            request("/probe", Some("Bearer sk-probe-mallory"), None),
            401,
        ));
    }
    if profile.jwt() {
        checks.extend(jwt_exchanges(keys)?);
    }
    Ok(checks)
}

/// The JWT and `DPoP` requests: allow, expired, a fresh proof, its replay.
fn jwt_exchanges(keys: &Keys) -> Result<Vec<Exchange>, String> {
    let token = keys.es256(&claims(ISSUER, 300, None)?)?;
    let expired = keys.es256(&claims(ISSUER, -600, None)?)?;
    let bound = keys.es256(&claims(DPOP_ISSUER, 300, Some(&keys.client_thumbprint()?))?)?;
    let proof = keys.dpop_proof("GET", &format!("{EXTERNAL_BASE_URL}/probe"), &bound)?;
    let dpop = request("/probe", Some(&format!("DPoP {bound}")), Some(&proof));
    Ok(vec![
        (
            "ES256 token",
            request("/probe", Some(&format!("Bearer {token}")), None),
            200,
        ),
        (
            "expired ES256 token",
            request("/probe", Some(&format!("Bearer {expired}")), None),
            401,
        ),
        ("DPoP-bound token with a fresh proof", dpop.clone(), 200),
        ("replayed DPoP proof", dpop, 401),
    ])
}

/// A `GET` with an optional `Authorization` and `DPoP` header.
fn request(path: &str, authorization: Option<&str>, dpop: Option<&str>) -> String {
    let authorization = authorization.map_or_else(String::new, |value| format!("Authorization: {value}\r\n"));
    let dpop = dpop.map_or_else(String::new, |value| format!("DPoP: {value}\r\n"));
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n{authorization}{dpop}Connection: close\r\n\r\n")
}

/// Access-token claims for `issuer`, expiring `ttl` seconds from now, bound
/// to `jkt` when given.
fn claims(issuer: &str, ttl: i64, jkt: Option<&str>) -> Result<Value, String> {
    let now = now();
    let mut claims = json!({
        "iss": issuer, "aud": AUDIENCE, "sub": "alice", "iat": now, "exp": now.saturating_add(ttl), "jti": fresh_jti()?,
    });
    if let Some(jkt) = jkt {
        claims["cnf"] = json!({ "jkt": jkt });
    }
    Ok(claims)
}

// -----------------------------------------------------------------------------
// HTTP
// -----------------------------------------------------------------------------

/// Wait until the Policy listener answers, or the container exits.
fn wait_until_serving(container: &Container, port: u16) -> Result<(), String> {
    let deadline = Instant::now() + STARTUP_DEADLINE;
    loop {
        if !container.running()? {
            return Err(format!(
                "the image exited instead of serving the Policy listener. Its log:\n{}",
                container.logs()?
            ));
        }
        if status_of(port, &request("/", None, None)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "the Policy listener did not answer within {STARTUP_DEADLINE:?}. Its log:\n{}",
                container.logs()?
            ));
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "a synchronous command-line tool with no async runtime"
        )]
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Send `request` and return the response's status code.
fn status_of(port: u16, request: &str) -> Result<u16, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|err| format!("cannot connect to the Policy listener: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| format!("socket: {err}"))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("cannot send the request: {err}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|err| format!("cannot read the response: {err}"))?;
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("no status line in the response: {response:?}"))
}

// -----------------------------------------------------------------------------
// Policy Files
// -----------------------------------------------------------------------------

/// Write the listener config, the policy and the key material it reads.
fn write_policy_files(work: &Path, profile: Profile, keys: &Keys) -> Result<(), String> {
    let mut files = vec![
        ("policy-config.yaml", listener_config()),
        ("policy.yaml", policy(profile)),
    ];
    if profile.api_key() {
        let digest = hex(&hash(MessageDigest::sha256(), API_KEY.as_bytes()).map_err(ossl)?);
        files.push((
            "api-keys.yaml",
            format!("keys:\n  - hash: \"sha256:{digest}\"\n    user: alice\n"),
        ));
    }
    if profile.jwt() {
        let public = keys.issuer.public_key_to_pem().map_err(ossl)?;
        files.push(("issuer.pem", String::from_utf8(public).map_err(|err| err.to_string())?));
    }
    for (name, contents) in files {
        let path = work.join(name);
        std::fs::write(&path, contents).map_err(|err| format!("cannot write {name}: {err}"))?;
        set_mode(&path, 0o644)?;
    }
    Ok(())
}

/// A plain-HTTP listener whose chain runs the `policy` filter and answers.
fn listener_config() -> String {
    format!(
        "listeners:\n  - name: policy\n    address: \"0.0.0.0:{POLICY_PORT}\"\n    filter_chains: [main]\nfilter_chains:\n  \
         - name: main\n    filters:\n      - filter: policy\n        config_path: {PROBE_MOUNT}/policy.yaml\n      - filter: \
         static_response\n        status: 200\n        body: policy\n"
    )
}

/// The policy document for `profile`.
fn policy(profile: Profile) -> String {
    let mut plugins = Vec::new();
    let mut authentication = Vec::new();
    if profile.api_key() {
        plugins.push(api_key_plugin());
        authentication.push("api-keys");
    }
    if profile.jwt() {
        plugins.push(jwt_plugin());
        authentication.push("jwt");
    }
    if authentication.is_empty() {
        return "plugins: []\n".to_owned();
    }
    format!(
        "engine_settings:\n  dispatch: policy\nplugins:\n{}global:\n  authentication: [{}]\n  authorization:\n    \
         pre_invocation:\n      - \"require(authenticated)\"\n",
        plugins.concat(),
        authentication.join(", ")
    )
}

/// The API-key plugin, reading the mounted key directory.
fn api_key_plugin() -> String {
    format!(
        "  - name: api-keys\n    kind: identity/api-key\n    hooks: [identity.resolve]\n    on_error: fail\n    config:\n      \
         credential: {{ kind: header, name: Authorization }}\n      prefix: \"Bearer sk-probe-\"\n      provider: {{ kind: \
         file, path: {PROBE_MOUNT}/api-keys.yaml, index: sha256 }}\n      record_map: {{ subject: {{ id: user }} }}\n"
    )
}

/// The JWT plugin with a bearer issuer and a `DPoP`-bound one.
fn jwt_plugin() -> String {
    format!(
        "  - name: jwt\n    kind: identity/jwt\n    hooks: [identity.resolve]\n    mode: sequential\n    on_error: fail\n    \
         capabilities: [read_headers]\n    config:\n      credential: {{ kind: header, name: Authorization }}\n      \
         claim_mapper: standard\n      trusted_issuers:\n{}{}",
        issuer_block(ISSUER, ""),
        issuer_block(
            DPOP_ISSUER,
            &format!(
                "          dpop: {{ mode: required, algorithms: [ES256], external_base_url: \"{EXTERNAL_BASE_URL}\" }}\n"
            )
        ),
    )
}

/// One ES256 trusted issuer reading the mounted public key, plus `extra`.
fn issuer_block(issuer: &str, extra: &str) -> String {
    format!(
        "        - issuer: \"{issuer}\"\n          audiences: [\"{AUDIENCE}\"]\n          algorithms: [ES256]\n          \
         decoding_key: {{ kind: pem_file, path: {PROBE_MOUNT}/issuer.pem }}\n{extra}"
    )
}

// -----------------------------------------------------------------------------
// Signing
// -----------------------------------------------------------------------------

/// The run's keys: the issuer's and the `DPoP` client's, both P-256.
struct Keys {
    /// Signs access tokens.
    issuer: PKey<Private>,
    /// Signs `DPoP` proofs.
    client: PKey<Private>,
}

impl Keys {
    /// Two fresh P-256 keys.
    fn generate() -> Result<Self, String> {
        let p256 = || -> Result<PKey<Private>, String> {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(ossl)?;
            PKey::from_ec_key(EcKey::generate(&group).map_err(ossl)?).map_err(ossl)
        };
        Ok(Self {
            issuer: p256()?,
            client: p256()?,
        })
    }

    /// An ES256 access token over `claims`.
    fn es256(&self, claims: &Value) -> Result<String, String> {
        compact(&json!({ "alg": "ES256", "typ": "JWT" }), claims, &self.issuer)
    }

    /// A `DPoP` proof for `method` and `url`, binding `access_token`.
    fn dpop_proof(&self, method: &str, url: &str, access_token: &str) -> Result<String, String> {
        let header = json!({ "alg": "ES256", "typ": "dpop+jwt", "jwk": p256_jwk(&self.client)? });
        let ath = URL_SAFE_NO_PAD.encode(hash(MessageDigest::sha256(), access_token.as_bytes()).map_err(ossl)?);
        let claims = json!({ "htm": method, "htu": url, "iat": now(), "jti": fresh_jti()?, "ath": ath });
        compact(&header, &claims, &self.client)
    }

    /// The RFC 7638 thumbprint of the client key.
    fn client_thumbprint(&self) -> Result<String, String> {
        let jwk = p256_jwk(&self.client)?;
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap_or_default(),
            jwk["y"].as_str().unwrap_or_default()
        );
        Ok(URL_SAFE_NO_PAD.encode(hash(MessageDigest::sha256(), canonical.as_bytes()).map_err(ossl)?))
    }
}

/// The compact JWS of `header` and `claims`, ES256-signed with `key`.
fn compact(header: &Value, claims: &Value, key: &PKey<Private>) -> Result<String, String> {
    let input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let mut signer = Signer::new(MessageDigest::sha256(), key).map_err(ossl)?;
    signer.update(input.as_bytes()).map_err(ossl)?;
    let signature = EcdsaSig::from_der(&signer.sign_to_vec().map_err(ossl)?).map_err(ossl)?;
    let mut raw = signature.r().to_vec_padded(32).map_err(ossl)?;
    raw.extend(signature.s().to_vec_padded(32).map_err(ossl)?);
    Ok(format!("{input}.{}", URL_SAFE_NO_PAD.encode(raw)))
}

/// The public JWK of a P-256 key.
fn p256_jwk(key: &PKey<Private>) -> Result<Value, String> {
    let ec = key.ec_key().map_err(ossl)?;
    let mut context = BigNumContext::new().map_err(ossl)?;
    let point = ec
        .public_key()
        .to_bytes(ec.group(), PointConversionForm::UNCOMPRESSED, &mut context)
        .map_err(ossl)?;
    let (x, y) = point
        .get(1..33)
        .zip(point.get(33..65))
        .ok_or("a P-256 point is 65 bytes uncompressed")?;
    Ok(json!({ "kty": "EC", "crv": "P-256", "x": URL_SAFE_NO_PAD.encode(x), "y": URL_SAFE_NO_PAD.encode(y) }))
}

/// Seconds since the Unix epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or_default()
}

/// A random `jti`; `Err` when OpenSSL's generator fails.
fn fresh_jti() -> Result<String, String> {
    let mut random = [0_u8; 16];
    openssl::rand::rand_bytes(&mut random).map_err(ossl)?;
    Ok(URL_SAFE_NO_PAD.encode(random))
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// An OpenSSL error as text.
#[expect(
    clippy::needless_pass_by_value,
    reason = "a `map_err` adapter takes the error by value"
)]
fn ossl(err: openssl::error::ErrorStack) -> String {
    format!("openssl: {err}")
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_profile_drives_its_own_plugins() {
        let keys = Keys::generate().expect("keys");
        let names = |profile| -> Vec<&str> {
            exchanges(profile, &keys)
                .expect("exchanges")
                .into_iter()
                .map(|(what, ..)| what)
                .collect()
        };
        assert_eq!(names(Profile::Engine), ["plugin-free policy admits"], "engine only");
        assert_eq!(names(Profile::ApiKey).len(), 2, "API-key allow and deny");
        assert_eq!(names(Profile::Jwt).len(), 4, "JWT allow, expired, DPoP and replay");
        assert_eq!(names(Profile::Both).len(), 6, "both");
    }

    #[test]
    fn the_policy_names_the_mounted_files_and_the_dpop_base_url() {
        let both = policy(Profile::Both);
        assert!(both.contains(&format!("{PROBE_MOUNT}/api-keys.yaml")), "{both}");
        assert!(both.contains(&format!("{PROBE_MOUNT}/issuer.pem")), "{both}");
        assert!(
            both.contains(EXTERNAL_BASE_URL),
            "the DPoP issuer sets external_base_url: {both}"
        );
        assert_eq!(policy(Profile::Engine), "plugins: []\n", "a plugin-free policy");
    }

    #[test]
    fn an_es256_token_verifies_against_the_issuer_key() {
        let keys = Keys::generate().expect("keys");
        let token = keys.es256(&claims(ISSUER, 60, None).expect("claims")).expect("token");
        let mut parts = token.rsplitn(2, '.');
        let signature = URL_SAFE_NO_PAD
            .decode(parts.next().expect("signature"))
            .expect("base64");
        let input = parts.next().expect("signing input");
        let (r, s) = signature.split_at(32);
        let der = EcdsaSig::from_private_components(
            openssl::bn::BigNum::from_slice(r).expect("r"),
            openssl::bn::BigNum::from_slice(s).expect("s"),
        )
        .expect("signature")
        .to_der()
        .expect("der");
        let mut verifier = openssl::sign::Verifier::new(MessageDigest::sha256(), &keys.issuer).expect("verifier");
        verifier.update(input.as_bytes()).expect("feed");
        assert!(
            verifier.verify(&der).expect("verify"),
            "the raw R || S signature verifies"
        );
    }
}
