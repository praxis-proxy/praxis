// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Raw TLS handshake records, for tests that need a peer no real TLS stack
//! would be: a client that offers exactly the algorithms the test names and
//! nothing else, or a server that answers a `ClientHello` with a chosen
//! `ServerHello` or alert.
//!
//! Nothing here does cryptography. A probe only needs to see how far the peer
//! under test gets: a `ServerHello` means the offer was acceptable, an alert
//! means it was refused. That is enough to prove what a listener will and will
//! not negotiate, and what an upstream connector offers and insists on, on
//! any host and in either FIPS branch.
//!
//! Wire formats: RFC 8446 (TLS 1.3) section 4, RFC 5246 (TLS 1.2) section 7.4,
//! RFC 7627 (Extended Master Secret), RFC 8422 (ECC cipher suites).

use std::{
    io::{Read as _, Write as _},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// TLS record content types.
const CONTENT_HANDSHAKE: u8 = 22;
/// The alert content type.
const CONTENT_ALERT: u8 = 21;

/// Handshake message types.
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
/// The `ServerHello` handshake type.
const HANDSHAKE_SERVER_HELLO: u8 = 2;

/// Extension types.
const EXT_SERVER_NAME: u16 = 0;
/// `supported_groups` (RFC 8422, RFC 8446 section 4.2.7).
const EXT_SUPPORTED_GROUPS: u16 = 10;
/// `ec_point_formats` (RFC 8422 section 5.1.2).
const EXT_EC_POINT_FORMATS: u16 = 11;
/// `signature_algorithms` (RFC 8446 section 4.2.3).
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
/// `extended_master_secret` (RFC 7627).
const EXT_EXTENDED_MASTER_SECRET: u16 = 23;
/// `supported_versions` (RFC 8446 section 4.2.1).
const EXT_SUPPORTED_VERSIONS: u16 = 43;
/// `key_share` (RFC 8446 section 4.2.8).
const EXT_KEY_SHARE: u16 = 51;

/// Protocol version codes.
pub const TLS12: u16 = 0x0303;
/// TLS 1.3 as `supported_versions` names it.
pub const TLS13: u16 = 0x0304;

/// How long a probe waits for the peer's first record.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

// -----------------------------------------------------------------------------
// Algorithm Codes
// -----------------------------------------------------------------------------

/// Cipher suite codes (IANA "TLS Cipher Suites").
pub mod suites {
    /// `TLS_AES_128_GCM_SHA256`.
    pub const TLS13_AES_128_GCM_SHA256: u16 = 0x1301;
    /// `TLS_AES_256_GCM_SHA384`.
    pub const TLS13_AES_256_GCM_SHA384: u16 = 0x1302;
    /// `TLS_CHACHA20_POLY1305_SHA256`.
    pub const TLS13_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
    pub const ECDHE_ECDSA_AES_128_GCM_SHA256: u16 = 0xC02B;
    /// `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`.
    pub const ECDHE_ECDSA_AES_256_GCM_SHA384: u16 = 0xC02C;
    /// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
    pub const ECDHE_RSA_AES_128_GCM_SHA256: u16 = 0xC02F;
    /// `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`.
    pub const ECDHE_RSA_AES_256_GCM_SHA384: u16 = 0xC030;
    /// `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`.
    pub const ECDHE_ECDSA_CHACHA20_POLY1305_SHA256: u16 = 0xCCA9;
    /// `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`.
    pub const ECDHE_RSA_CHACHA20_POLY1305_SHA256: u16 = 0xCCA8;

    /// Every ChaCha20-Poly1305 suite rustls knows. Not FIPS approved at any
    /// module version, so a FIPS deployment never offers or accepts one.
    pub const CHACHA20: &[u16] = &[
        TLS13_CHACHA20_POLY1305_SHA256,
        ECDHE_ECDSA_CHACHA20_POLY1305_SHA256,
        ECDHE_RSA_CHACHA20_POLY1305_SHA256,
    ];

    /// The AES-GCM suites, TLS 1.3 and 1.2: what a FIPS deployment negotiates.
    pub const AES_GCM: &[u16] = &[
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        ECDHE_ECDSA_AES_128_GCM_SHA256,
        ECDHE_ECDSA_AES_256_GCM_SHA384,
        ECDHE_RSA_AES_128_GCM_SHA256,
        ECDHE_RSA_AES_256_GCM_SHA384,
    ];

    /// Whether `suite` uses ChaCha20-Poly1305.
    pub fn is_chacha20(suite: u16) -> bool {
        CHACHA20.contains(&suite)
    }
}

/// Named group codes (IANA "TLS Supported Groups").
pub mod groups {
    /// `secp256r1` (NIST P-256).
    pub const SECP256R1: u16 = 0x0017;
    /// `secp384r1` (NIST P-384).
    pub const SECP384R1: u16 = 0x0018;
    /// `x25519`.
    pub const X25519: u16 = 0x001D;
    /// `X25519MLKEM768`, the hybrid of `draft-ietf-tls-ecdhe-mlkem`.
    pub const X25519MLKEM768: u16 = 0x11EC;
    /// `MLKEM768`, from `draft-ietf-tls-mlkem`.
    pub const MLKEM768: u16 = 0x0201;

    /// The NIST curves: approved key exchange under FIPS 140-3.
    pub const NIST: &[u16] = &[SECP256R1, SECP384R1];

    /// Whether `group` is one of the NIST curves.
    pub fn is_nist(group: u16) -> bool {
        NIST.contains(&group)
    }

    /// Whether `group` involves X25519, alone or hybrid.
    pub fn uses_x25519(group: u16) -> bool {
        matches!(group, X25519 | X25519MLKEM768)
    }

    /// A key share for `group` that a server will accept as far as the
    /// handshake needs to go to answer: a real public point for the NIST
    /// curves (a server completes the key exchange before it writes its
    /// `ServerHello`, and a random point is off the curve), and random bytes
    /// of the right length for X25519, where every 32-byte string is a
    /// valid public key, and for anything else.
    ///
    /// # Panics
    ///
    /// Panics when OpenSSL cannot generate an EC key, which in approved mode
    /// it can for both NIST curves.
    pub fn key_share(group: u16) -> Vec<u8> {
        use openssl::{
            bn::BigNumContext,
            ec::{EcGroup, EcKey, PointConversionForm},
            nid::Nid,
        };
        let curve = match group {
            SECP256R1 => Nid::X9_62_PRIME256V1,
            SECP384R1 => Nid::SECP384R1,
            X25519MLKEM768 => return super::random(1_216),
            MLKEM768 => return super::random(1_184),
            _ => return super::random(32),
        };
        let ec_group = EcGroup::from_curve_name(curve).expect("named curve");
        let key = EcKey::generate(&ec_group).expect("EC key generation");
        let mut ctx = BigNumContext::new().expect("bignum context");
        key.public_key()
            .to_bytes(&ec_group, PointConversionForm::UNCOMPRESSED, &mut ctx)
            .expect("uncompressed point")
    }
}

/// Signature scheme codes, from the IANA `SignatureScheme` registry.
pub mod sigalgs {
    /// `ecdsa_secp256r1_sha256`.
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    /// `ecdsa_secp384r1_sha384`.
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    /// `rsa_pss_rsae_sha256`.
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    /// `rsa_pss_rsae_sha384`.
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    /// `rsa_pkcs1_sha256`.
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    /// `ed25519`.
    pub const ED25519: u16 = 0x0807;

    /// The schemes a FIPS deployment can sign and verify with.
    pub const APPROVED: &[u16] = &[
        ECDSA_SECP256R1_SHA256,
        ECDSA_SECP384R1_SHA384,
        RSA_PSS_RSAE_SHA256,
        RSA_PSS_RSAE_SHA384,
        RSA_PKCS1_SHA256,
    ];
}

/// Alert descriptions (RFC 8446 section 6).
pub mod alerts {
    /// `handshake_failure`.
    pub const HANDSHAKE_FAILURE: u8 = 40;
    /// `illegal_parameter`.
    pub const ILLEGAL_PARAMETER: u8 = 47;
    /// `protocol_version`.
    pub const PROTOCOL_VERSION: u8 = 70;
    /// `insufficient_security`.
    pub const INSUFFICIENT_SECURITY: u8 = 71;
}

// -----------------------------------------------------------------------------
// ClientHello Builder
// -----------------------------------------------------------------------------

/// A `ClientHello` that offers exactly what the test says.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// The versions offered through `supported_versions`; empty means a
    /// TLS 1.2-only hello with no such extension, as a pre-1.3 client sends.
    pub versions: Vec<u16>,
    /// Cipher suites, in preference order.
    pub cipher_suites: Vec<u16>,
    /// Named groups, in preference order. A key share is sent for the first
    /// one when TLS 1.3 is offered.
    pub groups: Vec<u16>,
    /// Signature schemes.
    pub signature_algorithms: Vec<u16>,
    /// Whether to offer the Extended Master Secret extension.
    pub extended_master_secret: bool,
    /// The SNI host name, if any.
    pub server_name: Option<String>,
}

impl ClientHello {
    /// What a modern, FIPS-acceptable client offers: TLS 1.3 and 1.2, the
    /// AES-GCM suites, the NIST curves, approved signature schemes, EMS.
    pub fn approved(server_name: &str) -> Self {
        Self {
            versions: vec![TLS13, TLS12],
            cipher_suites: suites::AES_GCM.to_vec(),
            groups: groups::NIST.to_vec(),
            signature_algorithms: sigalgs::APPROVED.to_vec(),
            extended_master_secret: true,
            server_name: Some(server_name.to_owned()),
        }
    }

    /// A TLS 1.2-only hello with the AES-GCM suites and the NIST curves, as a
    /// pre-1.3 client sends it (no `supported_versions`), with or without EMS.
    pub fn tls12(server_name: &str, extended_master_secret: bool) -> Self {
        Self {
            versions: Vec::new(),
            cipher_suites: vec![
                suites::ECDHE_ECDSA_AES_128_GCM_SHA256,
                suites::ECDHE_ECDSA_AES_256_GCM_SHA384,
                suites::ECDHE_RSA_AES_128_GCM_SHA256,
                suites::ECDHE_RSA_AES_256_GCM_SHA384,
            ],
            groups: groups::NIST.to_vec(),
            signature_algorithms: sigalgs::APPROVED.to_vec(),
            extended_master_secret,
            server_name: Some(server_name.to_owned()),
        }
    }

    /// Serialize as one TLS record.
    ///
    /// # Panics
    ///
    /// Panics when a field is too long for its wire length prefix.
    pub fn to_record(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&TLS12.to_be_bytes());
        body.extend_from_slice(&random(32));
        // legacy_session_id: rustls' own clients send a random 32-byte id in
        // TLS 1.3 compatibility mode; an empty one is equally valid.
        body.push(0);
        body.extend_from_slice(&u16_vec(&self.cipher_suites));
        body.extend_from_slice(&[1, 0]); // compression methods: null only
        let extensions = self.extensions();
        push_u16(&mut body, u16::try_from(extensions.len()).expect("extensions length"));
        body.extend_from_slice(&extensions);
        handshake_record(HANDSHAKE_CLIENT_HELLO, &body)
    }

    /// The extensions block.
    fn extensions(&self) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = &self.server_name {
            push_extension(&mut extensions, EXT_SERVER_NAME, &server_name_extension(name));
        }
        push_extension(&mut extensions, EXT_SUPPORTED_GROUPS, &u16_vec(&self.groups));
        push_extension(&mut extensions, EXT_EC_POINT_FORMATS, &[1, 0]); // uncompressed
        push_extension(
            &mut extensions,
            EXT_SIGNATURE_ALGORITHMS,
            &u16_vec(&self.signature_algorithms),
        );
        if self.extended_master_secret {
            push_extension(&mut extensions, EXT_EXTENDED_MASTER_SECRET, &[]);
        }
        if !self.versions.is_empty() {
            let mut ext = Vec::new();
            push_u8_len_u16_vec(&mut ext, &self.versions);
            push_extension(&mut extensions, EXT_SUPPORTED_VERSIONS, &ext);
        }
        if self.versions.contains(&TLS13)
            && let Some(&group) = self.groups.first()
        {
            push_extension(&mut extensions, EXT_KEY_SHARE, &key_share_extension(group));
        }
        extensions
    }
}

/// The body of a `server_name` extension naming one host.
fn server_name_extension(name: &str) -> Vec<u8> {
    let mut list = vec![0]; // host_name
    push_u16(&mut list, u16::try_from(name.len()).expect("host name length"));
    list.extend_from_slice(name.as_bytes());
    let mut ext = Vec::new();
    push_u16(&mut ext, u16::try_from(list.len()).expect("server_name list length"));
    ext.extend_from_slice(&list);
    ext
}

/// The body of a `key_share` extension with one share for `group`; see
/// [`groups::key_share`] for what makes it acceptable.
fn key_share_extension(group: u16) -> Vec<u8> {
    let share = groups::key_share(group);
    let mut entry = Vec::new();
    push_u16(&mut entry, group);
    push_u16(&mut entry, u16::try_from(share.len()).expect("key share length"));
    entry.extend_from_slice(&share);
    let mut ext = Vec::new();
    push_u16(&mut ext, u16::try_from(entry.len()).expect("key_share length"));
    ext.extend_from_slice(&entry);
    ext
}

// -----------------------------------------------------------------------------
// ServerHello Builder
// -----------------------------------------------------------------------------

/// A TLS 1.2 `ServerHello` a rogue server answers with: it selects `suite`
/// and acknowledges EMS or not. The client under test decides whether to
/// continue on the strength of this message alone, before any certificate
/// is needed, which is why no further messages are ever sent.
///
/// # Panics
///
/// Panics when the extensions outgrow their wire length prefix, which a
/// fixed message never does.
pub fn tls12_server_hello(suite: u16, extended_master_secret: bool) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&TLS12.to_be_bytes());
    body.extend_from_slice(&random(32));
    body.push(0); // session id: none
    push_u16(&mut body, suite);
    body.push(0); // compression: null
    let mut extensions = Vec::new();
    push_extension(&mut extensions, EXT_EC_POINT_FORMATS, &[1, 0]);
    if extended_master_secret {
        push_extension(&mut extensions, EXT_EXTENDED_MASTER_SECRET, &[]);
    }
    push_u16(&mut body, u16::try_from(extensions.len()).expect("extensions length"));
    body.extend_from_slice(&extensions);
    handshake_record(HANDSHAKE_SERVER_HELLO, &body)
}

/// A fatal alert record.
pub fn alert(description: u8) -> Vec<u8> {
    vec![CONTENT_ALERT, 0x03, 0x03, 0, 2, 2, description]
}

// -----------------------------------------------------------------------------
// Client Probe
// -----------------------------------------------------------------------------

/// The peer's first record in reply to a `ClientHello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A `ServerHello`: the offer was acceptable. `version` is the selected
    /// version (`supported_versions` in TLS 1.3, the legacy field otherwise).
    ServerHello {
        /// The negotiated protocol version.
        version: u16,
        /// The selected cipher suite.
        cipher_suite: u16,
    },
    /// A fatal alert: the offer was refused.
    Alert {
        /// The alert description.
        description: u8,
    },
    /// The peer closed the connection without a record.
    Closed,
}

impl Reply {
    /// Whether the peer refused the offer, by alert or by closing.
    pub fn refused(&self) -> bool {
        !matches!(self, Self::ServerHello { .. })
    }
}

/// Send `hello` to `addr` and read the first record back.
///
/// # Panics
///
/// Panics when the connection cannot be made or the peer sends something
/// that is neither a `ServerHello` nor an alert within the timeout.
pub fn probe(addr: &str, hello: &ClientHello) -> Reply {
    let mut stream = TcpStream::connect(addr).expect("connect to the peer");
    stream
        .set_read_timeout(Some(RESPONSE_TIMEOUT))
        .expect("set read timeout");
    stream.write_all(&hello.to_record()).expect("send ClientHello");
    match read_record(&mut stream) {
        None => Reply::Closed,
        Some((CONTENT_ALERT, payload)) => Reply::Alert {
            description: payload.get(1).copied().expect("alert description"),
        },
        Some((CONTENT_HANDSHAKE, payload)) => parse_server_hello(&payload),
        Some((content_type, _)) => panic!("unexpected record type {content_type} in reply to ClientHello"),
    }
}

/// Decode the version and cipher suite out of a `ServerHello`.
fn parse_server_hello(payload: &[u8]) -> Reply {
    assert_eq!(
        payload.first().copied(),
        Some(HANDSHAKE_SERVER_HELLO),
        "expected a ServerHello handshake message"
    );
    let mut cursor = Cursor::new(&payload[4..]);
    let legacy_version = cursor.u16();
    cursor.skip(32);
    let session_id_len = usize::from(cursor.u8());
    cursor.skip(session_id_len);
    let cipher_suite = cursor.u16();
    cursor.skip(1); // compression
    let mut version = legacy_version;
    if cursor.remaining() >= 2 {
        let extensions_len = usize::from(cursor.u16());
        let mut extensions = Cursor::new(cursor.take(extensions_len));
        while extensions.remaining() >= 4 {
            let ext_type = extensions.u16();
            let ext_len = usize::from(extensions.u16());
            let data = extensions.take(ext_len);
            if ext_type == EXT_SUPPORTED_VERSIONS && data.len() == 2 {
                version = u16::from_be_bytes([data[0], data[1]]);
            }
        }
    }
    Reply::ServerHello { version, cipher_suite }
}

// -----------------------------------------------------------------------------
// ClientHello Parser
// -----------------------------------------------------------------------------

/// What a `ClientHello` offered, as a rogue server saw it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Offer {
    /// The versions from `supported_versions`, or just the legacy version.
    pub versions: Vec<u16>,
    /// The cipher suites, in order.
    pub cipher_suites: Vec<u16>,
    /// The named groups, in order.
    pub groups: Vec<u16>,
    /// The signature schemes.
    pub signature_algorithms: Vec<u16>,
    /// Whether Extended Master Secret was offered.
    pub extended_master_secret: bool,
    /// The SNI host name, if any.
    pub server_name: Option<String>,
}

impl Offer {
    /// Parse a `ClientHello` record.
    ///
    /// # Panics
    ///
    /// Panics on anything that is not a well-formed `ClientHello`.
    pub fn parse(record: &[u8]) -> Self {
        assert_eq!(
            record.first().copied(),
            Some(CONTENT_HANDSHAKE),
            "not a handshake record"
        );
        let payload = &record[5..];
        assert_eq!(
            payload.first().copied(),
            Some(HANDSHAKE_CLIENT_HELLO),
            "not a ClientHello"
        );
        let mut cursor = Cursor::new(&payload[4..]);
        let legacy_version = cursor.u16();
        cursor.skip(32);
        let session_id_len = usize::from(cursor.u8());
        cursor.skip(session_id_len);
        let suites_len = usize::from(cursor.u16());
        let cipher_suites = u16s(cursor.take(suites_len));
        let compression_len = usize::from(cursor.u8());
        cursor.skip(compression_len);

        let mut offer = Self {
            versions: vec![legacy_version],
            cipher_suites,
            ..Self::default()
        };
        if cursor.remaining() >= 2 {
            let extensions_len = usize::from(cursor.u16());
            offer.parse_extensions(cursor.take(extensions_len));
        }
        offer
    }

    /// Read every extension in the block.
    fn parse_extensions(&mut self, block: &[u8]) {
        let mut extensions = Cursor::new(block);
        while extensions.remaining() >= 4 {
            let ext_type = extensions.u16();
            let ext_len = usize::from(extensions.u16());
            let data = extensions.take(ext_len);
            self.parse_extension(ext_type, data);
        }
    }

    /// Record one extension the offer cares about.
    fn parse_extension(&mut self, ext_type: u16, data: &[u8]) {
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                let count = usize::from(data[0]);
                self.versions = u16s(&data[1..=count]);
            },
            EXT_SUPPORTED_GROUPS => {
                let count = usize::from(u16::from_be_bytes([data[0], data[1]]));
                self.groups = u16s(&data[2..2 + count]);
            },
            EXT_SIGNATURE_ALGORITHMS => {
                let count = usize::from(u16::from_be_bytes([data[0], data[1]]));
                self.signature_algorithms = u16s(&data[2..2 + count]);
            },
            EXT_EXTENDED_MASTER_SECRET => self.extended_master_secret = true,
            EXT_SERVER_NAME => {
                // list length (2), name type (1), name length (2), name
                let len = usize::from(u16::from_be_bytes([data[3], data[4]]));
                self.server_name = Some(String::from_utf8_lossy(&data[5..5 + len]).into_owned());
            },
            _ => {},
        }
    }
}

// -----------------------------------------------------------------------------
// Rogue Server
// -----------------------------------------------------------------------------

/// What a rogue server answers every `ClientHello` with.
#[derive(Debug, Clone)]
pub enum RogueReply {
    /// A fatal alert with this description.
    Alert(u8),
    /// A raw record, for example [`tls12_server_hello`].
    Record(Vec<u8>),
}

/// One connection as the rogue server saw it: what the client offered, and
/// how it reacted to the reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The client's `ClientHello`.
    pub offer: Offer,
    /// The alert the client sent back after the reply, if it sent one within
    /// a second. A client that accepts a `ServerHello` sends nothing and
    /// waits for the rest of the flight; one that refuses it answers with a
    /// fatal alert at once.
    pub client_alert: Option<u8>,
}

/// How long the rogue server waits for the client's reaction to its reply.
const REACTION_TIMEOUT: Duration = Duration::from_secs(1);

/// A server that records each `ClientHello` it receives, answers with a
/// fixed reply, records the client's reaction, then closes. It never
/// completes a handshake. Like the other backends in this crate, its accept
/// loop runs until the test process exits.
pub struct RogueServer {
    /// The port the server listens on.
    port: u16,
    /// The observations so far, in order.
    observations: mpsc::Receiver<Observation>,
}

impl RogueServer {
    /// Start a rogue server on a free loopback port.
    ///
    /// # Panics
    ///
    /// Panics when the listener cannot bind.
    pub fn start(reply: RogueReply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind rogue server");
        let port = listener.local_addr().expect("rogue server address").port();
        let (sender, observations) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let sender = sender.clone();
                let reply = reply.clone();
                std::thread::spawn(move || serve_one(stream, &reply, &sender));
            }
        });
        Self { port, observations }
    }

    /// The port the server listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The server's loopback address.
    pub fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Wait for the next connection to be served in full.
    ///
    /// # Panics
    ///
    /// Panics when no `ClientHello` arrives within the timeout.
    pub fn next(&self) -> Observation {
        self.observations
            .recv_timeout(RESPONSE_TIMEOUT.saturating_add(REACTION_TIMEOUT))
            .expect("a ClientHello reached the rogue server")
    }
}

/// Read one `ClientHello`, answer, read the reaction, report, close.
fn serve_one(mut stream: TcpStream, reply: &RogueReply, sender: &mpsc::Sender<Observation>) {
    stream
        .set_read_timeout(Some(RESPONSE_TIMEOUT))
        .expect("set read timeout");
    let Some((CONTENT_HANDSHAKE, payload)) = read_record(&mut stream) else {
        return;
    };
    let mut record = vec![CONTENT_HANDSHAKE, 0x03, 0x03];
    push_u16(&mut record, u16::try_from(payload.len()).expect("record length"));
    record.extend_from_slice(&payload);
    let offer = Offer::parse(&record);
    let bytes = match reply {
        RogueReply::Alert(description) => alert(*description),
        RogueReply::Record(record) => record.clone(),
    };
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
    stream
        .set_read_timeout(Some(REACTION_TIMEOUT))
        .expect("set reaction timeout");
    let client_alert = match read_record(&mut stream) {
        Some((CONTENT_ALERT, alert)) => alert.get(1).copied(),
        Some(_) | None => None,
    };
    let _ = sender.send(Observation { offer, client_alert });
}

// -----------------------------------------------------------------------------
// Record I/O
// -----------------------------------------------------------------------------

/// Read one TLS record: `(content type, payload)`, or `None` at end of
/// stream or timeout before any record.
fn read_record(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut header = [0_u8; 5];
    stream.read_exact(&mut header).ok()?;
    let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    let mut payload = vec![0_u8; len];
    stream.read_exact(&mut payload).ok()?;
    Some((header[0], payload))
}

/// Wrap a handshake message body in a handshake message and a record.
fn handshake_record(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut message = vec![message_type];
    let len = u32::try_from(body.len()).expect("handshake length");
    message.extend_from_slice(&len.to_be_bytes()[1..]);
    message.extend_from_slice(body);
    let mut record = vec![CONTENT_HANDSHAKE, 0x03, 0x03];
    push_u16(&mut record, u16::try_from(message.len()).expect("record length"));
    record.extend_from_slice(&message);
    record
}

/// Append a big-endian `u16`.
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// A `u16`-length-prefixed vector of `u16`.
fn u16_vec(values: &[u16]) -> Vec<u8> {
    let mut out = Vec::new();
    push_u16(&mut out, u16::try_from(values.len() * 2).expect("vector length"));
    for value in values {
        push_u16(&mut out, *value);
    }
    out
}

/// Append a `u8`-length-prefixed vector of `u16` (`supported_versions`).
fn push_u8_len_u16_vec(out: &mut Vec<u8>, values: &[u16]) {
    out.push(u8::try_from(values.len() * 2).expect("vector length"));
    for value in values {
        push_u16(out, *value);
    }
}

/// Append one extension.
fn push_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    push_u16(out, ext_type);
    push_u16(out, u16::try_from(data.len()).expect("extension length"));
    out.extend_from_slice(data);
}

/// Decode a byte string of big-endian `u16`.
fn u16s(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect()
}

/// Bytes that look random enough for a hello; the probe never derives keys
/// from them, so a cheap generator (xorshift64 seeded from the clock) is fine.
fn random(len: usize) -> Vec<u8> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut state = u64::try_from(nanos & u128::from(u64::MAX)).unwrap_or(0x9E37_79B9_7F4A_7C15) | 1;
    std::iter::repeat_with(|| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        u8::try_from(state >> 56).unwrap_or(0)
    })
    .take(len)
    .collect()
}

/// A bounds-checked reader over a byte slice.
struct Cursor<'bytes> {
    /// The bytes.
    bytes: &'bytes [u8],
    /// The read position.
    pos: usize,
}

impl<'bytes> Cursor<'bytes> {
    /// Start at the beginning of `bytes`.
    fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    /// Bytes left.
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Read one byte.
    fn u8(&mut self) -> u8 {
        let value = self.bytes[self.pos];
        self.pos += 1;
        value
    }

    /// Read a big-endian `u16`.
    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.u8(), self.u8()])
    }

    /// Skip `n` bytes.
    fn skip(&mut self, n: usize) {
        self.pos += n;
    }

    /// Take the next `n` bytes.
    fn take(&mut self, n: usize) -> &'bytes [u8] {
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        slice
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hello_round_trips_through_the_parser() {
        let hello = ClientHello::approved("example.test");
        let offer = Offer::parse(&hello.to_record());
        assert_eq!(offer.versions, vec![TLS13, TLS12]);
        assert_eq!(offer.cipher_suites, suites::AES_GCM.to_vec());
        assert_eq!(offer.groups, groups::NIST.to_vec());
        assert_eq!(offer.signature_algorithms, sigalgs::APPROVED.to_vec());
        assert!(offer.extended_master_secret);
        assert_eq!(offer.server_name.as_deref(), Some("example.test"));
    }

    #[test]
    fn a_tls12_hello_has_no_supported_versions() {
        let offer = Offer::parse(&ClientHello::tls12("example.test", false).to_record());
        assert_eq!(offer.versions, vec![TLS12], "the legacy version alone");
        assert!(!offer.extended_master_secret);
    }

    #[test]
    fn a_server_hello_parses_back() {
        let record = tls12_server_hello(suites::ECDHE_ECDSA_AES_128_GCM_SHA256, true);
        let reply = parse_server_hello(&record[5..]);
        assert_eq!(
            reply,
            Reply::ServerHello {
                version: TLS12,
                cipher_suite: suites::ECDHE_ECDSA_AES_128_GCM_SHA256
            }
        );
    }

    #[test]
    fn the_rogue_server_records_the_offer_and_answers() {
        let server = RogueServer::start(RogueReply::Alert(alerts::HANDSHAKE_FAILURE));
        let reply = probe(&server.addr(), &ClientHello::approved("rogue.test"));
        assert_eq!(
            reply,
            Reply::Alert {
                description: alerts::HANDSHAKE_FAILURE
            }
        );
        assert!(reply.refused());
        let seen = server.next();
        assert_eq!(seen.offer.server_name.as_deref(), Some("rogue.test"));
        assert_eq!(seen.client_alert, None, "the raw probe never answers an alert");
    }

    #[test]
    fn nist_key_shares_are_real_points() {
        let p256 = groups::key_share(groups::SECP256R1);
        assert_eq!(p256.len(), 65);
        assert_eq!(p256.first(), Some(&4), "uncompressed point");
        assert_eq!(groups::key_share(groups::SECP384R1).len(), 97);
        assert_eq!(groups::key_share(groups::X25519).len(), 32);
    }
}
