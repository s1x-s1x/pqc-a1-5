//! Hybrid X25519 + ML-KEM-768 key exchange inside a real TLS stack.
//!
//! Tier 3 of the project: the hybrid the Python harness implements, expressed against
//! rustls's real extension points and run through a real rustls handshake.
//!
//! The shape follows rustls's own post-quantum groups (`crypto/aws_lc_rs/pq/{mlkem,hybrid}.rs`),
//! which is where the two facts this prototype needed are written down:
//!
//! * A KEM group must implement **`SupportedKxGroup::start_and_complete`**, because the
//!   server's share is a **ciphertext** and cannot be produced by `start()`. The default
//!   `start_and_complete` calls `start()` then `complete()`, which for a KEM publishes a
//!   key where a ciphertext belongs; that is why the first version of this file
//!   negotiated nothing.
//! * A hybrid group is a *composition*: both sub-groups run, the shares concatenate
//!   post-quantum first and classical second, and so do the shared secrets.
//!
//! What this still does not do is hybrid *signatures*: rustls's `SignatureScheme` is a
//! closed enum, so a composite CertificateVerify needs a patched rustls or the
//! delegated-credentials route Celi et al. used. That remains a documented route.
//!
//! Run with the MSVC environment on PATH: `powershell -File tools\build_rust_prototype.ps1`

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::Arc;

use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand_core::OsRng;
use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, Error, NamedGroup, ServerConfig};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

/// ML-KEM-768 sizes from FIPS 203.
const MLKEM768_EK_BYTES: usize = 1184;
const MLKEM768_CT_BYTES: usize = 1088;
const MLKEM768_SHARED_BYTES: usize = 32;
const X25519_BYTES: usize = 32;
/// The code point the IANA draft assigns to X25519MLKEM768.
const X25519_MLKEM768_CODE_POINT: u16 = 0x11EC;
/// Private-use code point for ML-KEM-768 standing alone in this prototype.
const MLKEM768_CODE_POINT: u16 = 0x0F02;

type MlKem768Secret = <MlKem768 as KemCore>::DecapsulationKey;
type MlKem768Public = <MlKem768 as KemCore>::EncapsulationKey;
type MlKem768Ciphertext = ml_kem::Ciphertext<MlKem768>;

fn bad_share(what: &str) -> Error {
    Error::General(format!("invalid key share: {what}"))
}

/// ML-KEM-768 as a rustls group, with the KEM semantics a KEM needs.
///
/// `start` is the client: generate a key pair and publish the encapsulation key.
/// `start_and_complete` is the server: encapsulate to the client's key, publish the
/// **ciphertext** as the server's share, and keep the shared secret.
/// `complete` is the client again: decapsulate the server's ciphertext.
#[derive(Debug)]
struct MlKem768Group;

struct MlKem768Exchange {
    secret: MlKem768Secret,
    share: Vec<u8>,
}

impl SupportedKxGroup for MlKem768Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let (secret, public) = MlKem768::generate(&mut OsRng);
        Ok(Box::new(MlKem768Exchange {
            secret,
            share: public.as_bytes().to_vec(),
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let encoded: Array<u8, <MlKem768Public as EncodedSizeUser>::EncodedSize> = client_share
            .try_into()
            .map_err(|_| bad_share("wrong encapsulation key size"))?;
        let public = MlKem768Public::from_bytes(&encoded);
        let (ciphertext, shared) = public
            .encapsulate(&mut OsRng)
            .map_err(|_| bad_share("encapsulation failed"))?;
        Ok(CompletedKeyExchange {
            group: self.name(),
            // The ciphertext is the server's key share. This is the line the earlier
            // version of this file could not express.
            pub_key: ciphertext.as_slice().to_vec(),
            secret: SharedSecret::from(shared.as_slice().to_vec()),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::from(MLKEM768_CODE_POINT)
    }
}

impl ActiveKeyExchange for MlKem768Exchange {
    fn group(&self) -> NamedGroup {
        NamedGroup::from(MLKEM768_CODE_POINT)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != MLKEM768_CT_BYTES {
            return Err(bad_share("ciphertext has the wrong size"));
        }
        let ciphertext = MlKem768Ciphertext::try_from(peer_pub_key)
            .map_err(|_| bad_share("ciphertext has the wrong size"))?;
        let shared = self
            .secret
            .decapsulate(&ciphertext)
            .map_err(|_| bad_share("decapsulation failed"))?;
        Ok(SharedSecret::from(shared.as_slice().to_vec()))
    }
}

/// Hybrid group composed the way rustls composes its own: two sub-groups, shares and
/// secrets concatenated post-quantum first.
///
/// `client -> server`: `ek(1184) ‖ x_pub(32)` = 1216 bytes
/// `server -> client`: `ct(1088) ‖ y_pub(32)` = 1120 bytes
/// `secret           = ss_mlkem(32) ‖ ss_x25519(32)` = 64 bytes
///
/// The ciphertext travels in the ordinary key-share slot, which is why a KEM needs no
/// separate message: rustls reads whatever `pub_key` the group returns.
#[derive(Debug)]
struct HybridX25519MlKem768 {
    classical: &'static dyn SupportedKxGroup,
    post_quantum: &'static dyn SupportedKxGroup,
}

struct HybridExchange {
    classical: Box<dyn ActiveKeyExchange>,
    post_quantum: Box<dyn ActiveKeyExchange>,
    share: Vec<u8>,
}

impl SupportedKxGroup for HybridX25519MlKem768 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let post_quantum = self.post_quantum.start()?;
        let classical = self.classical.start()?;
        let mut share = Vec::with_capacity(MLKEM768_EK_BYTES + X25519_BYTES);
        share.extend_from_slice(post_quantum.pub_key());
        share.extend_from_slice(classical.pub_key());
        Ok(Box::new(HybridExchange {
            classical,
            post_quantum,
            share,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != MLKEM768_EK_BYTES + X25519_BYTES {
            return Err(bad_share("hybrid client share has the wrong size"));
        }
        let (pq_share, classical_share) = client_share.split_at(MLKEM768_EK_BYTES);
        let post_quantum = self.post_quantum.start_and_complete(pq_share)?;
        let classical = self.classical.start_and_complete(classical_share)?;

        let mut pub_key = Vec::with_capacity(MLKEM768_CT_BYTES + X25519_BYTES);
        pub_key.extend_from_slice(&post_quantum.pub_key);
        pub_key.extend_from_slice(&classical.pub_key);

        // Post-quantum first, matching rustls's own layout and the SP 800-56C ordering
        // note in its source: the element appearing first is the one that controls
        // approval, so the order is a documented choice rather than an accident.
        let mut secret = Vec::with_capacity(MLKEM768_SHARED_BYTES + X25519_BYTES);
        secret.extend_from_slice(post_quantum.secret.secret_bytes());
        secret.extend_from_slice(classical.secret.secret_bytes());

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key,
            secret: SharedSecret::from(secret),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::from(X25519_MLKEM768_CODE_POINT)
    }
}

impl ActiveKeyExchange for HybridExchange {
    fn group(&self) -> NamedGroup {
        NamedGroup::from(X25519_MLKEM768_CODE_POINT)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != MLKEM768_CT_BYTES + X25519_BYTES {
            return Err(bad_share("hybrid server share has the wrong size"));
        }
        let (pq_share, classical_share) = peer_pub_key.split_at(MLKEM768_CT_BYTES);
        let post_quantum = self.post_quantum.complete(pq_share)?;
        let classical = self.classical.complete(classical_share)?;
        let mut secret = Vec::with_capacity(MLKEM768_SHARED_BYTES + X25519_BYTES);
        secret.extend_from_slice(post_quantum.secret_bytes());
        secret.extend_from_slice(classical.secret_bytes());
        Ok(SharedSecret::from(secret))
    }
}

/// X25519 with a share padded to a hybrid size, as a **share-size control**: the same
/// handshake with a 1216-byte share but no post-quantum cryptography. The padding is
/// zeros and carries no security; it exists so the hybrid row can be attributed to its
/// shares rather than to the fact that *some* custom group was in play.
#[derive(Debug)]
struct PaddedX25519 {
    extra_bytes: usize,
    code_point: u16,
}

struct PaddedExchange {
    secret: StaticSecret,
    share: Vec<u8>,
    code_point: u16,
}

impl SupportedKxGroup for PaddedX25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = StaticSecret::random_from_rng(OsRng);
        let mut share = Vec::with_capacity(X25519_BYTES + self.extra_bytes);
        share.extend_from_slice(X25519PublicKey::from(&secret).as_bytes());
        share.resize(X25519_BYTES + self.extra_bytes, 0);
        Ok(Box::new(PaddedExchange {
            secret,
            share,
            code_point: self.code_point,
        }))
    }

    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() < X25519_BYTES {
            return Err(bad_share("padded share too short"));
        }
        let secret = StaticSecret::random_from_rng(OsRng);
        let mut x_array = [0u8; X25519_BYTES];
        x_array.copy_from_slice(&client_share[..X25519_BYTES]);
        let shared = secret.diffie_hellman(&X25519PublicKey::from(x_array));
        reject_zero_shared(shared.as_bytes(), "padded share-size control")?;
        let mut pub_key = X25519PublicKey::from(&secret).as_bytes().to_vec();
        pub_key.resize(X25519_BYTES + self.extra_bytes, 0);
        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key,
            secret: SharedSecret::from(shared.as_bytes().to_vec()),
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::from(self.code_point)
    }
}

impl ActiveKeyExchange for PaddedExchange {
    fn group(&self) -> NamedGroup {
        NamedGroup::from(self.code_point)
    }

    fn pub_key(&self) -> &[u8] {
        &self.share
    }

    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() < X25519_BYTES {
            return Err(bad_share("share too short"));
        }
        let mut x_array = [0u8; X25519_BYTES];
        x_array.copy_from_slice(&peer_pub_key[..X25519_BYTES]);
        let shared = self.secret.diffie_hellman(&X25519PublicKey::from(x_array));
        reject_zero_shared(shared.as_bytes(), "padded share-size control")?;
        Ok(SharedSecret::from(shared.as_bytes().to_vec()))
    }
}

/// A one-way byte pipe: both endpoints run in one thread, pumped deterministically.
#[derive(Default)]
struct Pipe {
    data: VecDeque<u8>,
    written: usize,
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let take = buf.len().min(self.data.len());
        for slot in buf.iter_mut().take(take) {
            *slot = self.data.pop_front().expect("length checked");
        }
        Ok(take)
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.data.extend(buf.iter().copied());
        self.written += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Outcome {
    client_bytes: usize,
    server_bytes: usize,
    certificate_bytes: usize,
    suite: String,
    group: String,
}

/// Run one TLS 1.3 handshake in memory with the given group list.
/// A throwaway CA and the leaf it issued, so the client has something real to verify.
///
/// The earlier version generated one self-signed certificate and installed a verifier
/// that accepted anything and validated no handshake signature. An audit of this
/// repository rated that the most serious finding in it: the prototype measured a key
/// exchange whose *authentication* was switched off, and a reader could copy that
/// configuration into a real client. Generating a CA costs a few lines and lets the
/// client use rustls's own verification path with no `dangerous()` escape hatch.
struct TestPki {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn test_pki() -> Result<TestPki, Box<dyn std::error::Error>> {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "hybrid-tls13 prototype test CA");
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let leaf_key = KeyPair::generate()?;
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_string()])?;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key)?;

    Ok(TestPki {
        ca: CertificateDer::from(ca_cert.der().to_vec()),
        leaf: CertificateDer::from(leaf_cert.der().to_vec()),
        key: PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|error| format!("key: {error}"))?,
    })
}

fn handshake(
    groups: Vec<&'static dyn SupportedKxGroup>,
    server_pki: &TestPki,
    trust: &CertificateDer<'static>,
) -> Result<Outcome, Box<dyn std::error::Error>> {
    let certificate_bytes = server_pki.leaf.as_ref().len();

    // The group list lives on the provider, not on the config: that is how rustls 0.23
    // takes a custom group.
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = groups;

    // Real verification, through rustls's webpki verifier: chain to the anchor, name,
    // validity, and the CertificateVerify signature made by the leaf's key.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trust.clone())?;

    let client_config = ClientConfig::builder_with_provider(Arc::new(provider.clone()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![server_pki.leaf.clone(), server_pki.ca.clone()],
            server_pki.key.clone_key(),
        )?;

    let server_name = ServerName::try_from("localhost")?;
    let mut client = rustls::ClientConnection::new(Arc::new(client_config), server_name)?;
    let mut server = rustls::ServerConnection::new(Arc::new(server_config))?;

    let mut client_to_server = Pipe::default();
    let mut server_to_client = Pipe::default();
    for _ in 0..64 {
        while client.wants_write() {
            client.write_tls(&mut client_to_server)?;
        }
        while server.wants_write() {
            server.write_tls(&mut server_to_client)?;
        }
        let mut progressed = false;
        while !client_to_server.data.is_empty() {
            server.read_tls(&mut client_to_server)?;
            server.process_new_packets()?;
            progressed = true;
        }
        while !server_to_client.data.is_empty() {
            client.read_tls(&mut server_to_client)?;
            client.process_new_packets()?;
            progressed = true;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            break;
        }
        if !progressed && !client.wants_write() && !server.wants_write() {
            break;
        }
    }
    if client.is_handshaking() || server.is_handshaking() {
        return Err("handshake did not complete within the pump budget".into());
    }

    Ok(Outcome {
        client_bytes: client_to_server.written,
        server_bytes: server_to_client.written,
        certificate_bytes,
        suite: format!("{:?}", client.negotiated_cipher_suite()),
        group: client
            .negotiated_key_exchange_group()
            .map(|group| format!("{group:?}"))
            .unwrap_or_else(|| "none".to_string()),
    })
}


/// Rejects the all-zero X25519 shared secret, as RFC 7748 section 6.1 requires.
///
/// The hybrid group's classical half is rustls's own X25519, which already does this;
/// this exists for the padded share-size control below, which calls `x25519-dalek`
/// directly and used to accept a low-order peer key. An audit found it there.
fn reject_zero_shared(shared: &[u8; X25519_BYTES], what: &str) -> Result<(), Error> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err(Error::General(format!(
            "{what}: X25519 produced the all-zero shared secret, which RFC 7748 section 6.1 \
             requires be rejected"
        )));
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mlkem: &'static dyn SupportedKxGroup = Box::leak(Box::new(MlKem768Group));
    let hybrid: &'static dyn SupportedKxGroup = Box::leak(Box::new(HybridX25519MlKem768 {
        classical: rustls::crypto::ring::kx_group::X25519,
        post_quantum: mlkem,
    }));
    let padded: &'static dyn SupportedKxGroup = Box::leak(Box::new(PaddedX25519 {
        extra_bytes: MLKEM768_EK_BYTES,
        code_point: 0x0F01,
    }));

    let x25519: &'static dyn SupportedKxGroup = rustls::crypto::ring::kx_group::X25519;
    let pki = test_pki()?;
    println!("{:<40}{:>9}{:>9}{:>9}{:>11}", "rustls TLS 1.3 group", "client", "server", "total", "delta");

    let mut baseline_total = 0usize;
    let mut hybrid_total = 0usize;
    // (label, negotiated group) per row, so the self-check below can read what rustls
    // actually selected instead of inferring it from byte counts.
    let mut negotiation_log: Vec<(String, String)> = Vec::new();
    for (label, groups, is_hybrid) in [
        ("X25519 only (classical baseline)", vec![x25519], false),
        ("X25519, share padded to 1216 B", vec![padded], false),
        ("ML-KEM-768 only (pure post-quantum)", vec![mlkem], false),
        ("X25519 + ML-KEM-768 (hybrid)", vec![hybrid], true),
    ] {
        let outcome = handshake(groups, &pki, &pki.ca)?;
        let total = outcome.client_bytes + outcome.server_bytes;
        if label.starts_with("X25519 only") {
            baseline_total = total;
        }
        if is_hybrid {
            hybrid_total = total;
        }
        negotiation_log.push((label.to_string(), outcome.group.clone()));
        let delta = if baseline_total == 0 {
            "0".to_string()
        } else {
            format!("{:+}", total as i64 - baseline_total as i64)
        };
        println!(
            "{:<40}{:>9}{:>9}{:>9}{:>11}",
            label, outcome.client_bytes, outcome.server_bytes, total, delta
        );
        println!(
            "    group {}, suite {}, certificate {} bytes",
            outcome.group, outcome.suite, outcome.certificate_bytes
        );
    }

    // Self-check on the NEGOTIATED GROUP, not on a byte threshold. An earlier version
    // required the byte delta to be at least the sum of the two share sizes, which fails
    // whenever the variable-length certificate and ECDSA DER come out a byte or two
    // shorter: an external review measured the hybrid group negotiating successfully and
    // this check still reporting failure in 2 of 10 runs. rustls reports the group only if
    // the handshake selected it and completed, which is the authoritative evidence.
    let hybrid_negotiated = negotiation_log.iter().any(|(label, group)| {
        label.starts_with("X25519 + ML-KEM-768") && group.contains("HybridX25519MlKem768")
    });
    if !hybrid_negotiated {
        println!();
        println!("PREMISE FALSIFIED: the hybrid group was not negotiated.");
        println!("  therefore no real-stack hybrid number is available from this run.");
        std::process::exit(2);
    }
    println!();
    println!(
        "hybrid key exchange negotiated in rustls: {:+} bytes over X25519 alone",
        hybrid_total as i64 - baseline_total as i64
    );
    println!(
        "  (the byte delta moves by a few bytes between runs because the certificate and \
         ECDSA DER lengths are variable; that is why the check reads the group, not the delta)"
    );

    // Negative controls. The rows above are only evidence of authentication if the client
    // would *refuse* a server it does not trust — an audit of this repository found the
    // prototype accepting any certificate and any handshake signature, which made every
    // row above silent about authentication.
    println!();
    let stranger = test_pki()?;
    match handshake(vec![hybrid], &pki, &stranger.ca) {
        Ok(_) => {
            println!("PREMISE FALSIFIED: the client accepted a server signed by a CA it does not trust.");
            std::process::exit(2);
        }
        Err(error) => {
            println!("negative control 1: an untrusted CA is rejected -> {error}");
        }
    }

    // The padded share-size control must refuse the all-zero X25519 shared secret, which a
    // low-order peer key produces and RFC 7748 section 6.1 requires be rejected.
    let zero_peer = [0u8; X25519_BYTES];
    match padded.start()?.complete(&zero_peer) {
        Ok(_) => {
            println!("PREMISE FALSIFIED: the padded control accepted the all-zero shared secret.");
            std::process::exit(2);
        }
        Err(error) => println!("negative control 2: all-zero X25519 share rejected -> {error}"),
    }
    let honest_peer = X25519PublicKey::from(&StaticSecret::random_from_rng(OsRng));
    match padded.start()?.complete(honest_peer.as_bytes()) {
        Ok(_) => println!("positive control: an honest X25519 share still completes"),
        Err(error) => {
            println!("PREMISE FALSIFIED: the padded control rejected an honest share -> {error}");
            std::process::exit(2);
        }
    }
    Ok(())
}
