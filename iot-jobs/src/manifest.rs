//! Signed firmware manifests.
//!
//! A release publishes `manifest.json`, canonical JSON
//!
//! ```text
//! {"contract":1,"factory_sha256":"<hex>","product":"vaktus","sha256":"<hex>","size":1462304,"version":"0.9.0"}
//! ```
//!
//! and `manifest.sig`, `base64(DER(ECDSA-P256-SHA256(manifest.json bytes)))`,
//! made with the product's signing key. The job document carries both, and
//! the key id. The device then:
//!
//! 1. verifies the signature against its compiled-in keyring ([`Keyring`]),
//! 2. checks that the manifest names its product and the job's version,
//! 3. hashes the image as it streams in and compares sha256 and size
//!    ([`ImageCheck`]) before the image may boot.
//!
//! The manifest binds product and version, so an old image renamed to a new
//! version, or one product's image offered to another, is refused. The OTA
//! controller checks the same signature before it creates a job.
//!
//! Canonical means: object keys sorted bytewise, no whitespace, integers
//! without exponent, strings with serde_json's escaping. The device refuses a
//! manifest that is not canonical, so there is exactly one byte string per
//! manifest and nothing can hide in formatting. `contract/v1/` holds the test
//! vector both this crate and the release tooling check.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest, Sha256};

// Signature verification. On the device, mbedTLS, which ESP-IDF links for
// TLS anyway; the pure-Rust `p256` crate would add ~59 KB to the image. On
// the host, `p256`, so the tests and test vectors keep running there. Both
// accept exactly the keys `spki_from_pem` lets through.
#[cfg(target_os = "espidf")]
mod mbedtls;
#[cfg(target_os = "espidf")]
use mbedtls::PublicKey;
#[cfg(not(target_os = "espidf"))]
mod rustcrypto;
#[cfg(not(target_os = "espidf"))]
use rustcrypto::PublicKey;

/// The manifest contract this crate implements.
pub const CONTRACT: u64 = 1;

/// A parsed, canonical manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub contract: u64,
    pub product: String,
    /// Bare `X.Y.Z`.
    pub version: String,
    /// Of `app.bin`, the OTA image.
    pub sha256: [u8; 32],
    /// Of `app.bin`, in bytes.
    pub size: u64,
    /// Of `factory.bin`, the first-flash image; lowercase hex.
    pub factory_sha256: String,
}

impl Manifest {
    /// Parses `bytes`, which must be the canonical encoding of the manifest.
    /// Fields the contract may add later are tolerated (and covered by the
    /// signature, and by the canonical check).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("manifest is not JSON: {e}"))?;
        if canonical(&value) != bytes {
            return Err("manifest is not in canonical form".into());
        }
        let obj = value.as_object().ok_or("manifest is not an object")?;
        let text = |k: &str| {
            obj.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("manifest has no {k}"))
        };
        let number = |k: &str| {
            obj.get(k)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("manifest has no {k}"))
        };
        let contract = number("contract")?;
        if contract != CONTRACT {
            return Err(format!(
                "manifest contract {contract}; this firmware implements {CONTRACT}"
            ));
        }
        let sha256 = parse_sha256(&text("sha256")?)?;
        let factory_sha256 = text("factory_sha256")?;
        parse_sha256(&factory_sha256)?;
        let version = text("version")?;
        crate::Version::parse(&version)?;
        if crate::normalize_version(&version) != version {
            return Err(format!("manifest version {version:?} is not bare X.Y.Z"));
        }
        Ok(Self {
            contract,
            product: text("product")?,
            version,
            sha256,
            size: number("size")?,
            factory_sha256,
        })
    }

    /// The canonical bytes, the ones that are signed.
    pub fn to_bytes(&self) -> Vec<u8> {
        canonical(&serde_json::json!({
            "contract": self.contract,
            "product": self.product,
            "version": self.version,
            "sha256": hex(&self.sha256),
            "size": self.size,
            "factory_sha256": self.factory_sha256,
        }))
    }

    /// What the image must hash to.
    pub fn expected(&self) -> Expected {
        Expected {
            sha256: self.sha256,
            size: self.size,
        }
    }
}

/// The canonical JSON encoding of `value`: keys sorted bytewise at every
/// level, no whitespace. Independent of serde_json's map ordering features.
pub fn canonical(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push(b'{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                out.extend(serde_json::to_vec(key).expect("a string serializes"));
                out.push(b':');
                write_canonical(&map[key], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => out.extend(serde_json::to_vec(scalar).expect("a scalar serializes")),
    }
}

fn parse_sha256(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(format!("{s:?} is not a lowercase hex SHA-256"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("checked hex");
    }
    Ok(out)
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The firmware-signing keys a device accepts, by key id.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    keys: Vec<(String, PublicKey)>,
}

impl Keyring {
    /// Builds the keyring from `(key_id, SubjectPublicKeyInfo PEM)` pairs.
    pub fn from_pems<'a>(
        pems: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, String> {
        let keys = pems
            .into_iter()
            .map(|(id, pem)| {
                spki_from_pem(pem)
                    .and_then(|spki| PublicKey::from_spki(&spki))
                    .map(|k| (id.to_string(), k))
                    .map_err(|e| format!("signing key {id}: not a P-256 public key PEM ({e})"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { keys })
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|(id, _)| id.as_str())
    }

    /// Verifies `sig_b64` over `message` with key `key_id`.
    pub fn verify(&self, key_id: &str, message: &[u8], sig_b64: &str) -> Result<(), String> {
        let (_, key) = self
            .keys
            .iter()
            .find(|(id, _)| id == key_id)
            .ok_or_else(|| format!("unknown signing key {key_id:?}"))?;
        let der = B64
            .decode(sig_b64.trim())
            .map_err(|_| "the signature is not base64".to_string())?;
        key.verify(message, &der)
            .map_err(|rejected| match rejected {
                Rejected::Malformed => "the signature is not DER ECDSA".to_string(),
                Rejected::Mismatch => format!("the signature does not verify with {key_id}"),
            })
    }
}

/// Why a backend refused a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rejected {
    /// Not a DER ECDSA signature.
    Malformed,
    /// Well formed, but not by this key over these bytes.
    Mismatch,
}

/// The DER SubjectPublicKeyInfo of a P-256 key with an uncompressed point,
/// up to the point's coordinates: SEQUENCE { SEQUENCE { id-ecPublicKey,
/// prime256v1 }, BIT STRING { 0x04 ... } }. What `ergo product init`,
/// OpenSSL and the `p256` crate write.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// The DER inside a `PUBLIC KEY` PEM, if it is a P-256 key in the one
/// layout both backends accept. platform-build checks the keyring on the
/// host, so a key the device would refuse fails the build instead.
fn spki_from_pem(pem: &str) -> Result<Vec<u8>, String> {
    let mut lines = pem.trim().lines().map(str::trim);
    if lines.next() != Some("-----BEGIN PUBLIC KEY-----") {
        return Err("no BEGIN PUBLIC KEY line".into());
    }
    let mut body = String::new();
    let mut ended = false;
    for line in lines.by_ref() {
        if line == "-----END PUBLIC KEY-----" {
            ended = true;
            break;
        }
        body.push_str(line);
    }
    if !ended || lines.next().is_some() {
        return Err("no END PUBLIC KEY line at the end".into());
    }
    let der = B64
        .decode(body)
        .map_err(|_| "the body is not base64".to_string())?;
    if der.len() != P256_SPKI_PREFIX.len() + 64 || !der.starts_with(&P256_SPKI_PREFIX) {
        return Err("not a P-256 SubjectPublicKeyInfo with an uncompressed point".into());
    }
    Ok(der)
}

/// What an image must hash to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expected {
    pub sha256: [u8; 32],
    pub size: u64,
}

/// Hashes an image as it streams in.
#[derive(Debug, Clone, Default)]
pub struct ImageCheck {
    hasher: Sha256,
    size: u64,
}

impl ImageCheck {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds the next bytes, in order.
    pub fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.size += bytes.len() as u64;
    }

    /// Bytes fed so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Compares with `expected`.
    pub fn finish(self, expected: &Expected) -> Result<(), String> {
        if self.size != expected.size {
            return Err(format!(
                "the image is {} B, the manifest says {} B",
                self.size, expected.size
            ));
        }
        let got: [u8; 32] = self.hasher.finalize().into();
        if got != expected.sha256 {
            return Err(format!(
                "the image hashes to {}, the manifest says {}",
                hex(&got),
                hex(&expected.sha256)
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::{EncodePublicKey, LineEnding};

    // The contract/v1 test vector, checked by the release tooling too.
    const V1_MANIFEST: &str = include_str!("../../contract/v1/manifest.json");
    const V1_SIG: &str = include_str!("../../contract/v1/manifest.sig");
    const V1_KEY: &str = include_str!("../../contract/v1/test-key.pub.pem");
    const V1_IMAGE: &[u8] = include_bytes!("../../contract/v1/app.bin");

    fn key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    fn sign(message: &[u8]) -> String {
        let sig: Signature = key().sign(message);
        B64.encode(sig.to_der().as_bytes())
    }

    fn keyring() -> Keyring {
        let pem = key()
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        Keyring::from_pems([("test-a", pem.as_str())]).unwrap()
    }

    fn manifest() -> Manifest {
        Manifest {
            contract: 1,
            product: "vaktus".into(),
            version: "0.9.0".into(),
            sha256: Sha256::digest(b"image").into(),
            size: 5,
            factory_sha256: "ab".repeat(32),
        }
    }

    #[test]
    fn the_contract_vector_verifies() {
        let bytes = V1_MANIFEST.trim_end_matches('\n').as_bytes();
        let manifest = Manifest::parse(bytes).unwrap();
        let ring = Keyring::from_pems([("test", V1_KEY)]).unwrap();
        ring.verify("test", bytes, V1_SIG).unwrap();
        let mut check = ImageCheck::new();
        for chunk in V1_IMAGE.chunks(7) {
            check.update(chunk);
        }
        check.finish(&manifest.expected()).unwrap();
        assert_eq!(manifest.to_bytes(), bytes);
    }

    #[test]
    fn manifests_round_trip_canonically() {
        let m = manifest();
        let bytes = m.to_bytes();
        assert!(bytes.starts_with(br#"{"contract":1,"factory_sha256":""#));
        assert_eq!(Manifest::parse(&bytes).unwrap(), m);
    }

    #[test]
    fn non_canonical_manifests_are_refused() {
        let canonical = String::from_utf8(manifest().to_bytes()).unwrap();
        let spaced = canonical.replace(",", ", ");
        assert!(Manifest::parse(spaced.as_bytes()).is_err());
        let v: Value = serde_json::from_str(&canonical).unwrap();
        let pretty = serde_json::to_vec_pretty(&v).unwrap();
        assert!(Manifest::parse(&pretty).is_err());
    }

    #[test]
    fn manifest_fields_are_checked() {
        let base: Value = serde_json::from_slice(&manifest().to_bytes()).unwrap();
        let with = |k: &str, v: Value| {
            let mut m = base.clone();
            m[k] = v;
            canonical(&m)
        };
        assert!(Manifest::parse(&with("contract", 2.into())).is_err());
        assert!(Manifest::parse(&with("sha256", "AB".repeat(32).into())).is_err());
        assert!(Manifest::parse(&with("version", "v0.9.0".into())).is_err());
        assert!(Manifest::parse(&with("version", "latest".into())).is_err());
        assert!(Manifest::parse(&with("size", (-1).into())).is_err());
        // An additive field is fine.
        assert!(Manifest::parse(&with("sbom", "x".into())).is_ok());
    }

    #[test]
    fn signatures_bind_the_exact_bytes() {
        let bytes = manifest().to_bytes();
        let sig = sign(&bytes);
        let ring = keyring();
        ring.verify("test-a", &bytes, &sig).unwrap();
        let mut tampered = bytes.clone();
        tampered[20] ^= 1;
        assert!(ring.verify("test-a", &tampered, &sig).is_err());
        assert!(ring.verify("test-b", &bytes, &sig).is_err());
        assert!(ring.verify("test-a", &bytes, "!!").is_err());
        assert!(ring.verify("test-a", &bytes, "AAAA").is_err());
        let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let foreign: Signature = other.sign(&bytes);
        assert!(ring
            .verify("test-a", &bytes, &B64.encode(foreign.to_der().as_bytes()))
            .is_err());
    }

    #[test]
    fn bad_keys_are_refused() {
        assert!(Keyring::from_pems([("x", "not a pem")]).is_err());
        let pem = |der: &[u8]| {
            format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                B64.encode(der)
            )
        };
        let spki = spki_from_pem(V1_KEY).unwrap();
        assert!(Keyring::from_pems([("x", pem(&spki).as_str())]).is_ok());
        // Not on the curve.
        let mut off_curve = spki.clone();
        off_curve[90] ^= 1;
        let err = Keyring::from_pems([("x", pem(&off_curve).as_str())]).unwrap_err();
        assert!(
            err.starts_with("signing key x: not a P-256 public key PEM ("),
            "{err}"
        );
        // A compressed point, which the device backend does not take.
        let compressed = key().verifying_key().to_sec1_point(true);
        let mut der = P256_SPKI_PREFIX[..23].to_vec();
        der.extend([0x03, 0x22, 0x00]);
        der.extend(compressed.as_bytes());
        der[1] = (der.len() - 2) as u8;
        assert!(Keyring::from_pems([("x", pem(&der).as_str())]).is_err());
        // Another named curve (1.2.840.10045.3.1.6, prime239v3).
        let mut other_curve = spki.clone();
        other_curve[22] = 0x06;
        assert!(Keyring::from_pems([("x", pem(&other_curve).as_str())]).is_err());
        // Armor.
        let body = V1_KEY.replace("PUBLIC KEY", "EC PUBLIC KEY");
        assert!(Keyring::from_pems([("x", body.as_str())]).is_err());
        let trailing = format!("{V1_KEY}junk\n");
        assert!(Keyring::from_pems([("x", trailing.as_str())]).is_err());
        let crlf = V1_KEY.replace('\n', "\r\n");
        assert!(Keyring::from_pems([("x", crlf.as_str())]).is_ok());
        assert!(Keyring::default().is_empty());
        assert_eq!(keyring().ids().collect::<Vec<_>>(), ["test-a"]);
    }

    #[test]
    fn images_must_match_hash_and_size() {
        let expected = manifest().expected();
        let mut ok = ImageCheck::new();
        ok.update(b"ima");
        ok.update(b"ge");
        assert_eq!(ok.size(), 5);
        ok.finish(&expected).unwrap();

        let mut short = ImageCheck::new();
        short.update(b"imag");
        assert!(short.finish(&expected).unwrap_err().contains("4 B"));

        let mut wrong = ImageCheck::new();
        wrong.update(b"IMAGE");
        assert!(wrong.finish(&expected).unwrap_err().contains("hashes to"));
    }
}
