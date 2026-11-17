//! Manifest signature verification with the pure-Rust `p256` crate: the
//! host backend (tests, platform-build's keyring check, tooling).

use super::{Rejected, P256_SPKI_PREFIX};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};

#[derive(Debug, Clone)]
pub(super) struct PublicKey(VerifyingKey);

impl PublicKey {
    /// `spki` is a P-256 SubjectPublicKeyInfo, already checked by
    /// [`super::spki_from_pem`] to have the uncompressed-point layout.
    pub(super) fn from_spki(spki: &[u8]) -> Result<Self, String> {
        // The SEC1 point starts at its 0x04 tag, the prefix's last byte.
        VerifyingKey::from_sec1_bytes(&spki[P256_SPKI_PREFIX.len() - 1..])
            .map(Self)
            .map_err(|_| "the point is not on the curve".to_string())
    }

    /// Verifies DER ECDSA `sig` over SHA-256 of `message`.
    pub(super) fn verify(&self, message: &[u8], sig: &[u8]) -> Result<(), Rejected> {
        let sig = Signature::from_der(sig).map_err(|_| Rejected::Malformed)?;
        self.0.verify(message, &sig).map_err(|_| Rejected::Mismatch)
    }
}
