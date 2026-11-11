//! A P-256 device key generated on the device and kept in NVS (`device_id/key`,
//! PKCS#8 PEM), for boards without a secure element.
//!
//! The key never leaves the device either: it is generated here, only its
//! public half is registered (`ergo commission` reads it off the console), and
//! AWS IoT issues the certificate for it from a CSR. What it does not have is
//! the ATECC608B's resistance to a flash dump; the quarantine group, the
//! publish limiter and the guard alarms bound what a copied key can cost.

use anyhow::{anyhow, bail, Result};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use p256::SecretKey;

/// Reads a P-256 key from PKCS#8 PEM. `None` for anything else, such as the
/// RSA key of a gateway enrolled with `CreateKeysAndCertificate`.
pub fn parse(pem: &str) -> Option<SigningKey> {
    SecretKey::from_pkcs8_pem(pem.trim())
        .ok()
        .map(|k| SigningKey::from(&k))
}

/// Generates a key. With `rf_quiet` (nothing has started Wi-Fi or Bluetooth
/// yet) the hardware RNG is first given the SAR ADC as an entropy source,
/// which ESP-IDF requires for true random numbers without the radio; with
/// the radio running it already has one.
pub fn generate(rf_quiet: bool) -> Result<(SigningKey, String)> {
    for _ in 0..8 {
        let mut secret = [0u8; 32];
        // SAFETY: plain FFI calls on a buffer of the stated size.
        unsafe {
            if rf_quiet {
                esp_idf_svc::sys::bootloader_random_enable();
            }
            esp_idf_svc::sys::esp_fill_random(secret.as_mut_ptr().cast(), secret.len());
            if rf_quiet {
                esp_idf_svc::sys::bootloader_random_disable();
            }
        }
        // A scalar of zero or ≥ n is refused; draw again (p ≈ 2^-32).
        if let Ok(key) = SecretKey::from_slice(&secret) {
            secret.fill(0);
            let pem = key
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| anyhow!("encoding the key: {e}"))?;
            return Ok((SigningKey::from(&key), pem.to_string()));
        }
    }
    bail!("the hardware RNG gave no usable P-256 scalar")
}

/// X||Y of the public key.
pub fn public_key(key: &SigningKey) -> [u8; 64] {
    let point = key.verifying_key().to_encoded_point(false);
    let mut out = [0u8; 64];
    out.copy_from_slice(&point.as_bytes()[1..65]);
    out
}

/// Signs a SHA-256 digest; returns r||s.
pub fn sign_digest(key: &SigningKey, digest: &[u8; 32]) -> Result<[u8; 64]> {
    let sig: Signature = key
        .sign_prehash(digest)
        .map_err(|e| anyhow!("signing: {e}"))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    Ok(out)
}
