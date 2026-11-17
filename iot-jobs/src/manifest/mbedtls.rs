//! Manifest signature verification with the mbedTLS that ESP-IDF links for
//! TLS already: the device backend. It keeps the pure-Rust P-256 stack
//! (`p256`, `ecdsa`, `elliptic-curve`, ...) out of the firmware image.
//!
//! The host tests cannot run this file; the bench checks it (iot-device-sdk
//! issue #4): a signed manifest verifies, a tampered one and an unknown key
//! id do not.

use super::Rejected;
use esp_idf_sys as sys;
use sha2::{Digest, Sha256};
use std::mem::MaybeUninit;

/// The key's SubjectPublicKeyInfo, parsed into an mbedTLS context per use:
/// a device verifies a manifest once per job, and plain bytes keep the
/// keyring `Clone`, `Send` and `Sync`.
#[derive(Debug, Clone)]
pub(super) struct PublicKey(Vec<u8>);

impl PublicKey {
    /// `spki` is a P-256 SubjectPublicKeyInfo, already checked by
    /// [`super::spki_from_pem`] to have the uncompressed-point layout.
    /// mbedTLS checks that the point is on the curve.
    pub(super) fn from_spki(spki: &[u8]) -> Result<Self, String> {
        Pk::parse(spki).map_err(|rc| format!("mbedTLS -0x{:04X}", rc.unsigned_abs()))?;
        Ok(Self(spki.to_vec()))
    }

    /// Verifies DER ECDSA `sig` over SHA-256 of `message`.
    pub(super) fn verify(&self, message: &[u8], sig: &[u8]) -> Result<(), Rejected> {
        let mut pk = Pk::parse(&self.0).map_err(|_| Rejected::Mismatch)?;
        let hash: [u8; 32] = Sha256::digest(message).into();
        // SAFETY: `pk` holds a parsed key; the buffers outlive the call.
        let rc = unsafe {
            sys::mbedtls_pk_verify(
                &mut pk.0,
                sys::mbedtls_md_type_t_MBEDTLS_MD_SHA256,
                hash.as_ptr(),
                hash.len(),
                sig.as_ptr(),
                sig.len(),
            )
        };
        match rc {
            0 => Ok(()),
            sys::MBEDTLS_ERR_ECP_VERIFY_FAILED => Err(Rejected::Mismatch),
            // ASN.1 errors, and a valid signature followed by extra bytes
            // (MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH).
            _ => Err(Rejected::Malformed),
        }
    }
}

/// An initialised `mbedtls_pk_context`, freed on drop.
struct Pk(sys::mbedtls_pk_context);

impl Pk {
    fn parse(der: &[u8]) -> Result<Self, i32> {
        let mut ctx = MaybeUninit::<sys::mbedtls_pk_context>::uninit();
        // SAFETY: mbedtls_pk_init fully initialises the context, after which
        // it may be moved (it holds only heap pointers) and must be freed,
        // which Drop does.
        let mut pk = unsafe {
            sys::mbedtls_pk_init(ctx.as_mut_ptr());
            Pk(ctx.assume_init())
        };
        // SAFETY: `der` outlives the call; DER input needs no terminator.
        let rc = unsafe { sys::mbedtls_pk_parse_public_key(&mut pk.0, der.as_ptr(), der.len()) };
        if rc != 0 {
            return Err(rc);
        }
        // SAFETY: a parsed context.
        if unsafe { sys::mbedtls_pk_get_type(&pk.0) } != sys::mbedtls_pk_type_t_MBEDTLS_PK_ECKEY {
            return Err(sys::MBEDTLS_ERR_PK_TYPE_MISMATCH);
        }
        Ok(pk)
    }
}

impl Drop for Pk {
    fn drop(&mut self) {
        // SAFETY: initialised in `parse`, freed once.
        unsafe { sys::mbedtls_pk_free(&mut self.0) }
    }
}
