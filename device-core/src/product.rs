//! What a product build declares about itself.
//!
//! `platform-build` reads the product repository's `platform.toml` at build
//! time and generates one `const` of [`Product`] (`include!`d by the firmware),
//! so every value here is public and compiled in: no secret ever is. The
//! endpoint is only a default: NVS `platform/endpoint` overrides it.

use crate::ids::MacType;

/// Where the device's private key lives. Decides how it enrols and which
/// frozen NVS layout holds its identity ([`crate::nvs::IdentityLayout`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStorage {
    /// An ATECC608B, slot 0. The key never leaves the chip; esp-tls signs the
    /// TLS handshake there. Vaktus.
    SecureElement,
    /// A P-256 key generated on the device and kept in NVS. The gateway (the
    /// ESP32-S3 has no secure element on this board).
    NvsSoftKey,
}

impl KeyStorage {
    /// Parses the `platform.toml` spelling.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "atecc608" => Ok(Self::SecureElement),
            "nvs-soft-key" => Ok(Self::NvsSoftKey),
            other => Err(format!(
                "unknown key storage {other:?} (atecc608 or nvs-soft-key)"
            )),
        }
    }

    /// The `platform.toml` spelling, which is also the device-sdk feature.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecureElement => "atecc608",
            Self::NvsSoftKey => "nvs-soft-key",
        }
    }
}

/// Cost limits the SDK enforces before AWS bills anything (`PLATFORM.md` §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Publishes per rolling minute, every topic included.
    pub publishes_per_minute: u32,
    /// Largest payload published. AWS IoT bills messaging per 5 KB.
    pub max_message_bytes: usize,
}

impl Limits {
    /// The platform default: 10 publishes a minute, 5 KB each.
    pub const DEFAULT: Self = Self {
        publishes_per_minute: 10,
        max_message_bytes: 5 * 1024,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// A firmware-signing public key the device accepts manifests from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigningKey {
    /// Key id as job documents name it, e.g. `vaktus-a`.
    pub id: &'static str,
    /// SubjectPublicKeyInfo PEM of a P-256 key.
    pub pem: &'static str,
}

/// One product build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Product {
    /// Product id, e.g. `vaktus` ([`crate::ids::is_product_id`]).
    pub id: &'static str,
    /// This build's version, `X.Y.Z` (from `FW_VERSION`, else the crate's).
    pub fw_version: &'static str,
    /// Default AWS IoT data endpoint (public).
    pub endpoint: &'static str,
    /// Fleet provisioning template the device enrols with.
    pub template: &'static str,
    /// Which MAC names the device.
    pub mac_type: MacType,
    /// Where the device key lives.
    pub key_storage: KeyStorage,
    /// Publish limits.
    pub limits: Limits,
    /// Keys that may sign this product's firmware.
    pub signing_keys: &'static [SigningKey],
}

impl Product {
    /// `mqtts://<endpoint>:8883`.
    pub fn broker_uri(endpoint: &str) -> String {
        format!("mqtts://{endpoint}:8883")
    }

    /// The `key_id`s of [`Self::signing_keys`], for the `platform` shadow.
    pub fn key_ids(&self) -> Vec<&'static str> {
        self.signing_keys.iter().map(|k| k.id).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_storage_round_trips() {
        for k in [KeyStorage::SecureElement, KeyStorage::NvsSoftKey] {
            assert_eq!(KeyStorage::parse(k.as_str()).unwrap(), k);
        }
        assert!(KeyStorage::parse("tpm").is_err());
    }

    #[test]
    fn the_broker_is_mutual_tls_on_8883() {
        assert_eq!(
            Product::broker_uri("abc-ats.iot.eu-central-1.amazonaws.com"),
            "mqtts://abc-ats.iot.eu-central-1.amazonaws.com:8883"
        );
    }
}
