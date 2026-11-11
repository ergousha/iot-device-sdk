//! The device key, wherever the product keeps it.

use anyhow::Result;
use device_core::nvs::Identity;

use crate::mqtt::Auth;

#[cfg(all(feature = "atecc608", feature = "nvs-soft-key"))]
compile_error!("device-sdk: enable exactly one of the features atecc608 and nvs-soft-key");
#[cfg(not(any(feature = "atecc608", feature = "nvs-soft-key")))]
compile_error!(
    "device-sdk: enable one of the features atecc608 and nvs-soft-key (platform.toml key_storage)"
);

/// The key storage this build was compiled for.
pub const STORAGE: device_core::product::KeyStorage = if cfg!(feature = "atecc608") {
    device_core::product::KeyStorage::SecureElement
} else {
    device_core::product::KeyStorage::NvsSoftKey
};

/// The device's P-256 key: its public half, and a way to sign with it.
pub struct DeviceKey {
    public_key: [u8; 64],
    #[cfg(feature = "atecc608")]
    serial: String,
    #[cfg(feature = "nvs-soft-key")]
    key: p256::ecdsa::SigningKey,
    #[cfg(feature = "nvs-soft-key")]
    pem: String,
}

impl DeviceKey {
    /// The chip's key. On a blank ATECC608B this is the one-way step: the
    /// zones are locked and the key generated in slot 0
    /// ([`crate::atecc::ensure_identity`]).
    #[cfg(feature = "atecc608")]
    pub fn load(_nvs: &esp_idf_svc::nvs::EspDefaultNvsPartition, _rf_quiet: bool) -> Result<Self> {
        let chip = crate::atecc::ensure_identity()?;
        Ok(Self {
            public_key: chip.public_key,
            serial: chip.serial,
        })
    }

    /// The soft key from NVS, generated and stored first if there is no P-256
    /// key there. Call only for a device that is not enrolled: an enrolled
    /// gateway from before the SDK keeps an RSA key in the same place.
    #[cfg(feature = "nvs-soft-key")]
    pub fn load(nvs: &esp_idf_svc::nvs::EspDefaultNvsPartition, rf_quiet: bool) -> Result<Self> {
        use anyhow::anyhow;
        use device_core::nvs::{load_soft_key, save_soft_key, IdentityLayout};

        let mut ns = crate::kv::NvsKv::open(nvs, IdentityLayout::SoftKey.namespace())?;
        if let Some(pem) = load_soft_key(&ns).map_err(|e| anyhow!(e))? {
            if let Some(key) = crate::soft_key::parse(&pem) {
                return Ok(Self::soft(key, pem));
            }
            log::warn!("device key: the stored key is not P-256; generating a new one");
        }
        let (key, pem) = crate::soft_key::generate(rf_quiet)?;
        save_soft_key(&mut ns, &pem).map_err(|e| anyhow!(e))?;
        log::info!("device key: generated a P-256 key");
        Ok(Self::soft(key, pem))
    }

    /// The soft key already stored, if it is P-256; never generates one.
    #[cfg(feature = "nvs-soft-key")]
    pub fn existing(nvs: &esp_idf_svc::nvs::EspDefaultNvsPartition) -> Option<Self> {
        let ns = crate::kv::NvsKv::open(nvs, device_core::nvs::IdentityLayout::SoftKey.namespace())
            .ok()?;
        let pem = device_core::nvs::load_soft_key(&ns).ok()??;
        crate::soft_key::parse(&pem).map(|k| Self::soft(k, pem))
    }

    /// The chip's key (reading it is harmless once the chip is set up).
    #[cfg(feature = "atecc608")]
    pub fn existing(nvs: &esp_idf_svc::nvs::EspDefaultNvsPartition) -> Option<Self> {
        Self::load(nvs, false).ok()
    }

    #[cfg(feature = "nvs-soft-key")]
    fn soft(key: p256::ecdsa::SigningKey, pem: String) -> Self {
        Self {
            public_key: crate::soft_key::public_key(&key),
            key,
            pem,
        }
    }

    /// X||Y.
    pub fn public_key(&self) -> &[u8; 64] {
        &self.public_key
    }

    /// X||Y as the registry takes it: 128 uppercase hex digits.
    pub fn public_key_hex(&self) -> String {
        device_core::ids::hex(&self.public_key)
    }

    /// The ATECC608B serial number, for the shadow.
    pub fn secure_element_serial(&self) -> Option<&str> {
        #[cfg(feature = "atecc608")]
        return Some(&self.serial);
        #[cfg(not(feature = "atecc608"))]
        None
    }

    /// Signs a SHA-256 digest; returns r||s.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
        #[cfg(feature = "atecc608")]
        return crate::atecc::sign(digest);
        #[cfg(feature = "nvs-soft-key")]
        crate::soft_key::sign_digest(&self.key, digest)
    }

    /// The identity record for a certificate issued for this key.
    pub fn identity(&self, thing_name: String, certificate_pem: String) -> Identity {
        Identity {
            thing_name,
            certificate_pem,
            #[cfg(feature = "atecc608")]
            public_key: self.public_key_hex(),
            #[cfg(not(feature = "atecc608"))]
            public_key: String::new(),
            #[cfg(feature = "nvs-soft-key")]
            private_key_pem: self.pem.clone(),
            #[cfg(not(feature = "nvs-soft-key"))]
            private_key_pem: String::new(),
        }
    }

    /// Whether a stored identity belongs to this key. A secure-element
    /// record names the chip key it was issued for: a swapped module enrols
    /// again instead of failing every handshake. A soft-key record carries its
    /// own key.
    pub fn owns(&self, identity: &Identity) -> bool {
        #[cfg(feature = "atecc608")]
        return identity.public_key == self.public_key_hex();
        #[cfg(feature = "nvs-soft-key")]
        {
            let _ = identity;
            true
        }
    }
}

/// How a stored identity authenticates its TLS connection.
pub fn auth(identity: &Identity) -> Auth<'_> {
    #[cfg(feature = "atecc608")]
    return Auth::SecureElement {
        cert: &identity.certificate_pem,
    };
    #[cfg(feature = "nvs-soft-key")]
    Auth::Pem {
        cert: &identity.certificate_pem,
        key: &identity.private_key_pem,
    }
}
