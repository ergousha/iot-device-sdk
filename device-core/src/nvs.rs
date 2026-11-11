//! The frozen NVS layouts, and the identity records kept in them.
//!
//! Frozen means: devices in the field have data under these namespaces and
//! keys, written by earlier firmware, and every later image must read it. A
//! rename strands the device (it would enrol again, and the registry allows
//! that only at the bench). New data goes under new keys; old keys are never
//! repurposed.
//!
//! | Namespace | Keys | Written by |
//! |---|---|---|
//! | `cloud` | `thing`, `cert`, `pubkey` | secure-element products (Vaktus) |
//! | `device_id` | `cert`, `key`, `thing` | soft-key products (the gateway) |
//! | `ota_job` | `pending`, `attempts` (JSON blobs) | the Jobs client |
//! | `platform` | console keys ([`crate::console::Key`]), `boot_fw`, `boot_cnt`, `last_job` | the SDK |
//!
//! The logic is written against [`Kv`], one namespace of NVS, so it runs on
//! the host against [`MemKv`] or a dump of a real device's partition.

use std::collections::BTreeMap;

use crate::product::KeyStorage;
use crate::shadow::LastJob;

/// The namespace the SDK owns.
pub const PLATFORM_NS: &str = "platform";
/// The Jobs client's namespace.
pub const JOBS_NS: &str = "ota_job";

/// Keys of [`PLATFORM_NS`] besides the console's.
pub mod platform_keys {
    /// Version that booted last (string).
    pub const BOOT_FW: &str = "boot_fw";
    /// Boots of that version (u32).
    pub const BOOT_COUNT: &str = "boot_cnt";
    /// The last settled OTA job (JSON string).
    pub const LAST_JOB: &str = "last_job";
}

/// Keys of [`JOBS_NS`].
pub mod job_keys {
    pub const PENDING: &str = "pending";
    pub const ATTEMPTS: &str = "attempts";
}

/// One NVS namespace.
pub trait Kv {
    fn get_str(&self, key: &str) -> Result<Option<String>, String>;
    fn set_str(&mut self, key: &str, value: &str) -> Result<(), String>;
    fn get_u32(&self, key: &str) -> Result<Option<u32>, String>;
    fn set_u32(&mut self, key: &str, value: u32) -> Result<(), String>;
    fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>, String>;
    fn set_blob(&mut self, key: &str, value: &[u8]) -> Result<(), String>;
    /// Removes `key`; a missing key is not an error.
    fn remove(&mut self, key: &str) -> Result<(), String>;
}

/// A typed NVS value.
///
/// `U32`, `Str` and `Blob` are what the SDK writes and what [`Kv`] reads.
/// `Int` is any other ESP-IDF integer type: the SDK never writes one, but a
/// partition written by other firmware (or by ESP-IDF itself) can hold them,
/// and a dump read on the host (`nvs-image`) keeps them rather than dropping
/// them. [`Kv::get_u32`] on an `Int` is a type error, as `nvs_get_u32` on an
/// `nvs_set_u8` key is on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    U32(u32),
    Str(String),
    Blob(Vec<u8>),
    /// An integer of a type other than u32. `ty` is the ESP-IDF item type
    /// code ([`int_type`]); `value` is the number itself, which an `i128`
    /// holds exactly for every type up to u64 and i64.
    Int {
        ty: u8,
        value: i128,
    },
}

/// ESP-IDF's item type codes for the integers [`Value::Int`] carries (the
/// `ItemType` enum of `nvs_flash`; u32 is `0x04` and is [`Value::U32`]).
pub mod int_type {
    pub const U8: u8 = 0x01;
    pub const I8: u8 = 0x11;
    pub const U16: u8 = 0x02;
    pub const I16: u8 = 0x12;
    pub const I32: u8 = 0x14;
    pub const U64: u8 = 0x08;
    pub const I64: u8 = 0x18;
}

/// An in-memory namespace, for tests and for reading dumps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemKv(pub BTreeMap<String, Value>);

impl Kv for MemKv {
    fn get_str(&self, key: &str) -> Result<Option<String>, String> {
        match self.0.get(key) {
            None => Ok(None),
            Some(Value::Str(s)) => Ok(Some(s.clone())),
            Some(_) => Err(format!("{key} is not a string")),
        }
    }
    fn set_str(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.0.insert(key.into(), Value::Str(value.into()));
        Ok(())
    }
    fn get_u32(&self, key: &str) -> Result<Option<u32>, String> {
        match self.0.get(key) {
            None => Ok(None),
            Some(Value::U32(n)) => Ok(Some(*n)),
            Some(_) => Err(format!("{key} is not a u32")),
        }
    }
    fn set_u32(&mut self, key: &str, value: u32) -> Result<(), String> {
        self.0.insert(key.into(), Value::U32(value));
        Ok(())
    }
    fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        match self.0.get(key) {
            None => Ok(None),
            Some(Value::Blob(b)) => Ok(Some(b.clone())),
            Some(_) => Err(format!("{key} is not a blob")),
        }
    }
    fn set_blob(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        self.0.insert(key.into(), Value::Blob(value.to_vec()));
        Ok(())
    }
    fn remove(&mut self, key: &str) -> Result<(), String> {
        self.0.remove(key);
        Ok(())
    }
}

/// Where a product's identity lives; fixed by its [`KeyStorage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityLayout {
    /// `cloud`: `thing`, `cert`, `pubkey` (X||Y hex the cert was issued for).
    SecureElement,
    /// `device_id`: `cert`, `key` (PEM), `thing`.
    SoftKey,
}

impl IdentityLayout {
    pub fn for_storage(storage: KeyStorage) -> Self {
        match storage {
            KeyStorage::SecureElement => Self::SecureElement,
            KeyStorage::NvsSoftKey => Self::SoftKey,
        }
    }

    pub fn namespace(self) -> &'static str {
        match self {
            Self::SecureElement => "cloud",
            Self::SoftKey => "device_id",
        }
    }
}

const KEY_THING: &str = "thing";
const KEY_CERT: &str = "cert";
const KEY_PUBKEY: &str = "pubkey";
const KEY_PRIVATE: &str = "key";

/// A device's own AWS IoT identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub thing_name: String,
    pub certificate_pem: String,
    /// Secure element: the chip key (X||Y hex) the certificate was issued
    /// for. Empty in records from before it was stored.
    pub public_key: String,
    /// Soft key: the private key PEM (P-256 for SDK enrolments; RSA in
    /// gateways enrolled with `CreateKeysAndCertificate`).
    pub private_key_pem: String,
}

/// Loads the identity, if a complete one is stored. A record missing its
/// thing name or certificate is no identity: the device enrols again.
pub fn load_identity(layout: IdentityLayout, kv: &impl Kv) -> Result<Option<Identity>, String> {
    let Some(thing_name) = kv.get_str(KEY_THING)?.filter(|t| !t.is_empty()) else {
        return Ok(None);
    };
    let Some(certificate_pem) = kv
        .get_str(KEY_CERT)?
        .filter(|c| c.contains("BEGIN CERTIFICATE"))
    else {
        return Ok(None);
    };
    let mut identity = Identity {
        thing_name,
        certificate_pem,
        public_key: String::new(),
        private_key_pem: String::new(),
    };
    match layout {
        IdentityLayout::SecureElement => {
            identity.public_key = kv.get_str(KEY_PUBKEY)?.unwrap_or_default();
        }
        IdentityLayout::SoftKey => {
            let Some(key) = kv
                .get_str(KEY_PRIVATE)?
                .filter(|k| k.contains("PRIVATE KEY"))
            else {
                return Ok(None);
            };
            identity.private_key_pem = key;
        }
    }
    Ok(Some(identity))
}

/// Stores an identity. The thing name goes last: [`load_identity`] needs it,
/// so a power cut midway leaves no half identity.
pub fn save_identity(
    layout: IdentityLayout,
    kv: &mut impl Kv,
    id: &Identity,
) -> Result<(), String> {
    kv.set_str(KEY_CERT, &id.certificate_pem)?;
    match layout {
        IdentityLayout::SecureElement => kv.set_str(KEY_PUBKEY, &id.public_key)?,
        IdentityLayout::SoftKey => kv.set_str(KEY_PRIVATE, &id.private_key_pem)?,
    }
    kv.set_str(KEY_THING, &id.thing_name)
}

/// Removes the identity (re-enrolment at the bench). A soft key is kept with
/// it unless `keep_key` is false.
pub fn erase_identity(
    layout: IdentityLayout,
    kv: &mut impl Kv,
    keep_key: bool,
) -> Result<(), String> {
    kv.remove(KEY_THING)?;
    kv.remove(KEY_CERT)?;
    match layout {
        IdentityLayout::SecureElement => kv.remove(KEY_PUBKEY),
        IdentityLayout::SoftKey if keep_key => Ok(()),
        IdentityLayout::SoftKey => kv.remove(KEY_PRIVATE),
    }
}

/// A soft-key product's private key, enrolled or not.
pub fn load_soft_key(kv: &impl Kv) -> Result<Option<String>, String> {
    Ok(kv
        .get_str(KEY_PRIVATE)?
        .filter(|k| k.contains("PRIVATE KEY")))
}

/// Stores a newly generated soft key, before it is registered.
pub fn save_soft_key(kv: &mut impl Kv, pem: &str) -> Result<(), String> {
    kv.set_str(KEY_PRIVATE, pem)
}

/// The claim credential written at the bench, if both halves are there.
pub fn load_claim(platform: &impl Kv) -> Result<Option<(String, String)>, String> {
    use crate::console::Key;
    let cert = platform.get_str(Key::ClaimCert.nvs_key())?;
    let key = platform.get_str(Key::ClaimKey.nvs_key())?;
    Ok(cert.zip(key))
}

/// Erases the claim credential: it is only needed until the device has its
/// own certificate, and it must not sit in flash after that.
pub fn erase_claim(platform: &mut impl Kv) -> Result<(), String> {
    use crate::console::Key;
    platform.remove(Key::ClaimCert.nvs_key())?;
    platform.remove(Key::ClaimKey.nvs_key())
}

/// Erases everything the console can write (`PLATFORM ERASE`).
pub fn erase_console_keys(platform: &mut impl Kv) -> Result<(), String> {
    for key in crate::console::Key::ALL {
        platform.remove(key.nvs_key())?;
    }
    Ok(())
}

/// Wi-Fi written at the bench (or copied there by a transitional build).
pub fn load_wifi(platform: &impl Kv) -> Result<Option<(String, String)>, String> {
    use crate::console::Key;
    let Some(ssid) = platform
        .get_str(Key::WifiSsid.nvs_key())?
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let psk = platform
        .get_str(Key::WifiPsk.nvs_key())?
        .unwrap_or_default();
    Ok(Some((ssid, psk)))
}

/// The endpoint to use: NVS `platform/endpoint` if set, else the compiled-in
/// default. Devices deployed before the SDK have no `platform` namespace and
/// still connect.
pub fn endpoint(platform: &impl Kv, compiled: &str) -> String {
    use crate::console::Key;
    platform
        .get_str(Key::Endpoint.nvs_key())
        .ok()
        .flatten()
        .filter(|e| crate::console::Key::Endpoint.validate(e).is_ok())
        .unwrap_or_else(|| compiled.to_string())
}

/// Counts this boot: returns the boot count of the running version and stores
/// it ([`crate::shadow::next_boot_count`]). `fresh_install` (the image is
/// still pending verification, i.e. on its first boot after an OTA install)
/// starts the count over even for a version that booted before.
pub fn count_boot(
    platform: &mut impl Kv,
    running_fw: &str,
    fresh_install: bool,
) -> Result<u32, String> {
    let stored_fw = platform.get_str(platform_keys::BOOT_FW).ok().flatten();
    let stored = platform.get_u32(platform_keys::BOOT_COUNT).ok().flatten();
    let count = if fresh_install {
        1
    } else {
        crate::shadow::next_boot_count(stored_fw.as_deref(), stored, running_fw)
    };
    if stored_fw.as_deref() != Some(running_fw) {
        platform.set_str(platform_keys::BOOT_FW, running_fw)?;
    }
    platform.set_u32(platform_keys::BOOT_COUNT, count)?;
    Ok(count)
}

/// The last settled job, if recorded and readable.
pub fn load_last_job(platform: &impl Kv) -> Option<LastJob> {
    let raw = platform.get_str(platform_keys::LAST_JOB).ok().flatten()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_last_job(platform: &mut impl Kv, job: &LastJob) -> Result<(), String> {
    let raw = serde_json::to_string(job).map_err(|e| e.to_string())?;
    platform.set_str(platform_keys::LAST_JOB, &raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const KEY: &str = "-----BEGIN EC PRIVATE KEY-----\nMHc\n-----END EC PRIVATE KEY-----\n";

    fn identity() -> Identity {
        Identity {
            thing_name: "28848553144F".into(),
            certificate_pem: CERT.into(),
            public_key: String::new(),
            private_key_pem: KEY.into(),
        }
    }

    #[test]
    fn the_layouts_are_the_ones_in_the_field() {
        assert_eq!(IdentityLayout::SecureElement.namespace(), "cloud");
        assert_eq!(IdentityLayout::SoftKey.namespace(), "device_id");
        assert_eq!(
            IdentityLayout::for_storage(KeyStorage::NvsSoftKey),
            IdentityLayout::SoftKey
        );
    }

    #[test]
    fn identities_round_trip_per_layout() {
        let mut kv = MemKv::default();
        save_identity(IdentityLayout::SoftKey, &mut kv, &identity()).unwrap();
        assert_eq!(
            load_identity(IdentityLayout::SoftKey, &kv).unwrap(),
            Some(identity())
        );
        assert_eq!(
            kv.0.keys().collect::<Vec<_>>(),
            ["cert", "key", "thing"],
            "the gateway's frozen keys"
        );

        let mut kv = MemKv::default();
        let se = Identity {
            public_key: "AB".repeat(64),
            private_key_pem: String::new(),
            ..identity()
        };
        save_identity(IdentityLayout::SecureElement, &mut kv, &se).unwrap();
        assert_eq!(kv.0.keys().collect::<Vec<_>>(), ["cert", "pubkey", "thing"]);
        assert_eq!(
            load_identity(IdentityLayout::SecureElement, &kv).unwrap(),
            Some(se)
        );
    }

    #[test]
    fn half_records_are_no_identity() {
        let mut kv = MemKv::default();
        kv.set_str("cert", CERT).unwrap();
        kv.set_str("key", KEY).unwrap();
        assert_eq!(load_identity(IdentityLayout::SoftKey, &kv).unwrap(), None);
        kv.set_str("thing", "28848553144F").unwrap();
        kv.set_str("key", "garbage").unwrap();
        assert_eq!(load_identity(IdentityLayout::SoftKey, &kv).unwrap(), None);
        // A secure-element record from before the key was stored still loads,
        // with no key: the firmware then enrols again.
        let mut kv = MemKv::default();
        kv.set_str("cert", CERT).unwrap();
        kv.set_str("thing", "38182B8456F4").unwrap();
        let id = load_identity(IdentityLayout::SecureElement, &kv)
            .unwrap()
            .unwrap();
        assert!(id.public_key.is_empty());
    }

    #[test]
    fn erasing_an_identity_can_keep_the_soft_key() {
        let mut kv = MemKv::default();
        save_identity(IdentityLayout::SoftKey, &mut kv, &identity()).unwrap();
        erase_identity(IdentityLayout::SoftKey, &mut kv, true).unwrap();
        assert_eq!(load_identity(IdentityLayout::SoftKey, &kv).unwrap(), None);
        assert_eq!(load_soft_key(&kv).unwrap().as_deref(), Some(KEY));
        erase_identity(IdentityLayout::SoftKey, &mut kv, false).unwrap();
        assert!(kv.0.is_empty());
    }

    #[test]
    fn the_claim_is_erased_with_nothing_else() {
        let mut kv = MemKv::default();
        kv.set_str("claim_cert", CERT).unwrap();
        assert_eq!(load_claim(&kv).unwrap(), None, "both halves needed");
        kv.set_str("claim_key", KEY).unwrap();
        kv.set_str("wifi_ssid", "home").unwrap();
        assert!(load_claim(&kv).unwrap().is_some());
        erase_claim(&mut kv).unwrap();
        assert_eq!(load_claim(&kv).unwrap(), None);
        assert_eq!(
            load_wifi(&kv).unwrap(),
            Some(("home".into(), String::new()))
        );
        erase_console_keys(&mut kv).unwrap();
        assert!(kv.0.is_empty());
    }

    #[test]
    fn the_endpoint_override_must_be_an_aws_endpoint() {
        let mut kv = MemKv::default();
        assert_eq!(
            endpoint(&kv, "compiled.amazonaws.com"),
            "compiled.amazonaws.com"
        );
        kv.set_str("endpoint", "x-ats.iot.eu-west-1.amazonaws.com")
            .unwrap();
        assert_eq!(
            endpoint(&kv, "compiled"),
            "x-ats.iot.eu-west-1.amazonaws.com"
        );
        kv.set_str("endpoint", "evil.example.com").unwrap();
        assert_eq!(endpoint(&kv, "compiled"), "compiled");
    }

    #[test]
    fn boots_are_counted_per_version() {
        let mut kv = MemKv::default();
        assert_eq!(count_boot(&mut kv, "0.8.0", false).unwrap(), 1);
        assert_eq!(count_boot(&mut kv, "0.8.0", false).unwrap(), 2);
        assert_eq!(count_boot(&mut kv, "0.9.0", false).unwrap(), 1);
        assert_eq!(count_boot(&mut kv, "0.9.0", false).unwrap(), 2);
        // Rolled back, then the same version installed again.
        assert_eq!(count_boot(&mut kv, "0.9.0", true).unwrap(), 1);
        assert_eq!(count_boot(&mut kv, "0.9.0", false).unwrap(), 2);
        assert_eq!(kv.get_str("boot_fw").unwrap().as_deref(), Some("0.9.0"));
    }

    #[test]
    fn other_integer_types_are_not_u32() {
        let mut kv = MemKv::default();
        kv.0.insert(
            "boot_cnt".into(),
            Value::Int {
                ty: int_type::U8,
                value: 3,
            },
        );
        assert!(kv.get_u32("boot_cnt").is_err());
        assert!(kv.get_str("boot_cnt").is_err());
    }

    #[test]
    fn the_last_job_round_trips() {
        let mut kv = MemKv::default();
        assert_eq!(load_last_job(&kv), None);
        let job = LastJob {
            id: "ota-vaktus-0_9_0-c".into(),
            status: "FAILED".into(),
            reason: "rollback".into(),
        };
        save_last_job(&mut kv, &job).unwrap();
        assert_eq!(load_last_job(&kv), Some(job));
        kv.set_str("last_job", "{").unwrap();
        assert_eq!(load_last_job(&kv), None);
    }
}
