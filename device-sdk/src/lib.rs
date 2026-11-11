//! The ESP-IDF side of the platform's device contract.
//!
//! ```ignore
//! include!(concat!(env!("OUT_DIR"), "/platform.rs")); // platform-build
//!
//! fn main() -> anyhow::Result<()> {
//!     device_sdk::start_rollback_guard();
//!     let nvs = EspDefaultNvsPartition::take()?;
//!     let platform = device_sdk::Platform::init(&PLATFORM, nvs.clone())?;
//!     // ... bring up the network (platform.wifi() has bench-provisioned Wi-Fi)
//!     let identity = platform.identity()?;          // enrols if it has to
//!     let mut session = platform.connect(&identity, &Default::default())?;
//!     loop {
//!         match session.poll(Duration::from_millis(100)) {
//!             Some(Event::Connected) => { /* subscribe the product's topics */ }
//!             Some(Event::Message { topic, data }) => { /* the product's own */ }
//!             Some(Event::Restart) => device_sdk::restart_into_update(),
//!             _ => {}
//!         }
//!     }
//! }
//! ```
//!
//! What the SDK does for every product (`PLATFORM.md`):
//!
//! * **No secrets in images.** The endpoint and template are compiled in from
//!   `platform.toml`; the claim and Wi-Fi arrive over the serial console at
//!   the bench ([`device_core::console`]), and the claim is erased once the
//!   device has its own certificate.
//! * **Enrolment with a CSR**, key in an ATECC608B (`atecc608`) or in NVS
//!   (`nvs-soft-key`), refusals backed off from a minute to six hours.
//! * **A publish limiter** on every message, and reconnects paced by the same
//!   backoff.
//! * **OTA** through AWS IoT Jobs: signed manifests checked against the
//!   compiled-in keyring, only greater versions, the image hashed as it
//!   streams in, rollback unless the new image reaches AWS IoT.
//! * **The `platform` shadow**: version, slot, boot reason and count, the last
//!   job; and the telemetry switch.

use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use device_core::ids::{Mac, MacType};
use device_core::nvs::{Identity, PLATFORM_NS};
use device_core::product::Product;
use esp_idf_svc::nvs::EspDefaultNvsPartition;

pub use device_core as core;
pub use iot_jobs as jobs_protocol;

#[cfg(feature = "atecc608")]
pub mod atecc;
mod boot;
mod console;
mod job_store;
mod jobs;
mod key;
mod kv;
pub mod mqtt;
mod ota;
mod provision;
mod session;
#[cfg(feature = "nvs-soft-key")]
mod soft_key;

pub use boot::{
    boot_reason, clock_is_set, restart, running_slot, running_unverified, start_rollback_guard,
    uptime_s, RESTART_GRACE, VERIFY_DEADLINE,
};
pub use key::DeviceKey;
pub use kv::NvsKv;
pub use mqtt::Mqtt;
pub use session::{ConnectOptions, Event, Session};

/// Amazon Root CA 1: AWS IoT's ATS endpoints chain to it.
pub const ROOT_CA: &str = concat!(include_str!("../certs/AmazonRootCA1.pem"), "\0");

static STATUS: Mutex<String> = Mutex::new(String::new());
static KEY_SERIAL: Mutex<Option<String>> = Mutex::new(None);

/// One line on the cloud link's state, for a product's UI.
pub fn status() -> String {
    let s = STATUS.lock().map(|s| s.clone()).unwrap_or_default();
    if s.is_empty() {
        "-".into()
    } else {
        s
    }
}

pub(crate) fn set_status(s: impl Into<String>) {
    let s = s.into();
    log::info!("platform: {s}");
    if let Ok(mut status) = STATUS.lock() {
        *status = s;
    }
}

pub(crate) fn remember_key(key: &DeviceKey) {
    if let (Some(serial), Ok(mut slot)) = (key.secure_element_serial(), KEY_SERIAL.lock()) {
        *slot = Some(serial.to_string());
    }
}

/// The ATECC608B serial number, once the key has been read.
pub fn secure_element_serial() -> Option<String> {
    KEY_SERIAL.lock().ok().and_then(|s| s.clone())
}

/// Waits [`RESTART_GRACE`] for the last Jobs status to leave, then restarts
/// into the update just installed.
pub fn restart_into_update() -> ! {
    std::thread::sleep(RESTART_GRACE);
    restart()
}

/// The device's MAC of `mac_type`.
pub fn read_mac(mac_type: MacType) -> Mac {
    let mut mac = [0u8; 6];
    let ty = match mac_type {
        MacType::WifiSta => esp_idf_svc::sys::esp_mac_type_t_ESP_MAC_WIFI_STA,
        MacType::Eth => esp_idf_svc::sys::esp_mac_type_t_ESP_MAC_ETH,
    };
    // SAFETY: a 6-byte buffer, as esp_read_mac requires.
    unsafe { esp_idf_svc::sys::esp_read_mac(mac.as_mut_ptr(), ty) };
    Mac(mac)
}

/// What this boot is.
#[derive(Debug, Clone)]
pub struct BootInfo {
    /// Why the chip reset ([`device_core::shadow::boot_reason_name`]).
    pub reason: &'static str,
    /// Boots of this firmware version, this one included.
    pub count: u32,
    /// Running OTA slot.
    pub slot: String,
}

/// The platform side of a product firmware.
#[derive(Clone)]
pub struct Platform {
    pub(crate) product: &'static Product,
    pub(crate) nvs: EspDefaultNvsPartition,
    pub(crate) mac: Mac,
    pub(crate) boot: BootInfo,
}

impl Platform {
    /// Call early at boot, before the network: counts the boot, sets up the
    /// publish limiter, makes sure a soft-key device has its key (generated
    /// while the radio is still off, for the RNG's sake), and starts the
    /// serial console.
    pub fn init(product: &'static Product, nvs: EspDefaultNvsPartition) -> Result<Self> {
        if product.key_storage != key::STORAGE {
            bail!(
                "platform.toml says key_storage {} but device-sdk was built with {}",
                product.key_storage.as_str(),
                key::STORAGE.as_str()
            );
        }
        mqtt::init_limiter(product.limits);
        let mut platform_ns = NvsKv::open(&nvs, PLATFORM_NS)?;
        let count = device_core::nvs::count_boot(&mut platform_ns, product.fw_version)
            .unwrap_or_else(|e| {
                log::warn!("could not count this boot: {e}");
                1
            });
        let p = Self {
            product,
            mac: read_mac(product.mac_type),
            boot: BootInfo {
                reason: boot::boot_reason(),
                count,
                slot: boot::running_slot(),
            },
            nvs,
        };
        log::info!(
            "platform: {} {} on {} (thing {}), boot {} of this version ({})",
            product.id,
            product.fw_version,
            p.boot.slot,
            p.mac.thing_name(),
            p.boot.count,
            p.boot.reason
        );
        #[cfg(feature = "nvs-soft-key")]
        if !p.enrolled() {
            // Announce right away: a blank board on the bench is waiting for
            // `ergo commission`, which needs this line.
            console::announce(&p, None, true);
        }
        console::start(p.clone());
        Ok(p)
    }

    pub fn product(&self) -> &'static Product {
        self.product
    }

    pub fn mac(&self) -> Mac {
        self.mac
    }

    pub fn boot(&self) -> &BootInfo {
        &self.boot
    }

    /// True if an identity is stored.
    pub fn enrolled(&self) -> bool {
        let layout = device_core::nvs::IdentityLayout::for_storage(self.product.key_storage);
        NvsKv::open(&self.nvs, layout.namespace())
            .ok()
            .and_then(|ns| device_core::nvs::load_identity(layout, &ns).ok().flatten())
            .is_some()
    }

    /// Wi-Fi written at the bench, if any: `(ssid, psk)`.
    pub fn wifi(&self) -> Option<(String, String)> {
        let ns = NvsKv::open(&self.nvs, PLATFORM_NS).ok()?;
        device_core::nvs::load_wifi(&ns).ok().flatten()
    }

    /// Stores Wi-Fi in NVS `platform` unless some is stored already. For a
    /// transitional build that carries its Wi-Fi compiled in from before the
    /// SDK: the next build no longer does, and reads it from here. Returns
    /// whether it stored anything.
    pub fn seed_wifi(&self, ssid: &str, psk: &str) -> Result<bool> {
        use device_core::console::Key;
        use device_core::nvs::Kv;
        if ssid.is_empty() || self.wifi().is_some() {
            return Ok(false);
        }
        Key::WifiSsid.validate(ssid).map_err(anyhow::Error::msg)?;
        Key::WifiPsk.validate(psk).map_err(anyhow::Error::msg)?;
        let mut ns = NvsKv::open(&self.nvs, PLATFORM_NS)?;
        // The PSK first: the SSID is what makes the pair count.
        ns.set_str(Key::WifiPsk.nvs_key(), psk)
            .map_err(anyhow::Error::msg)?;
        ns.set_str(Key::WifiSsid.nvs_key(), ssid)
            .map_err(anyhow::Error::msg)?;
        log::info!("platform: stored the compiled-in Wi-Fi in NVS");
        Ok(true)
    }

    /// The device's identity: the stored one, or a new one from enrolment.
    /// Blocks until the device has one (waiting for the bench if it has no
    /// claim). Needs the network and, for TLS, a set clock.
    pub fn identity(&self) -> Result<Identity> {
        provision::ensure_identity(self).context("enrolment")
    }

    /// Connects as `identity` and marks the running image valid. Retries until
    /// the first CONNACK, with the platform's backoff.
    pub fn connect(&self, identity: &Identity, opts: &ConnectOptions) -> Result<Session> {
        Session::connect(self, identity, opts)
    }
}
