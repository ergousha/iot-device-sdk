//! The ATECC608B, through Microchip CryptoAuthLib (`espressif/esp-cryptoauthlib`,
//! TrustCustom). Its I2C pins and address come from the product's sdkconfig
//! (Vaktus: SDA GPIO32, SCL GPIO25, 0xC0).
//!
//! Slot 0 holds the device's P-256 private key. It is generated inside the
//! chip on first boot and can never be read, written or regenerated: the
//! slot is locked right after. esp-tls signs the TLS handshake with it
//! (`use_secure_element`); this module only sets the chip up, reads the
//! public key, and signs the CSR digest during provisioning.
//!
//! Two CryptoAuthLib device contexts are in play:
//!
//! - This module's calls run on a private one (`atcab_init_ext`), released
//!   when each call is done.
//! - esp-tls uses the global one for the MQTT handshake: `esp_init_atecc608a`
//!   re-creates it on every secure-element connection (`atcab_init_ext`
//!   releases the previous one first), and the ECDSA sign callback keeps a
//!   raw pointer to it for the whole handshake. But esp-tls also calls
//!   `atcab_release()` at the end of *every* TLS session, prayer-time and OTA
//!   HTTPS included, on any task. One ending during an MQTT handshake would
//!   free the device that handshake is signing with, and dropping the I2C
//!   driver's last reference would delete it under a running transfer.
//!   [`__wrap_atcab_release`] makes that call a no-op (`-Wl,--wrap` in
//!   `.cargo/config.toml`), so the global device is only ever replaced by the
//!   next secure-element connection, on the esp-mqtt task that uses it.

use std::sync::Mutex;

use anyhow::{bail, Result};
use device_core::atecc::{self as secure_element, LockState};
use esp_idf_svc::sys::atca;

/// Replaces `atcab_release()` for every caller outside CryptoAuthLib's own
/// `atca_basic.c` (`-Wl,--wrap=atcab_release`), which in this firmware means
/// esp-tls's session cleanup. See the module documentation.
#[no_mangle]
pub extern "C" fn __wrap_atcab_release() -> atca::ATCA_STATUS {
    0 // ATCA_SUCCESS
}

const KEY_SLOT: u16 = 0;
const LOCK_ZONE_CONFIG: u8 = 0x00;
const LOCK_ZONE_DATA: u8 = 0x01;

/// One user of the chip at a time.
static CHIP: Mutex<()> = Mutex::new(());

/// What the chip says about itself.
#[derive(Debug, Clone)]
pub struct ChipIdentity {
    /// 9-byte serial number, hex.
    pub serial: String,
    /// Slot-0 public key, X||Y.
    pub public_key: [u8; 64],
}

fn hex(bytes: &[u8]) -> String {
    device_core::ids::hex(bytes)
}

/// Runs `f` on a fresh private device context.
fn with_chip<T>(f: impl FnOnce(atca::ATCADevice) -> Result<T>) -> Result<T> {
    let _guard = CHIP.lock().unwrap_or_else(|e| e.into_inner());
    let mut device: atca::ATCADevice = core::ptr::null_mut();
    // SAFETY: the default config is CryptoAuthLib's static, built from
    // sdkconfig; the device pointer is ours until atcab_release_ext.
    let st = unsafe {
        atca::atcab_init_ext(
            &mut device,
            core::ptr::addr_of_mut!(atca::cfg_ateccx08a_i2c_default),
        )
    };
    if st != 0 || device.is_null() {
        bail!("ATECC608B not reachable (atcab_init_ext 0x{st:02X}); is it on the I2C header?");
    }
    let result = f(device);
    unsafe { atca::atcab_release_ext(&mut device) };
    result
}

fn check(what: &str, st: atca::ATCA_STATUS) -> Result<()> {
    if st != 0 {
        bail!("ATECC608B {what} failed: 0x{st:02X}");
    }
    Ok(())
}

/// Makes sure the chip is set up and returns its identity. On a blank chip
/// this is the one-way step: lock the configuration zone as it came from the
/// factory (slot 0 is already a P-256 private key, external signing, written
/// only by GenKey), lock the data zone, generate the key in slot 0, and lock
/// slot 0 so the key can never be replaced. Each step checks the lock state
/// first, so a power cut between steps resumes where it stopped.
pub fn ensure_identity() -> Result<ChipIdentity> {
    with_chip(|dev| unsafe {
        let mut serial = [0u8; 9];
        check(
            "read serial",
            atca::calib_read_serial_number(dev, serial.as_mut_ptr()),
        )?;

        let mut config = [0u8; 128];
        check(
            "read config",
            atca::calib_read_config_zone(dev, config.as_mut_ptr()),
        )?;
        let slot0_config = u16::from_le_bytes([config[20], config[21]]);
        let slot0_key_config = u16::from_le_bytes([config[96], config[97]]);

        let mut locked = false;
        check(
            "lock state",
            atca::calib_is_locked(dev, LOCK_ZONE_CONFIG, &mut locked),
        )?;
        // SlotLocked (bytes 88-89): bit n clear = slot n locked.
        let slot0_locked = u16::from_le_bytes([config[88], config[89]]) & 1 == 0;
        // Before anything one-way: an unlocked chip must be exactly factory
        // fresh, a locked one must still be usable as the device key.
        let lock = LockState {
            config_locked: locked,
            slot0_locked,
        };
        if let Err(why) = secure_element::check_slot0(slot0_config, slot0_key_config, lock) {
            bail!("ATECC608B {why}");
        }
        if !locked {
            log::warn!("ATECC608B: locking the configuration zone (one-way)");
            check("lock config zone", atca::calib_lock_config_zone(dev))?;
        }
        check(
            "lock state",
            atca::calib_is_locked(dev, LOCK_ZONE_DATA, &mut locked),
        )?;
        if !locked {
            log::warn!("ATECC608B: locking the data zone (one-way)");
            check("lock data zone", atca::calib_lock_data_zone(dev))?;
        }

        // Re-read the lock bytes: the zone was read before the locks above.
        check(
            "read config",
            atca::calib_read_config_zone(dev, config.as_mut_ptr()),
        )?;
        let slot0_locked = u16::from_le_bytes([config[88], config[89]]) & 1 == 0;

        let mut public_key = [0u8; 64];
        if slot0_locked {
            check(
                "read public key",
                atca::calib_get_pubkey(dev, KEY_SLOT, public_key.as_mut_ptr()),
            )?;
        } else {
            log::warn!(
                "ATECC608B: generating the device key in slot 0 and locking the slot (one-way)"
            );
            check(
                "generate key",
                atca::calib_genkey(dev, KEY_SLOT, public_key.as_mut_ptr()),
            )?;
            check("lock slot 0", atca::calib_lock_data_slot(dev, KEY_SLOT))?;
        }

        Ok(ChipIdentity {
            serial: hex(&serial),
            public_key,
        })
    })
}

/// Signs a SHA-256 digest with the slot-0 key; returns r||s.
pub fn sign(digest: &[u8; 32]) -> Result<[u8; 64]> {
    with_chip(|dev| {
        let mut signature = [0u8; 64];
        // SAFETY: both buffers are the sizes the call expects.
        check("sign", unsafe {
            atca::calib_sign_ext(dev, KEY_SLOT, digest.as_ptr(), signature.as_mut_ptr())
        })?;
        Ok(signature)
    })
}
