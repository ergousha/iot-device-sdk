//! What the running image knows about itself, and the rollback guard.
//!
//! A freshly installed image is kept only once it has reached AWS IoT with
//! its identity ([`mark_valid`], called by the session on CONNACK). Until
//! then the bootloader rolls it back on the next reset, and
//! [`start_rollback_guard`] makes sure that reset happens if the image never
//! gets there, whatever the rest of the firmware is doing.

use std::ffi::CStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use esp_idf_svc::ota::EspOta;
use esp_idf_svc::sys::{
    esp_ota_get_last_invalid_partition, esp_ota_get_running_partition, esp_ota_get_state_partition,
    esp_ota_img_states_t, esp_ota_img_states_t_ESP_OTA_IMG_NEW,
    esp_ota_img_states_t_ESP_OTA_IMG_PENDING_VERIFY, esp_partition_t, ESP_OK,
};
use iot_jobs::BootFacts;

/// How long a fresh OTA image has to reach AWS IoT before it is rolled back.
pub const VERIFY_DEADLINE: Duration = Duration::from_secs(10 * 60);

/// How long the status that precedes a restart into a new image gets to reach
/// the wire. Losing it is not fatal: the next boot settles the job from NVS.
pub const RESTART_GRACE: Duration = Duration::from_millis(1500);

static MARKED_VALID: AtomicBool = AtomicBool::new(false);

/// Marks the running image valid, so it is not rolled back.
pub(crate) fn mark_valid() -> Result<()> {
    let mut ota = EspOta::new()?;
    ota.mark_running_slot_valid()?;
    MARKED_VALID.store(true, Ordering::SeqCst);
    log::info!("firmware marked valid (no rollback)");
    Ok(())
}

/// What this boot can tell about its own image, for settling a pending OTA
/// job. `valid` is the result of [`mark_valid`]. Never fails: a slot that
/// cannot be read is reported as unknown.
pub(crate) fn boot_facts(fw_version: &str, valid: &Result<()>) -> BootFacts {
    BootFacts {
        running_version: fw_version.to_string(),
        running_slot: running_slot(),
        // Sound: a pointer into the static partition table, or null.
        invalid_slot: label(unsafe { esp_ota_get_last_invalid_partition() }),
        valid_error: valid.as_ref().err().map(|e| format!("{e:#}")),
    }
}

/// Label of the running slot, e.g. `ota_0`; empty if unknown.
pub fn running_slot() -> String {
    // Sound: a pointer into the static partition table, or null.
    label(unsafe { esp_ota_get_running_partition() }).unwrap_or_default()
}

/// True while the running image is a fresh OTA image that has not marked
/// itself valid: one the bootloader rolls back if the device resets now.
pub fn running_unverified() -> bool {
    let mut state: esp_ota_img_states_t = Default::default();
    // Sound: the running partition is never null in a booted app, and `state`
    // outlives the call. An image without an otadata record reports
    // ESP_ERR_NOT_FOUND, and is not unverified either.
    let err = unsafe { esp_ota_get_state_partition(esp_ota_get_running_partition(), &mut state) };
    err == ESP_OK
        && (state == esp_ota_img_states_t_ESP_OTA_IMG_PENDING_VERIFY
            || state == esp_ota_img_states_t_ESP_OTA_IMG_NEW)
}

/// Call first thing at boot: restarts an unverified OTA image that has not
/// reached AWS IoT within [`VERIFY_DEADLINE`], so the bootloader rolls it
/// back.
pub fn start_rollback_guard() {
    if !running_unverified() {
        return;
    }
    log::warn!(
        "running a new OTA image that is not verified yet; it is rolled back unless it reaches AWS IoT within {} s",
        VERIFY_DEADLINE.as_secs()
    );
    let spawned = std::thread::Builder::new()
        .name("rollback-guard".into())
        .stack_size(3 * 1024)
        .spawn(|| {
            std::thread::sleep(VERIFY_DEADLINE);
            if !MARKED_VALID.load(Ordering::SeqCst) {
                log::error!(
                    "the new image never reached AWS IoT; restarting so the bootloader rolls it back"
                );
                restart();
            }
        });
    if let Err(e) = spawned {
        log::error!("could not start the rollback guard: {e}");
    }
}

/// Restarts the chip. Does not return.
pub fn restart() -> ! {
    // SAFETY: always sound; esp_restart does not return.
    unsafe { esp_idf_svc::sys::esp_restart() }
}

/// Why the chip last reset, by the contract's names.
pub fn boot_reason() -> &'static str {
    // SAFETY: a plain getter.
    device_core::shadow::boot_reason_name(unsafe { esp_idf_svc::sys::esp_reset_reason() })
}

/// Seconds since boot.
pub fn uptime_s() -> u64 {
    // SAFETY: a plain getter.
    (unsafe { esp_idf_svc::sys::esp_timer_get_time() } / 1_000_000) as u64
}

/// Milliseconds since boot, for the limiter.
pub(crate) fn now_ms() -> u64 {
    // SAFETY: a plain getter.
    (unsafe { esp_idf_svc::sys::esp_timer_get_time() } / 1_000) as u64
}

/// True once SNTP (or anything else) has set the clock. TLS checks
/// certificate dates, so nothing connects before.
pub fn clock_is_set() -> bool {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() > 1_750_000_000)
        .unwrap_or(false)
}

/// Label of a partition from the partition table.
///
/// Read directly rather than through `EspOta::get_*_slot`, which also parses
/// the image's app descriptor into a 24-byte version string and fails outright
/// when the image in the slot has a longer one.
pub(crate) fn label(partition: *const esp_partition_t) -> Option<String> {
    // Sound: a non-null pointer from the OTA API points into the partition
    // table, which lives for the whole program, and ESP-IDF keeps `label`
    // NUL-terminated.
    let partition = unsafe { partition.as_ref() }?;
    let label = unsafe { CStr::from_ptr(partition.label.as_ptr()) };
    let label = label.to_string_lossy().into_owned();
    (!label.is_empty()).then_some(label)
}

/// A random number from the hardware RNG.
pub(crate) fn random_u32() -> u32 {
    // SAFETY: a plain getter.
    unsafe { esp_idf_svc::sys::esp_random() }
}
