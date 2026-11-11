//! Writes an OTA image into the inactive slot, checking it against its signed
//! manifest as it streams in.
//!
//! The download resumes where it stopped (HTTP Range) on a dropped
//! connection; every byte is fed to the manifest check in order, so a resumed
//! image is hashed exactly as a straight one. Nothing is activated unless the
//! sha256 and size match the manifest (when the job was signed) and ESP-IDF's
//! own image check passes.

use std::ptr;

use anyhow::Context;
use embedded_svc::http::Headers;
use esp_idf_svc::http::client::{Configuration as HttpConfiguration, EspHttpConnection};
use esp_idf_svc::sys::{
    esp, esp_ota_abort, esp_ota_begin, esp_ota_end, esp_ota_get_next_update_partition,
    esp_ota_handle_t, esp_ota_set_boot_partition, esp_ota_write, OTA_WITH_SEQUENTIAL_WRITES,
};
use iot_jobs::{Expected, ImageCheck, InstallError};
use log::{error, info};

/// Download attempts per update before it is given up. A failed read resumes
/// where it stopped, so these cost only what was lost. The usual cause is
/// transient: with CONFIG_MBEDTLS_DYNAMIC_BUFFER every incoming TLS record
/// needs a fresh ~16.7 KB block, and on a busy heap one is occasionally not
/// there.
const MAX_DOWNLOAD_TRIES: u32 = 5;

/// Downloads `url` into the next OTA slot, checks it, calls `before_activate`
/// with the slot's label and, if that succeeds, makes the slot the boot slot.
/// Returns the label.
pub fn perform_ota(
    url: &str,
    expected: Option<&Expected>,
    before_activate: impl FnOnce(&str) -> Result<(), String>,
) -> Result<String, InstallError> {
    let download = |e: anyhow::Error| InstallError::Download(format!("{e:#}"));
    info!(
        "OTA: starting (free heap {} B, largest block {} B, {})",
        unsafe { esp_idf_svc::sys::esp_get_free_heap_size() },
        largest_free_block(),
        if expected.is_some() {
            "signed manifest"
        } else {
            "unsigned job"
        }
    );

    // Raw esp_ota_* rather than EspOta: EspOta::initiate_update passes
    // OTA_SIZE_UNKNOWN, which erases the whole slot up front. Flash erases
    // stall both cores, freezing the UI for seconds. OTA_WITH_SEQUENTIAL_WRITES
    // erases each sector just before it is written instead.
    // SAFETY: the partition pointer comes from the static partition table.
    let partition = unsafe { esp_ota_get_next_update_partition(ptr::null()) };
    let slot = crate::boot::label(partition)
        .ok_or_else(|| InstallError::Download("no OTA partition to update".into()))?;
    let mut handle: esp_ota_handle_t = 0;
    esp!(unsafe { esp_ota_begin(partition, OTA_WITH_SEQUENTIAL_WRITES as usize, &mut handle) })
        .context("starting the OTA write")
        .map_err(download)?;
    // Frees the handle on any early return; disarmed once esp_ota_end ran.
    let mut guard = AbortOnDrop(Some(handle));

    info!("OTA: writing to {slot}");
    let mut dl = Download {
        url,
        handle,
        written: 0,
        total: None,
        limit: expected.map(|e| e.size),
        check: ImageCheck::new(),
    };
    let mut tries = 1;
    loop {
        match dl.resume() {
            Ok(()) => break,
            Err(Failed::Verify(e)) => return Err(InstallError::Verify(e)),
            Err(Failed::Network(e)) if tries < MAX_DOWNLOAD_TRIES => {
                log::warn!(
                    "OTA: download interrupted at {} bytes ({e:#}); resuming, try {} of {MAX_DOWNLOAD_TRIES} \
                     (largest free block {} B)",
                    dl.written,
                    tries + 1,
                    largest_free_block()
                );
                std::thread::sleep(std::time::Duration::from_secs(2 * u64::from(tries)));
                tries += 1;
            }
            Err(Failed::Network(e)) => {
                return Err(download(e.context(format!(
                    "OTA download failed {MAX_DOWNLOAD_TRIES} times"
                ))))
            }
        }
    }
    info!("OTA: downloaded {} bytes", dl.written);

    if let Some(expected) = expected {
        dl.check.finish(expected).map_err(InstallError::Verify)?;
        info!("OTA: the image matches its signed manifest");
    }
    guard.0 = None;
    esp!(unsafe { esp_ota_end(handle) })
        .context("ESP-IDF's image check")
        .map_err(|e| InstallError::Verify(format!("{e:#}")))?;
    before_activate(&slot).map_err(InstallError::Activate)?;
    esp!(unsafe { esp_ota_set_boot_partition(partition) })
        .context("activating the new image")
        .map_err(download)?;
    info!("OTA: {slot} is the boot slot; ready to restart");
    Ok(slot)
}

enum Failed {
    /// Worth resuming.
    Network(anyhow::Error),
    /// The image is not the one the manifest names; stop.
    Verify(String),
}

impl From<anyhow::Error> for Failed {
    fn from(e: anyhow::Error) -> Self {
        Failed::Network(e)
    }
}

impl From<esp_idf_svc::sys::EspError> for Failed {
    fn from(e: esp_idf_svc::sys::EspError) -> Self {
        Failed::Network(e.into())
    }
}

impl From<esp_idf_svc::io::EspIOError> for Failed {
    fn from(e: esp_idf_svc::io::EspIOError) -> Self {
        Failed::Network(e.into())
    }
}

/// An image download in progress, resumable from `written`.
struct Download<'a> {
    url: &'a str,
    handle: esp_ota_handle_t,
    /// Bytes written to the slot so far.
    written: usize,
    /// Image size, from the first response's Content-Length.
    total: Option<usize>,
    /// The manifest's size: never write more.
    limit: Option<u64>,
    check: ImageCheck,
}

impl Download<'_> {
    /// Fetches the rest of the image (from `written` on) and writes it.
    fn resume(&mut self) -> Result<(), Failed> {
        let http_config = HttpConfiguration {
            crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
            // The request line may carry a presigned URL (~1.5 KB).
            buffer_size_tx: Some(4096),
            buffer_size: Some(4096),
            ..Default::default()
        };
        let mut connection = EspHttpConnection::new(&http_config)?;
        let range = format!("bytes={}-", self.written);
        let mut headers = vec![("Accept", "application/octet-stream")];
        if self.written > 0 {
            headers.push(("Range", range.as_str()));
        }
        connection.initiate_request(esp_idf_svc::http::Method::Get, self.url, &headers)?;
        connection.initiate_response()?;

        let status = connection.status();
        let expected = if self.written == 0 { 200 } else { 206 };
        if status != expected {
            error!("OTA download: HTTP status {status}, expected {expected}");
            return Err(anyhow::anyhow!("HTTP status {status} (expected {expected})").into());
        }
        if self.written == 0 {
            self.total = connection.content_len().map(|n| n as usize);
            if let (Some(total), Some(limit)) = (self.total, self.limit) {
                if total as u64 != limit {
                    return Err(Failed::Verify(format!(
                        "the server offers {total} B, the manifest says {limit} B"
                    )));
                }
            }
        } else {
            // "bytes <first>-<last>/<size>": it must continue where we stopped.
            let range = connection.header("Content-Range").unwrap_or_default();
            let first = range
                .strip_prefix("bytes ")
                .and_then(|r| r.split('-').next())
                .and_then(|n| n.parse::<usize>().ok());
            if first != Some(self.written) {
                return Err(anyhow::anyhow!(
                    "resumed at the wrong offset (Content-Range {range:?}, wanted {})",
                    self.written
                )
                .into());
            }
        }

        let mut buf = [0u8; 4096];
        loop {
            let n = connection.read(&mut buf)?;
            if n == 0 {
                break; // EOF
            }
            if let Some(limit) = self.limit {
                if (self.written + n) as u64 > limit {
                    return Err(Failed::Verify(format!(
                        "the image is longer than the manifest's {limit} B"
                    )));
                }
            }
            self.check.update(&buf[..n]);
            esp!(unsafe { esp_ota_write(self.handle, buf.as_ptr().cast(), n) })
                .context("writing the OTA image")?;
            let before = self.written;
            self.written += n;
            if self.written / (4096 * 40) != before / (4096 * 40) {
                info!("OTA: {} bytes", self.written);
            }
        }
        if let Some(total) = self.total {
            if self.written < total {
                return Err(anyhow::anyhow!(
                    "connection closed at {} of {total} bytes",
                    self.written
                )
                .into());
            }
        }
        Ok(())
    }
}

/// Largest block the 8-bit heap can hand out, for the download logs.
fn largest_free_block() -> usize {
    unsafe { esp_idf_svc::sys::heap_caps_get_largest_free_block(esp_idf_svc::sys::MALLOC_CAP_8BIT) }
}

/// Aborts an unfinished OTA write, freeing its handle.
struct AbortOnDrop(Option<esp_ota_handle_t>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            // SAFETY: a handle from esp_ota_begin that esp_ota_end has not
            // consumed.
            unsafe { esp_ota_abort(handle) };
        }
    }
}
