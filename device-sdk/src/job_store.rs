//! The OTA job whose outcome is still open, kept across the reboot.
//!
//! The image that installs an update cannot know whether it will work, so it
//! records the job here and the next boot reads it back to report the outcome
//! (`iot_jobs::settle`). The record is written after the image is
//! verified but before it is activated, so the new image can never boot
//! without it: a power cut any earlier leaves the running image active, and
//! the Jobs service simply offers the job again.
//!
//! Next to it, the number of downloads of a job started so far
//! (`iot_jobs::DownloadAttempts`): a download that crashes the device
//! leaves nothing else behind, and without the count would start again at
//! every boot.
//!
//! It lives in the default `nvs` partition, next to the device identity: a
//! few hundred bytes written once per update. The namespace and keys are
//! frozen (`device_core::nvs::JOBS_NS`): both products' devices in the field
//! have them.

use anyhow::{anyhow, Context, Result};
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

use iot_jobs::client::Store;
use iot_jobs::{is_job_id, DownloadAttempts, PendingUpdate};
use serde::de::DeserializeOwned;
use serde::Serialize;

const NAMESPACE: &str = device_core::nvs::JOBS_NS;
const KEY_PENDING: &str = device_core::nvs::job_keys::PENDING;
const KEY_ATTEMPTS: &str = device_core::nvs::job_keys::ATTEMPTS;

/// Largest record we will read back. A real one is about 150 B; the bound
/// keeps a corrupt length on flash from driving the allocation.
const MAX_RECORD_BYTES: usize = 512;

/// Read/write access to the pending OTA job.
pub struct JobStore {
    nvs: EspNvs<NvsDefault>,
}

impl JobStore {
    /// Opens (and creates if needed) the `ota_job` namespace.
    pub fn new(partition: EspDefaultNvsPartition) -> Result<Self> {
        let nvs = EspNvs::new(partition, NAMESPACE, true)
            .with_context(|| format!("opening NVS namespace {NAMESPACE:?}"))?;
        Ok(Self { nvs })
    }

    /// The pending job, if there is one.
    ///
    /// An unreadable record is discarded rather than reported: it must not
    /// keep the Jobs plane from ever taking work again. If the job it named
    /// was already installed, the Jobs service still has its outcome open and
    /// offers it again, and the `rebooting` status details settle it from
    /// there.
    pub fn load(&self) -> Option<PendingUpdate> {
        match self.try_load() {
            Ok(pending) => pending,
            Err(e) => {
                log::warn!("discarding unusable OTA job record: {e:#}");
                if let Err(e) = self.clear() {
                    log::warn!("could not remove it: {e:#}");
                }
                None
            }
        }
    }

    fn try_load(&self) -> Result<Option<PendingUpdate>> {
        let Some(pending) = self.read::<PendingUpdate>(KEY_PENDING)? else {
            return Ok(None);
        };
        if !pending.is_well_formed() {
            return Err(anyhow!(
                "record names an invalid job id {:?}",
                pending.job_id
            ));
        }
        Ok(Some(pending))
    }

    /// Records `pending`, replacing any earlier record.
    pub fn save(&self, pending: &PendingUpdate) -> Result<()> {
        self.write(KEY_PENDING, pending)
            .context("writing the OTA job record")?;
        log::info!(
            "recorded OTA job {} ({} -> {} in {})",
            pending.job_id,
            pending.from_version,
            pending.target_version,
            pending.target_slot
        );
        Ok(())
    }

    /// Removes the record. Not having one is not an error.
    pub fn clear(&self) -> Result<()> {
        self.nvs
            .remove(KEY_PENDING)
            .context("removing the OTA job record")?;
        Ok(())
    }

    /// The download count, if any. One that cannot be read is dropped: the
    /// count starts over, which costs at most a few more downloads.
    pub fn load_attempts(&self) -> Option<DownloadAttempts> {
        match self.read::<DownloadAttempts>(KEY_ATTEMPTS) {
            Ok(Some(attempts)) if is_job_id(&attempts.job_id) => Some(attempts),
            Ok(None) => None,
            Ok(Some(_)) | Err(_) => {
                log::warn!("discarding unusable OTA download count");
                let _ = self.clear_attempts();
                None
            }
        }
    }

    /// Records the download count.
    pub fn save_attempts(&self, attempts: &DownloadAttempts) -> Result<()> {
        self.write(KEY_ATTEMPTS, attempts)
            .context("writing the OTA download count")
    }

    /// Removes the download count. Not having one is not an error.
    pub fn clear_attempts(&self) -> Result<()> {
        self.nvs
            .remove(KEY_ATTEMPTS)
            .context("removing the OTA download count")?;
        Ok(())
    }

    fn read<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>> {
        let Some(len) = self.nvs.blob_len(key)? else {
            return Ok(None);
        };
        if len > MAX_RECORD_BYTES {
            return Err(anyhow!(
                "record is {len} B, over the {MAX_RECORD_BYTES} B we accept"
            ));
        }
        let mut buf = vec![0u8; len];
        let Some(raw) = self.nvs.get_blob(key, &mut buf)? else {
            return Ok(None);
        };
        Ok(Some(
            serde_json::from_slice(raw).context("record is not valid JSON")?,
        ))
    }

    fn write(&self, key: &str, value: &impl Serialize) -> Result<()> {
        let raw = serde_json::to_vec(value)?;
        if raw.len() > MAX_RECORD_BYTES {
            return Err(anyhow!(
                "record is {} B, over the {MAX_RECORD_BYTES} B budget",
                raw.len()
            ));
        }
        self.nvs.set_blob(key, &raw)?;
        Ok(())
    }
}

impl Store for JobStore {
    fn load(&self) -> Option<PendingUpdate> {
        JobStore::load(self)
    }

    fn save(&self, pending: &PendingUpdate) -> std::result::Result<(), String> {
        JobStore::save(self, pending).map_err(|e| format!("{e:#}"))
    }

    fn clear(&self) -> std::result::Result<(), String> {
        JobStore::clear(self).map_err(|e| format!("{e:#}"))
    }

    fn load_attempts(&self) -> Option<DownloadAttempts> {
        JobStore::load_attempts(self)
    }

    fn save_attempts(&self, attempts: &DownloadAttempts) -> std::result::Result<(), String> {
        JobStore::save_attempts(self, attempts).map_err(|e| format!("{e:#}"))
    }

    fn clear_attempts(&self) -> std::result::Result<(), String> {
        JobStore::clear_attempts(self).map_err(|e| format!("{e:#}"))
    }
}
