//! AWS IoT Jobs wire format for firmware updates, and the bookkeeping that
//! carries an update's outcome across the reboot.
//!
//! An update's outcome is only known after the reboot. Until the new image has
//! run, reached AWS IoT and marked itself valid, the bootloader can still roll
//! it back, so the image that downloaded it cannot honestly report SUCCEEDED.
//! Instead it records the job ([`PendingUpdate`], which the firmware keeps in
//! NVS), reports IN_PROGRESS in the [`PHASE_REBOOTING`] phase, and restarts.
//! Whichever image boots next settles the job from what it can see about
//! itself ([`settle`]): the new image reports SUCCEEDED, the previous one,
//! after a rollback, reports FAILED with the reason. A job for the version
//! already running is settled without installing anything
//! ([`is_already_running`]).
//!
//! Only the pure parts live here: parsing `$next/get/accepted`, deciding the
//! outcome, and encoding the status updates. NVS, the OTA partitions and MQTT
//! are the firmware's.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The one job operation this firmware understands.
pub const OP_FIRMWARE_UPDATE: &str = "firmware_update";

/// `statusDetails.phase` while the image is being downloaded.
pub const PHASE_DOWNLOADING: &str = "downloading";

/// `statusDetails.phase` once the image is written and the device restarts
/// into it.
///
/// The Jobs service offers an execution again for as long as it is
/// IN_PROGRESS, and it still is when the device comes back. One seen in this
/// phase has already been installed: it is settled, never downloaded again,
/// or every boot would start the same update over.
pub const PHASE_REBOOTING: &str = "rebooting";

/// `statusDetails.reason`: the device is running its previous image.
pub const REASON_ROLLED_BACK: &str = "rolled back";
/// `statusDetails.reason`: the new image runs, but is not the version the job
/// named.
pub const REASON_VERSION_MISMATCH: &str = "version mismatch";
/// `statusDetails.reason`: the new image runs but could not mark itself
/// valid, so the next reset rolls it back.
pub const REASON_NOT_VALID: &str = "not marked valid";
/// `statusDetails.reason`: nothing recorded says which image the job
/// installed, so its outcome cannot be told.
pub const REASON_UNCONFIRMED: &str = "unconfirmed";
/// `statusDetails.reason`: the image was never activated.
pub const REASON_INSTALL_FAILED: &str = "install failed";

/// `stepTimeoutInMinutes` sent with the [`PHASE_REBOOTING`] update.
///
/// If neither image comes back to settle the job, the Jobs service ends the
/// execution TIMED_OUT instead of leaving it IN_PROGRESS forever. Jobs from
/// the OTA pipeline carry a job-wide in-progress timeout as well
/// (iot-platform-infra#3); this one also covers a job created by hand. A
/// healthy update settles within a minute or two; the margin covers a
/// rollback, which costs a failed boot of the new image first, and a few WiFi
/// retries (each a restart, see `docs/OPCUA_INTEGRATION_TEST.md` §9.9). A
/// device that reports after the timer fired is told the execution already
/// ended, and moves on.
pub const REBOOT_STEP_TIMEOUT_MIN: u32 = 30;

/// Longest `statusDetails` value sent, in characters.
const MAX_DETAIL_CHARS: usize = 128;

/// Longest job id AWS IoT accepts.
const MAX_JOB_ID_LEN: usize = 64;

/// A job payload that could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedJob(pub String);

impl fmt::Display for MalformedJob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed job payload: {}", self.0)
    }
}

impl std::error::Error for MalformedJob {}

/// A firmware update job this firmware is willing to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareJob {
    /// Job id; also part of the topic the status goes to.
    pub job_id: String,
    /// HTTPS URL of the image.
    pub url: String,
    /// `firmware_version` from the job document, normalised with
    /// [`normalize_version`]. Empty if the document names none.
    pub target_version: String,
}

impl FirmwareJob {
    /// The record to keep once the image is written to `target_slot`.
    pub fn pending(&self, from_version: &str, target_slot: &str) -> PendingUpdate {
        PendingUpdate {
            job_id: self.job_id.clone(),
            from_version: normalize_version(from_version).to_string(),
            target_version: self.target_version.clone(),
            target_slot: target_slot.to_string(),
        }
    }
}

/// An installed update whose outcome the next boot has to report.
///
/// The firmware writes this to NVS before it activates the new image, so no
/// boot of that image can happen without it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingUpdate {
    /// Job id.
    pub job_id: String,
    /// Version the device ran when it took the job.
    #[serde(default)]
    pub from_version: String,
    /// Normalised version the job asked for; empty if it named none.
    #[serde(default)]
    pub target_version: String,
    /// Partition the image was written to, e.g. `ota_1`.
    #[serde(default)]
    pub target_slot: String,
}

impl PendingUpdate {
    /// True when the record can be acted on. A record read back from flash is
    /// checked with this before its job id is put into a topic.
    pub fn is_well_formed(&self) -> bool {
        is_job_id(&self.job_id)
    }
}

/// What the booted image can tell about itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BootFacts {
    /// Version of the running image, as the shadow reports it (`fw`).
    pub running_version: String,
    /// Partition the running image was loaded from; empty if unknown.
    pub running_slot: String,
    /// Partition the bootloader last marked invalid or aborted, if any.
    pub invalid_slot: Option<String>,
    /// Why marking the running image valid failed, if it did.
    pub valid_error: Option<String>,
}

/// How a pending update ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The new image runs, is the version the job named, and is marked valid.
    Succeeded,
    /// Anything else.
    Failed {
        /// Short, stable category; one of the `REASON_*` constants.
        reason: &'static str,
        /// What was observed, for a human.
        detail: String,
    },
}

/// Decides how `pending` ended, from what this boot can see.
///
/// The partition is the primary evidence and the version the secondary: a
/// rebuilt image can carry the same version as the one it replaces, but it
/// cannot run from the slot it was not written to. The bootloader's own
/// verdict, the slot it last marked invalid, only sharpens the detail.
pub fn settle(pending: &PendingUpdate, boot: &BootFacts) -> Outcome {
    let target_slot = pending.target_slot.as_str();
    let running_slot = boot.running_slot.as_str();
    let target = normalize_version(&pending.target_version);
    let running = normalize_version(&boot.running_version);
    let slots_known = !target_slot.is_empty() && !running_slot.is_empty();
    let rejected_by_bootloader = !target_slot.is_empty()
        && running_slot != target_slot
        && boot.invalid_slot.as_deref() == Some(target_slot);

    if rejected_by_bootloader {
        let mut detail = format!("the bootloader marked {target_slot} invalid");
        if !running_slot.is_empty() {
            detail.push_str(&format!(" and booted {running_slot}"));
        }
        return failed(REASON_ROLLED_BACK, detail);
    }
    if slots_known && running_slot != target_slot {
        return failed(
            REASON_ROLLED_BACK,
            format!("booted {running_slot}, not {target_slot}"),
        );
    }

    if !target.is_empty() && running != target {
        return if slots_known {
            failed(
                REASON_VERSION_MISMATCH,
                format!("{running_slot} runs {running}, the job named {target}"),
            )
        } else {
            failed(
                REASON_ROLLED_BACK,
                format!("running {running}, not {target}"),
            )
        };
    }

    if !slots_known && target.is_empty() {
        return failed(
            REASON_UNCONFIRMED,
            "no record of the slot or version the job installed".to_string(),
        );
    }

    if let Some(e) = &boot.valid_error {
        return failed(REASON_NOT_VALID, e.clone());
    }

    Outcome::Succeeded
}

fn failed(reason: &'static str, detail: String) -> Outcome {
    Outcome::Failed { reason, detail }
}

/// True when `job` names the version this image already is, and this image
/// has marked itself valid: there is nothing to install.
///
/// OTA jobs target a thing group continuously, so a unit flashed over USB
/// with the current release, or one that joins the group late, is offered the
/// job for the image it already runs; installing it again would cost a 5 MB
/// download and a reboot for nothing. It also settles a job whose `rebooting`
/// status and NVS record were both lost after its image did come up. Nothing
/// is installed here, so the version alone decides: a rebuild shipped under an
/// unchanged version is not installed, and has to be given a new one.
pub fn is_already_running(job: &FirmwareJob, boot: &BootFacts) -> bool {
    !job.target_version.is_empty()
        && job.target_version == normalize_version(&boot.running_version)
        && boot.valid_error.is_none()
}

/// Reduces a version string to the part the two sides can agree on.
///
/// The job document names the image by its S3 object key minus `.bin`, e.g.
/// `firmware_v0.1.0` (the release workflow uploads `firmware_${TAG_NAME}.bin`,
/// and the tag may also carry a component prefix); the firmware knows itself
/// as `CARGO_PKG_VERSION`, e.g. `0.1.0`. Both reduce to `0.1.0`: the text from
/// the first `N.N` that starts a word, without a leading `v`. A word starts
/// after a separator such as `_`, `-` or `/`, but not after a dot, so the
/// middle of a version is never taken for its start. Anything after it, such
/// as a pre-release, is kept, so `0.1.0-rc.1` never matches `0.1.0`. A string
/// with no such version is returned trimmed, and compared as is.
pub fn normalize_version(raw: &str) -> &str {
    let s = raw.trim();
    let s = match s.len().checked_sub(4) {
        Some(cut) if s.is_char_boundary(cut) && s[cut..].eq_ignore_ascii_case(".bin") => &s[..cut],
        _ => s,
    };

    let mut prev: Option<char> = None;
    for (i, c) in s.char_indices() {
        let starts_word = prev.is_none_or(|p| !p.is_alphanumeric() && p != '.');
        prev = Some(c);
        if !starts_word {
            continue;
        }
        let rest = &s[i..];
        let rest = rest.strip_prefix(['v', 'V']).unwrap_or(rest);
        if starts_with_dotted_number(rest) {
            return rest;
        }
    }
    s
}

/// True for `123.4…`: digits, a dot, a digit.
fn starts_with_dotted_number(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = b.iter().take_while(|c| c.is_ascii_digit()).count();
    digits > 0 && b.get(digits) == Some(&b'.') && b.get(digits + 1).is_some_and(u8::is_ascii_digit)
}

/// True for an id AWS IoT could have issued: 1–64 of `[A-Za-z0-9_-]`.
///
/// Checked because the id is put into a topic. One carrying `+` or `#` would
/// make the publish a protocol error, and AWS IoT drops the whole connection
/// for that.
pub fn is_job_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_JOB_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What a `$next/get/accepted` response asks of this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextJob {
    /// No job is pending.
    Idle,
    /// A job for an operation this firmware does not implement. Normal, not
    /// an error.
    Unsupported {
        /// Job id.
        job_id: String,
        /// The `operation` it asked for.
        operation: String,
    },
    /// A firmware job this firmware will not run.
    Refused {
        /// Job id.
        job_id: String,
        /// Why.
        reason: String,
    },
    /// A firmware update to download and install.
    Install(FirmwareJob),
    /// A firmware update this device already installed and rebooted for, with
    /// no record of it left on the device. Settle it; never download it again.
    Settle(PendingUpdate),
}

/// Parses a `$next/get/accepted` payload.
pub fn parse_next(payload: &[u8]) -> Result<NextJob, MalformedJob> {
    let json: Value = serde_json::from_slice(payload).map_err(|e| MalformedJob(e.to_string()))?;
    let Some(execution) = json.get("execution").filter(|e| !e.is_null()) else {
        return Ok(NextJob::Idle);
    };

    let job_id = execution
        .get("jobId")
        .and_then(Value::as_str)
        .ok_or_else(|| MalformedJob("execution has no jobId".into()))?;
    if !is_job_id(job_id) {
        return Err(MalformedJob(format!("invalid jobId {job_id:?}")));
    }
    let job_id = job_id.to_string();

    // The API reference types jobDocument as a string; AWS IoT delivers an
    // object. Accept both.
    let doc = match execution.get("jobDocument") {
        Some(Value::String(s)) => serde_json::from_str(s).unwrap_or(Value::Null),
        Some(doc) => doc.clone(),
        None => Value::Null,
    };
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).unwrap_or("").to_string();

    let operation = text(&doc, "operation");
    if operation != OP_FIRMWARE_UPDATE {
        return Ok(NextJob::Unsupported { job_id, operation });
    }
    let target_version = normalize_version(&text(&doc, "firmware_version")).to_string();

    let details = execution.get("statusDetails").unwrap_or(&Value::Null);
    if text(execution, "status") == "IN_PROGRESS" && text(details, "phase") == PHASE_REBOOTING {
        let recorded = text(details, "target");
        return Ok(NextJob::Settle(PendingUpdate {
            job_id,
            from_version: text(details, "from"),
            target_version: if recorded.is_empty() {
                target_version
            } else {
                normalize_version(&recorded).to_string()
            },
            target_slot: text(details, "target_slot"),
        }));
    }

    let url = text(&doc, "download_url");
    if url.is_empty() {
        return Ok(NextJob::Refused {
            job_id,
            reason: "the job document has no download_url".into(),
        });
    }
    // Refuse plaintext downloads: an unauthenticated firmware image is a
    // remote code execution primitive.
    if !url.starts_with("https://") {
        return Ok(NextJob::Refused {
            job_id,
            reason: "download_url is not https".into(),
        });
    }

    Ok(NextJob::Install(FirmwareJob {
        job_id,
        url,
        target_version,
    }))
}

/// A `jobs/{jobId}/update/rejected` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Error code, e.g. `InvalidStateTransition`; empty if unreadable.
    pub code: String,
    /// Human-readable reason.
    pub message: String,
}

impl Rejection {
    /// True when the same update can succeed later.
    ///
    /// Everything else means the execution cannot take it: it was cancelled,
    /// timed out, deleted, or already ended by an earlier attempt whose answer
    /// was lost. Retrying those would never end.
    pub fn is_transient(&self) -> bool {
        matches!(self.code.as_str(), "RequestThrottled" | "InternalError")
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Parses a `jobs/{jobId}/update/rejected` payload. Never fails: a rejection
/// that cannot be read is still a rejection.
pub fn parse_rejection(payload: &[u8]) -> Rejection {
    #[derive(Deserialize)]
    struct Envelope {
        #[serde(default)]
        code: String,
        #[serde(default)]
        message: String,
    }
    match serde_json::from_slice::<Envelope>(payload) {
        Ok(e) => Rejection {
            code: e.code,
            message: e.message,
        },
        Err(e) => Rejection {
            code: String::new(),
            message: format!("unreadable rejection: {e}"),
        },
    }
}

/// An `UpdateJobExecution` request, for `$aws/things/{thing}/jobs/{jobId}/update`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusUpdate {
    status: &'static str,
    details: BTreeMap<&'static str, String>,
    step_timeout_min: Option<u32>,
}

impl StatusUpdate {
    fn new(status: &'static str) -> Self {
        Self {
            status,
            details: BTreeMap::new(),
            step_timeout_min: None,
        }
    }

    /// Adds a `statusDetails` entry.
    ///
    /// AWS IoT rejects the whole update if any value is empty or holds a
    /// control character, so the value is reduced to printable ASCII and
    /// capped, and an empty one is left out.
    fn detail(mut self, key: &'static str, value: &str) -> Self {
        let clean: String = value
            .chars()
            .map(|c| if c.is_ascii_graphic() { c } else { ' ' })
            .take(MAX_DETAIL_CHARS)
            .collect();
        let clean = clean.trim();
        if !clean.is_empty() {
            self.details.insert(key, clean.to_string());
        }
        self
    }

    /// The job execution status this update sets.
    pub fn status(&self) -> &'static str {
        self.status
    }

    /// One `statusDetails` value, if present.
    pub fn detail_value(&self, key: &str) -> Option<&str> {
        self.details.get(key).map(String::as_str)
    }

    /// The request body.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = serde_json::json!({
            "status": self.status,
            "statusDetails": self.details,
        });
        if let Some(minutes) = self.step_timeout_min {
            body["stepTimeoutInMinutes"] = minutes.into();
        }
        serde_json::to_vec(&body).expect("a status update is always serialisable")
    }
}

/// IN_PROGRESS, before the download starts.
pub fn downloading(job: &FirmwareJob, running_version: &str) -> StatusUpdate {
    StatusUpdate::new("IN_PROGRESS")
        .detail("phase", PHASE_DOWNLOADING)
        .detail("from", normalize_version(running_version))
        .detail("target", &job.target_version)
}

/// IN_PROGRESS, once the image is written and recorded, right before the
/// restart into it. Carries everything [`parse_next`] needs to settle the job
/// should the device come back without its record.
pub fn rebooting(pending: &PendingUpdate) -> StatusUpdate {
    let mut update = StatusUpdate::new("IN_PROGRESS")
        .detail("phase", PHASE_REBOOTING)
        .detail("from", &pending.from_version)
        .detail("target", &pending.target_version)
        .detail("target_slot", &pending.target_slot);
    update.step_timeout_min = Some(REBOOT_STEP_TIMEOUT_MIN);
    update
}

/// FAILED, when the image could not be downloaded, written or activated. The
/// running image is still the boot image.
pub fn install_failed(job: &FirmwareJob, error: &str) -> StatusUpdate {
    StatusUpdate::new("FAILED")
        .detail("reason", REASON_INSTALL_FAILED)
        .detail("detail", error)
        .detail("target", &job.target_version)
}

/// SUCCEEDED, for a job [`is_already_running`] found nothing to do for.
pub fn already_running(boot: &BootFacts) -> StatusUpdate {
    StatusUpdate::new("SUCCEEDED")
        .detail("detail", "already running this version; nothing installed")
        .detail("running", normalize_version(&boot.running_version))
        .detail("running_slot", &boot.running_slot)
}

/// The terminal update for a settled job.
pub fn settled(pending: &PendingUpdate, boot: &BootFacts, outcome: &Outcome) -> StatusUpdate {
    let update = match outcome {
        Outcome::Succeeded => StatusUpdate::new("SUCCEEDED").detail("from", &pending.from_version),
        Outcome::Failed { reason, detail } => StatusUpdate::new("FAILED")
            .detail("reason", reason)
            .detail("detail", detail)
            .detail("target", &pending.target_version)
            .detail("target_slot", &pending.target_slot),
    };
    update
        .detail("running", normalize_version(&boot.running_version))
        .detail("running_slot", &boot.running_slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending() -> PendingUpdate {
        PendingUpdate {
            job_id: "ota-firmware_v0-2-0-1790540983".into(),
            from_version: "0.1.0".into(),
            target_version: "0.2.0".into(),
            target_slot: "ota_1".into(),
        }
    }

    fn booted(version: &str, slot: &str) -> BootFacts {
        BootFacts {
            running_version: version.into(),
            running_slot: slot.into(),
            invalid_slot: None,
            valid_error: None,
        }
    }

    fn reason(outcome: &Outcome) -> &'static str {
        match outcome {
            Outcome::Failed { reason, .. } => reason,
            Outcome::Succeeded => "succeeded",
        }
    }

    fn body(update: &StatusUpdate) -> Value {
        serde_json::from_slice(&update.encode()).unwrap()
    }

    // --- normalize_version ---------------------------------------------------

    #[test]
    fn the_job_document_and_the_crate_version_normalise_alike() {
        assert_eq!(normalize_version("firmware_v0.1.0"), "0.1.0");
        assert_eq!(normalize_version("0.1.0"), "0.1.0");
        assert_eq!(normalize_version("v0.1.0"), "0.1.0");
        assert_eq!(normalize_version("  V0.1.0\n"), "0.1.0");
        assert_eq!(normalize_version("firmware_v0.1.0.bin"), "0.1.0");
        assert_eq!(normalize_version("firmware_v0.1.0.BIN"), "0.1.0");
    }

    #[test]
    fn a_component_prefix_does_not_hide_the_version() {
        // The digit in "esp32" does not start a word, so it is not taken for
        // the version.
        assert_eq!(
            normalize_version("firmware_esp32-opcua-gateway-v0.2.0"),
            "0.2.0"
        );
        assert_eq!(normalize_version("esp32-opcua-gateway-v1.10.3"), "1.10.3");
    }

    #[test]
    fn a_pre_release_is_kept_so_it_never_matches_the_release() {
        assert_eq!(normalize_version("firmware_v0.2.0-rc.1"), "0.2.0-rc.1");
        assert_ne!(
            normalize_version("firmware_v0.2.0-rc.1"),
            normalize_version("0.2.0")
        );
        assert_eq!(normalize_version("0.2.0-1"), "0.2.0-1");
    }

    #[test]
    fn normalising_twice_changes_nothing() {
        for raw in ["firmware_v0.1.0", "0.1.0-rc.1", "latest", "", "v2"] {
            let once = normalize_version(raw);
            assert_eq!(normalize_version(once), once, "{raw:?}");
        }
    }

    #[test]
    fn a_string_without_a_version_is_compared_as_is() {
        assert_eq!(normalize_version(" latest "), "latest");
        assert_eq!(normalize_version("v2"), "v2");
        assert_eq!(normalize_version(""), "");
        assert_eq!(normalize_version(".bin"), "");
    }

    #[test]
    fn non_ascii_input_does_not_panic() {
        assert_eq!(normalize_version("fw_ü0.1.0"), "fw_ü0.1.0");
        assert_eq!(normalize_version("ü_v0.1.0"), "0.1.0");
        assert_eq!(normalize_version("ü"), "ü");
    }

    // --- settle ---------------------------------------------------------------

    #[test]
    fn the_new_image_in_its_slot_settles_succeeded() {
        assert_eq!(
            settle(&pending(), &booted("0.2.0", "ota_1")),
            Outcome::Succeeded
        );
    }

    #[test]
    fn a_rollback_seen_by_the_bootloader_settles_failed() {
        let mut boot = booted("0.1.0", "ota_0");
        boot.invalid_slot = Some("ota_1".into());
        let outcome = settle(&pending(), &boot);
        assert_eq!(reason(&outcome), REASON_ROLLED_BACK);
        let Outcome::Failed { detail, .. } = outcome else {
            unreachable!()
        };
        assert!(detail.contains("marked ota_1 invalid"), "{detail}");
    }

    #[test]
    fn booting_the_other_slot_is_a_rollback_even_without_the_bootloader_saying_so() {
        // E.g. power lost after the record was written but before the new
        // slot was activated.
        let outcome = settle(&pending(), &booted("0.1.0", "ota_0"));
        assert_eq!(reason(&outcome), REASON_ROLLED_BACK);
    }

    #[test]
    fn the_slot_decides_even_when_the_versions_agree() {
        // A rebuild shipped under the version it replaces, rolled back.
        let mut same = pending();
        same.target_version = "0.1.0".into();
        let outcome = settle(&same, &booted("0.1.0", "ota_0"));
        assert_eq!(reason(&outcome), REASON_ROLLED_BACK);
    }

    #[test]
    fn a_stale_invalid_slot_does_not_fail_an_image_running_from_its_slot() {
        let mut boot = booted("0.2.0", "ota_1");
        boot.invalid_slot = Some("ota_0".into());
        assert_eq!(settle(&pending(), &boot), Outcome::Succeeded);
    }

    #[test]
    fn the_wrong_version_in_the_right_slot_is_a_mismatch_not_a_rollback() {
        let outcome = settle(&pending(), &booted("0.1.9", "ota_1"));
        assert_eq!(reason(&outcome), REASON_VERSION_MISMATCH);
    }

    #[test]
    fn versions_are_compared_normalised() {
        let mut from_doc = pending();
        from_doc.target_version = "firmware_v0.2.0".into();
        assert_eq!(
            settle(&from_doc, &booted("0.2.0", "ota_1")),
            Outcome::Succeeded
        );
    }

    #[test]
    fn without_slot_information_the_version_decides() {
        assert_eq!(settle(&pending(), &booted("0.2.0", "")), Outcome::Succeeded);
        assert_eq!(
            reason(&settle(&pending(), &booted("0.1.0", ""))),
            REASON_ROLLED_BACK
        );
        let mut unknown_slot = pending();
        unknown_slot.target_slot.clear();
        assert_eq!(
            reason(&settle(&unknown_slot, &booted("0.1.0", "ota_0"))),
            REASON_ROLLED_BACK
        );
    }

    #[test]
    fn a_job_without_a_version_is_settled_on_the_slot_alone() {
        let mut unversioned = pending();
        unversioned.target_version.clear();
        assert_eq!(
            settle(&unversioned, &booted("0.2.0", "ota_1")),
            Outcome::Succeeded
        );
        assert_eq!(
            reason(&settle(&unversioned, &booted("0.1.0", "ota_0"))),
            REASON_ROLLED_BACK
        );
    }

    #[test]
    fn with_nothing_to_go_on_the_outcome_is_not_guessed() {
        let mut blank = pending();
        blank.target_version.clear();
        blank.target_slot.clear();
        assert_eq!(
            reason(&settle(&blank, &booted("0.2.0", "ota_1"))),
            REASON_UNCONFIRMED
        );
    }

    #[test]
    fn an_image_that_could_not_mark_itself_valid_did_not_succeed() {
        let mut boot = booted("0.2.0", "ota_1");
        boot.valid_error = Some("ESP_ERR_OTA_ROLLBACK_FAILED".into());
        let outcome = settle(&pending(), &boot);
        assert_eq!(reason(&outcome), REASON_NOT_VALID);
    }

    #[test]
    fn a_rollback_is_reported_as_such_even_if_marking_valid_failed() {
        let mut boot = booted("0.1.0", "ota_0");
        boot.valid_error = Some("whatever".into());
        assert_eq!(reason(&settle(&pending(), &boot)), REASON_ROLLED_BACK);
    }

    // --- is_already_running -----------------------------------------------------

    fn job_for(version: &str) -> FirmwareJob {
        FirmwareJob {
            job_id: "j".into(),
            url: "https://x".into(),
            target_version: normalize_version(version).to_string(),
        }
    }

    #[test]
    fn a_job_for_the_running_version_needs_no_install() {
        let boot = booted("0.2.0", "ota_0");
        assert!(is_already_running(&job_for("firmware_v0.2.0"), &boot));
        let update = already_running(&boot);
        assert_eq!(update.status(), "SUCCEEDED");
        assert_eq!(update.detail_value("running"), Some("0.2.0"));
        assert_eq!(update.detail_value("running_slot"), Some("ota_0"));
    }

    #[test]
    fn any_other_version_is_installed() {
        let boot = booted("0.2.0", "ota_0");
        assert!(!is_already_running(&job_for("firmware_v0.3.0"), &boot));
        assert!(!is_already_running(&job_for("firmware_v0.1.0"), &boot));
        assert!(!is_already_running(&job_for("firmware_v0.2.0-rc.1"), &boot));
    }

    #[test]
    fn a_job_without_a_version_is_always_installed() {
        assert!(!is_already_running(&job_for(""), &booted("0.2.0", "ota_0")));
    }

    #[test]
    fn an_image_that_is_not_marked_valid_is_not_already_running() {
        let mut boot = booted("0.2.0", "ota_1");
        boot.valid_error = Some("ESP_FAIL".into());
        assert!(!is_already_running(&job_for("firmware_v0.2.0"), &boot));
    }

    // --- parse_next -------------------------------------------------------------

    const QUEUED: &str = r#"{
      "clientToken": "x",
      "timestamp": 1790540990,
      "execution": {
        "jobId": "ota-firmware_v0-2-0-1790540983",
        "thingName": "gw-1",
        "status": "QUEUED",
        "queuedAt": 1790540984,
        "versionNumber": 1,
        "executionNumber": 1,
        "jobDocument": {
          "operation": "firmware_update",
          "firmware_version": "firmware_v0.2.0",
          "download_url": "https://bucket.s3.amazonaws.com/firmware_v0.2.0.bin?X-Amz-Signature=abc"
        }
      }
    }"#;

    fn with_execution(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut v: Value = serde_json::from_str(QUEUED).unwrap();
        edit(&mut v["execution"]);
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn a_queued_firmware_job_is_installed() {
        let NextJob::Install(job) = parse_next(QUEUED.as_bytes()).unwrap() else {
            panic!("expected Install");
        };
        assert_eq!(job.job_id, "ota-firmware_v0-2-0-1790540983");
        assert!(job.url.starts_with("https://bucket.s3.amazonaws.com/"));
        assert_eq!(job.target_version, "0.2.0");
    }

    #[test]
    fn an_empty_queue_is_idle() {
        assert_eq!(
            parse_next(br#"{"timestamp":1,"clientToken":"x"}"#),
            Ok(NextJob::Idle)
        );
        assert_eq!(parse_next(br#"{"execution":null}"#), Ok(NextJob::Idle));
    }

    #[test]
    fn an_interrupted_download_is_installed_again() {
        // Power lost mid-download: the old image is still active, so trying
        // again is right.
        let payload = with_execution(|e| {
            e["status"] = "IN_PROGRESS".into();
            e["statusDetails"] = serde_json::json!({"phase": "downloading", "target": "0.2.0"});
        });
        assert!(matches!(parse_next(&payload), Ok(NextJob::Install(_))));
    }

    #[test]
    fn an_execution_reoffered_after_its_reboot_is_settled_not_reinstalled() {
        let update = rebooting(&pending());
        let details = body(&update)["statusDetails"].clone();
        let payload = with_execution(|e| {
            e["status"] = "IN_PROGRESS".into();
            e["statusDetails"] = details;
        });
        assert_eq!(parse_next(&payload), Ok(NextJob::Settle(pending())));
    }

    #[test]
    fn a_settle_without_a_recorded_target_falls_back_to_the_document() {
        let payload = with_execution(|e| {
            e["status"] = "IN_PROGRESS".into();
            e["statusDetails"] = serde_json::json!({"phase": "rebooting", "target_slot": "ota_1"});
        });
        let Ok(NextJob::Settle(p)) = parse_next(&payload) else {
            panic!("expected Settle");
        };
        assert_eq!(p.target_version, "0.2.0");
        assert_eq!(p.target_slot, "ota_1");
    }

    #[test]
    fn the_rebooting_phase_only_counts_while_in_progress() {
        let payload = with_execution(|e| {
            e["statusDetails"] = serde_json::json!({"phase": "rebooting"});
        });
        assert!(matches!(parse_next(&payload), Ok(NextJob::Install(_))));
    }

    #[test]
    fn other_operations_are_left_alone() {
        let payload = with_execution(|e| e["jobDocument"]["operation"] = "reboot".into());
        assert_eq!(
            parse_next(&payload),
            Ok(NextJob::Unsupported {
                job_id: "ota-firmware_v0-2-0-1790540983".into(),
                operation: "reboot".into()
            })
        );
    }

    #[test]
    fn plaintext_and_missing_urls_are_refused() {
        let http = with_execution(|e| {
            e["jobDocument"]["download_url"] = "http://bucket/firmware.bin".into()
        });
        assert!(matches!(parse_next(&http), Ok(NextJob::Refused { .. })));
        let none = with_execution(|e| {
            e["jobDocument"]
                .as_object_mut()
                .unwrap()
                .remove("download_url");
        });
        assert!(matches!(parse_next(&none), Ok(NextJob::Refused { .. })));
    }

    #[test]
    fn a_job_document_delivered_as_a_string_is_read() {
        let payload = with_execution(|e| {
            let doc = e["jobDocument"].to_string();
            e["jobDocument"] = doc.into();
        });
        assert!(matches!(parse_next(&payload), Ok(NextJob::Install(_))));
    }

    #[test]
    fn a_job_id_that_cannot_go_into_a_topic_is_malformed() {
        let payload = with_execution(|e| e["jobId"] = "a/#".into());
        assert!(parse_next(&payload).is_err());
        assert!(parse_next(b"not json").is_err());
    }

    #[test]
    fn job_ids_follow_the_aws_pattern() {
        assert!(is_job_id("ota-firmware_v0-1-0-1790540983"));
        assert!(!is_job_id(""));
        assert!(!is_job_id("a+b"));
        assert!(!is_job_id(&"a".repeat(65)));
        assert!(is_job_id(&"a".repeat(64)));
    }

    // --- rejections -------------------------------------------------------------

    #[test]
    fn a_terminal_execution_is_not_retried() {
        for code in [
            "InvalidStateTransition",
            "TerminalStateReached",
            "ResourceNotFound",
        ] {
            let r = parse_rejection(
                format!(r#"{{"code":"{code}","message":"no","clientToken":"x"}}"#).as_bytes(),
            );
            assert_eq!(r.code, code);
            assert!(!r.is_transient(), "{code}");
        }
    }

    #[test]
    fn throttling_and_service_errors_are_retried() {
        assert!(
            parse_rejection(br#"{"code":"RequestThrottled","message":"slow down"}"#).is_transient()
        );
        assert!(parse_rejection(br#"{"code":"InternalError"}"#).is_transient());
    }

    #[test]
    fn an_unreadable_rejection_is_still_final() {
        let r = parse_rejection(b"garbage");
        assert!(r.code.is_empty());
        assert!(!r.is_transient());
    }

    // --- status updates -----------------------------------------------------------

    #[test]
    fn the_download_is_reported_in_progress_with_its_target() {
        let NextJob::Install(job) = parse_next(QUEUED.as_bytes()).unwrap() else {
            unreachable!()
        };
        let b = body(&downloading(&job, "0.1.0"));
        assert_eq!(b["status"], "IN_PROGRESS");
        assert_eq!(b["statusDetails"]["phase"], PHASE_DOWNLOADING);
        assert_eq!(b["statusDetails"]["from"], "0.1.0");
        assert_eq!(b["statusDetails"]["target"], "0.2.0");
        assert!(b.get("stepTimeoutInMinutes").is_none());
    }

    #[test]
    fn the_reboot_is_reported_in_progress_with_a_step_timeout() {
        let b = body(&rebooting(&pending()));
        assert_eq!(b["status"], "IN_PROGRESS");
        assert_eq!(b["statusDetails"]["phase"], PHASE_REBOOTING);
        assert_eq!(b["statusDetails"]["target"], "0.2.0");
        assert_eq!(b["statusDetails"]["target_slot"], "ota_1");
        assert_eq!(b["stepTimeoutInMinutes"], REBOOT_STEP_TIMEOUT_MIN);
    }

    #[test]
    fn success_names_what_is_running() {
        let boot = booted("0.2.0", "ota_1");
        let update = settled(&pending(), &boot, &Outcome::Succeeded);
        assert_eq!(update.status(), "SUCCEEDED");
        assert_eq!(update.detail_value("running"), Some("0.2.0"));
        assert_eq!(update.detail_value("running_slot"), Some("ota_1"));
        assert_eq!(update.detail_value("from"), Some("0.1.0"));
        assert_eq!(update.detail_value("reason"), None);
    }

    #[test]
    fn a_rollback_is_reported_failed_with_its_reason() {
        let mut boot = booted("0.1.0", "ota_0");
        boot.invalid_slot = Some("ota_1".into());
        let outcome = settle(&pending(), &boot);
        let update = settled(&pending(), &boot, &outcome);
        assert_eq!(update.status(), "FAILED");
        assert_eq!(update.detail_value("reason"), Some(REASON_ROLLED_BACK));
        assert_eq!(update.detail_value("running"), Some("0.1.0"));
        assert_eq!(update.detail_value("target"), Some("0.2.0"));
        assert_eq!(update.detail_value("target_slot"), Some("ota_1"));
        assert!(update.detail_value("detail").is_some());
    }

    #[test]
    fn details_are_values_aws_accepts() {
        let job = FirmwareJob {
            job_id: "j".into(),
            url: "https://x".into(),
            target_version: String::new(),
        };
        let long = format!("line one\nline two\t{}", "x".repeat(300));
        let update = install_failed(&job, &long);
        let detail = update.detail_value("detail").unwrap();
        assert!(detail.len() <= MAX_DETAIL_CHARS);
        assert!(detail.chars().all(|c| c.is_ascii_graphic() || c == ' '));
        // An empty value would make AWS reject the whole update; it is left out.
        assert_eq!(update.detail_value("target"), None);
        let b = body(&update);
        assert!(b["statusDetails"]
            .as_object()
            .unwrap()
            .values()
            .all(|v| !v.as_str().unwrap().is_empty()));
    }

    #[test]
    fn a_pending_record_survives_serialisation() {
        let raw = serde_json::to_vec(&pending()).unwrap();
        let back: PendingUpdate = serde_json::from_slice(&raw).unwrap();
        assert_eq!(back, pending());
        assert!(back.is_well_formed());
        let bad: PendingUpdate = serde_json::from_str(r#"{"job_id":"a#"}"#).unwrap();
        assert!(!bad.is_well_formed());
    }
}
