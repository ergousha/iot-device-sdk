//! The `platform` named shadow: what every device reports about itself, and
//! the one setting the platform sends it (telemetry opt-in).
//!
//! Reported on connect, whenever a field other than `uptime_s` changes, and
//! every [`REPORT_EVERY_S`]. The OTA controller's soak gate reads it: after an
//! update, a canary must report the new `fw` with `boot_count_since_update ==
//! 1` and a `boot_reason` that is not a crash ([`is_crash`]).
//!
//! Devices subscribe to exactly three answers of this shadow (`get/accepted`,
//! `get/rejected`, `update/delta`), never `shadow/#`: every message delivered
//! is billed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The named shadow.
pub const NAME: &str = "platform";

/// Periodic report interval: 6 h.
pub const REPORT_EVERY_S: u64 = 6 * 3600;

/// The topics of one named shadow of one thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Topics {
    pub update: String,
    pub get: String,
    pub get_accepted: String,
    pub get_rejected: String,
    pub update_delta: String,
}

impl Topics {
    pub fn new(thing: &str, shadow: &str) -> Self {
        let base = format!("$aws/things/{thing}/shadow/name/{shadow}");
        Self {
            update: format!("{base}/update"),
            get: format!("{base}/get"),
            get_accepted: format!("{base}/get/accepted"),
            get_rejected: format!("{base}/get/rejected"),
            update_delta: format!("{base}/update/delta"),
        }
    }

    /// What the device subscribes to: the answers it acts on, nothing more.
    pub fn subscriptions(&self) -> [&str; 3] {
        [&self.get_accepted, &self.get_rejected, &self.update_delta]
    }

    /// True for a topic of this shadow the device handles.
    pub fn owns(&self, topic: &str) -> bool {
        self.subscriptions().contains(&topic)
    }
}

/// The last OTA job this device settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastJob {
    pub id: String,
    /// `SUCCEEDED`, `FAILED` or `REJECTED`.
    pub status: String,
    /// The failure reason, if any (`PLATFORM.md` §8).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Telemetry as reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TelemetryState {
    pub enabled: bool,
}

/// The `reported` state of the `platform` shadow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub contract: u32,
    pub product: String,
    /// Running version, `X.Y.Z`.
    pub fw: String,
    /// Running OTA slot, e.g. `ota_0`.
    pub slot: String,
    /// Why the chip last reset ([`boot_reason_name`]).
    pub boot_reason: String,
    /// Boots of this `fw` so far; 1 on the first boot after an update.
    pub boot_count_since_update: u32,
    pub uptime_s: u64,
    /// Signing key ids this image accepts.
    pub key_id: Vec<String>,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "last_job_reported"
    )]
    pub last_job: Option<LastJob>,
    /// Echoes the desired setting, so the shadow holds no standing delta
    /// (each update with a delta would publish another billed message).
    pub telemetry: TelemetryState,
}

/// `last_job` as reported. The shadow merges `reported`: a field left out keeps
/// its old value, so a success after a failure would still show the failure's
/// reason. `reason` is therefore always sent, as `null` (which deletes it)
/// when there is none. NVS keeps [`LastJob`]'s own encoding.
fn last_job_reported<S: serde::Serializer>(job: &Option<LastJob>, s: S) -> Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct Reported<'a> {
        id: &'a str,
        status: &'a str,
        reason: Option<&'a str>,
    }
    match job {
        Some(j) => Reported {
            id: &j.id,
            status: &j.status,
            reason: (!j.reason.is_empty()).then_some(j.reason.as_str()),
        }
        .serialize(s),
        None => s.serialize_none(),
    }
}

impl Report {
    /// The update payload: `{"state":{"reported":{..}}}`.
    pub fn to_update(&self) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "state": { "reported": self } }))
            .expect("serializable")
    }

    /// True when `other` differs in anything but uptime: worth a report now.
    pub fn changed_from(&self, other: &Report) -> bool {
        let mut a = self.clone();
        a.uptime_s = other.uptime_s;
        a != *other
    }
}

/// The settings the platform may set in `desired`. Every field is optional:
/// absent means "unchanged" in a delta and "default" in a full document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Desired {
    pub telemetry_enabled: Option<bool>,
}

/// Reads `desired` from a `get/accepted` document, or the `state` of an
/// `update/delta`. Unknown fields are ignored (the contract grows additively);
/// a field of the wrong type is ignored too, never fatal.
pub fn parse_desired(topic_is_delta: bool, payload: &[u8]) -> Result<Desired, String> {
    let doc: Value =
        serde_json::from_slice(payload).map_err(|e| format!("unreadable shadow document: {e}"))?;
    let state = if topic_is_delta {
        &doc["state"]
    } else {
        &doc["state"]["desired"]
    };
    Ok(Desired {
        telemetry_enabled: state["telemetry"]["enabled"].as_bool(),
    })
}

/// The boot count to store and report for this boot, given what the previous
/// boot stored. A different (or no) stored version means this is the first
/// boot of the running image.
pub fn next_boot_count(
    stored_fw: Option<&str>,
    stored_count: Option<u32>,
    running_fw: &str,
) -> u32 {
    match (stored_fw, stored_count) {
        (Some(fw), Some(n)) if fw == running_fw => n.saturating_add(1),
        _ => 1,
    }
}

/// The name of an ESP-IDF `esp_reset_reason_t`.
pub fn boot_reason_name(code: u32) -> &'static str {
    match code {
        1 => "poweron",
        2 => "ext",
        3 => "sw",
        4 => "panic",
        5 => "int_wdt",
        6 => "task_wdt",
        7 => "wdt",
        8 => "deepsleep",
        9 => "brownout",
        10 => "sdio",
        11 => "usb",
        12 => "jtag",
        13 => "efuse",
        14 => "pwr_glitch",
        15 => "cpu_lockup",
        _ => "unknown",
    }
}

/// True for a reset caused by the firmware failing. The soak gate refuses a
/// release whose canary booted for one of these.
pub fn is_crash(reason: &str) -> bool {
    matches!(
        reason,
        "panic" | "int_wdt" | "task_wdt" | "wdt" | "cpu_lockup"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        Report {
            contract: 1,
            product: "vaktus".into(),
            fw: "0.9.0".into(),
            slot: "ota_1".into(),
            boot_reason: "sw".into(),
            boot_count_since_update: 1,
            uptime_s: 42,
            key_id: vec!["vaktus-a".into()],
            last_job: Some(LastJob {
                id: "ota-vaktus-0_9_0-c".into(),
                status: "SUCCEEDED".into(),
                reason: String::new(),
            }),
            telemetry: TelemetryState { enabled: false },
        }
    }

    #[test]
    fn the_device_subscribes_to_three_answers_only() {
        let t = Topics::new("38182B8456F4", NAME);
        assert_eq!(
            t.subscriptions(),
            [
                "$aws/things/38182B8456F4/shadow/name/platform/get/accepted",
                "$aws/things/38182B8456F4/shadow/name/platform/get/rejected",
                "$aws/things/38182B8456F4/shadow/name/platform/update/delta",
            ]
        );
        assert_eq!(
            t.update,
            "$aws/things/38182B8456F4/shadow/name/platform/update"
        );
        assert!(t.owns(&t.update_delta));
        assert!(!t.owns(&t.update));
    }

    #[test]
    fn the_report_has_the_contract_fields() {
        let v: Value = serde_json::from_slice(&report().to_update()).unwrap();
        let r = &v["state"]["reported"];
        assert_eq!(r["contract"], 1);
        assert_eq!(r["fw"], "0.9.0");
        assert_eq!(r["boot_count_since_update"], 1);
        assert_eq!(r["key_id"][0], "vaktus-a");
        assert_eq!(r["last_job"]["status"], "SUCCEEDED");
        // Sent as null, so the shadow drops an earlier failure's reason.
        assert!(r["last_job"]["reason"].is_null());
        assert!(r["last_job"].as_object().unwrap().contains_key("reason"));
        assert_eq!(r["telemetry"]["enabled"], false);

        let mut none = report();
        none.last_job = None;
        let v: Value = serde_json::from_slice(&none.to_update()).unwrap();
        assert!(v["state"]["reported"].get("last_job").is_none());
    }

    #[test]
    fn a_failed_job_reports_its_reason() {
        let mut failed = report();
        failed.last_job = Some(LastJob {
            id: "ota-vaktus-0_9_0-c".into(),
            status: "FAILED".into(),
            reason: "rollback".into(),
        });
        let v: Value = serde_json::from_slice(&failed.to_update()).unwrap();
        assert_eq!(v["state"]["reported"]["last_job"]["reason"], "rollback");
    }

    #[test]
    fn nvs_keeps_the_last_job_without_an_empty_reason() {
        let job = report().last_job.unwrap();
        let raw = serde_json::to_string(&job).unwrap();
        assert!(!raw.contains("reason"), "{raw}");
        assert_eq!(serde_json::from_str::<LastJob>(&raw).unwrap(), job);
    }

    #[test]
    fn uptime_alone_is_not_a_change() {
        let a = report();
        let mut b = report();
        b.uptime_s = 9999;
        assert!(!b.changed_from(&a));
        b.boot_reason = "panic".into();
        assert!(b.changed_from(&a));
    }

    #[test]
    fn desired_telemetry_is_read_from_documents_and_deltas() {
        let doc =
            br#"{"state":{"desired":{"telemetry":{"enabled":true}},"reported":{}},"version":3}"#;
        assert_eq!(
            parse_desired(false, doc).unwrap().telemetry_enabled,
            Some(true)
        );
        let delta = br#"{"version":4,"state":{"telemetry":{"enabled":false}}}"#;
        assert_eq!(
            parse_desired(true, delta).unwrap().telemetry_enabled,
            Some(false)
        );
        let other = br#"{"state":{"desired":{"something":1}}}"#;
        assert_eq!(parse_desired(false, other).unwrap(), Desired::default());
        let wrong_type = br#"{"state":{"desired":{"telemetry":{"enabled":"yes"}}}}"#;
        assert_eq!(
            parse_desired(false, wrong_type).unwrap(),
            Desired::default()
        );
        assert!(parse_desired(false, b"nope").is_err());
    }

    #[test]
    fn the_boot_count_restarts_with_each_image() {
        assert_eq!(next_boot_count(None, None, "0.9.0"), 1);
        assert_eq!(next_boot_count(Some("0.8.0"), Some(7), "0.9.0"), 1);
        assert_eq!(next_boot_count(Some("0.9.0"), Some(1), "0.9.0"), 2);
        assert_eq!(next_boot_count(Some("0.9.0"), None, "0.9.0"), 1);
        assert_eq!(
            next_boot_count(Some("0.9.0"), Some(u32::MAX), "0.9.0"),
            u32::MAX
        );
    }

    #[test]
    fn crashes_are_told_from_ordinary_resets() {
        assert_eq!(boot_reason_name(4), "panic");
        assert_eq!(boot_reason_name(6), "task_wdt");
        assert_eq!(boot_reason_name(99), "unknown");
        for crash in ["panic", "task_wdt", "int_wdt"] {
            assert!(is_crash(crash));
        }
        for fine in ["poweron", "sw", "brownout", "ext"] {
            assert!(!is_crash(fine));
        }
    }
}
