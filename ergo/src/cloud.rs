//! The AWS calls `ergo` makes, behind one small trait so that every flow runs
//! against a fake in the tests. [`crate::aws::Aws`] is the real one.

use std::fmt;

use anyhow::{anyhow, bail, Result};

use crate::record::Record;

/// SSM parameter the platform's kill switch writes (`claim-window.sh` reads
/// the same one).
pub const GUARD_STATE_PARAMETER: &str = "/esp32-ztp/guard/state";
/// SSM parameters holding the shared claim credential. The platform's OTA
/// controller writes them when it rotates the claim (after site windows and
/// on demand); nothing but `ergo` reads them.
pub const CLAIM_CERT_PARAMETER: &str = "/iot-platform/claim/cert";
pub const CLAIM_KEY_PARAMETER: &str = "/iot-platform/claim/key";
/// The IoT policy whose single target is the claim certificate.
pub const CLAIM_POLICY: &str = "esp32-ztp-claim-policy";

/// A value that must never be printed or logged. `Debug` is redacted and there
/// is no `Display`; the only way to the text is [`Secret::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// The shared claim credential, from SSM.
#[derive(Debug, Clone)]
pub struct ClaimCredential {
    pub certificate_pem: String,
    pub private_key: Secret,
}

/// Result of writing a registry record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Put {
    Written,
    /// A record for this MAC exists and overwriting was not asked for.
    AlreadyRegistered,
}

/// Result of deleting a registry record that has not enrolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delete {
    Deleted,
    /// The record shows the device enrolled; it was kept.
    Provisioned,
    /// No record.
    Missing,
}

/// The AWS side of `register` and `commission`.
///
/// Implementations take `&self`: the flows hold one reference across awaits.
#[allow(async_fn_in_trait)]
pub trait Cloud {
    /// The raw JSON of [`GUARD_STATE_PARAMETER`].
    async fn guard_state(&self) -> Result<String>;
    /// `PutItem`; conditional on no record for the MAC unless `overwrite`.
    async fn put_record(&self, record: &Record, overwrite: bool) -> Result<Put>;
    /// Consistent read of the record's `provisioned`; `None` if there is no
    /// record.
    async fn get_provisioned(&self, mac: &str) -> Result<Option<bool>>;
    /// Deletes the record unless it shows the device enrolled.
    async fn delete_record_if_unprovisioned(&self, mac: &str) -> Result<Delete>;
    /// The claim certificate and key, decrypted.
    async fn claim_credential(&self) -> Result<ClaimCredential>;
    /// The ARNs attached to [`CLAIM_POLICY`] (see [`claim_cert_id`]).
    async fn claim_policy_targets(&self) -> Result<Vec<String>>;
    /// `UpdateCertificate` to ACTIVE or INACTIVE.
    async fn set_claim_active(&self, cert_id: &str, active: bool) -> Result<()>;
}

/// The claim certificate id: the claim policy must have exactly one target,
/// and it must be a certificate (`arn:aws:iot:<region>:<account>:cert/<id>`).
pub fn claim_cert_id(targets: &[String]) -> Result<String> {
    let [target] = targets else {
        bail!(
            "expected exactly one certificate on {CLAIM_POLICY}, found {}: {targets:?}",
            targets.len()
        );
    };
    let id = target
        .rsplit_once(":cert/")
        .map(|(_, id)| id)
        .filter(|id| !id.is_empty() && id.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| anyhow!("the target of {CLAIM_POLICY} is not a certificate: {target}"))?;
    Ok(id.to_string())
}

/// Refuses unless the guard state says `"tripped": false`, exactly as
/// `claim-window.sh` does: a missing or unreadable field refuses too.
pub fn check_guard(state: &str) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(state)
        .map_err(|e| anyhow!("{GUARD_STATE_PARAMETER} is not JSON ({e}): {state}"))?;
    if value.get("tripped") != Some(&serde_json::Value::Bool(false)) {
        bail!(
            "refusing: the guard is tripped: {state}\n\
             investigate, then run iot-platform/scripts/guard-reset.sh"
        );
    }
    Ok(())
}

/// The command that closes the claim by hand when `ergo` could not.
pub fn disarm_command(cert_id: &str, region: &str) -> String {
    format!(
        "aws iot update-certificate --certificate-id {cert_id} --new-status INACTIVE --region {region}"
    )
}

/// The first 12 digits of a certificate id, as `claim-window.sh` prints it.
pub fn short_id(cert_id: &str) -> &str {
    cert_id.get(..12).unwrap_or(cert_id)
}

/// What to say when a record exists and `--reprovision` was not given.
pub fn already_registered(mac: &str) -> String {
    format!(
        "{mac} is already registered; use --reprovision at the bench to overwrite its record \
         (which resets provisioned=false and allows one more enrolment)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_claim_is_the_single_certificate_target() {
        let arn = "arn:aws:iot:eu-central-1:123456789012:cert/0a1b2c3d4e5f".to_string();
        assert_eq!(
            claim_cert_id(std::slice::from_ref(&arn)).unwrap(),
            "0a1b2c3d4e5f"
        );
        assert!(claim_cert_id(&[]).is_err());
        assert!(claim_cert_id(&[arn.clone(), arn]).is_err());
        assert!(claim_cert_id(&["arn:aws:iot:eu-central-1:1:thinggroup/x".into()]).is_err());
        assert!(claim_cert_id(&["arn:aws:iot:eu-central-1:1:cert/".into()]).is_err());
    }

    #[test]
    fn only_an_untripped_guard_allows_arming() {
        assert!(check_guard(r#"{"tripped":false,"since":"x"}"#).is_ok());
        for state in [
            r#"{"tripped":true}"#,
            r#"{"tripped":"false"}"#,
            r#"{"tripped":null}"#,
            r#"{}"#,
            "not json",
        ] {
            assert!(check_guard(state).is_err(), "{state}");
        }
    }

    #[test]
    fn secrets_do_not_debug_print() {
        let s = Secret::new("hunter2hunter2".into());
        assert!(!format!("{s:?}").contains("hunter2"));
        let c = ClaimCredential {
            certificate_pem: "cert".into(),
            private_key: s,
        };
        assert!(!format!("{c:?}").contains("hunter2"));
    }
}
