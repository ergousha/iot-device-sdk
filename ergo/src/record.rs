//! The device registry record, and the normalisation of what goes into it.
//!
//! The pre-provisioning hook (`iot-platform-infra/lambda/pre_provisioning_hook`)
//! compares strings, so a MAC or key spelled differently from what the device
//! presents would be rejected without saying why. Everything is normalised
//! here, once, to the exact form the hook and the firmware use.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use aws_sdk_dynamodb::types::AttributeValue;
use device_core::ids::{is_product_id, Mac};

/// Terraform's `<project_name>-device-registry`.
pub const DEFAULT_TABLE: &str = "esp32-ztp-device-registry";
pub const DEFAULT_REGION: &str = "eu-central-1";

/// Default enrolment window of a record, in minutes.
pub const DEFAULT_ENROL_MINUTES: u32 = 60;
/// Longest enrolment window: a week. A record that can enrol forever is a
/// standing invitation for whoever extracts the claim from some image.
pub const MAX_ENROL_MINUTES: u32 = 7 * 24 * 60;

/// Normalises a MAC to the registry key the hook looks up: six uppercase hex
/// octets separated by `:`. Accepts `:`/`-`/no separators, any case.
pub fn normalise_mac(input: &str) -> Result<Mac> {
    Mac::parse(input.trim()).map_err(|_| {
        anyhow::anyhow!(
            "{input:?} is not a MAC address; expected six hex octets, e.g. AA:BB:CC:DD:EE:FF"
        )
    })
}

/// Normalises a P-256 public key to the uppercase hex of X||Y (128 digits).
///
/// Accepts what an ATECC608 reports (64 bytes of X||Y) and the uncompressed
/// SEC1 form with its `04` prefix, with `:` and whitespace anywhere. Whether
/// the point is on the curve is checked by the hook, which refuses a bad key.
pub fn normalise_public_key(input: &str) -> Result<String> {
    let hex: String = input
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("the public key is not hex");
    }
    match hex.len() {
        128 => Ok(hex),
        130 if hex.starts_with("04") => Ok(hex[2..].to_string()),
        n => bail!("the public key has {n} hex digits; expected 128 (X||Y) or 130 (04||X||Y)"),
    }
}

/// Checks a product id against the infrastructure's rule.
pub fn check_product(input: &str) -> Result<String> {
    if !is_product_id(input) {
        bail!("product {input:?}: 2-16 lowercase letters and digits, starting with a letter");
    }
    Ok(input.to_string())
}

/// One registry record, as the hook reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// `AA:BB:CC:DD:EE:FF`, the table's key.
    pub mac: String,
    pub product: String,
    /// X||Y, 128 uppercase hex digits. The certificate the device enrols with
    /// must be for this key.
    pub public_key: String,
    pub canary: bool,
    /// Unix seconds; the hook rejects the device after this.
    pub enrol_by: u64,
    /// RFC 3339, UTC.
    pub registered_at: String,
}

impl Record {
    pub fn new(
        mac: &Mac,
        product: &str,
        public_key: &str,
        canary: bool,
        minutes: u32,
        now: SystemTime,
    ) -> Self {
        let now = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            mac: mac.colon(),
            product: product.to_string(),
            public_key: public_key.to_string(),
            canary,
            enrol_by: now + u64::from(minutes) * 60,
            registered_at: rfc3339(now),
        }
    }

    /// The DynamoDB item. `allowed` is always true and `provisioned` always
    /// false: writing a record is what allows one enrolment.
    pub fn item(&self) -> HashMap<String, AttributeValue> {
        HashMap::from([
            ("mac_address".into(), AttributeValue::S(self.mac.clone())),
            ("product".into(), AttributeValue::S(self.product.clone())),
            (
                "public_key".into(),
                AttributeValue::S(self.public_key.clone()),
            ),
            ("allowed".into(), AttributeValue::Bool(true)),
            ("provisioned".into(), AttributeValue::Bool(false)),
            (
                "enrol_by".into(),
                AttributeValue::N(self.enrol_by.to_string()),
            ),
            ("canary".into(), AttributeValue::Bool(self.canary)),
            (
                "registered_at".into(),
                AttributeValue::S(self.registered_at.clone()),
            ),
        ])
    }
}

/// Formats Unix seconds as RFC 3339 UTC (`2023-11-14T22:13:20Z`).
pub fn rfc3339(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const KEY: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\
                       FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";

    #[test]
    fn macs_are_normalised_to_the_registry_key() {
        for input in [
            "AA:BB:CC:DD:EE:0F",
            "aa:bb:cc:dd:ee:0f",
            "AA-BB-CC-DD-EE-0F",
            "aabbccddee0f",
            " aabbccddee0f\n",
        ] {
            assert_eq!(
                normalise_mac(input).unwrap().colon(),
                "AA:BB:CC:DD:EE:0F",
                "{input}"
            );
        }
    }

    #[test]
    fn malformed_macs_are_refused() {
        for input in [
            "",
            "AA:BB:CC:DD:EE",
            "AA:BB:CC:DD:EE:FF:00",
            "GG:BB:CC:DD:EE:FF",
        ] {
            assert!(normalise_mac(input).is_err(), "{input}");
        }
    }

    #[test]
    fn keys_are_normalised_to_x_and_y() {
        let with_colons: String = format!("04{}", KEY.to_lowercase())
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let with_spaces = format!("{} \n {}", &KEY[..64], &KEY[64..]);
        for key in [KEY.to_string(), with_colons, with_spaces] {
            assert_eq!(normalise_public_key(&key).unwrap(), KEY, "{key}");
        }
    }

    #[test]
    fn malformed_keys_are_refused() {
        for bad in [
            KEY[..126].to_string(),
            format!("05{KEY}"),
            format!("{}ZZ", &KEY[..126]),
            String::new(),
        ] {
            assert!(normalise_public_key(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn products_follow_the_infrastructure_rule() {
        assert_eq!(check_product("vaktus").unwrap(), "vaktus");
        for bad in ["", "v", "Vaktus", "vak tus", "1vaktus", "abcdefghijklmnopq"] {
            assert!(check_product(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn rfc3339_formats_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn the_item_is_what_the_hook_reads() {
        let mac = Mac::parse("38182b8456f4").unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let record = Record::new(&mac, "vaktus", KEY, true, 90, now);
        let item = record.item();
        let s = |k: &str| match &item[k] {
            AttributeValue::S(s) => s.clone(),
            other => panic!("{k}: {other:?}"),
        };
        let b = |k: &str| match &item[k] {
            AttributeValue::Bool(b) => *b,
            other => panic!("{k}: {other:?}"),
        };
        assert_eq!(s("mac_address"), "38:18:2B:84:56:F4");
        assert_eq!(s("product"), "vaktus");
        assert_eq!(s("public_key"), KEY);
        assert!(b("allowed"));
        assert!(!b("provisioned"));
        assert!(b("canary"));
        assert_eq!(
            item["enrol_by"],
            AttributeValue::N((1_700_000_000u64 + 90 * 60).to_string()),
            "a Number, as the hook's int64 field needs"
        );
        assert_eq!(s("registered_at"), "2023-11-14T22:13:20Z");
        assert_eq!(item.len(), 8);
    }
}
