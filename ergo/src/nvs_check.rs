//! `ergo nvs-check`: what the SDK will see in a device's NVS partition.
//!
//! Reads a dump (`esptool.py read_flash <nvs offset> <size> nvs.bin`) and
//! reports the identity the firmware would load, through the same
//! `device_core::nvs` functions the firmware uses, so a migration can be
//! checked before an image is flashed. No key material is printed: for the
//! private key and the claim only lengths and the PEM type line.

use std::io::Write;

use anyhow::{anyhow, Context, Result};
use device_core::nvs::{
    load_identity, load_last_job, platform_keys, IdentityLayout, Kv, MemKv, JOBS_NS, PLATFORM_NS,
};
use device_core::product::KeyStorage;

/// The key storage a known product uses.
pub fn product_storage(product: &str) -> Result<KeyStorage> {
    match product {
        "vaktus" => Ok(KeyStorage::SecureElement),
        "gateway" => Ok(KeyStorage::NvsSoftKey),
        other => Err(anyhow!(
            "unknown product {other:?} (vaktus or gateway); give --key-storage instead"
        )),
    }
}

/// Reads and reports a dump. `Ok(false)`: no identity loads.
pub fn check_dump(
    path: &std::path::Path,
    layout: IdentityLayout,
    out: &mut dyn Write,
) -> Result<bool> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let partition = nvs_image::parse(&bytes)
        .map_err(|e| anyhow!("{} is not a readable NVS partition: {e}", path.display()))?;
    let namespaces: Vec<String> = partition.namespaces().map(str::to_string).collect();
    report(
        layout,
        &namespaces,
        partition.skipped(),
        |name| partition.namespace(name),
        out,
    )
}

/// The first line of a PEM, without key material: `-----BEGIN ... -----`.
fn pem_type(pem: &str) -> &str {
    pem.lines()
        .map(str::trim)
        .find(|l| l.starts_with("-----BEGIN "))
        .unwrap_or("(no PEM header)")
}

/// Writes the report. Returns whether an identity loads.
pub fn report<'a>(
    layout: IdentityLayout,
    namespaces: &[String],
    skipped: usize,
    namespace: impl Fn(&str) -> Option<&'a MemKv>,
    out: &mut dyn Write,
) -> Result<bool> {
    if namespaces.is_empty() {
        writeln!(out, "namespaces: (none: an erased or blank partition)")?;
    } else {
        writeln!(out, "namespaces: {}", namespaces.join(", "))?;
    }
    if skipped > 0 {
        writeln!(
            out,
            "skipped: {skipped} entries (erased, corrupt or unsupported)"
        )?;
    }

    let ns = layout.namespace();
    writeln!(out, "identity ({ns}):")?;
    let loaded = match namespace(ns) {
        None => {
            writeln!(out, "  no namespace {ns}: the device would enrol")?;
            false
        }
        Some(kv) => match load_identity(layout, kv) {
            Err(e) => {
                writeln!(out, "  unreadable: {e}")?;
                false
            }
            Ok(None) => {
                writeln!(
                    out,
                    "  incomplete (thing, certificate{}): the device would enrol",
                    if layout == IdentityLayout::SoftKey {
                        " or key"
                    } else {
                        ""
                    }
                )?;
                describe_present(kv, out)?;
                false
            }
            Ok(Some(id)) => {
                writeln!(out, "  thing: {}", id.thing_name)?;
                writeln!(
                    out,
                    "  certificate: {} bytes, {}",
                    id.certificate_pem.len(),
                    pem_type(&id.certificate_pem)
                )?;
                match layout {
                    IdentityLayout::SecureElement if id.public_key.is_empty() => {
                        writeln!(out, "  public key: none recorded (an older record)")?
                    }
                    IdentityLayout::SecureElement => {
                        writeln!(out, "  public key: {} hex digits", id.public_key.len())?
                    }
                    IdentityLayout::SoftKey => writeln!(
                        out,
                        "  private key: {} bytes, {}",
                        id.private_key_pem.len(),
                        pem_type(&id.private_key_pem)
                    )?,
                }
                true
            }
        },
    };

    writeln!(out, "platform:")?;
    match namespace(PLATFORM_NS) {
        None => writeln!(out, "  no namespace (firmware from before the SDK)")?,
        Some(kv) => {
            let fw = kv.get_str(platform_keys::BOOT_FW).ok().flatten();
            let count = kv.get_u32(platform_keys::BOOT_COUNT).ok().flatten();
            writeln!(
                out,
                "  boot_fw: {}  boot_cnt: {}",
                fw.as_deref().unwrap_or("-"),
                count.map_or("-".to_string(), |c| c.to_string())
            )?;
            match load_last_job(kv) {
                Some(job) if job.reason.is_empty() => {
                    writeln!(out, "  last job: {} {}", job.id, job.status)?
                }
                Some(job) => writeln!(
                    out,
                    "  last job: {} {} ({})",
                    job.id, job.status, job.reason
                )?,
                None => writeln!(out, "  last job: none")?,
            }
            for key in device_core::console::Key::ALL {
                let name = key.nvs_key();
                if let Ok(Some(value)) = kv.get_str(name) {
                    if key.is_secret() || name == "claim_cert" {
                        writeln!(out, "  {name}: set ({} bytes)", value.len())?;
                    } else {
                        writeln!(out, "  {name}: {value}")?;
                    }
                }
            }
            if loaded && kv.get_str("claim_key").ok().flatten().is_some() {
                writeln!(
                    out,
                    "  WARNING: the claim key is still stored next to an identity"
                )?;
            }
        }
    }
    if let Some(kv) = namespace(JOBS_NS) {
        let keys: Vec<&str> = kv.0.keys().map(String::as_str).collect();
        writeln!(out, "ota_job: {}", keys.join(", "))?;
    }
    writeln!(
        out,
        "{}",
        if loaded {
            "OK: the SDK loads this identity"
        } else {
            "NO IDENTITY: the device would enrol again"
        }
    )?;
    Ok(loaded)
}

/// Names (never values) of what an incomplete identity namespace holds.
fn describe_present(kv: &MemKv, out: &mut dyn Write) -> Result<()> {
    let keys: Vec<&str> = kv.0.keys().map(String::as_str).collect();
    writeln!(out, "  keys present: {}", keys.join(", "))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use device_core::nvs::{save_identity, save_last_job, Identity};
    use device_core::shadow::LastJob;
    use std::collections::BTreeMap;

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n";
    const KEY: &str =
        "-----BEGIN EC PRIVATE KEY-----\nSECRETKEYBYTES\n-----END EC PRIVATE KEY-----\n";

    fn run(layout: IdentityLayout, spaces: &BTreeMap<String, MemKv>) -> (bool, String) {
        let names: Vec<String> = spaces.keys().cloned().collect();
        let mut out = Vec::new();
        let loaded = report(layout, &names, 2, |n| spaces.get(n), &mut out).unwrap();
        (loaded, String::from_utf8(out).unwrap())
    }

    #[test]
    fn a_gateway_identity_is_reported_without_its_key() {
        let mut id = MemKv::default();
        save_identity(
            IdentityLayout::SoftKey,
            &mut id,
            &Identity {
                thing_name: "28848553144F".into(),
                certificate_pem: CERT.into(),
                public_key: String::new(),
                private_key_pem: KEY.into(),
            },
        )
        .unwrap();
        let mut platform = MemKv::default();
        platform.set_str("boot_fw", "0.9.0").unwrap();
        platform.set_u32("boot_cnt", 3).unwrap();
        platform.set_str("wifi_ssid", "home").unwrap();
        platform.set_str("wifi_psk", "SECRETPSK123").unwrap();
        platform.set_str("claim_key", KEY).unwrap();
        save_last_job(
            &mut platform,
            &LastJob {
                id: "ota-gateway-0_9_0-a".into(),
                status: "SUCCEEDED".into(),
                reason: String::new(),
            },
        )
        .unwrap();
        let spaces = BTreeMap::from([
            ("device_id".to_string(), id),
            ("platform".to_string(), platform),
            ("nvs.net80211".to_string(), MemKv::default()),
        ]);
        let (loaded, out) = run(IdentityLayout::SoftKey, &spaces);
        assert!(loaded, "{out}");
        for expected in [
            "namespaces: device_id, nvs.net80211, platform",
            "skipped: 2",
            "thing: 28848553144F",
            &format!(
                "certificate: {} bytes, -----BEGIN CERTIFICATE-----",
                CERT.len()
            ),
            &format!(
                "private key: {} bytes, -----BEGIN EC PRIVATE KEY-----",
                KEY.len()
            ),
            "boot_fw: 0.9.0  boot_cnt: 3",
            "last job: ota-gateway-0_9_0-a SUCCEEDED",
            "wifi_ssid: home",
            "wifi_psk: set (12 bytes)",
            "WARNING: the claim key is still stored",
            "OK: the SDK loads",
        ] {
            assert!(out.contains(expected), "{expected:?} missing from:\n{out}");
        }
        for secret in ["SECRETKEYBYTES", "SECRETPSK123", "MIIBcert"] {
            assert!(!out.contains(secret), "{secret} printed:\n{out}");
        }
    }

    #[test]
    fn the_wrong_layout_finds_no_identity() {
        let mut cloud = MemKv::default();
        cloud.set_str("thing", "38182B8456F4").unwrap();
        cloud.set_str("cert", CERT).unwrap();
        cloud.set_str("pubkey", &"AB".repeat(64)).unwrap();
        let spaces = BTreeMap::from([("cloud".to_string(), cloud)]);

        let (loaded, out) = run(IdentityLayout::SecureElement, &spaces);
        assert!(loaded, "{out}");
        assert!(out.contains("public key: 128 hex digits"), "{out}");
        assert!(out.contains("platform:\n  no namespace"), "{out}");

        let (loaded, out) = run(IdentityLayout::SoftKey, &spaces);
        assert!(!loaded);
        assert!(out.contains("no namespace device_id"), "{out}");
        assert!(out.contains("NO IDENTITY"), "{out}");
    }

    #[test]
    fn a_half_identity_lists_key_names_only() {
        let mut id = MemKv::default();
        id.set_str("cert", CERT).unwrap();
        id.set_str("key", KEY).unwrap();
        let spaces = BTreeMap::from([("device_id".to_string(), id)]);
        let (loaded, out) = run(IdentityLayout::SoftKey, &spaces);
        assert!(!loaded);
        assert!(out.contains("keys present: cert, key"), "{out}");
        assert!(!out.contains("SECRETKEYBYTES"));
    }

    #[test]
    fn products_map_to_their_storage() {
        assert_eq!(
            product_storage("vaktus").unwrap(),
            KeyStorage::SecureElement
        );
        assert_eq!(product_storage("gateway").unwrap(), KeyStorage::NvsSoftKey);
        assert!(product_storage("other").is_err());
    }
}
