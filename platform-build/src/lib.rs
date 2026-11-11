//! Build-script helper for a product firmware.
//!
//! ```ignore
//! // build.rs
//! fn main() {
//!     platform_build::configure();
//! }
//! // src/main.rs
//! include!(concat!(env!("OUT_DIR"), "/platform.rs")); // pub const PLATFORM: Product
//! ```
//!
//! [`configure`]:
//!
//! 1. reads `platform.toml` and generates `$OUT_DIR/platform.rs`, one
//!    `pub const PLATFORM: device_sdk::core::product::Product`;
//! 2. pins the version: `FW_VERSION` from the environment (the release
//!    workflow sets it to the tag), else the crate version; it must be
//!    `X.Y.Z`. Exported to the crate as `env!("FW_VERSION")` too;
//! 3. compiles in the signing keyring, `keys/<key_id>.pub.pem`, after checking
//!    that each is a P-256 public key;
//! 4. checks `partitions.csv` against the frozen rows `platform.toml` pins
//!    (deployed devices cannot have their partition table rewritten);
//! 5. relays esp-idf-sys's configuration and stages the bootloader this build
//!    produced for espflash.
//!
//! There is no AWS access and no secret anywhere in the build: the endpoint,
//! template and keys are public, and the claim and Wi-Fi are written to the
//! device at the bench (`ergo commission`).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use device_core::ids::{is_product_id, MacType};
use device_core::product::{KeyStorage, Limits};
use serde::Deserialize;

/// `platform.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformToml {
    pub product: ProductSection,
    pub cloud: CloudSection,
    #[serde(default)]
    pub limits: Option<LimitsSection>,
    #[serde(default)]
    pub signing: SigningSection,
    pub flash: FlashSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductSection {
    /// Product id, e.g. `vaktus`.
    pub id: String,
    /// `esp32`, `esp32s3`, ...: must match the build target.
    pub chip: String,
    /// `wifi_sta` or `eth`.
    pub mac_type: String,
    /// `atecc608` or `nvs-soft-key`.
    pub key_storage: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudSection {
    /// AWS IoT data endpoint (public).
    pub endpoint: String,
    /// Fleet provisioning template.
    pub template: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsSection {
    pub publishes_per_minute: u32,
    pub max_message_bytes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningSection {
    /// Key ids; each is `keys/<id>.pub.pem`.
    #[serde(default)]
    pub keys: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlashSection {
    /// The partition table, relative to the crate.
    pub partitions: String,
    /// Rows deployed devices already have; never to change.
    #[serde(default)]
    pub frozen: Vec<FrozenPartition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenPartition {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// Everything the generated constant needs, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub id: String,
    pub fw_version: String,
    pub endpoint: String,
    pub template: String,
    pub mac_type: MacType,
    pub key_storage: KeyStorage,
    pub limits: Limits,
    /// `(id, pem)`.
    pub signing_keys: Vec<(String, String)>,
}

/// Runs every step; call it from the product's `build.rs`. Panics (fails the
/// build) with a clear message on any problem.
pub fn configure() {
    let dir = PathBuf::from(env("CARGO_MANIFEST_DIR"));
    let target = env("TARGET");
    let fw_version = std::env::var("FW_VERSION")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env("CARGO_PKG_VERSION"));
    for watched in ["platform.toml", "keys", "partitions.csv"] {
        println!("cargo:rerun-if-changed={watched}");
    }
    println!("cargo:rerun-if-env-changed=FW_VERSION");

    let resolved =
        resolve(&dir, &target, &fw_version).unwrap_or_else(|e| panic!("platform.toml: {e}"));
    println!("cargo:rustc-env=FW_VERSION={}", resolved.fw_version);
    let out = PathBuf::from(env("OUT_DIR")).join("platform.rs");
    std::fs::write(&out, generate(&resolved))
        .unwrap_or_else(|e| panic!("writing {}: {e}", out.display()));
    warn_about_leftover_secrets(&dir);

    embuild::espidf::sysenv::output();
    stage_bootloader();
}

/// Reads and checks `platform.toml` in `dir` for a build of `target`.
pub fn resolve(dir: &Path, target: &str, fw_version: &str) -> Result<Resolved, String> {
    let path = dir.join("platform.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let toml: PlatformToml = toml::from_str(&text).map_err(|e| e.to_string())?;
    let p = &toml.product;

    if !is_product_id(&p.id) {
        return Err(format!(
            "product.id {:?}: 2-16 lowercase letters and digits, starting with a letter",
            p.id
        ));
    }
    let target_chip = target.split('-').nth(1).unwrap_or_default();
    if p.chip != target_chip {
        return Err(format!(
            "product.chip is {:?} but the build target is {target}",
            p.chip
        ));
    }
    let version = iot_jobs::Version::parse(fw_version)?;
    if version.to_string() != fw_version {
        return Err(format!(
            "FW_VERSION {fw_version:?} is not a bare X.Y.Z version"
        ));
    }
    let mac_type = MacType::parse(&p.mac_type)?;
    let key_storage = KeyStorage::parse(&p.key_storage)?;

    let endpoint = &toml.cloud.endpoint;
    device_core::console::Key::Endpoint
        .validate(endpoint)
        .map_err(|e| format!("cloud.endpoint {endpoint:?}: {e}"))?;
    let template = &toml.cloud.template;
    if template.is_empty()
        || !template
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(format!(
            "cloud.template {template:?} is not a template name"
        ));
    }

    let limits = match &toml.limits {
        None => Limits::DEFAULT,
        Some(l) => {
            if l.publishes_per_minute == 0 || l.max_message_bytes == 0 {
                return Err("limits must be positive".into());
            }
            // The broker's own ceiling; anything higher is a typo.
            if l.max_message_bytes > 128 * 1024 {
                return Err("limits.max_message_bytes is over AWS IoT's 128 KB".into());
            }
            Limits {
                publishes_per_minute: l.publishes_per_minute,
                max_message_bytes: l.max_message_bytes,
            }
        }
    };

    let mut signing_keys = Vec::new();
    for id in &toml.signing.keys {
        if id.is_empty()
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "signing key id {id:?}: letters, digits, '-' and '_'"
            ));
        }
        let key_path = dir.join("keys").join(format!("{id}.pub.pem"));
        let pem = std::fs::read_to_string(&key_path)
            .map_err(|e| format!("{}: {e}", key_path.display()))?;
        if pem.contains("PRIVATE") {
            return Err(format!("{} holds a private key", key_path.display()));
        }
        signing_keys.push((id.clone(), pem));
    }
    iot_jobs::Keyring::from_pems(signing_keys.iter().map(|(i, p)| (i.as_str(), p.as_str())))?;

    let table_path = dir.join(&toml.flash.partitions);
    let table = std::fs::read_to_string(&table_path)
        .map_err(|e| format!("{}: {e}", table_path.display()))?;
    check_partitions(&table, &toml.flash.frozen)?;

    Ok(Resolved {
        id: p.id.clone(),
        fw_version: fw_version.to_string(),
        endpoint: endpoint.clone(),
        template: template.clone(),
        mac_type,
        key_storage,
        limits,
        signing_keys,
    })
}

/// One row of a partition table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionRow {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

/// Parses an ESP-IDF partition CSV. Every row must spell out its offset:
/// a blank one lets the generator pack rows, so editing one row would move
/// every later one under deployed devices.
pub fn parse_partitions(csv: &str) -> Result<Vec<PartitionRow>, String> {
    let mut rows = Vec::new();
    for (n, line) in csv.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split(',').map(str::trim).collect();
        if cols.len() < 5 {
            return Err(format!("partitions line {}: expected 5+ columns", n + 1));
        }
        let number = |s: &str, what: &str| {
            parse_size(s).ok_or_else(|| format!("partitions line {}: {what} {s:?}", n + 1))
        };
        if cols[3].is_empty() {
            return Err(format!(
                "partitions line {}: {} has no explicit offset",
                n + 1,
                cols[0]
            ));
        }
        rows.push(PartitionRow {
            name: cols[0].to_string(),
            offset: number(cols[3], "offset")?,
            size: number(cols[4], "size")?,
        });
    }
    Ok(rows)
}

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    let (digits, mult) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 1024),
        b'M' | b'm' => (&s[..s.len() - 1], 1024 * 1024),
        _ => (s, 1),
    };
    digits.parse::<u64>().ok().map(|n| n * mult)
}

/// Checks that every frozen row is in `csv` with its offset and size.
pub fn check_partitions(csv: &str, frozen: &[FrozenPartition]) -> Result<(), String> {
    let rows = parse_partitions(csv)?;
    for f in frozen {
        let row = rows
            .iter()
            .find(|r| r.name == f.name)
            .ok_or_else(|| format!("frozen partition {} is missing from the table", f.name))?;
        if row.offset != f.offset || row.size != f.size {
            return Err(format!(
                "frozen partition {} is at 0x{:x} size 0x{:x}; deployed devices have 0x{:x} size 0x{:x}",
                f.name, row.offset, row.size, f.offset, f.size
            ));
        }
    }
    Ok(())
}

/// The source of `platform.rs`.
pub fn generate(r: &Resolved) -> String {
    let mac = match r.mac_type {
        MacType::WifiSta => "WifiSta",
        MacType::Eth => "Eth",
    };
    let storage = match r.key_storage {
        KeyStorage::SecureElement => "SecureElement",
        KeyStorage::NvsSoftKey => "NvsSoftKey",
    };
    let mut keys = String::new();
    for (id, pem) in &r.signing_keys {
        let _ = write!(
            keys,
            "::device_sdk::core::product::SigningKey {{ id: {id:?}, pem: {pem:?} }}, "
        );
    }
    format!(
        "/// This build, as `platform.toml` and the build environment describe it.\n\
         /// Generated by platform-build.\n\
         pub const PLATFORM: ::device_sdk::core::product::Product = ::device_sdk::core::product::Product {{\n\
         \x20   id: {id:?},\n\
         \x20   fw_version: {fw:?},\n\
         \x20   endpoint: {endpoint:?},\n\
         \x20   template: {template:?},\n\
         \x20   mac_type: ::device_sdk::core::ids::MacType::{mac},\n\
         \x20   key_storage: ::device_sdk::core::product::KeyStorage::{storage},\n\
         \x20   limits: ::device_sdk::core::product::Limits {{ publishes_per_minute: {ppm}, max_message_bytes: {mmb} }},\n\
         \x20   signing_keys: &[{keys}],\n\
         }};\n",
        id = r.id,
        fw = r.fw_version,
        endpoint = r.endpoint,
        template = r.template,
        ppm = r.limits.publishes_per_minute,
        mmb = r.limits.max_message_bytes,
    )
}

/// Files the pre-SDK build wrote: nothing reads them any more, and they hold
/// the claim credential.
fn warn_about_leftover_secrets(dir: &Path) {
    for leftover in [
        "certs/claim.crt.pem",
        "certs/claim.private.key",
        "aws-env.sh",
    ] {
        if dir.join(leftover).exists() {
            println!(
                "cargo:warning={leftover} is no longer used by the build and may hold a secret; delete it"
            );
        }
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set (run from a build script)"))
}

/// Copies the second-stage bootloader this build produced to
/// `<target-dir>/bootloader.bin`, where `espflash.toml` and the runner find
/// it.
///
/// `espflash flash` otherwise writes its own bundled bootloader, built without
/// `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`: it ignores OTA image states and
/// never rolls a bad image back. OTA never replaces the bootloader, so what USB
/// flashing writes is what the unit keeps.
///
/// esp-idf-sys builds it under its own hashed `OUT_DIR`; the right one is the
/// build directory in the C include arguments it passes on
/// (`-isystem<OUT_DIR>/build/config`).
pub fn stage_bootloader() {
    let out_dir = PathBuf::from(env("OUT_DIR"));
    // <target-dir>/<triple>/<profile>/build/<pkg>-<hash>/out
    let target_dir = out_dir
        .ancestors()
        .nth(5)
        .expect("OUT_DIR is <target-dir>/<triple>/<profile>/build/<pkg>-<hash>/out");
    let staged = target_dir.join("bootloader.bin");
    // Never leave an earlier build's bootloader there for espflash to write.
    let _ = std::fs::remove_file(&staged);

    let args = embuild::espidf::sysenv::cincl_args()
        .expect("esp-idf-svc relays esp-idf-sys's C include arguments")
        .args;
    let build_dir = args
        .split_whitespace()
        .filter_map(|arg| arg.trim_matches('"').strip_prefix("-isystem"))
        .map(Path::new)
        .find(|dir| dir.ends_with("build/config"))
        .and_then(Path::parent)
        .unwrap_or_else(|| {
            panic!("no <esp-idf build>/build/config in esp-idf-sys's include arguments: {args}")
        });
    let built = build_dir.join("bootloader").join("bootloader.bin");
    std::fs::copy(&built, &staged).unwrap_or_else(|e| {
        panic!(
            "copying the bootloader {} to {}: {e}",
            built.display(),
            staged.display()
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = include_str!("../../contract/v1/test-key.pub.pem");
    const TABLE: &str = "\
# Name,     Type, SubType,  Offset,    Size,      Flags
nvs,        data, nvs,      0x9000,    0x6000,
phy_init,   data, phy,      0xf000,    0x1000,
otadata,    data, ota,      0x10000,   0x2000,
ota_0,      app,  ota_0,    0x20000,   1984K,
";

    fn crate_dir(toml: &str, keys: &[(&str, &str)]) -> PathBuf {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "platform-build-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("keys")).unwrap();
        std::fs::write(dir.join("platform.toml"), toml).unwrap();
        std::fs::write(dir.join("partitions.csv"), TABLE).unwrap();
        for (id, pem) in keys {
            std::fs::write(dir.join("keys").join(format!("{id}.pub.pem")), pem).unwrap();
        }
        dir
    }

    const VAKTUS: &str = r#"
[product]
id = "vaktus"
chip = "esp32"
mac_type = "wifi_sta"
key_storage = "atecc608"

[cloud]
endpoint = "abc123-ats.iot.eu-central-1.amazonaws.com"
template = "esp32-ztp-vaktus-fleet-template"

[signing]
keys = ["vaktus-a"]

[flash]
partitions = "partitions.csv"
frozen = [
  { name = "nvs", offset = 0x9000, size = 0x6000 },
  { name = "otadata", offset = 0x10000, size = 0x2000 },
]
"#;

    #[test]
    fn a_product_resolves_and_generates_its_constant() {
        let dir = crate_dir(VAKTUS, &[("vaktus-a", KEY)]);
        let r = resolve(&dir, "xtensa-esp32-espidf", "0.9.0").unwrap();
        assert_eq!(r.id, "vaktus");
        assert_eq!(r.mac_type, MacType::WifiSta);
        assert_eq!(r.key_storage, KeyStorage::SecureElement);
        assert_eq!(r.limits, Limits::DEFAULT);
        assert_eq!(r.signing_keys.len(), 1);
        let src = generate(&r);
        assert!(src.contains("pub const PLATFORM: ::device_sdk::core::product::Product"));
        assert!(src.contains("fw_version: \"0.9.0\""));
        assert!(src.contains("id: \"vaktus-a\", pem: \"-----BEGIN PUBLIC KEY-----\\n"));
    }

    #[test]
    fn the_build_target_must_be_the_products_chip() {
        let dir = crate_dir(VAKTUS, &[("vaktus-a", KEY)]);
        let e = resolve(&dir, "xtensa-esp32s3-espidf", "0.9.0").unwrap_err();
        assert!(e.contains("esp32s3"), "{e}");
    }

    #[test]
    fn versions_must_be_bare_semver() {
        let dir = crate_dir(VAKTUS, &[("vaktus-a", KEY)]);
        for bad in ["v0.9.0", "0.9", "latest", "0.9.0+build"] {
            assert!(resolve(&dir, "xtensa-esp32-espidf", bad).is_err(), "{bad}");
        }
        assert!(resolve(&dir, "xtensa-esp32-espidf", "1.0.0-rc.1").is_ok());
    }

    #[test]
    fn signing_keys_must_exist_and_be_public() {
        let dir = crate_dir(VAKTUS, &[]);
        assert!(resolve(&dir, "xtensa-esp32-espidf", "0.9.0").is_err());
        let dir = crate_dir(VAKTUS, &[("vaktus-a", "-----BEGIN PRIVATE KEY-----\nx\n")]);
        assert!(resolve(&dir, "xtensa-esp32-espidf", "0.9.0")
            .unwrap_err()
            .contains("private key"));
        let dir = crate_dir(VAKTUS, &[("vaktus-a", "garbage")]);
        assert!(resolve(&dir, "xtensa-esp32-espidf", "0.9.0").is_err());
    }

    #[test]
    fn no_keys_is_allowed_until_releases_are_signed() {
        let toml = VAKTUS.replace("keys = [\"vaktus-a\"]", "keys = []");
        let dir = crate_dir(&toml, &[]);
        let r = resolve(&dir, "xtensa-esp32-espidf", "0.9.0").unwrap();
        assert!(r.signing_keys.is_empty());
        assert!(generate(&r).contains("signing_keys: &[],"));
    }

    #[test]
    fn unknown_fields_and_bad_values_are_refused() {
        for (from, to) in [
            ("mac_type = \"wifi_sta\"", "mac_type = \"base\""),
            ("key_storage = \"atecc608\"", "key_storage = \"tpm\""),
            ("id = \"vaktus\"", "id = \"Vaktus\""),
            (
                "template = \"esp32-ztp-vaktus-fleet-template\"",
                "template = \"a b\"",
            ),
            ("[signing]", "[signing]\nextra = 1"),
            (
                "endpoint = \"abc123-ats.iot.eu-central-1.amazonaws.com\"",
                "endpoint = \"example.com\"",
            ),
        ] {
            let dir = crate_dir(&VAKTUS.replace(from, to), &[("vaktus-a", KEY)]);
            assert!(
                resolve(&dir, "xtensa-esp32-espidf", "0.9.0").is_err(),
                "{to}"
            );
        }
    }

    #[test]
    fn frozen_partitions_are_checked() {
        let frozen = |name: &str, offset, size| FrozenPartition {
            name: name.into(),
            offset,
            size,
        };
        check_partitions(TABLE, &[frozen("nvs", 0x9000, 0x6000)]).unwrap();
        check_partitions(TABLE, &[frozen("ota_0", 0x20000, 1984 * 1024)]).unwrap();
        assert!(check_partitions(TABLE, &[frozen("nvs", 0x9000, 0x5000)]).is_err());
        assert!(check_partitions(TABLE, &[frozen("coredump", 0, 1)]).is_err());
        assert!(parse_partitions("nvs, data, nvs, , 0x6000,").is_err());
    }

    #[test]
    fn limits_can_be_raised() {
        let toml = VAKTUS.replace(
            "[signing]",
            "[limits]\npublishes_per_minute = 30\nmax_message_bytes = 10240\n\n[signing]",
        );
        let dir = crate_dir(&toml, &[("vaktus-a", KEY)]);
        let r = resolve(&dir, "xtensa-esp32-espidf", "0.9.0").unwrap();
        assert_eq!(r.limits.publishes_per_minute, 30);
    }
}
