//! A real device's NVS dump, when one is given:
//!
//! ```sh
//! espflash read-flash 0x9000 0x6000 ~/dumps/vaktus.nvs.bin   # offset/size from the partition table
//! NVS_DUMP=~/dumps/vaktus.nvs.bin NVS_LAYOUT=secure-element \
//!     cargo test -p nvs-image --test dump -- --nocapture
//! ```
//!
//! Give an absolute path: cargo runs the test from `nvs-image/`.
//!
//! The dump holds the device's secrets (private key, Wi-Fi password): keep it
//! outside the repository, never commit it. The test prints the thing name
//! and the lengths of what it found, nothing else.

use device_core::nvs::{load_identity, IdentityLayout};

#[test]
fn a_real_dump_holds_an_identity() {
    let Some(path) = std::env::var_os("NVS_DUMP") else {
        println!("skipped: set NVS_DUMP=<dump path> and NVS_LAYOUT=secure-element|soft-key");
        return;
    };
    let layout = match std::env::var("NVS_LAYOUT").as_deref() {
        Ok("secure-element") => IdentityLayout::SecureElement,
        Ok("soft-key") => IdentityLayout::SoftKey,
        other => panic!("NVS_LAYOUT must be secure-element or soft-key, not {other:?}"),
    };
    let image = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (a relative NVS_DUMP is read from nvs-image/)",
            std::path::Path::new(&path).display()
        )
    });
    let partition = nvs_image::parse(&image).expect("an NVS partition image");
    println!(
        "namespaces: {:?}, skipped entries: {}",
        partition.namespaces().collect::<Vec<_>>(),
        partition.skipped()
    );
    let kv = partition
        .namespace(layout.namespace())
        .unwrap_or_else(|| panic!("no `{}` namespace in the dump", layout.namespace()));
    let id = load_identity(layout, kv)
        .expect("the identity keys have the frozen types")
        .expect("a complete identity");
    println!(
        "thing {}: certificate {} B, public key {} chars, private key {} B",
        id.thing_name,
        id.certificate_pem.len(),
        id.public_key.len(),
        id.private_key_pem.len()
    );
    match layout {
        IdentityLayout::SecureElement => assert!(
            id.public_key.is_empty() || id.public_key.len() == 128,
            "pubkey is X||Y hex"
        ),
        IdentityLayout::SoftKey => assert!(id.private_key_pem.contains("PRIVATE KEY")),
    }
}
