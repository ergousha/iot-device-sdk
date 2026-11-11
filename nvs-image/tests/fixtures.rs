//! The parser against images made by ESP-IDF's own `nvs_partition_gen.py`
//! (see `fixtures/README.md`), laid out as the two canaries store their data.

mod common;

use common::fixture;
use device_core::nvs::{count_boot, int_type, load_identity, IdentityLayout, Kv, MemKv, Value};

fn vaktus_cert() -> String {
    let body: String = (0..18).map(|_| "FAKE".repeat(16) + "\n").collect();
    format!("-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n")
}

const GATEWAY_CERT: &str = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n";
const GATEWAY_KEY: &str = "-----BEGIN EC PRIVATE KEY-----\nFAKE\n-----END EC PRIVATE KEY-----\n";
const PENDING: &[u8] = br#"{"job_id":"ota-vaktus-0_9_0-c","from_version":"0.8.0","target_version":"0.9.0","target_slot":"ota_1"}"#;

fn ns<'a>(p: &'a nvs_image::Partition, name: &str) -> &'a MemKv {
    p.namespace(name)
        .unwrap_or_else(|| panic!("no namespace {name}"))
}

#[test]
fn the_secure_element_identity_loads_from_a_vaktus_image() {
    let p = nvs_image::parse(&fixture("vaktus.bin")).unwrap();
    assert_eq!(p.skipped(), 0);
    let layout = IdentityLayout::SecureElement;
    let id = load_identity(layout, ns(&p, layout.namespace()))
        .unwrap()
        .expect("identity");
    assert_eq!(id.thing_name, "38182B8456F4");
    assert_eq!(id.certificate_pem, vaktus_cert());
    assert!(id.certificate_pem.len() > 1000, "spans many entries");
    assert_eq!(id.public_key, "0123456789ABCDEF".repeat(8));
    assert_eq!(id.private_key_pem, "");

    // The other layout finds nothing here.
    assert_eq!(p.namespace(IdentityLayout::SoftKey.namespace()), None);
}

#[test]
fn every_namespace_of_the_vaktus_image_reads_back_exactly() {
    let p = nvs_image::parse(&fixture("vaktus.bin")).unwrap();
    assert_eq!(
        p.namespaces().collect::<Vec<_>>(),
        ["cloud", "fixture", "ota_job", "wifi"]
    );
    assert_eq!(
        ns(&p, "cloud").0.keys().collect::<Vec<_>>(),
        ["cert", "pubkey", "thing"]
    );
    let jobs = ns(&p, "ota_job");
    assert_eq!(jobs.get_blob("pending").unwrap().as_deref(), Some(PENDING));
    assert!(jobs.get_str("pending").is_err(), "a blob is not a string");
    assert_eq!(
        ns(&p, "wifi").get_str("ssid").unwrap().as_deref(),
        Some("fake-net")
    );
}

#[test]
fn a_blob_split_over_three_pages_reassembles() {
    let image = fixture("vaktus.bin");
    let expected = fixture("large.bin");
    assert_eq!(
        expected,
        (0..9000).map(|i| (i % 251) as u8).collect::<Vec<_>>()
    );

    // The generator really split it: a blob index for it naming 3 chunks.
    let index = image
        .chunks_exact(4096)
        .flat_map(|page| page[64..].chunks_exact(32))
        .find(|e| e[1] == 0x48 && e[8..19] == *b"large_blob\0")
        .expect("a BLOB_IDX entry");
    assert_eq!(u32::from_le_bytes(index[24..28].try_into().unwrap()), 9000);
    assert_eq!(index[28], 3, "chunk count");

    let p = nvs_image::parse(&image).unwrap();
    let blob = ns(&p, "fixture").get_blob("large_blob").unwrap().unwrap();
    assert_eq!(blob, expected);
}

#[test]
fn the_soft_key_identity_loads_from_a_gateway_image() {
    let p = nvs_image::parse(&fixture("gateway.bin")).unwrap();
    assert_eq!(p.skipped(), 0);
    assert_eq!(
        p.namespaces().collect::<Vec<_>>(),
        ["device_id", "platform"]
    );
    let layout = IdentityLayout::SoftKey;
    let id = load_identity(layout, ns(&p, layout.namespace()))
        .unwrap()
        .expect("identity");
    assert_eq!(id.thing_name, "28848553144F");
    assert_eq!(id.certificate_pem, GATEWAY_CERT);
    assert_eq!(id.private_key_pem, GATEWAY_KEY);
    assert_eq!(id.public_key, "");
    assert_eq!(p.namespace(IdentityLayout::SecureElement.namespace()), None);

    let platform = ns(&p, "platform");
    assert_eq!(platform.get_u32("boot_cnt").unwrap(), Some(3));
    assert_eq!(
        platform.get_str("boot_fw").unwrap().as_deref(),
        Some("0.4.0")
    );
    // The SDK's own logic runs on what the device stored.
    let mut platform = platform.clone();
    assert_eq!(count_boot(&mut platform, "0.4.0", false).unwrap(), 4);
}

fn assert_all_types(p: &nvs_image::Partition) {
    assert_eq!(p.skipped(), 0);
    let kv = ns(p, "types");
    let int = |ty, value| Value::Int { ty, value };
    let expected = [
        ("u8", int(int_type::U8, 255)),
        ("i8", int(int_type::I8, -128)),
        ("u16", int(int_type::U16, 65535)),
        ("i16", int(int_type::I16, -32768)),
        ("u32", Value::U32(u32::MAX)),
        ("i32", int(int_type::I32, i32::MIN.into())),
        ("u64", int(int_type::U64, u64::MAX.into())),
        ("i64", int(int_type::I64, i64::MIN.into())),
        ("str", Value::Str("hello".into())),
        ("blob", Value::Blob(vec![0xDE, 0xAD, 0xBE, 0xEF])),
    ];
    for (key, value) in expected {
        assert_eq!(kv.0.get(key), Some(&value), "{key}");
    }
    assert_eq!(kv.0.len(), 10);
}

#[test]
fn every_integer_type_reads_back_in_format_version_2() {
    let image = fixture("types_v2.bin");
    assert_eq!(image[8], 0xFE);
    assert_all_types(&nvs_image::parse(&image).unwrap());
}

#[test]
fn format_version_1_single_page_blobs_read_too() {
    let image = fixture("types_v1.bin");
    assert_eq!(image[8], 0xFF);
    assert!(
        image[64..4096]
            .chunks_exact(32)
            .any(|e| e[1] == 0x41 && e[8..13] == *b"blob\0"),
        "the blob is a version-1 BLOB item"
    );
    assert_all_types(&nvs_image::parse(&image).unwrap());
}

/// A guard on the fixtures themselves: every PEM in them is fake.
#[test]
fn the_fixtures_hold_no_real_key_material() {
    for csv in ["vaktus.csv", "gateway.csv", "types.csv"] {
        let text = String::from_utf8(fixture(csv)).unwrap();
        let mut in_pem = false;
        let mut pems = 0;
        for line in text.lines() {
            if line.contains("-----BEGIN") {
                in_pem = true;
                pems += 1;
            } else if line.contains("-----END") {
                in_pem = false;
            } else if in_pem {
                let fake = !line.is_empty()
                    && line.len() % 4 == 0
                    && line.as_bytes().chunks(4).all(|c| c == b"FAKE");
                assert!(fake, "{csv}: a PEM line that is not FAKE: {line:?}");
            }
        }
        assert!(!in_pem, "{csv}: unterminated PEM");
        if csv != "types.csv" {
            assert!(pems > 0, "{csv}: the guard saw no PEM");
        }
    }
}
