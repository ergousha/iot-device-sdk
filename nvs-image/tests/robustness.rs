//! Damaged, hostile and power-cut images: the parser skips what ESP-IDF would
//! skip, counts it, and never panics.

mod common;

use common::{entry, fixture, image, seal, Page, Rng, ACTIVE, FULL, PAGE};
use device_core::nvs::{load_identity, IdentityLayout, Kv};

/// The byte offset of the entry header for `key` in an image.
fn entry_offset(image: &[u8], ty: u8, key: &str) -> usize {
    let mut padded = [0u8; 16];
    padded[..key.len()].copy_from_slice(key.as_bytes());
    (0..image.len() / PAGE)
        .flat_map(|p| (0..126).map(move |i| p * PAGE + Page::offset(i)))
        .find(|&at| image[at + 1] == ty && image[at + 8..at + 24] == padded)
        .unwrap_or_else(|| panic!("no entry for {key}"))
}

fn identity(image: &[u8]) -> Option<device_core::nvs::Identity> {
    let p = nvs_image::parse(image).unwrap();
    let kv = p.namespace("cloud")?;
    load_identity(IdentityLayout::SecureElement, kv).unwrap()
}

#[test]
fn a_truncated_image_is_an_error() {
    let image = fixture("vaktus.bin");
    for len in [image.len() - 1, PAGE + 1, 4095, 1] {
        let err = nvs_image::parse(&image[..len]).unwrap_err();
        assert!(err.contains("4096"), "{err}");
    }
    let empty = nvs_image::parse(&[]).unwrap();
    assert_eq!(empty.namespaces().count(), 0);
}

#[test]
fn erased_flash_is_an_empty_partition() {
    for fill in [0xFF, 0x00] {
        let p = nvs_image::parse(&vec![fill; 6 * PAGE]).unwrap();
        assert_eq!(p.namespaces().count(), 0);
        assert_eq!(p.skipped(), 0);
    }
}

#[test]
fn a_damaged_entry_header_is_skipped_and_counted_once() {
    let mut image = fixture("vaktus.bin");
    let at = entry_offset(&image, 0x21, "thing");
    image[at + 9] ^= 0x01; // "thing" -> "tiing": the CRC no longer matches
    let p = nvs_image::parse(&image).unwrap();
    assert_eq!(p.skipped(), 1);
    let cloud = p.namespace("cloud").unwrap();
    assert_eq!(cloud.get_str("thing").unwrap(), None);
    assert!(
        cloud.get_str("cert").unwrap().is_some(),
        "the rest still reads"
    );
    assert_eq!(identity(&image), None, "no thing name, no identity");

    // A header spanning 40 entries: its payload entries are not counted again.
    let mut image = fixture("vaktus.bin");
    let at = entry_offset(&image, 0x21, "cert");
    image[at + 2] ^= 0x01; // span
    let p = nvs_image::parse(&image).unwrap();
    assert_eq!(p.skipped(), 1);
    assert_eq!(p.namespace("cloud").unwrap().get_str("cert").unwrap(), None);
    assert_eq!(
        p.namespace("cloud")
            .unwrap()
            .get_str("pubkey")
            .unwrap()
            .as_deref(),
        Some("0123456789ABCDEF".repeat(8).as_str()),
        "the item after the damaged span still reads"
    );
}

#[test]
fn a_damaged_payload_is_skipped_and_counted() {
    let mut image = fixture("vaktus.bin");
    let at = entry_offset(&image, 0x21, "cert");
    image[at + 32 + 100] ^= 0x20;
    let p = nvs_image::parse(&image).unwrap();
    assert_eq!(p.skipped(), 1);
    assert_eq!(p.namespace("cloud").unwrap().get_str("cert").unwrap(), None);
    assert_eq!(identity(&image), None);
}

#[test]
fn a_damaged_blob_chunk_drops_the_blob() {
    let mut image = fixture("vaktus.bin");
    // The second chunk of large_blob: page 1, entry 0.
    let at = PAGE + Page::offset(0);
    assert_eq!(&image[at + 8..at + 18], b"large_blob");
    image[at + 32 + 7] ^= 0xFF;
    let p = nvs_image::parse(&image).unwrap();
    // The chunk's CRC, then the blob it belongs to.
    assert_eq!(p.skipped(), 2);
    assert_eq!(p.namespace("fixture"), None);
    assert!(identity(&image).is_some(), "other namespaces are untouched");
}

#[test]
fn a_page_with_a_bad_header_crc_is_ignored() {
    let mut image = fixture("gateway.bin");
    image[4] ^= 0x01; // sequence number, under the header CRC
    let p = nvs_image::parse(&image).unwrap();
    assert_eq!(p.namespaces().count(), 0);
}

#[test]
fn a_newer_format_version_is_an_error() {
    let image = Page::with_version(FULL, 0, 0xFD).bytes();
    let err = nvs_image::parse(&image).unwrap_err();
    assert!(err.contains("newer"), "{err}");
}

#[test]
fn a_duplicate_on_a_higher_sequence_page_wins() {
    // The newer page first in flash: the sequence number decides, not the
    // position.
    let mut newer = Page::new(ACTIVE, 7);
    newer.str(1, "thing", "NEWER");
    newer.u32(1, "count", 2);
    let mut older = Page::new(FULL, 3);
    older.namespace("cloud", 1);
    older.str(1, "thing", "OLDER");
    older.u32(1, "count", 1);
    older.str(1, "only_old", "kept");
    let p = nvs_image::parse(&image([newer, older])).unwrap();
    let kv = p.namespace("cloud").unwrap();
    assert_eq!(kv.get_str("thing").unwrap().as_deref(), Some("NEWER"));
    assert_eq!(kv.get_u32("count").unwrap(), Some(2));
    assert_eq!(kv.get_str("only_old").unwrap().as_deref(), Some("kept"));
    assert_eq!(p.skipped(), 0);
}

#[test]
fn within_a_page_the_later_entry_wins() {
    let mut page = Page::new(ACTIVE, 0);
    page.namespace("platform", 1);
    page.u32(1, "boot_cnt", 1);
    page.u32(1, "boot_cnt", 2);
    page.str(1, "boot_fw", "0.4.0");
    let erased = page.str(1, "boot_fw", "0.5.0");
    page.set_state(erased, 0b00); // erased: not read
    let p = nvs_image::parse(&page.bytes()).unwrap();
    let kv = p.namespace("platform").unwrap();
    assert_eq!(kv.get_u32("boot_cnt").unwrap(), Some(2));
    assert_eq!(kv.get_str("boot_fw").unwrap().as_deref(), Some("0.4.0"));
}

#[test]
fn a_blob_with_a_missing_chunk_falls_back_to_an_older_complete_copy() {
    // Version at chunk_start 0 is complete; the rewrite at chunk_start 128
    // lost its second chunk.
    let mut old = Page::new(FULL, 1);
    old.namespace("ota_job", 1);
    old.chunk(1, "pending", 0, b"old-");
    old.chunk(1, "pending", 1, b"copy");
    old.blob_index(1, "pending", 8, 2, 0);
    let mut new = Page::new(ACTIVE, 2);
    new.chunk(1, "pending", 128, b"new-");
    new.blob_index(1, "pending", 8, 2, 128);
    let p = nvs_image::parse(&image([old, new])).unwrap();
    let kv = p.namespace("ota_job").unwrap();
    assert_eq!(
        kv.get_blob("pending").unwrap().as_deref(),
        Some(&b"old-copy"[..])
    );
    assert_eq!(p.skipped(), 1, "the incomplete newer copy");
}

#[test]
fn a_blob_whose_size_disagrees_is_skipped() {
    let mut page = Page::new(ACTIVE, 0);
    page.namespace("ota_job", 1);
    page.chunk(1, "pending", 0, b"abc");
    page.blob_index(1, "pending", 4, 1, 0);
    page.chunk(1, "attempts", 0, b"abc");
    page.blob_index(1, "attempts", 3, 1, 0);
    // Chunks nobody names are ignored, as ESP-IDF erases them.
    page.chunk(1, "orphan", 0, b"xyz");
    let p = nvs_image::parse(&page.bytes()).unwrap();
    let kv = p.namespace("ota_job").unwrap();
    assert_eq!(kv.get_blob("pending").unwrap(), None);
    assert_eq!(
        kv.get_blob("attempts").unwrap().as_deref(),
        Some(&b"abc"[..])
    );
    assert_eq!(kv.0.len(), 1);
    assert_eq!(p.skipped(), 1);
}

#[test]
fn a_span_that_is_not_fully_written_is_skipped() {
    let mut page = Page::new(ACTIVE, 0);
    page.namespace("wifi", 1);
    let at = page.str(1, "ssid", &"x".repeat(40)); // header + 2 payload entries
    page.set_state(at + 2, 0b11); // power cut before the last was marked
    page.u32(1, "after", 9);
    let p = nvs_image::parse(&page.bytes()).unwrap();
    let kv = p.namespace("wifi").unwrap();
    assert_eq!(kv.get_str("ssid").unwrap(), None);
    assert_eq!(kv.get_u32("after").unwrap(), Some(9));
    assert_eq!(p.skipped(), 1);
}

#[test]
fn inconsistent_headers_with_valid_crcs_are_skipped() {
    let mut page = Page::new(FULL, 0);
    page.namespace("ns", 1);
    let size = |n: u16| {
        let mut d = [0xFF; 8];
        d[0..2].copy_from_slice(&n.to_le_bytes());
        d
    };
    page.raw(&[
        entry(1, 0x04, 2, 0xFF, "span2", [0; 8]), // integer with span 2
        entry(1, 0x21, 2, 0xFF, "toolong", size(100)), // span disagrees with size
        entry(1, 0x21, 126, 0xFF, "pastend", size(3968)), // runs past the page
        entry(1, 0x42, 2, 0xFF, "chunkany", size(4)), // chunk with CHUNK_ANY
        entry(1, 0x48, 1, 0, "idxchunk", [0; 8]), // index with a chunk index
        entry(1, 0x48, 1, 0xFF, "huge", [0xFF; 8]), // index larger than possible
        entry(1, 0x77, 1, 0xFF, "badtype", [0; 8]), // unknown type
    ]);
    page.u32(1, "fine", 1);
    let p = nvs_image::parse(&page.bytes()).unwrap();
    assert_eq!(
        p.namespace("ns").unwrap().0.keys().collect::<Vec<_>>(),
        ["fine"]
    );
    assert_eq!(p.skipped(), 1, "one run of bad entries");
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for round in 0..300 {
        let pages = 1 + rng.below(4);
        let mut image = vec![0u8; pages * PAGE];
        rng.fill(&mut image);
        for p in 0..pages {
            let page = &mut image[p * PAGE..(p + 1) * PAGE];
            if round % 3 != 0 {
                // A valid page header, so the entries are actually read.
                let state = [ACTIVE, FULL, 0xFFFF_FFF8][rng.below(3)];
                page[0..4].copy_from_slice(&state.to_le_bytes());
                page[8] = 0xFE | (rng.byte() & 1);
                let crc = common::crc32(&page[4..28]);
                page[28..32].copy_from_slice(&crc.to_le_bytes());
            }
            if round % 3 == 2 {
                // Valid CRCs on random headers: exercises the span and size
                // checks with hostile values.
                for i in 0..126 {
                    let at = Page::offset(i);
                    let e: &mut [u8; 32] = (&mut page[at..at + 32]).try_into().unwrap();
                    e[0] = rng.byte() % 4;
                    e[1] = [0x01, 0x04, 0x21, 0x41, 0x42, 0x48, 0x18, 0x99][rng.below(8)];
                    if rng.below(2) == 0 {
                        e[0] = 0;
                        e[1] = 0x01;
                        e[2] = 1;
                    }
                    seal(e);
                }
            }
        }
        let _ = nvs_image::parse(&image);
    }
}

#[test]
fn mutated_fixtures_never_panic() {
    let mut rng = Rng(42);
    for name in ["vaktus.bin", "gateway.bin", "types_v1.bin"] {
        let original = fixture(name);
        for _ in 0..300 {
            let mut image = original.clone();
            for _ in 0..1 + rng.below(8) {
                let at = rng.below(image.len());
                image[at] ^= 1 << rng.below(8);
            }
            let p = nvs_image::parse(&image).expect("same length, same format");
            let _ = p.namespaces().count();
        }
    }
}

#[test]
fn debug_output_names_keys_but_never_values() {
    let p = nvs_image::parse(&fixture("gateway.bin")).unwrap();
    let debug = format!("{p:?}");
    assert!(
        debug.contains("device_id") && debug.contains("\"key\""),
        "{debug}"
    );
    assert!(
        !debug.contains("FAKE") && !debug.contains("PRIVATE"),
        "{debug}"
    );
}
