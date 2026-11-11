//! Reads an ESP-IDF NVS partition image on the host.
//!
//! The image is the raw bytes of an `nvs`-subtype data partition: a dump of a
//! device's flash (`espflash read-flash <offset> <size> dump.nvs.bin`,
//! `esptool.py read_flash`) or the output of ESP-IDF's
//! `nvs_partition_gen.py`. [`parse`] turns it into one
//! [`MemKv`](device_core::nvs::MemKv) per namespace, so the same
//! `device_core::nvs` logic the firmware runs (`load_identity` and friends)
//! can run on the host against what a real device has in flash. That is how
//! the platform proves a new SDK reads the identity records devices in the
//! field already hold.
//!
//! ```no_run
//! use device_core::nvs::{load_identity, IdentityLayout};
//!
//! # fn main() -> Result<(), String> {
//! let image = std::fs::read("dumps/vaktus.nvs.bin").map_err(|e| e.to_string())?;
//! let partition = nvs_image::parse(&image)?;
//! let layout = IdentityLayout::SecureElement;
//! let identity = match partition.namespace(layout.namespace()) {
//!     Some(kv) => load_identity(layout, kv)?,
//!     None => None,
//! };
//! println!("{:?}", identity.map(|id| id.thing_name));
//! # Ok(())
//! # }
//! ```
//!
//! # Secrets
//!
//! **Never commit a real dump.** A device's NVS holds its private key (soft-key
//! products), its certificate, the claim credential if it was never erased,
//! and Wi-Fi passwords. Keep dumps outside the repository, or under `dumps/`
//! or named `*.nvs.bin` (both are git-ignored here), and point the dump test
//! at one with `NVS_DUMP=<path> NVS_LAYOUT=secure-element|soft-key`. The test
//! fixtures in `tests/fixtures/` are generated from CSVs with fake PEMs.
//! [`Partition`]'s `Debug` prints namespace and key names only, never values.
//!
//! # Format (ESP-IDF v5 `nvs_flash`, format version 2)
//!
//! All integers are little-endian. CRCs are CRC-32 (zlib's) seeded with
//! `0xFFFFFFFF`, i.e. `zlib.crc32(data, 0xFFFFFFFF)`.
//!
//! - The partition is a run of 4096-byte pages. A page starts with a 32-byte
//!   header: state `u32`, sequence number `u32`, format version `u8` (`0xFE`
//!   = version 2, `0xFF` = version 1), 19 reserved bytes, and the CRC of bytes
//!   4..28. States: `0xFFFFFFFF` empty, `0xFFFFFFFE` active, `0xFFFFFFFC`
//!   full, `0xFFFFFFF8` freeing, `0xFFFFFFF0` corrupt. Active, full and
//!   freeing pages are read; any other state, or a header whose CRC fails, is
//!   skipped as ESP-IDF does. A version below `0xFE` is a newer format than
//!   this reader knows, and is an error.
//! - 32 bytes of entry-state bitmap follow: 2 bits per entry, entry `i` at bits
//!   `2*(i%4)` of byte `i/4`. `0b11` empty, `0b10` written, `0b00` erased.
//!   Only written entries are read.
//! - Then 126 entries of 32 bytes: namespace index `u8`, type `u8`, span `u8`,
//!   chunk index `u8`, CRC `u32` (over bytes 0..4 and 8..32), key `[u8; 16]`
//!   (NUL-padded), data `[u8; 8]`.
//! - Namespace index 0 holds the namespace table: a `u8` item whose key is the
//!   namespace name and whose value is its index.
//! - Integers (`u8 0x01`, `i8 0x11`, `u16 0x02`, `i16 0x12`, `u32 0x04`,
//!   `i32 0x14`, `u64 0x08`, `i64 0x18`) sit in the data field, span 1.
//! - Strings (`0x21`), version-1 blobs (`0x41`) and blob chunks (`0x42`):
//!   data is size `u16`, reserved `u16`, CRC of the payload `u32`; the payload
//!   fills the next `span - 1` entries of the same page. Strings are stored
//!   with their NUL terminator.
//! - Version-2 blobs are split into chunks of at most one page: a blob index
//!   (`0x48`, chunk index `0xFF`, data: total size `u32`, chunk count `u8`,
//!   first chunk index `u8`) names chunks `start..start+count`, each a `0x42`
//!   item with the same namespace and key. The first chunk index is 0 or 128,
//!   alternating as the blob is rewritten, so old and new chunks never clash.
//!
//! # How the reader resolves an image
//!
//! - An entry whose CRC fails, whose type is unknown, or whose span or size is
//!   inconsistent is skipped, as ESP-IDF skips (erases) it at mount. A run of
//!   such entries counts once in [`Partition::skipped`]: the payload entries
//!   of an item whose header is damaged are not counted again.
//! - A string or blob whose payload CRC fails, or whose span is not fully
//!   written, is skipped and counted.
//! - If an item appears more than once (a power cut between writing the new
//!   copy and erasing the old one), the copy on the page with the higher
//!   sequence number wins, and within a page the later entry.
//! - A version-2 blob is reassembled from the chunks its newest index names. A
//!   blob with a missing chunk or whose chunk sizes do not add up to its size
//!   is skipped and counted; an older complete copy, if any, is used instead.
//!   Chunks no index names (left by a power cut) are ignored, as ESP-IDF
//!   erases them.
//! - Strings end at their first NUL. A string that is not UTF-8 is kept as a
//!   [`Value::Blob`] of its stored bytes, so `get_str` reports the type.
//! - `u32` reads as [`Value::U32`]; every other integer as [`Value::Int`]
//!   with its ESP-IDF type code.
//!
//! The reader never panics: sizes and spans come from flash and are checked
//! before use. It does not decrypt: an encrypted NVS partition (NVS
//! encryption, or flash encryption without a decrypting read) reads as
//! garbage, i.e. as an empty partition or skipped entries.

use std::collections::BTreeMap;
use std::fmt;

use device_core::nvs::{MemKv, Value};

const PAGE_SIZE: usize = 4096;
const ENTRY_SIZE: usize = 32;
const ENTRY_COUNT: usize = 126;
const ENTRY_TABLE_OFFSET: usize = 32;
const FIRST_ENTRY_OFFSET: usize = 64;

const PAGE_ACTIVE: u32 = 0xFFFF_FFFE;
const PAGE_FULL: u32 = 0xFFFF_FFFC;
const PAGE_FREEING: u32 = 0xFFFF_FFF8;

/// Format version 2 (multi-page blobs); version 1 is `0xFF`. Lower is newer.
const NVS_VERSION: u8 = 0xFE;

const ENTRY_WRITTEN: u8 = 0b10;
const CHUNK_ANY: u8 = 0xFF;
const NS_INDEX: u8 = 0;
const NS_ANY: u8 = 0xFF;

/// ESP-IDF's `ItemType`.
mod ty {
    pub const U8: u8 = 0x01;
    pub const I8: u8 = 0x11;
    pub const U16: u8 = 0x02;
    pub const I16: u8 = 0x12;
    pub const U32: u8 = 0x04;
    pub const I32: u8 = 0x14;
    pub const U64: u8 = 0x08;
    pub const I64: u8 = 0x18;
    pub const SZ: u8 = 0x21;
    pub const BLOB: u8 = 0x41;
    pub const BLOB_DATA: u8 = 0x42;
    pub const BLOB_IDX: u8 = 0x48;
}

/// The largest size a blob index may declare (`Item::checkHeaderConsistency`):
/// 127 chunks of one page each.
const MAX_BLOB_SIZE: u32 = (u8::MAX as u32 / 2) * (ENTRY_COUNT as u32 - 1) * ENTRY_SIZE as u32;

/// A parsed NVS partition: its namespaces and their entries.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Partition {
    namespaces: BTreeMap<String, MemKv>,
    skipped: usize,
}

impl Partition {
    /// The entries of one namespace, if it has any.
    pub fn namespace(&self, name: &str) -> Option<&MemKv> {
        self.namespaces.get(name)
    }

    /// Every namespace name present (with at least one entry), in order.
    pub fn namespaces(&self) -> impl Iterator<Item = &str> {
        self.namespaces.keys().map(String::as_str)
    }

    /// Entries skipped because of a bad CRC or an inconsistent span/blob.
    pub fn skipped(&self) -> usize {
        self.skipped
    }
}

/// Names and types only: a partition holds private keys and passwords.
impl fmt::Debug for Partition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Keys<'a>(&'a MemKv);
        impl fmt::Debug for Keys<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_map()
                    .entries(self.0 .0.iter().map(|(k, v)| (k, type_name(v))))
                    .finish()
            }
        }
        f.debug_struct("Partition")
            .field(
                "namespaces",
                &self
                    .namespaces
                    .iter()
                    .map(|(name, kv)| (name, Keys(kv)))
                    .collect::<BTreeMap<_, _>>(),
            )
            .field("skipped", &self.skipped)
            .finish()
    }
}

fn type_name(value: &Value) -> String {
    match value {
        Value::U32(_) => "u32".into(),
        Value::Str(s) => format!("str[{}]", s.len()),
        Value::Blob(b) => format!("blob[{}]", b.len()),
        Value::Int { ty, .. } => format!("int({ty:#04x})"),
    }
}

/// Parses an NVS partition image.
///
/// Errors only when the image cannot be an NVS partition at all: its length
/// is not a whole number of pages, or a page declares a newer NVS format
/// than this reader knows. Damaged entries are skipped and counted
/// ([`Partition::skipped`]); an image with no readable page (erased flash,
/// all `0xFF`) is an empty partition.
pub fn parse(image: &[u8]) -> Result<Partition, String> {
    if image.len() % PAGE_SIZE != 0 {
        return Err(format!(
            "NVS image is {} bytes, not a whole number of {PAGE_SIZE}-byte pages",
            image.len()
        ));
    }
    let mut found = Found::default();
    for (page_no, page) in image.chunks_exact(PAGE_SIZE).enumerate() {
        found.read_page(page_no, page)?;
    }
    Ok(found.resolve())
}

/// Where an item was found: a greater `Order` is a newer write.
/// (sequence number, page position, entry index)
type Order = (u32, usize, usize);

enum Item {
    Value(Value),
    BlobIndex {
        size: u32,
        chunk_count: u8,
        chunk_start: u8,
    },
}

/// One blob's chunks: chunk index → (where, payload), newest copy only.
type Chunks = BTreeMap<u8, (Order, Vec<u8>)>;

/// Everything readable in the image, before duplicates are resolved.
#[derive(Default)]
struct Found {
    /// Namespace name → (where, index), newest definition only.
    namespaces: BTreeMap<String, (Order, u8)>,
    /// (namespace index, key) → every copy found.
    items: BTreeMap<(u8, String), Vec<(Order, Item)>>,
    /// (namespace index, key) → chunk index → newest chunk.
    chunks: BTreeMap<(u8, String), Chunks>,
    skipped: usize,
}

/// A checked entry header.
struct Header {
    ns: u8,
    ty: u8,
    span: u8,
    chunk: u8,
    key: String,
    data: [u8; 8],
}

impl Header {
    /// Port of `Item::checkHeaderConsistency`: CRC, known type, and span and
    /// size consistent with each other and with the room left in the page.
    fn check(entry: &[u8], index: usize) -> Option<Header> {
        let raw: &[u8; ENTRY_SIZE] = entry.try_into().ok()?;
        let crc = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let mut hasher = crc32fast::Hasher::new_with_initial(0xFFFF_FFFF);
        hasher.update(&raw[0..4]);
        hasher.update(&raw[8..32]);
        if hasher.finalize() != crc {
            return None;
        }
        let mut data = [0u8; 8];
        data.copy_from_slice(&raw[24..32]);
        let key_bytes = &raw[8..24];
        let key_len = key_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let header = Header {
            ns: raw[0],
            ty: raw[1],
            span: raw[2],
            chunk: raw[3],
            key: String::from_utf8_lossy(&key_bytes[..key_len]).into_owned(),
            data,
        };
        let consistent = match header.ty {
            ty::U8 | ty::I8 | ty::U16 | ty::I16 | ty::U32 | ty::I32 | ty::U64 | ty::I64 => {
                header.span == 1
            }
            ty::BLOB_IDX => {
                header.span == 1
                    && header.chunk == CHUNK_ANY
                    && header.blob_index().0 <= MAX_BLOB_SIZE
            }
            ty::SZ | ty::BLOB | ty::BLOB_DATA => {
                let (size, _) = header.var_len();
                let size = usize::from(size);
                let room = ENTRY_COUNT.saturating_sub(index);
                (header.ty != ty::BLOB_DATA || header.chunk != CHUNK_ANY)
                    && size <= room.saturating_sub(1) * ENTRY_SIZE
                    && usize::from(header.span) <= room
                    && usize::from(header.span) == size.div_ceil(ENTRY_SIZE) + 1
            }
            _ => false,
        };
        consistent.then_some(header)
    }

    fn is_var_len(&self) -> bool {
        matches!(self.ty, ty::SZ | ty::BLOB | ty::BLOB_DATA)
    }

    /// (payload size, payload CRC) of a string or blob (chunk).
    fn var_len(&self) -> (u16, u32) {
        let d = &self.data;
        (
            u16::from_le_bytes([d[0], d[1]]),
            u32::from_le_bytes([d[4], d[5], d[6], d[7]]),
        )
    }

    /// (total size, chunk count, first chunk index) of a blob index.
    fn blob_index(&self) -> (u32, u8, u8) {
        let d = &self.data;
        (u32::from_le_bytes([d[0], d[1], d[2], d[3]]), d[4], d[5])
    }

    /// The value of an integer item.
    fn integer(&self) -> Option<Value> {
        let d = &self.data;
        let value: i128 = match self.ty {
            ty::U32 => return Some(Value::U32(u32::from_le_bytes([d[0], d[1], d[2], d[3]]))),
            ty::U8 => d[0].into(),
            ty::I8 => i8::from_le_bytes([d[0]]).into(),
            ty::U16 => u16::from_le_bytes([d[0], d[1]]).into(),
            ty::I16 => i16::from_le_bytes([d[0], d[1]]).into(),
            ty::I32 => i32::from_le_bytes([d[0], d[1], d[2], d[3]]).into(),
            ty::U64 => u64::from_le_bytes(*d).into(),
            ty::I64 => i64::from_le_bytes(*d).into(),
            _ => return None,
        };
        Some(Value::Int { ty: self.ty, value })
    }
}

fn crc32(data: &[u8]) -> u32 {
    let mut hasher = crc32fast::Hasher::new_with_initial(0xFFFF_FFFF);
    hasher.update(data);
    hasher.finalize()
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    bytes
        .get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(u32::MAX)
}

impl Found {
    fn read_page(&mut self, page_no: usize, page: &[u8]) -> Result<(), String> {
        if page.len() != PAGE_SIZE {
            return Ok(());
        }
        let state = le32(page, 0);
        if !matches!(state, PAGE_ACTIVE | PAGE_FULL | PAGE_FREEING) {
            return Ok(());
        }
        if crc32(&page[4..28]) != le32(page, 28) {
            // ESP-IDF marks the page corrupt and reads nothing from it.
            return Ok(());
        }
        let seq = le32(page, 4);
        let version = page[8];
        if version < NVS_VERSION {
            return Err(format!(
                "page {page_no} is NVS format version {version:#04x}, newer than this reader \
                 (it reads {NVS_VERSION:#04x} and 0xff)"
            ));
        }

        let table = &page[ENTRY_TABLE_OFFSET..FIRST_ENTRY_OFFSET];
        let written = |i: usize| (table[i / 4] >> ((i % 4) * 2)) & 0b11 == ENTRY_WRITTEN;
        let entry = |i: usize| {
            let start = FIRST_ENTRY_OFFSET + i * ENTRY_SIZE;
            &page[start..start + ENTRY_SIZE]
        };

        let mut i = 0;
        let mut in_bad_run = false;
        while i < ENTRY_COUNT {
            if !written(i) {
                in_bad_run = false;
                i += 1;
                continue;
            }
            let Some(header) = Header::check(entry(i), i) else {
                if !in_bad_run {
                    self.skipped += 1;
                }
                in_bad_run = true;
                i += 1;
                continue;
            };
            in_bad_run = false;
            let order = (seq, page_no, i);

            if !header.is_var_len() {
                self.add_fixed(order, header);
                i += 1;
                continue;
            }

            // `check` bounds span and size by the room left in the page.
            let span = usize::from(header.span).max(1);
            let (size, data_crc) = header.var_len();
            let start = FIRST_ENTRY_OFFSET + (i + 1) * ENTRY_SIZE;
            let payload = page.get(start..start + usize::from(size));
            let whole = (i + 1..i + span).all(|j| j < ENTRY_COUNT && written(j));
            match payload {
                Some(payload) if whole && crc32(payload) == data_crc => {
                    self.add_var_len(order, header, payload.to_vec());
                }
                _ => self.skipped += 1,
            }
            i += span;
        }
        Ok(())
    }

    fn add_fixed(&mut self, order: Order, header: Header) {
        if header.ns == NS_INDEX {
            if header.ty == ty::U8 {
                let index = header.data[0];
                if index != NS_INDEX && index != NS_ANY {
                    let slot = self.namespaces.entry(header.key).or_insert((order, index));
                    if order >= slot.0 {
                        *slot = (order, index);
                    }
                }
            }
            return;
        }
        let item = if header.ty == ty::BLOB_IDX {
            let (size, chunk_count, chunk_start) = header.blob_index();
            Item::BlobIndex {
                size,
                chunk_count,
                chunk_start,
            }
        } else {
            match header.integer() {
                Some(value) => Item::Value(value),
                None => return,
            }
        };
        self.items
            .entry((header.ns, header.key))
            .or_default()
            .push((order, item));
    }

    fn add_var_len(&mut self, order: Order, header: Header, payload: Vec<u8>) {
        if header.ns == NS_INDEX {
            return;
        }
        let value = match header.ty {
            ty::BLOB_DATA => {
                let chunks = self.chunks.entry((header.ns, header.key)).or_default();
                let slot = chunks.entry(header.chunk).or_insert((order, Vec::new()));
                if order >= slot.0 {
                    *slot = (order, payload);
                }
                return;
            }
            ty::SZ => {
                let end = payload
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(payload.len());
                match std::str::from_utf8(&payload[..end]) {
                    Ok(s) => Value::Str(s.to_owned()),
                    Err(_) => Value::Blob(payload),
                }
            }
            _ => Value::Blob(payload),
        };
        self.items
            .entry((header.ns, header.key))
            .or_default()
            .push((order, Item::Value(value)));
    }

    fn resolve(self) -> Partition {
        let Found {
            namespaces,
            items,
            chunks,
            mut skipped,
        } = self;

        // Namespace index → name. Two names claiming one index is corruption;
        // the newer definition wins.
        let mut names: BTreeMap<u8, (Order, String)> = BTreeMap::new();
        for (name, (order, index)) in namespaces {
            match names.get(&index) {
                Some((other, _)) if *other > order => {}
                _ => {
                    names.insert(index, (order, name));
                }
            }
        }

        let mut out: BTreeMap<String, MemKv> = BTreeMap::new();
        for ((ns, key), mut copies) in items {
            let Some((_, ns_name)) = names.get(&ns) else {
                continue;
            };
            copies.sort_by_key(|(order, _)| *order);
            let blob_chunks = chunks.get(&(ns, key.clone()));
            let mut value = None;
            for (_, item) in copies.into_iter().rev() {
                match item {
                    Item::Value(v) => {
                        value = Some(v);
                        break;
                    }
                    Item::BlobIndex {
                        size,
                        chunk_count,
                        chunk_start,
                    } => match assemble(blob_chunks, size, chunk_count, chunk_start) {
                        Some(blob) => {
                            value = Some(Value::Blob(blob));
                            break;
                        }
                        None => skipped += 1,
                    },
                }
            }
            if let Some(value) = value {
                out.entry(ns_name.clone()).or_default().0.insert(key, value);
            }
        }
        Partition {
            namespaces: out,
            skipped,
        }
    }
}

/// Joins chunks `start..start+count`; `None` if one is missing or the sizes
/// do not add up.
fn assemble(chunks: Option<&Chunks>, size: u32, count: u8, start: u8) -> Option<Vec<u8>> {
    let size = usize::try_from(size).ok()?;
    let mut blob = Vec::new();
    for k in 0..count {
        let index = start.checked_add(k).filter(|&i| i != CHUNK_ANY)?;
        let (_, chunk) = chunks?.get(&index)?;
        if blob.len() + chunk.len() > size {
            return None;
        }
        blob.extend_from_slice(chunk);
    }
    (blob.len() == size).then_some(blob)
}
