//! A minimal NVS page writer for tests that need images ESP-IDF's generator
//! cannot produce: duplicates, sequence numbers out of order, damaged entries.
//! The fixtures in `fixtures/` come from Espressif's own generator instead.

#![allow(dead_code)]

pub const PAGE: usize = 4096;
pub const ACTIVE: u32 = 0xFFFF_FFFE;
pub const FULL: u32 = 0xFFFF_FFFC;
pub const V2: u8 = 0xFE;

pub const U32: u8 = 0x04;
pub const U8: u8 = 0x01;
pub const SZ: u8 = 0x21;
pub const BLOB_DATA: u8 = 0x42;
pub const BLOB_IDX: u8 = 0x48;

pub fn crc32(data: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new_with_initial(0xFFFF_FFFF);
    h.update(data);
    h.finalize()
}

/// One 32-byte entry header with a correct CRC.
pub fn entry(ns: u8, ty: u8, span: u8, chunk: u8, key: &str, data: [u8; 8]) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0] = ns;
    e[1] = ty;
    e[2] = span;
    e[3] = chunk;
    e[8..8 + key.len()].copy_from_slice(key.as_bytes());
    e[24..32].copy_from_slice(&data);
    seal(&mut e);
    e
}

/// Recomputes an entry header's CRC.
pub fn seal(e: &mut [u8; 32]) {
    let mut h = crc32fast::Hasher::new_with_initial(0xFFFF_FFFF);
    h.update(&e[0..4]);
    h.update(&e[8..32]);
    let crc = h.finalize();
    e[4..8].copy_from_slice(&crc.to_le_bytes());
}

pub struct Page {
    buf: Vec<u8>,
    next: usize,
}

impl Page {
    pub fn new(state: u32, seq: u32) -> Self {
        Self::with_version(state, seq, V2)
    }

    pub fn with_version(state: u32, seq: u32, version: u8) -> Self {
        let mut buf = vec![0xFF; PAGE];
        buf[0..4].copy_from_slice(&state.to_le_bytes());
        buf[4..8].copy_from_slice(&seq.to_le_bytes());
        buf[8] = version;
        let crc = crc32(&buf[4..28]);
        buf[28..32].copy_from_slice(&crc.to_le_bytes());
        Self { buf, next: 0 }
    }

    /// Writes raw 32-byte entries and marks them written; returns the index
    /// of the first.
    pub fn raw(&mut self, entries: &[[u8; 32]]) -> usize {
        let first = self.next;
        for e in entries {
            let at = 64 + self.next * 32;
            self.buf[at..at + 32].copy_from_slice(e);
            self.set_state(self.next, 0b10);
            self.next += 1;
        }
        first
    }

    pub fn set_state(&mut self, index: usize, state: u8) {
        let byte = &mut self.buf[32 + index / 4];
        let shift = (index % 4) * 2;
        *byte = (*byte & !(0b11 << shift)) | (state << shift);
    }

    pub fn namespace(&mut self, name: &str, index: u8) -> usize {
        let mut data = [0xFF; 8];
        data[0] = index;
        self.raw(&[entry(0, U8, 1, 0xFF, name, data)])
    }

    pub fn u32(&mut self, ns: u8, key: &str, value: u32) -> usize {
        let mut data = [0xFF; 8];
        data[0..4].copy_from_slice(&value.to_le_bytes());
        self.raw(&[entry(ns, U32, 1, 0xFF, key, data)])
    }

    /// A string, stored with its NUL as ESP-IDF does.
    pub fn str(&mut self, ns: u8, key: &str, value: &str) -> usize {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.var_len(ns, SZ, 0xFF, key, &bytes)
    }

    pub fn chunk(&mut self, ns: u8, key: &str, chunk: u8, data: &[u8]) -> usize {
        self.var_len(ns, BLOB_DATA, chunk, key, data)
    }

    pub fn blob_index(&mut self, ns: u8, key: &str, size: u32, count: u8, start: u8) -> usize {
        let mut data = [0xFF; 8];
        data[0..4].copy_from_slice(&size.to_le_bytes());
        data[4] = count;
        data[5] = start;
        self.raw(&[entry(ns, BLOB_IDX, 1, 0xFF, key, data)])
    }

    pub fn var_len(&mut self, ns: u8, ty: u8, chunk: u8, key: &str, payload: &[u8]) -> usize {
        let n = payload.len().div_ceil(32);
        let mut data = [0xFF; 8];
        data[0..2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        data[4..8].copy_from_slice(&crc32(payload).to_le_bytes());
        let mut entries = vec![entry(ns, ty, (n + 1) as u8, chunk, key, data)];
        for c in payload.chunks(32) {
            let mut e = [0xFF; 32];
            e[..c.len()].copy_from_slice(c);
            entries.push(e);
        }
        self.raw(&entries)
    }

    /// The byte offset of entry `index` within the page.
    pub fn offset(index: usize) -> usize {
        64 + index * 32
    }

    pub fn bytes(self) -> Vec<u8> {
        self.buf
    }
}

pub fn image(pages: impl IntoIterator<Item = Page>) -> Vec<u8> {
    pages.into_iter().flat_map(Page::bytes).collect()
}

/// A small deterministic PRNG (xorshift64*), so the fuzz tests are
/// reproducible without a dependency.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    pub fn byte(&mut self) -> u8 {
        self.next() as u8
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            *b = self.byte();
        }
    }
}

pub fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}
