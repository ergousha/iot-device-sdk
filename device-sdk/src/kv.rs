//! NVS namespaces as [`device_core::nvs::Kv`].

use anyhow::{Context, Result};
use device_core::nvs::Kv;
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

/// Largest string read back. NVS strings are at most 4000 bytes; the bound
/// keeps a corrupt length from driving the allocation.
const MAX_STR: usize = 4000;
/// Largest blob read back.
const MAX_BLOB: usize = 4096;

/// One namespace of the default `nvs` partition.
pub struct NvsKv(EspNvs<NvsDefault>);

impl NvsKv {
    /// Opens (and creates, if needed) `namespace`.
    pub fn open(partition: &EspDefaultNvsPartition, namespace: &str) -> Result<Self> {
        Ok(Self(
            EspNvs::new(partition.clone(), namespace, true)
                .with_context(|| format!("opening NVS namespace {namespace:?}"))?,
        ))
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

impl Kv for NvsKv {
    fn get_str(&self, key: &str) -> Result<Option<String>, String> {
        let Some(len) = self.0.str_len(key).map_err(err)? else {
            return Ok(None);
        };
        if len > MAX_STR + 1 {
            return Err(format!("{key} is {len} B, over the {MAX_STR} B accepted"));
        }
        let mut buf = vec![0u8; len.max(1)];
        Ok(self
            .0
            .get_str(key, &mut buf)
            .map_err(err)?
            .map(str::to_string))
    }

    fn set_str(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.0.set_str(key, value).map_err(err)
    }

    fn get_u32(&self, key: &str) -> Result<Option<u32>, String> {
        self.0.get_u32(key).map_err(err)
    }

    fn set_u32(&mut self, key: &str, value: u32) -> Result<(), String> {
        self.0.set_u32(key, value).map_err(err)
    }

    fn get_blob(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        let Some(len) = self.0.blob_len(key).map_err(err)? else {
            return Ok(None);
        };
        if len > MAX_BLOB {
            return Err(format!("{key} is {len} B, over the {MAX_BLOB} B accepted"));
        }
        let mut buf = vec![0u8; len];
        Ok(self
            .0
            .get_blob(key, &mut buf)
            .map_err(err)?
            .map(<[u8]>::to_vec))
    }

    fn set_blob(&mut self, key: &str, value: &[u8]) -> Result<(), String> {
        self.0.set_blob(key, value).map_err(err)
    }

    fn remove(&mut self, key: &str) -> Result<(), String> {
        self.0.remove(key).map(|_| ()).map_err(err)
    }
}
