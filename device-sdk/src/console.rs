//! The device end of bench provisioning over the serial console
//! ([`device_core::console`]).
//!
//! A thread polls stdin (non-blocking in ESP-IDF's default console VFS) for
//! `PLATFORM ...` lines and answers on stdout. It writes only NVS
//! `platform` keys, and never echoes or logs a value.

use std::io::Write as _;
use std::sync::atomic::Ordering;
use std::time::Duration;

use device_core::console::{Command, Register, Reply, MAX_LINE};
use device_core::nvs::{self, IdentityLayout, Kv, PLATFORM_NS};

use crate::key::DeviceKey;
use crate::kv::NvsKv;
use crate::Platform;

/// Enough for base64, NVS and generating or parsing a P-256 key.
const STACK: usize = 6 * 1024;
const POLL: Duration = Duration::from_millis(50);

/// Prints one protocol line, whole.
pub(crate) fn emit(reply: Reply) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", reply.encode());
    let _ = out.flush();
}

/// Prints the REGISTER line: what `ergo` registers. `key` if the caller has
/// it at hand; otherwise it is read here.
pub(crate) fn announce(p: &Platform, key: Option<&DeviceKey>, rf_quiet: bool) {
    let layout = IdentityLayout::for_storage(p.product.key_storage);
    let enrolled = NvsKv::open(&p.nvs, layout.namespace())
        .ok()
        .and_then(|ns| nvs::load_identity(layout, &ns).ok().flatten())
        .is_some();
    let owned;
    let key = match key {
        Some(k) => Some(k),
        None => {
            owned = if enrolled {
                // Never generate a key next to an identity: an enrolled
                // gateway from before the SDK keeps its RSA key there.
                DeviceKey::existing(&p.nvs)
            } else {
                DeviceKey::load(&p.nvs, rf_quiet).ok()
            };
            owned.as_ref()
        }
    };
    emit(Reply::Register(Register {
        product: p.product.id.to_string(),
        mac: p.mac.colon(),
        thing: p.mac.thing_name(),
        pubkey: key.map_or_else(|| "-".to_string(), DeviceKey::public_key_hex),
        fw: p.product.fw_version.to_string(),
        enrolled,
    }));
}

/// Starts the console thread.
pub(crate) fn start(p: Platform) {
    let spawned = std::thread::Builder::new()
        .name("platform-console".into())
        .stack_size(STACK)
        .spawn(move || run(&p));
    if let Err(e) = spawned {
        log::error!("could not start the platform console: {e}");
    }
}

fn run(p: &Platform) {
    let mut line: Vec<u8> = Vec::new();
    let mut overflow = false;
    let mut buf = [0u8; 256];
    loop {
        // SAFETY: reading into a buffer of the stated size from fd 0.
        let n = unsafe {
            esp_idf_svc::sys::read(
                esp_idf_svc::sys::STDIN_FILENO as i32,
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n <= 0 {
            std::thread::sleep(POLL);
            continue;
        }
        for &b in &buf[..n as usize] {
            match b {
                b'\n' | b'\r' => {
                    if !overflow && !line.is_empty() {
                        if let Ok(text) = std::str::from_utf8(&line) {
                            handle(p, text);
                        }
                    }
                    line.clear();
                    overflow = false;
                }
                _ if line.len() >= MAX_LINE => overflow = true,
                _ => line.push(b),
            }
        }
    }
}

fn handle(p: &Platform, text: &str) {
    let Some(parsed) = Command::parse(text) else {
        return;
    };
    let command = match parsed {
        Ok(c) => c,
        Err(message) => {
            let verb = text
                .split_whitespace()
                .nth(1)
                .unwrap_or("?")
                .chars()
                .take(16)
                .collect();
            emit(Reply::Err { verb, message });
            return;
        }
    };
    let verb = command.verb().to_string();
    let ok = |key: Option<String>| {
        emit(Reply::Ok {
            verb: verb.clone(),
            key,
        })
    };
    let err = |message: String| {
        emit(Reply::Err {
            verb: verb.clone(),
            message,
        })
    };
    match command {
        Command::Info => {
            announce(p, None, false);
            ok(None);
        }
        Command::Set { key, value } => {
            match NvsKv::open(&p.nvs, PLATFORM_NS)
                .map_err(|e| format!("{e:#}"))
                .and_then(|mut ns| ns.set_str(key.nvs_key(), &value))
            {
                Ok(()) => {
                    log::info!("console: stored platform/{}", key.nvs_key());
                    ok(Some(key.nvs_key().to_string()));
                }
                Err(e) => err(e),
            }
        }
        Command::Erase => match NvsKv::open(&p.nvs, PLATFORM_NS)
            .map_err(|e| format!("{e:#}"))
            .and_then(|mut ns| nvs::erase_console_keys(&mut ns))
        {
            Ok(()) => {
                log::warn!("console: erased the claim, Wi-Fi and endpoint");
                ok(None);
            }
            Err(e) => err(e),
        },
        Command::Enrol => {
            crate::provision::ENROL_NOW.store(true, Ordering::SeqCst);
            ok(None);
        }
        Command::Forget => match forget(p) {
            Ok(()) => {
                ok(None);
                log::warn!("console: identity forgotten; restarting to enrol again");
                std::thread::sleep(Duration::from_millis(500));
                crate::boot::restart();
            }
            Err(e) => err(e),
        },
    }
}

/// Drops the identity. A P-256 soft key stays (it may be registered again);
/// any other soft key goes, so the device generates a P-256 one as it comes
/// back. A chip key never changes.
fn forget(p: &Platform) -> Result<(), String> {
    let layout = IdentityLayout::for_storage(p.product.key_storage);
    let mut ns = NvsKv::open(&p.nvs, layout.namespace()).map_err(|e| format!("{e:#}"))?;
    let keep_key = layout == IdentityLayout::SecureElement || DeviceKey::existing(&p.nvs).is_some();
    nvs::erase_identity(layout, &mut ns, keep_key)
}
