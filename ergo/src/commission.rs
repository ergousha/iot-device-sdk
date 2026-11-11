//! `ergo register` and `ergo commission`: putting a device on the platform at
//! the bench.
//!
//! A device enrols itself by AWS IoT Fleet Provisioning with the shared claim
//! certificate. Two things keep that safe: the claim is INACTIVE except during
//! a short window the owner opens, and the pre-provisioning hook approves only
//! a MAC with a registry record (`allowed`, not yet `provisioned`, the right
//! product, the certificate's public key, `enrol_by` not passed). Images carry
//! no secrets: the claim credential and Wi-Fi reach the device only here, over
//! its USB serial console ([`device_core::console`]).
//!
//! # The bench flow (`ergo commission`)
//!
//! 1. **Guard.** Read SSM `/esp32-ztp/guard/state`; refuse unless
//!    `"tripped": false`, as `claim-window.sh` does. Nothing else happens on a
//!    tripped platform, not even opening the port.
//! 2. **Ask the device.** Open the port and send `PLATFORM INFO` every 3 s
//!    (the board may still be booting; opening the port can reset it) until a
//!    `REGISTER` line arrives, for up to 30 s. Check its product. An enrolled
//!    device stops here, unless `--reprovision`: then `PLATFORM FORGET` drops
//!    its identity, the device restarts, and `INFO` is repeated (up to 60 s)
//!    until it reports itself unenrolled, with its (possibly new) key.
//! 3. **Register.** Write the registry record from what the device reported:
//!    its MAC, its public key (128 hex; `-`, a legacy RSA identity, is refused),
//!    `enrol_by` = now + `--minutes`. The write fails if a record exists,
//!    unless `--reprovision`, which overwrites it.
//! 4. **Write the device.** `PLATFORM SET` the claim certificate and key (from
//!    SSM, decrypted, held in memory only), the Wi-Fi SSID and passphrase (the
//!    passphrase from the environment variable `--wifi-psk-env` names), and
//!    the endpoint override. Each must be answered `OK SET <key>` within 5 s.
//! 5. **Arm.** Re-check the guard, find the claim certificate (the single
//!    target of `esp32-ztp-claim-policy`) and set it ACTIVE. From here on,
//!    every way out sets it INACTIVE again, Ctrl-C included.
//! 6. **Enrol.** Send `PLATFORM ENROL` and poll the registry (consistent read,
//!    every 5 s) for up to `--wait-minutes` until the hook has marked the
//!    record `provisioned`. Then wait (up to 60 s) for the device's
//!    `EVENT enrolled`, so the claim stays active until it has its
//!    certificate; the device erases the claim from its flash itself.
//! 7. **Close.** Success: claim INACTIVE, print the thing name. Failure,
//!    timeout or Ctrl-C: claim INACTIVE first (if it could not be, print the
//!    `aws iot update-certificate` command to run), then delete the record if
//!    it still shows `provisioned = false`, then `PLATFORM ERASE` (claim, Wi-Fi
//!    and endpoint leave the device). A record that turned out provisioned
//!    means the device enrolled at the last moment: it and the device are left
//!    alone. Exit non-zero.
//!
//! No secret (claim key, Wi-Fi passphrase) is ever printed, logged, written to
//! a file or put in an error message; they travel only to the device, base64
//! encoded on the `SET` line.

use std::future::Future;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use device_core::console::{Command, Key, Register, Reply};
use device_core::ids::Mac;
use tokio::time::Instant;

use crate::cloud::{
    already_registered, check_guard, claim_cert_id, disarm_command, short_id, Cloud, Delete, Put,
    Secret,
};
use crate::record::{normalise_mac, rfc3339, Record};
use crate::serial::Console;
use crate::term::Term;

/// How long the device has to announce itself.
pub const INFO_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a device restarting after `FORGET` has to announce itself.
pub const RESTART_TIMEOUT: Duration = Duration::from_secs(60);
/// `INFO` is repeated this often while waiting.
pub const INFO_RESEND: Duration = Duration::from_secs(3);
/// How long a command has to be answered.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the registry is read while the device enrols.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// How long the claim stays active after the hook approved, waiting for the
/// device to report its certificate.
pub const ENROLLED_GRACE: Duration = Duration::from_secs(60);
/// Bound on each cleanup call, so a hung request cannot keep `ergo` running.
pub const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);

/// `ergo register`: writes one record.
pub async fn register<C: Cloud>(
    cloud: &C,
    record: &Record,
    overwrite: bool,
    term: &mut Term<'_>,
) -> Result<()> {
    match cloud.put_record(record, overwrite).await? {
        Put::Written => {
            term.say(format!(
                "OK: {} registered as product {}{}; it may enrol until {} (allowed=true, provisioned=false)",
                record.mac,
                record.product,
                if record.canary { " (canary)" } else { "" },
                rfc3339(record.enrol_by),
            ));
            Ok(())
        }
        Put::AlreadyRegistered => bail!(already_registered(&record.mac)),
    }
}

/// What `ergo commission` was asked to do.
#[derive(Debug, Clone)]
pub struct CommissionOpts {
    pub product: String,
    pub canary: bool,
    /// SSID and passphrase (empty: open network).
    pub wifi: Option<(String, Secret)>,
    pub endpoint: Option<String>,
    /// Record lifetime (`enrol_by`).
    pub minutes: u32,
    pub reprovision: bool,
    /// How long to wait for enrolment once the claim is active.
    pub wait: Duration,
    /// For the printed recovery command.
    pub region: String,
}

/// What has been done so far, so that cleanup undoes exactly that.
#[derive(Debug, Default)]
struct Progress {
    /// The MAC of the record this run wrote.
    record: Option<String>,
    /// A `SET` was sent: the device may hold the claim or Wi-Fi.
    device_written: bool,
    /// Activation of this certificate was requested (perhaps not completed).
    armed: Option<String>,
}

/// `ergo commission`. Returns the thing name of the enrolled device.
///
/// `open` opens the console (after the guard check). `interrupt` resolves on
/// Ctrl-C; it is raced against every step, and cleanup runs after it.
pub async fn commission<C: Cloud, P: Console>(
    cloud: &C,
    open: impl FnOnce() -> Result<P>,
    opts: &CommissionOpts,
    now: SystemTime,
    interrupt: impl Future<Output = ()>,
    term: &mut Term<'_>,
) -> Result<String> {
    let mut port: Option<P> = None;
    let mut progress = Progress::default();
    let result = {
        let steps = steps(cloud, open, opts, now, &mut port, &mut progress, term);
        tokio::select! {
            result = steps => result,
            () = interrupt => Err(anyhow!("interrupted")),
        }
    };
    match result {
        Ok(thing) => {
            if let Some(cert) = progress.armed.take() {
                if !disarm(cloud, &cert, &opts.region, term).await {
                    bail!(
                        "{thing} enrolled, but the claim is still ACTIVE: run {}",
                        disarm_command(&cert, &opts.region)
                    );
                }
            }
            term.say(format!("{thing} enrolled"));
            Ok(thing)
        }
        Err(e) => {
            clean_up(cloud, port.as_mut(), progress, &opts.region, term).await;
            Err(e)
        }
    }
}

async fn steps<C: Cloud, P: Console>(
    cloud: &C,
    open: impl FnOnce() -> Result<P>,
    opts: &CommissionOpts,
    now: SystemTime,
    port: &mut Option<P>,
    progress: &mut Progress,
    term: &mut Term<'_>,
) -> Result<String> {
    // 1. Guard.
    check_guard(&cloud.guard_state().await?)?;

    // 2. Ask the device.
    let port = port.insert(open()?);
    let mut device = handshake(port, INFO_TIMEOUT, |_| true, term).await?;
    describe(&device, term);
    check_device_product(&device, &opts.product)?;
    if device.enrolled {
        if !opts.reprovision {
            bail!(
                "the device is already enrolled as {}; to enrol it again (new certificate), \
                 run with --reprovision",
                device.thing
            );
        }
        term.say("--reprovision: the device forgets its identity and restarts");
        port.send_line(&Command::Forget.encode())?;
        expect_ok(port, "FORGET", None, term).await?;
        let mac = device.mac.clone();
        device = handshake(port, RESTART_TIMEOUT, |r| !r.enrolled, term)
            .await
            .context("waiting for the device to come back without its identity")?;
        describe(&device, term);
        check_device_product(&device, &opts.product)?;
        if device.mac != mac {
            bail!(
                "the device reported MAC {} before FORGET and {} after",
                mac,
                device.mac
            );
        }
    }
    let mac = device_mac(&device)?;
    let public_key = device_public_key(&device.pubkey)?;

    // 3. Register.
    let record = Record::new(
        &mac,
        &opts.product,
        &public_key,
        opts.canary,
        opts.minutes,
        now,
    );
    match cloud.put_record(&record, opts.reprovision).await? {
        Put::Written => progress.record = Some(record.mac.clone()),
        Put::AlreadyRegistered => bail!(already_registered(&record.mac)),
    }
    term.say(format!(
        "registered {} as {}, may enrol until {}",
        record.mac,
        record.product,
        rfc3339(record.enrol_by)
    ));

    // 4. Write the device.
    let claim = cloud.claim_credential().await?;
    let mut writes: Vec<(Key, &str)> = vec![
        (Key::ClaimCert, &claim.certificate_pem),
        (Key::ClaimKey, claim.private_key.expose()),
    ];
    if let Some((ssid, psk)) = &opts.wifi {
        writes.push((Key::WifiSsid, ssid));
        writes.push((Key::WifiPsk, psk.expose()));
    }
    if let Some(endpoint) = &opts.endpoint {
        writes.push((Key::Endpoint, endpoint));
    }
    // All checked before the first is sent; the messages never quote a value.
    for (key, value) in &writes {
        key.validate(value)
            .map_err(|why| anyhow!("the value for {} is not valid: {why}", key.nvs_key()))?;
    }
    progress.device_written = true;
    for (key, value) in writes {
        let line = Command::Set {
            key,
            value: value.to_string(),
        }
        .encode();
        port.send_line(&line)?;
        expect_ok(port, "SET", Some(key.nvs_key()), term).await?;
        term.say(format!("  set {}", key.nvs_key()));
    }
    drop(claim);

    // 5. Arm.
    check_guard(&cloud.guard_state().await?)?;
    let cert = claim_cert_id(&cloud.claim_policy_targets().await?)?;
    progress.armed = Some(cert.clone());
    cloud.set_claim_active(&cert, true).await?;
    term.say(format!(
        "claim {} ACTIVE for at most {} min; Ctrl-C aborts and closes it",
        short_id(&cert),
        opts.wait.as_secs().div_ceil(60)
    ));

    // 6. Enrol.
    port.send_line(&Command::Enrol.encode())?;
    wait_enrolled(cloud, port, &record.mac, &device.thing, opts.wait, term).await
}

fn describe(r: &Register, term: &mut Term<'_>) {
    term.say(format!(
        "device: product={} mac={} thing={} fw={} enrolled={}",
        r.product, r.mac, r.thing, r.fw, r.enrolled
    ));
}

fn check_device_product(device: &Register, product: &str) -> Result<()> {
    if device.product != product {
        bail!(
            "the device runs product {:?}, not {product:?}: wrong board or wrong --product",
            device.product
        );
    }
    Ok(())
}

/// The device's MAC, checked against the thing name it reports: the hook
/// rejects a device whose thing name is not its MAC.
fn device_mac(device: &Register) -> Result<Mac> {
    let mac = normalise_mac(&device.mac)?;
    if device.thing != mac.thing_name() {
        bail!(
            "the device reports thing {} for MAC {}; the platform requires {}",
            device.thing,
            mac.colon(),
            mac.thing_name()
        );
    }
    Ok(mac)
}

/// The key the device reported: exactly 128 hex digits (X||Y).
pub fn device_public_key(pubkey: &str) -> Result<String> {
    if pubkey == "-" {
        bail!(
            "the device has no P-256 key to register (pubkey=-: a legacy RSA identity); \
             run with --reprovision to make it forget that identity and generate one"
        );
    }
    if pubkey.len() != 128 || !pubkey.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("the device reported a public key that is not 128 hex digits: {pubkey:?}");
    }
    Ok(pubkey.to_ascii_uppercase())
}

/// The next protocol reply before `deadline`, echoing events to stderr and
/// skipping log lines. `None` at the deadline.
async fn next_reply<P: Console>(
    port: &mut P,
    deadline: Instant,
    term: &mut Term<'_>,
) -> Result<Option<Reply>> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let Some(line) = port.read_line(left).await? else {
            return Ok(None);
        };
        match Reply::parse(&line) {
            Some(event @ Reply::Event { .. }) => term.warn(format!("device: {}", event.encode())),
            Some(reply) => return Ok(Some(reply)),
            None => {}
        }
        // A console flooding log lines must not keep the wait open.
        if Instant::now() >= deadline {
            return Ok(None);
        }
    }
}

/// Sends `INFO` every [`INFO_RESEND`] until a `REGISTER` that `accept`s.
async fn handshake<P: Console>(
    port: &mut P,
    timeout: Duration,
    accept: impl Fn(&Register) -> bool,
    term: &mut Term<'_>,
) -> Result<Register> {
    let deadline = Instant::now() + timeout;
    loop {
        port.send_line(&Command::Info.encode())?;
        let resend = (Instant::now() + INFO_RESEND).min(deadline);
        while let Some(reply) = next_reply(port, resend, term).await? {
            if let Reply::Register(register) = reply {
                if accept(&register) {
                    return Ok(register);
                }
            }
        }
        if Instant::now() >= deadline {
            bail!(
                "no REGISTER line from the device within {} s: is this the right port, \
                 and does the firmware include the platform console?",
                timeout.as_secs()
            );
        }
    }
}

/// Waits for `OK <verb> [<key>]`; any `ERR` or silence aborts.
async fn expect_ok<P: Console>(
    port: &mut P,
    verb: &str,
    key: Option<&str>,
    term: &mut Term<'_>,
) -> Result<()> {
    let what = match key {
        Some(key) => format!("{verb} {key}"),
        None => verb.to_string(),
    };
    let deadline = Instant::now() + REPLY_TIMEOUT;
    while let Some(reply) = next_reply(port, deadline, term).await? {
        match reply {
            Reply::Ok { verb: v, key: k }
                if v == verb && (key.is_none() || k.as_deref() == key) =>
            {
                return Ok(())
            }
            Reply::Err { verb: v, message } => {
                bail!("the device refused {what}: ERR {v} {message}")
            }
            _ => {}
        }
    }
    bail!("no answer to {what} within {} s", REPLY_TIMEOUT.as_secs())
}

/// Polls the registry until the hook marks the record provisioned, echoing
/// device events, then gives the device [`ENROLLED_GRACE`] to report that it
/// holds its certificate.
async fn wait_enrolled<C: Cloud, P: Console>(
    cloud: &C,
    port: &mut P,
    mac: &str,
    thing: &str,
    wait: Duration,
    term: &mut Term<'_>,
) -> Result<String> {
    let deadline = Instant::now() + wait;
    let mut next_poll = Instant::now();
    let mut approved_at: Option<Instant> = None;
    let mut reported: Option<String> = None;
    loop {
        let now = Instant::now();
        if let Some(at) = approved_at {
            if let Some(thing) = reported {
                return Ok(thing);
            }
            if now >= at + ENROLLED_GRACE {
                term.warn(format!(
                    "the registry shows {mac} enrolled, but the device did not report \
                     `EVENT enrolled` within {} s; check its console",
                    ENROLLED_GRACE.as_secs()
                ));
                return Ok(thing.to_string());
            }
        } else {
            if now >= next_poll {
                match cloud.get_provisioned(mac).await? {
                    Some(true) => {
                        term.say("registry: the hook approved the device");
                        approved_at = Some(Instant::now());
                        continue;
                    }
                    Some(false) => {}
                    None => bail!("the registry record for {mac} disappeared"),
                }
                next_poll = Instant::now() + POLL_INTERVAL;
            }
            if Instant::now() >= deadline {
                bail!(
                    "the device did not enrol within {} min (the registry still shows \
                     provisioned=false); check its console log",
                    wait.as_secs().div_ceil(60)
                );
            }
        }
        let until = match approved_at {
            Some(at) => at + ENROLLED_GRACE,
            None => next_poll.min(deadline),
        };
        let left = until.saturating_duration_since(Instant::now());
        let Some(line) = port.read_line(left).await? else {
            continue;
        };
        match Reply::parse(&line) {
            Some(event @ Reply::Event { .. }) => {
                term.warn(format!("device: {}", event.encode()));
                if let Reply::Event { name, fields } = event {
                    if name == "enrolled" {
                        let named = fields.into_iter().find(|(k, _)| k == "thing");
                        reported = Some(named.map_or_else(|| thing.to_string(), |(_, v)| v));
                        next_poll = Instant::now();
                    }
                }
            }
            Some(Reply::Ok { verb, .. }) if verb == "ENROL" => {
                term.say("device: enrolling");
            }
            Some(Reply::Err { verb, message }) if verb == "ENROL" => {
                bail!("the device refused ENROL: {message}")
            }
            _ => {}
        }
    }
}

/// Sets the claim INACTIVE. On failure prints the command that does it by
/// hand, and returns false.
async fn disarm<C: Cloud>(cloud: &C, cert: &str, region: &str, term: &mut Term<'_>) -> bool {
    let failure =
        match tokio::time::timeout(CLEANUP_TIMEOUT, cloud.set_claim_active(cert, false)).await {
            Ok(Ok(())) => {
                term.say(format!("claim {} INACTIVE again.", short_id(cert)));
                return true;
            }
            Ok(Err(e)) => format!("{e:#}"),
            Err(_) => "timed out".to_string(),
        };
    term.warn(format!(
        "!! could not deactivate the claim {} ({failure}); run:\n   {}",
        short_id(cert),
        disarm_command(cert, region)
    ));
    false
}

/// Undoes what `progress` records, most important first: the claim, the
/// registry record, the device.
async fn clean_up<C: Cloud, P: Console>(
    cloud: &C,
    port: Option<&mut P>,
    progress: Progress,
    region: &str,
    term: &mut Term<'_>,
) {
    if let Some(cert) = &progress.armed {
        disarm(cloud, cert, region, term).await;
    }
    let mut enrolled_after_all = false;
    if let Some(mac) = &progress.record {
        let deleted =
            tokio::time::timeout(CLEANUP_TIMEOUT, cloud.delete_record_if_unprovisioned(mac))
                .await
                .unwrap_or_else(|_| Err(anyhow!("timed out")));
        match deleted {
            Ok(Delete::Deleted) => term.say(format!("registry record {mac} deleted")),
            Ok(Delete::Missing) => {}
            Ok(Delete::Provisioned) => {
                enrolled_after_all = true;
                term.warn(format!(
                    "the registry shows {mac} enrolled after all: its record is kept and \
                     the device is not erased; check its console"
                ));
            }
            Err(e) => term.warn(format!(
                "could not delete the registry record {mac} ({e:#}); it stops working at enrol_by"
            )),
        }
    }
    if progress.device_written && !enrolled_after_all {
        if let Some(port) = port {
            let erased = match port.send_line(&Command::Erase.encode()) {
                Ok(()) => expect_ok(port, "ERASE", None, term).await,
                Err(e) => Err(e),
            };
            match erased {
                Ok(()) => term.say("device: claim, Wi-Fi and endpoint erased"),
                Err(e) => term.warn(format!(
                    "!! could not confirm that the device erased the claim ({e:#}); \
                     send `PLATFORM ERASE` on its console or erase its NVS"
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests;
