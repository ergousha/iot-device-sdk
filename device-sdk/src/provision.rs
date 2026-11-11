//! Enrolment: from a claim credential written at the bench to the device's
//! own certificate.
//!
//! 1. The device key signs a CSR (in the ATECC608B, or with the soft key).
//! 2. Connect as `claim-<MAC12>` with the claim from NVS `platform`.
//! 3. `CreateCertificateFromCsr`, then `RegisterThing` on the product's
//!    template. The pre-provisioning hook approves only a device registered
//!    for this product with exactly this public key, once, in its window.
//! 4. Store the identity, erase the claim.
//!
//! Without a claim the device waits for the bench (`ergo commission`). A
//! refusal backs off from a minute to six hours with jitter; the console's
//! `ENROL` skips the wait.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use device_core::backoff::Backoff;
use device_core::console::Reply;
use device_core::nvs::{self, Identity, IdentityLayout, PLATFORM_NS};
use device_core::{csr, provision as wire};

use crate::key::DeviceKey;
use crate::kv::NvsKv;
use crate::mqtt::{self, Auth, Mqtt, MqttEvent};
use crate::Platform;

const ANSWER_TIMEOUT: Duration = Duration::from_secs(20);
/// How often a device without a claim looks again.
const COMMISSION_POLL: Duration = Duration::from_secs(30);

/// Set by the console's `ENROL`: try now.
pub(crate) static ENROL_NOW: AtomicBool = AtomicBool::new(false);

/// Sleeps `d`, or less if the console asks to enrol now.
fn wait(d: Duration) {
    let deadline = Instant::now() + d;
    while Instant::now() < deadline {
        if ENROL_NOW.swap(false, Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1).min(deadline - Instant::now()));
    }
}

/// Why an enrolment attempt failed.
enum Failure {
    /// The platform refused: not registered, wrong key or product, already
    /// enrolled, outside the window, or the claim is not active.
    Refused(String),
    /// Anything else: network, timeout, the chip.
    Error(anyhow::Error),
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Self {
        Failure::Error(e)
    }
}

/// Loads the device's identity, or enrols until it has one.
pub(crate) fn ensure_identity(p: &Platform) -> Result<Identity> {
    let layout = IdentityLayout::for_storage(p.product.key_storage);
    let mut backoff = Backoff::refused();
    let mut announced = false;
    loop {
        let ns = NvsKv::open(&p.nvs, layout.namespace())?;
        let stored = nvs::load_identity(layout, &ns).map_err(|e| anyhow!(e))?;
        drop(ns);
        // A soft-key record carries its key; a secure-element record must be
        // for this chip.
        if let Some(id) = stored {
            if layout == IdentityLayout::SoftKey {
                tidy_claim(p);
                return Ok(id);
            }
            let key = DeviceKey::load(&p.nvs, false)?;
            crate::remember_key(&key);
            if key.owns(&id) {
                tidy_claim(p);
                return Ok(id);
            }
            log::warn!(
                "the stored identity {} is not for this chip's key; enrolling again",
                id.thing_name
            );
        }

        let key = DeviceKey::load(&p.nvs, false)?;
        crate::remember_key(&key);
        if !announced {
            crate::console::announce(p, Some(&key), false);
            announced = true;
        }
        let platform = NvsKv::open(&p.nvs, PLATFORM_NS)?;
        let claim = nvs::load_claim(&platform).map_err(|e| anyhow!(e))?;
        let endpoint = nvs::endpoint(&platform, p.product.endpoint);
        drop(platform);

        let Some((claim_cert, claim_key)) = claim else {
            crate::set_status(format!("awaiting commissioning ({})", p.mac));
            wait(COMMISSION_POLL);
            continue;
        };

        crate::set_status("enrolling...");
        match enrol(p, &key, &endpoint, &claim_cert, &claim_key) {
            Ok(id) => {
                let mut ns = NvsKv::open(&p.nvs, layout.namespace())?;
                nvs::save_identity(layout, &mut ns, &id).map_err(|e| anyhow!(e))?;
                tidy_claim(p);
                crate::console::emit(Reply::Event {
                    name: "enrolled".into(),
                    fields: vec![("thing".into(), id.thing_name.clone())],
                });
                log::info!("enrolled as {}; the claim is erased", id.thing_name);
                return Ok(id);
            }
            Err(failure) => {
                let (refused, why) = match failure {
                    Failure::Refused(why) => (true, why),
                    Failure::Error(e) => (false, format!("{e:#}")),
                };
                let delay = backoff.next_delay_s(crate::boot::random_u32());
                log::warn!(
                    "enrolment {}: {why}; next attempt in {delay} s",
                    if refused { "refused" } else { "failed" }
                );
                crate::console::emit(Reply::Event {
                    name: "enrol_failed".into(),
                    fields: vec![
                        ("refused".into(), refused.to_string()),
                        ("retry_s".into(), delay.to_string()),
                    ],
                });
                crate::set_status(if refused {
                    format!("enrolment refused ({})", p.mac)
                } else {
                    "enrolment failed; retrying".to_string()
                });
                wait(Duration::from_secs(delay));
            }
        }
    }
}

/// Erases a claim left in NVS once the device has its own identity. Removing
/// a key that is not there writes nothing.
fn tidy_claim(p: &Platform) {
    match NvsKv::open(&p.nvs, PLATFORM_NS) {
        Ok(mut platform) => {
            if let Err(e) = nvs::erase_claim(&mut platform) {
                log::warn!("could not erase the claim: {e}");
            }
        }
        Err(e) => log::warn!("could not erase the claim: {e:#}"),
    }
}

fn enrol(
    p: &Platform,
    key: &DeviceKey,
    endpoint: &str,
    claim_cert: &str,
    claim_key: &str,
) -> Result<Identity, Failure> {
    let thing = p.mac.thing_name();
    // The CSR first: if the key cannot sign, there is no point connecting.
    let info = csr::request_info(&thing, key.public_key());
    let signature = key.sign_digest(&csr::digest(&info))?;
    let csr_pem = csr::to_pem(&csr::assemble(&info, &signature));

    let uri = device_core::product::Product::broker_uri(endpoint);
    let client_id = p.mac.claim_client_id();
    let (client, events) = Mqtt::connect(&mqtt::Settings {
        uri: &uri,
        client_id: &client_id,
        root_ca: crate::ROOT_CA,
        auth: Auth::Pem {
            cert: claim_cert,
            key: claim_key,
        },
        buffer_size: 4096,
        auto_reconnect: false,
    })?;
    if let Err(e) = mqtt::wait_connected(&events, Duration::from_secs(30)) {
        // An INACTIVE claim fails the handshake: that is the platform's no.
        return Err(if e.refused {
            Failure::Refused(format!("claim connection refused ({})", e.detail))
        } else {
            Failure::Error(anyhow!("claim connection: {}", e.detail))
        });
    }
    log::info!("enrolment: connected with the claim as {client_id}");

    let answers = wire::answer_topics(p.product.template);
    for t in &answers {
        client.subscribe(t)?;
    }
    // Let the SUBACKs land before the requests, or the answer can be missed.
    std::thread::sleep(Duration::from_millis(1500));
    let [csr_accepted, csr_rejected, reg_accepted, reg_rejected] = &answers;

    client.publish(
        wire::CREATE_FROM_CSR_TOPIC,
        &wire::create_from_csr_request(&csr_pem),
    )?;
    let (topic, payload) = answer(&events, &[csr_accepted, csr_rejected])?;
    if &topic == csr_rejected {
        let why = format!(
            "CreateCertificateFromCsr: {}",
            wire::describe_rejection(&payload)
        );
        return Err(if wire::refused(&payload) {
            Failure::Refused(why)
        } else {
            Failure::Error(anyhow!(why))
        });
    }
    let issued = wire::parse_issued(&payload).map_err(|e| anyhow!(e))?;
    log::info!("enrolment: certificate {} issued", issued.certificate_id);

    client.publish(
        &wire::register_topic(p.product.template),
        &wire::register_request(&issued.ownership_token, &p.mac),
    )?;
    let (topic, payload) = answer(&events, &[reg_accepted, reg_rejected])?;
    if &topic == reg_rejected {
        let why = format!("RegisterThing: {}", wire::describe_rejection(&payload));
        return Err(if wire::refused(&payload) {
            Failure::Refused(why)
        } else {
            Failure::Error(anyhow!(why))
        });
    }
    let thing_name = wire::parse_registered(&payload).map_err(|e| anyhow!(e))?;
    log::info!("enrolment: APPROVED, thing {thing_name}");
    drop(client);
    Ok(key.identity(thing_name, issued.certificate_pem))
}

fn answer(events: &Receiver<MqttEvent>, topics: &[&String]) -> Result<(String, Vec<u8>)> {
    let deadline = Instant::now() + ANSWER_TIMEOUT;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match events.recv_timeout(left) {
            Ok(MqttEvent::Message { topic, data }) if topics.iter().any(|t| **t == topic) => {
                return Ok((topic, data))
            }
            Ok(MqttEvent::Disconnected) => anyhow::bail!("the claim connection dropped"),
            Ok(_) => continue,
            Err(_) => anyhow::bail!(
                "no answer on {} within {} s",
                topics[0],
                ANSWER_TIMEOUT.as_secs()
            ),
        }
    }
}
