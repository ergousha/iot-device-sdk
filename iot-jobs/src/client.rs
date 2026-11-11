//! The Jobs state machine: what the device does with each Jobs message.
//!
//! An update is reported SUCCEEDED by the image it installed, never by the one
//! that downloaded it: until the new image has reached AWS IoT and marked
//! itself valid, the bootloader can still roll it back. So a boot that
//! installs an update ends with the execution IN_PROGRESS and the job recorded
//! in NVS ([`Store`]), and the next boot *settles* it: SUCCEEDED from the
//! new image, FAILED "rolled back" from the previous one.
//!
//! Until the Jobs service has acknowledged that outcome, no other job is
//! taken. In particular the same execution, which the service offers again at
//! boot because it is still IN_PROGRESS, is never downloaded a second time.
//! A job for the version already running is settled the same way, without a
//! download, and so is a job this firmware refuses, as REJECTED.
//!
//! Written against [`Transport`], [`Store`] and [`Installer`] so that it runs
//! on the host: the firmware plugs in MQTT, NVS and the OTA partitions
//! (`src/jobs.rs`), the tests below plug in fakes.

use std::time::{Duration, Instant};

use super::{
    self as jobs, Admission, BootFacts, DownloadAttempts, Expected, FirmwareJob, InstallError,
    Keyring, NextJob, Outcome, PendingUpdate, Policy, StatusUpdate,
};

/// How long an outcome may go unacknowledged before it is sent again.
///
/// The Jobs service answers in well under a second. Silence means the request
/// or the answer was lost, or the request was throttled; a reconnect also
/// sends it again.
pub const SETTLE_RETRY: Duration = Duration::from_secs(30);

/// How long the device waits, before activating a downloaded image, to hear
/// whether its job is still wanted. Silence installs it.
pub const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The MQTT operations the Jobs plane needs, all at QoS 1 and never retained.
pub trait Transport {
    /// Publishes `payload` on `topic`.
    fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<(), String>;
    /// Subscribes to `topic`.
    fn subscribe(&mut self, topic: &str) -> Result<(), String>;
    /// Drops the subscription to `topic`.
    fn unsubscribe(&mut self, topic: &str) -> Result<(), String>;
    /// Waits up to `timeout` for a message on one of `topics`, and returns its
    /// topic and payload. Whatever else arrives meanwhile is kept for the
    /// caller's own loop, not lost.
    fn wait_for(&mut self, topics: &[&str], timeout: Duration) -> Option<(String, Vec<u8>)>;
}

/// What survives a reboot: the update whose outcome is open, and how many
/// downloads of a job have started.
pub trait Store {
    /// The update whose outcome the next boot reports, if any.
    fn load(&self) -> Option<PendingUpdate>;
    /// Records `pending`, replacing any earlier record.
    fn save(&self, pending: &PendingUpdate) -> Result<(), String>;
    /// Removes the record; not having one is not an error.
    fn clear(&self) -> Result<(), String>;
    /// The download count, if any.
    fn load_attempts(&self) -> Option<DownloadAttempts>;
    /// Records the download count.
    fn save_attempts(&self, attempts: &DownloadAttempts) -> Result<(), String>;
    /// Removes the download count; not having one is not an error.
    fn clear_attempts(&self) -> Result<(), String>;
}

/// Writes an image to the next OTA slot.
pub trait Installer {
    /// Downloads `url`, writes and verifies it (against `expected`, when the
    /// job was signed: every byte hashed as it streams in, and the size),
    /// calls `before_activate` with the slot's label, and only if that
    /// succeeds makes the slot the boot slot. Returns the label. Does not
    /// restart. A `before_activate` failure is [`InstallError::Activate`].
    fn install(
        &mut self,
        url: &str,
        expected: Option<&Expected>,
        before_activate: &mut dyn FnMut(&str) -> Result<(), String>,
    ) -> Result<String, InstallError>;
}

/// A job outcome the Jobs service has acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settled {
    pub job_id: String,
    /// `SUCCEEDED`, `FAILED` or `REJECTED`.
    pub status: &'static str,
    /// The [`jobs::reason`] code, if any.
    pub reason: String,
}

/// What the caller does after [`JobsClient::handle`].
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// Carry on.
    Continue,
    /// An update is installed: restart into it, after giving the last status
    /// a moment to get onto the wire.
    Restart,
}

/// Jobs topics and state for a single thing.
pub struct JobsClient<S, I> {
    /// `$aws/things/{thing}/jobs/`: every topic this client owns starts so.
    prefix: String,
    notify_next: String,
    next_accepted: String,
    next_get: String,
    store: S,
    installer: I,
    boot: BootFacts,
    /// The outcome this boot is reporting, until the Jobs service takes it.
    settling: Option<Settling>,
    /// Jobs whose outcome the service refused outright during this boot. An
    /// execution it still holds open is offered again on the next
    /// `$next/get`; settling it again would only be refused again, in a loop
    /// as fast as the round trip.
    dropped: Vec<String>,
    /// The platform product this firmware is, if set with
    /// [`Self::with_product`].
    product: Option<String>,
    /// Keys that may sign manifests ([`Self::with_keyring`]).
    keyring: Keyring,
    /// Refuse unsigned jobs ([`Self::signed_only`]).
    signed_only: bool,
    /// The last outcome the service acknowledged, until taken.
    settled: Option<Settled>,
}

/// A job outcome on its way to the Jobs service.
struct Settling {
    job_id: String,
    status: &'static str,
    reason: String,
    update: String,
    accepted: String,
    rejected: String,
    payload: Vec<u8>,
    sent_at: Option<Instant>,
}

impl Settling {
    /// Subscribes to the answer, then publishes the outcome.
    ///
    /// The subscriptions are renewed on every send, which costs nothing when
    /// they already exist: a SUBSCRIBE lost on the way would otherwise leave
    /// the answer unheard, and the Jobs plane waiting for it until the next
    /// reconnect.
    fn send(&mut self, client: &mut impl Transport) {
        self.sent_at = Some(Instant::now());
        for topic in [&self.accepted, &self.rejected] {
            if let Err(e) = client.subscribe(topic) {
                log::warn!("could not subscribe to {topic}: {e}");
            }
        }
        if let Err(e) = client.publish(&self.update, &self.payload) {
            log::warn!("could not report OTA job {}: {e}", self.job_id);
        }
    }
}

impl<S: Store, I: Installer> JobsClient<S, I> {
    /// Builds the topic set for `thing_name`.
    ///
    /// `boot` is what this boot knows about its own image, taken after it
    /// marked itself valid. A job left pending by the previous boot is settled
    /// against it once [`Self::start`] runs.
    pub fn new(thing_name: &str, store: S, installer: I, boot: BootFacts) -> Self {
        let prefix = format!("$aws/things/{thing_name}/jobs/");
        let mut client = Self {
            notify_next: format!("{prefix}notify-next"),
            next_accepted: format!("{prefix}$next/get/accepted"),
            next_get: format!("{prefix}$next/get"),
            prefix,
            store,
            installer,
            boot,
            settling: None,
            dropped: Vec::new(),
            product: None,
            keyring: Keyring::default(),
            signed_only: false,
            settled: None,
        };
        if let Some(pending) = client.store.load() {
            if jobs::was_activated(&pending, &client.boot) {
                client.settle(pending);
            } else {
                // Power was cut between the record and the activation. The
                // execution is still IN_PROGRESS `downloading`, and is
                // offered, and downloaded, again.
                log::warn!(
                    "OTA job {}: {} was recorded but never activated; {} still runs from {}. \
                     Taking the job up again",
                    pending.job_id,
                    pending.target_slot,
                    client.boot.running_version,
                    client.boot.running_slot
                );
                if let Err(e) = client.store.clear() {
                    log::warn!("{e}");
                }
            }
        }
        client
    }

    /// Refuses (REJECTED) every update whose job document names another
    /// product, before anything is downloaded and before the version is even
    /// compared: two products may well share a version number. A document
    /// that names no product (from before the platform had products) is still
    /// accepted.
    pub fn with_product(mut self, product: &str) -> Self {
        self.product = Some(product.to_string());
        self
    }

    /// The keys a signed manifest may be signed with.
    pub fn with_keyring(mut self, keyring: Keyring) -> Self {
        self.keyring = keyring;
        self
    }

    /// Refuses (FAILED `sig`) every job without a signed manifest.
    pub fn signed_only(mut self, on: bool) -> Self {
        self.signed_only = on;
        self
    }

    /// The outcome the Jobs service acknowledged most recently, once.
    pub fn take_settled(&mut self) -> Option<Settled> {
        self.settled.take()
    }

    /// Subscribes, then reports the outcome still owed, or else asks for any
    /// job that is already queued. Safe to call again after a reconnect.
    pub fn start(&mut self, client: &mut impl Transport) -> Result<(), String> {
        client.subscribe(&self.notify_next)?;
        client.subscribe(&self.next_accepted)?;
        if let Some(settling) = self.settling.as_mut() {
            settling.send(client);
            return Ok(());
        }
        client.publish(&self.next_get, b"{}")?;
        Ok(())
    }

    /// Sends an outcome again if the Jobs service has not acknowledged it by
    /// `now`.
    pub fn tick(&mut self, client: &mut impl Transport, now: Instant) {
        let Some(settling) = self.settling.as_mut() else {
            return;
        };
        if settling
            .sent_at
            .is_some_and(|at| now.saturating_duration_since(at) < SETTLE_RETRY)
        {
            return;
        }
        log::warn!(
            "OTA job {}: outcome not acknowledged; sending it again",
            settling.job_id
        );
        settling.send(client);
    }

    /// True when `topic` belongs to this client: any Jobs topic of this
    /// thing, so that a late answer is not mistaken for someone else's.
    pub fn owns(&self, topic: &str) -> bool {
        topic.starts_with(&self.prefix)
    }

    /// Handles one Jobs message.
    ///
    /// [`Next::Restart`] means an update is installed and the device has to
    /// restart into it.
    pub fn handle(&mut self, topic: &str, payload: &[u8], client: &mut impl Transport) -> Next {
        if let Some(settling) = &self.settling {
            if topic == settling.accepted {
                log::info!("OTA job {}: outcome recorded", settling.job_id);
                self.settled = Some(Settled {
                    job_id: settling.job_id.clone(),
                    status: settling.status,
                    reason: settling.reason.clone(),
                });
                self.finish_settling(client);
            } else if topic == settling.rejected {
                let rejection = jobs::parse_rejection(payload);
                if rejection.is_transient() {
                    log::warn!(
                        "OTA job {}: outcome not taken ({rejection}); will retry",
                        settling.job_id
                    );
                    return Next::Continue;
                }
                // The execution has already ended: cancelled, timed out, or
                // settled by an earlier attempt whose answer was lost. There
                // is nothing left to report, and retrying would never end.
                log::warn!(
                    "OTA job {}: outcome rejected ({rejection}); dropping it",
                    settling.job_id
                );
                self.dropped.push(settling.job_id.clone());
                self.finish_settling(client);
            } else {
                // Everything else waits until the outcome is on record: the
                // service keeps offering this same execution while it is
                // IN_PROGRESS, and a queued job would start a second update on
                // top of one nobody has confirmed.
                log::debug!("ignoring {topic} while OTA job {} settles", settling.job_id);
            }
            return Next::Continue;
        }

        if topic == self.notify_next {
            // The notification carries a copy of the job document, but only
            // the `$next/get` answer is used: that is where AWS IoT fills in
            // the presigned download URL.
            log::info!("job notification; requesting details");
            let _ = client.publish(&self.next_get, b"{}");
            return Next::Continue;
        }
        if topic != self.next_accepted {
            return Next::Continue;
        }

        let next = jobs::parse_next(payload);
        if let Ok(
            NextJob::Install(FirmwareJob { job_id, .. })
            | NextJob::Settle(PendingUpdate { job_id, .. })
            | NextJob::Refused { job_id, .. }
            | NextJob::Unsupported { job_id, .. },
        ) = &next
        {
            if self.dropped.contains(job_id) {
                log::warn!(
                    "OTA job {job_id}: its outcome was refused earlier; ignoring it until reboot"
                );
                return Next::Continue;
            }
        }
        match next {
            Ok(NextJob::Idle) => Next::Continue,
            Ok(NextJob::Unsupported { job_id, operation }) => {
                // Left QUEUED, it would block every job queued behind it.
                log::warn!("job {job_id}: unsupported operation {operation:?}; reporting REJECTED");
                let detail = format!("unsupported operation {operation:?}");
                self.report(&job_id, &jobs::refused(jobs::reason::OPERATION, &detail));
                self.send_report(client);
                Next::Continue
            }
            Ok(NextJob::Refused {
                job_id,
                code,
                reason,
            }) => {
                // Left QUEUED, it would be offered again at every boot.
                log::error!("refusing OTA job {job_id}: {reason}; reporting REJECTED");
                self.report(&job_id, &jobs::refused(code, &reason));
                self.send_report(client);
                Next::Continue
            }
            Ok(NextJob::Install(job)) => self.take_job(job, client),
            Ok(NextJob::Settle(pending)) => {
                // Installed and rebooted for, but not in NVS: the record was
                // lost. The status details the reboot left behind stand in.
                log::warn!(
                    "OTA job {} is IN_PROGRESS after its reboot with no record on the device; settling it",
                    pending.job_id
                );
                self.settle(pending);
                self.send_report(client);
                Next::Continue
            }
            Err(e) => {
                log::warn!("unusable job description: {e}");
                Next::Continue
            }
        }
    }

    /// Decides on a firmware job ([`jobs::admit`]) and runs it if admitted.
    fn take_job(&mut self, job: FirmwareJob, client: &mut impl Transport) -> Next {
        let product = self.product.clone().unwrap_or_else(|| job.product.clone());
        let policy = Policy {
            product: &product,
            keyring: &self.keyring,
            signed_only: self.signed_only,
        };
        let expected = match jobs::admit(&job, &self.boot, &policy) {
            Admission::Install { expected } => expected,
            Admission::AlreadyRunning => {
                log::info!(
                    "OTA job {}: {} is already running; reporting SUCCEEDED without a download",
                    job.job_id,
                    self.boot.running_version
                );
                self.report(&job.job_id, &jobs::already_running(&self.boot));
                self.send_report(client);
                return Next::Continue;
            }
            Admission::AlreadyNewer => {
                log::info!(
                    "OTA job {}: {:?} is not newer than the running {}; reporting SUCCEEDED without a download",
                    job.job_id,
                    job.target_version,
                    self.boot.running_version
                );
                self.report(&job.job_id, &jobs::already_newer(&job, &self.boot));
                self.send_report(client);
                return Next::Continue;
            }
            Admission::Reject { code, detail } => {
                log::error!(
                    "refusing OTA job {}: {detail}; reporting REJECTED",
                    job.job_id
                );
                self.report(&job.job_id, &jobs::refused(code, &detail));
                self.send_report(client);
                return Next::Continue;
            }
            Admission::Fail { code, detail } => {
                log::error!("OTA job {}: {code}: {detail}; reporting FAILED", job.job_id);
                self.report(&job.job_id, &jobs::install_failed(&job, code, &detail));
                self.send_report(client);
                return Next::Continue;
            }
        };
        match jobs::next_attempt(self.store.load_attempts().as_ref(), &job.job_id) {
            Some(attempt) => {
                if let Err(e) = self.store.save_attempts(&attempt) {
                    // Uncounted, a crashing download repeats until the job
                    // times out, as it did before there was a count.
                    log::warn!("{e}");
                }
                self.run_update(&job, expected, attempt.count, client)
            }
            None => {
                log::error!(
                    "OTA job {}: {} downloads started and none finished; reporting FAILED",
                    job.job_id,
                    jobs::MAX_DOWNLOAD_ATTEMPTS
                );
                let update = jobs::download_interrupted(&job, jobs::MAX_DOWNLOAD_ATTEMPTS);
                self.report(&job.job_id, &update);
                self.send_report(client);
                Next::Continue
            }
        }
    }

    /// Decides the outcome of `pending` and queues it for [`Self::start`].
    fn settle(&mut self, pending: PendingUpdate) {
        let outcome = jobs::settle(&pending, &self.boot);
        match &outcome {
            Outcome::Succeeded => log::info!(
                "OTA job {}: {} is running from {}; reporting SUCCEEDED",
                pending.job_id,
                self.boot.running_version,
                self.boot.running_slot
            ),
            Outcome::Failed { reason, detail } => log::warn!(
                "OTA job {}: {reason} ({detail}); reporting FAILED",
                pending.job_id
            ),
        }
        let update = jobs::settled(&pending, &self.boot, &outcome);
        self.report(&pending.job_id, &update);
    }

    /// Queues a terminal status for `job_id`; nothing else is taken on until
    /// the Jobs service has answered it.
    fn report(&mut self, job_id: &str, status: &StatusUpdate) {
        let update = self.update_topic(job_id);
        let payload = status.encode();
        self.settling = Some(Settling {
            job_id: job_id.to_string(),
            status: status.status(),
            reason: status
                .detail_value("reason")
                .unwrap_or_default()
                .to_string(),
            accepted: format!("{update}/accepted"),
            rejected: format!("{update}/rejected"),
            update,
            payload,
            sent_at: None,
        });
    }

    /// Sends the queued status now rather than on the next [`Self::start`].
    fn send_report(&mut self, client: &mut impl Transport) {
        if let Some(settling) = self.settling.as_mut() {
            settling.send(client);
        }
    }

    /// Forgets the settled job and goes back to taking work.
    fn finish_settling(&mut self, client: &mut impl Transport) {
        let Some(settling) = self.settling.take() else {
            return;
        };
        if let Err(e) = self.store.clear() {
            // Harmless: the next boot reports again and is told it is done.
            log::warn!("{e}");
        }
        self.forget_attempts(&settling.job_id);
        for topic in [&settling.accepted, &settling.rejected] {
            if let Err(e) = client.unsubscribe(topic) {
                log::warn!("could not unsubscribe from {topic}: {e}");
            }
        }
        // Whatever was queued behind this job can run now.
        let _ = client.publish(&self.next_get, b"{}");
    }

    /// Drops the download count, if it is `job_id`'s.
    fn forget_attempts(&self, job_id: &str) {
        if self
            .store
            .load_attempts()
            .is_some_and(|a| a.job_id == job_id)
        {
            if let Err(e) = self.store.clear_attempts() {
                log::warn!("{e}");
            }
        }
    }

    fn update_topic(&self, job_id: &str) -> String {
        format!("{}{job_id}/update", self.prefix)
    }

    fn run_update(
        &mut self,
        job: &FirmwareJob,
        expected: Option<Expected>,
        attempt: u32,
        client: &mut impl Transport,
    ) -> Next {
        let update_topic = self.update_topic(job.job_id.as_str());
        let describe = Describe::new(&self.prefix, &job.job_id);
        log::info!(
            "starting OTA job {} ({} -> {:?}), download {attempt} of at most {}",
            job.job_id,
            self.boot.running_version,
            job.target_version,
            jobs::MAX_DOWNLOAD_ATTEMPTS
        );
        // Subscribed now, so the answer has somewhere to go when it is asked
        // for at the end of the download.
        describe.subscribe(client);
        let _ = client.publish(
            &update_topic,
            &jobs::downloading(job, &self.boot.running_version).encode(),
        );

        let store = &self.store;
        let from = self.boot.running_version.as_str();
        let mut unwanted = None;
        let installed = self
            .installer
            .install(&job.url, expected.as_ref(), &mut |slot| {
                // The download blocked every message for its whole length; a
                // cancellation sent meanwhile is only heard now.
                if let Err(why) = describe.still_wanted(client) {
                    unwanted = Some(why.clone());
                    return Err(why);
                }
                // Before activation, so the new image never boots without it.
                store.save(&job.pending(from, slot))
            });
        describe.unsubscribe(client);

        match installed {
            Ok(slot) => {
                let pending = job.pending(from, &slot);
                let _ = client.publish(&update_topic, &jobs::rebooting(&pending).encode());
                // Losing that status is not fatal: the next boot settles the
                // job from the NVS record, not from this message.
                log::info!("OTA image in {slot}; restarting into it");
                Next::Restart
            }
            Err(e) => {
                // The running image is still the boot image; a record written
                // just before a failed activation must not outlive it.
                if let Err(e) = self.store.clear() {
                    log::warn!("{e}");
                }
                self.forget_attempts(&job.job_id);
                if let Some(why) = unwanted {
                    // Nothing to report: the execution has ended already.
                    log::warn!("OTA job {}: not installing it, because {why}", job.job_id);
                    let _ = client.publish(&self.next_get, b"{}");
                } else {
                    log::error!("OTA failed: {e}");
                    let update = jobs::install_failed(job, e.code(), e.detail());
                    self.report(&job.job_id, &update);
                    self.send_report(client);
                }
                Next::Continue
            }
        }
    }
}

/// `DescribeJobExecution` for one job: is it still wanted?
struct Describe {
    get: String,
    accepted: String,
    rejected: String,
}

impl Describe {
    fn new(prefix: &str, job_id: &str) -> Self {
        let get = format!("{prefix}{job_id}/get");
        Self {
            accepted: format!("{get}/accepted"),
            rejected: format!("{get}/rejected"),
            get,
        }
    }

    fn subscribe(&self, client: &mut impl Transport) {
        for topic in [&self.accepted, &self.rejected] {
            if let Err(e) = client.subscribe(topic) {
                log::warn!("could not subscribe to {topic}: {e}");
            }
        }
    }

    fn unsubscribe(&self, client: &mut impl Transport) {
        for topic in [&self.accepted, &self.rejected] {
            if let Err(e) = client.unsubscribe(topic) {
                log::warn!("could not unsubscribe from {topic}: {e}");
            }
        }
    }

    /// Asks, and waits up to [`DESCRIBE_TIMEOUT`]. No answer is a yes.
    fn still_wanted(&self, client: &mut impl Transport) -> Result<(), String> {
        if let Err(e) = client.publish(&self.get, br#"{"includeJobDocument":false}"#) {
            log::warn!("could not ask whether the job is still wanted ({e}); installing it");
            return Ok(());
        }
        match client.wait_for(&[&self.accepted, &self.rejected], DESCRIBE_TIMEOUT) {
            Some((topic, payload)) => {
                let wanted = jobs::execution_wanted(topic == self.accepted, &payload);
                if wanted.is_ok() {
                    log::info!(
                        "the job is still wanted ({}); activating the image",
                        String::from_utf8_lossy(&payload)
                            .chars()
                            .take(160)
                            .collect::<String>()
                    );
                }
                wanted
            }
            None => {
                log::warn!(
                    "no answer within {} s on whether the job is still wanted; installing it",
                    DESCRIBE_TIMEOUT.as_secs()
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
// Most tests look at what was sent, not at what `handle` returned.
#[allow(unused_must_use)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use serde_json::{json, Value};

    use super::*;

    const THING: &str = "gw-1";
    const JOB: &str = "ota-firmware_v0-2-0-1790540983";
    const PREFIX: &str = "$aws/things/gw-1/jobs/";

    fn topic(rest: &str) -> String {
        format!("{PREFIX}{rest}")
    }

    /// Records what the client sends; answers `wait_for` from a script.
    #[derive(Default)]
    struct Wire {
        published: Vec<(String, Value)>,
        subscribed: Vec<String>,
        unsubscribed: Vec<String>,
        answers: VecDeque<(String, Vec<u8>)>,
        waited: Vec<Vec<String>>,
    }

    impl Transport for Wire {
        fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<(), String> {
            let body = serde_json::from_slice(payload).unwrap_or(Value::Null);
            self.published.push((topic.to_string(), body));
            Ok(())
        }

        fn subscribe(&mut self, topic: &str) -> Result<(), String> {
            self.subscribed.push(topic.to_string());
            Ok(())
        }

        fn unsubscribe(&mut self, topic: &str) -> Result<(), String> {
            self.unsubscribed.push(topic.to_string());
            Ok(())
        }

        fn wait_for(&mut self, topics: &[&str], _: Duration) -> Option<(String, Vec<u8>)> {
            self.waited
                .push(topics.iter().map(|t| t.to_string()).collect());
            self.answers.pop_front()
        }
    }

    impl Wire {
        fn topics(&self) -> Vec<&str> {
            self.published.iter().map(|(t, _)| t.as_str()).collect()
        }

        /// Bodies published on `jobs/{JOB}/update`.
        fn updates(&self) -> Vec<&Value> {
            let update = topic(&format!("{JOB}/update"));
            self.published
                .iter()
                .filter(|(t, _)| *t == update)
                .map(|(_, b)| b)
                .collect()
        }

        fn asked_for_next(&self) -> bool {
            self.topics().contains(&topic("$next/get").as_str())
        }

        fn clear(&mut self) {
            self.published.clear();
            self.subscribed.clear();
            self.unsubscribed.clear();
        }
    }

    /// NVS, in memory. The client owns it; the tests look through
    /// `client.store`.
    #[derive(Default)]
    struct Nvs {
        pending: RefCell<Option<PendingUpdate>>,
        attempts: RefCell<Option<DownloadAttempts>>,
    }

    impl Store for Nvs {
        fn load(&self) -> Option<PendingUpdate> {
            self.pending.borrow().clone()
        }

        fn save(&self, pending: &PendingUpdate) -> Result<(), String> {
            *self.pending.borrow_mut() = Some(pending.clone());
            Ok(())
        }

        fn clear(&self) -> Result<(), String> {
            *self.pending.borrow_mut() = None;
            Ok(())
        }

        fn load_attempts(&self) -> Option<DownloadAttempts> {
            self.attempts.borrow().clone()
        }

        fn save_attempts(&self, attempts: &DownloadAttempts) -> Result<(), String> {
            *self.attempts.borrow_mut() = Some(attempts.clone());
            Ok(())
        }

        fn clear_attempts(&self) -> Result<(), String> {
            *self.attempts.borrow_mut() = None;
            Ok(())
        }
    }

    /// An OTA that writes to `ota_1`, or fails before activation if `fail`
    /// says so.
    #[derive(Default)]
    struct Ota {
        fail: Option<String>,
        installs: u32,
        activated: bool,
    }

    impl Installer for Ota {
        fn install(
            &mut self,
            _url: &str,
            _expected: Option<&Expected>,
            before_activate: &mut dyn FnMut(&str) -> Result<(), String>,
        ) -> Result<String, InstallError> {
            self.installs += 1;
            if let Some(e) = &self.fail {
                return Err(InstallError::Download(e.clone()));
            }
            before_activate("ota_1").map_err(InstallError::Activate)?;
            self.activated = true;
            Ok("ota_1".into())
        }
    }

    type Client = JobsClient<Nvs, Ota>;

    fn boot(version: &str, slot: &str) -> BootFacts {
        BootFacts {
            running_version: version.into(),
            running_slot: slot.into(),
            invalid_slot: None,
            valid_error: None,
        }
    }

    fn pending() -> PendingUpdate {
        PendingUpdate {
            job_id: JOB.into(),
            from_version: "0.1.0".into(),
            target_version: "0.2.0".into(),
            target_slot: "ota_1".into(),
        }
    }

    fn client_with(store: Nvs, boot: BootFacts) -> Client {
        JobsClient::new(THING, store, Ota::default(), boot)
    }

    /// A fresh boot of 0.1.0 from `ota_0`, nothing pending.
    fn idle_client() -> Client {
        client_with(Nvs::default(), boot("0.1.0", "ota_0"))
    }

    fn recorded(pending: PendingUpdate) -> Nvs {
        let store = Nvs::default();
        *store.pending.borrow_mut() = Some(pending);
        store
    }

    fn offer(job_id: &str, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut execution = json!({
            "jobId": job_id,
            "status": "QUEUED",
            "jobDocument": {
                "operation": "firmware_update",
                "firmware_version": "firmware_v0.2.0",
                "download_url": "https://bucket.s3.amazonaws.com/firmware_v0.2.0.bin?sig=abc",
            },
        });
        edit(&mut execution);
        serde_json::to_vec(&json!({ "execution": execution })).unwrap()
    }

    fn queued() -> Vec<u8> {
        offer(JOB, |_| {})
    }

    fn deliver(client: &mut Client, wire: &mut Wire, rest: &str, payload: &[u8]) -> Next {
        let topic = topic(rest);
        assert!(client.owns(&topic), "{topic}");
        client.handle(&topic, payload, wire)
    }

    fn described(status: &str) -> (String, Vec<u8>) {
        (
            topic(&format!("{JOB}/get/accepted")),
            serde_json::to_vec(&json!({ "execution": { "jobId": JOB, "status": status } }))
                .unwrap(),
        )
    }

    // --- settling an update across the reboot -----------------------------------

    #[test]
    fn the_new_image_reports_the_recorded_job_before_taking_any_other() {
        let mut client = client_with(recorded(pending()), boot("0.2.0", "ota_1"));
        let mut wire = Wire::default();
        client.start(&mut wire).unwrap();

        let updates = wire.updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0]["status"], "SUCCEEDED");
        assert!(wire
            .subscribed
            .contains(&topic(&format!("{JOB}/update/accepted"))));
        assert!(!wire.asked_for_next(), "no other job while one settles");
    }

    #[test]
    fn nothing_else_is_taken_while_an_outcome_is_unacknowledged() {
        let mut client = client_with(recorded(pending()), boot("0.2.0", "ota_1"));
        let mut wire = Wire::default();
        client.start(&mut wire).unwrap();
        wire.clear();

        // The same execution, offered again because it is still IN_PROGRESS,
        // and a notification: both ignored, nothing downloaded.
        let again = offer(JOB, |e| e["status"] = "IN_PROGRESS".into());
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &again),
            Next::Continue
        );
        deliver(&mut client, &mut wire, "notify-next", b"{}");
        assert!(wire.published.is_empty());
        assert_eq!(client.installer.installs, 0);
    }

    #[test]
    fn an_acknowledged_outcome_clears_the_record_and_takes_the_next_job() {
        let store = recorded(pending());
        *store.attempts.borrow_mut() = Some(DownloadAttempts {
            job_id: JOB.into(),
            count: 1,
        });
        let mut client = client_with(store, boot("0.2.0", "ota_1"));
        let mut wire = Wire::default();
        client.start(&mut wire).unwrap();
        wire.clear();

        deliver(
            &mut client,
            &mut wire,
            &format!("{JOB}/update/accepted"),
            b"{}",
        );
        assert_eq!(client.store.load(), None);
        assert_eq!(client.store.load_attempts(), None);
        assert!(wire
            .unsubscribed
            .contains(&topic(&format!("{JOB}/update/accepted"))));
        assert!(wire.asked_for_next());
    }

    #[test]
    fn an_unacknowledged_outcome_is_sent_again_after_30_s_and_on_reconnect() {
        let mut client = client_with(recorded(pending()), boot("0.2.0", "ota_1"));
        let mut wire = Wire::default();
        client.start(&mut wire).unwrap();
        wire.clear();

        client.tick(&mut wire, Instant::now() + Duration::from_secs(1));
        assert!(wire.updates().is_empty(), "not yet");
        client.tick(
            &mut wire,
            Instant::now() + SETTLE_RETRY + Duration::from_secs(1),
        );
        assert_eq!(wire.updates().len(), 1);

        // A transient refusal is retried too, not dropped.
        let throttled = br#"{"code":"RequestThrottled","message":"slow down"}"#;
        deliver(
            &mut client,
            &mut wire,
            &format!("{JOB}/update/rejected"),
            throttled,
        );
        assert!(client.store.load().is_some());
        wire.clear();
        client.start(&mut wire).unwrap();
        assert_eq!(wire.updates().len(), 1, "a reconnect sends it again");
    }

    #[test]
    fn a_refused_outcome_is_dropped_and_its_job_ignored_until_reboot() {
        let mut client = client_with(recorded(pending()), boot("0.2.0", "ota_1"));
        let mut wire = Wire::default();
        client.start(&mut wire).unwrap();
        let ended = br#"{"code":"InvalidStateTransition","message":"CANCELED"}"#;
        deliver(
            &mut client,
            &mut wire,
            &format!("{JOB}/update/rejected"),
            ended,
        );
        assert_eq!(client.store.load(), None);
        assert!(wire.asked_for_next());
        wire.clear();

        // Offered again: neither settled again nor installed.
        let again = offer(JOB, |e| {
            e["status"] = "IN_PROGRESS".into();
            e["statusDetails"] = json!({"phase": "rebooting", "target_slot": "ota_1"});
        });
        deliver(&mut client, &mut wire, "$next/get/accepted", &again);
        deliver(&mut client, &mut wire, "$next/get/accepted", &queued());
        assert!(wire.published.is_empty());
        assert_eq!(client.installer.installs, 0);

        // Another job is taken.
        let other = offer("ota-other", |e| {
            e["jobDocument"]["firmware_version"] = "firmware_v0.3.0".into()
        });
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &other),
            Next::Restart
        );
    }

    #[test]
    fn a_job_reoffered_after_its_reboot_without_a_record_is_settled() {
        let mut client = client_with(Nvs::default(), boot("0.2.0", "ota_1"));
        let mut wire = Wire::default();
        client.start(&mut wire).unwrap();
        wire.clear();
        let after_reboot = offer(JOB, |e| {
            e["status"] = "IN_PROGRESS".into();
            e["statusDetails"] = json!({"phase": "rebooting", "from": "0.1.0", "target": "0.2.0", "target_slot": "ota_1"});
        });
        deliver(&mut client, &mut wire, "$next/get/accepted", &after_reboot);
        assert_eq!(wire.updates()[0]["status"], "SUCCEEDED");
        assert_eq!(client.installer.installs, 0);
    }

    // --- a power cut between the record and the activation ----------------------

    #[test]
    fn a_record_for_an_image_never_activated_is_dropped_and_the_job_retried() {
        // The image that downloaded it, still in ota_0; nothing marked invalid.
        let mut client = client_with(recorded(pending()), boot("0.1.0", "ota_0"));
        let mut wire = Wire::default();
        client.start(&mut wire).unwrap();
        assert!(wire.updates().is_empty(), "not reported FAILED");
        assert_eq!(client.store.load(), None);
        assert!(wire.asked_for_next());

        // Still `downloading`, so offered and installed again.
        let interrupted = offer(JOB, |e| {
            e["status"] = "IN_PROGRESS".into();
            e["statusDetails"] = json!({"phase": "downloading"});
        });
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &interrupted),
            Next::Restart
        );
    }

    #[test]
    fn a_real_rollback_is_still_reported_failed() {
        let mut rolled_back = boot("0.1.0", "ota_0");
        rolled_back.invalid_slot = Some("ota_1".into());
        let mut client = client_with(recorded(pending()), rolled_back);
        let mut wire = Wire::default();
        client.start(&mut wire).unwrap();
        let updates = wire.updates();
        assert_eq!(updates[0]["status"], "FAILED");
        assert_eq!(
            updates[0]["statusDetails"]["reason"],
            jobs::reason::ROLLBACK
        );
    }

    // --- installing ---------------------------------------------------------------

    #[test]
    fn an_update_is_recorded_before_activation_and_restarts_into_it() {
        let mut client = idle_client();
        let mut wire = Wire::default();
        wire.answers.push_back(described("IN_PROGRESS"));
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &queued()),
            Next::Restart
        );
        assert!(client.installer.activated);
        assert_eq!(client.store.load(), Some(pending()));
        assert_eq!(client.store.load_attempts().unwrap().count, 1);

        let updates = wire.updates();
        assert_eq!(updates.len(), 2);
        assert_eq!(
            updates[0]["statusDetails"]["phase"],
            jobs::PHASE_DOWNLOADING
        );
        assert_eq!(updates[1]["statusDetails"]["phase"], jobs::PHASE_REBOOTING);
        assert_eq!(updates[1]["statusDetails"]["target_slot"], "ota_1");
        // It asked whether the job was still wanted, and waited for the answer.
        assert!(wire
            .topics()
            .contains(&topic(&format!("{JOB}/get")).as_str()));
        assert_eq!(
            wire.waited,
            [[
                topic(&format!("{JOB}/get/accepted")),
                topic(&format!("{JOB}/get/rejected"))
            ]]
        );
        assert!(wire
            .unsubscribed
            .contains(&topic(&format!("{JOB}/get/accepted"))));
    }

    #[test]
    fn a_job_cancelled_during_the_download_is_not_installed() {
        let mut client = idle_client();
        let mut wire = Wire::default();
        wire.answers.push_back(described("CANCELED"));
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &queued()),
            Next::Continue
        );
        assert!(!client.installer.activated);
        assert_eq!(
            client.store.load(),
            None,
            "no record for an image never activated"
        );
        assert_eq!(client.store.load_attempts(), None);
        // Nothing reported past `downloading`: the execution has ended.
        assert_eq!(wire.updates().len(), 1);
        assert!(wire.asked_for_next());
    }

    #[test]
    fn a_job_cancelled_during_the_download_is_refused_a_description_and_not_installed() {
        // How the service actually answers for a cancelled execution.
        let mut client = idle_client();
        let mut wire = Wire::default();
        wire.answers.push_back((
            topic(&format!("{JOB}/get/rejected")),
            br#"{"code":"TerminalStateReached","message":"Job Execution has reached terminal state. It is neither IN_PROGRESS nor QUEUED"}"#.to_vec(),
        ));
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &queued()),
            Next::Continue
        );
        assert!(!client.installer.activated);
        assert_eq!(client.store.load(), None);
    }

    #[test]
    fn a_job_deleted_during_the_download_is_not_installed() {
        let mut client = idle_client();
        let mut wire = Wire::default();
        wire.answers.push_back((
            topic(&format!("{JOB}/get/rejected")),
            br#"{"code":"ResourceNotFound","message":"gone"}"#.to_vec(),
        ));
        deliver(&mut client, &mut wire, "$next/get/accepted", &queued());
        assert!(!client.installer.activated);
    }

    #[test]
    fn no_answer_on_the_job_installs_it_anyway() {
        let mut client = idle_client();
        let mut wire = Wire::default();
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &queued()),
            Next::Restart
        );
        assert!(client.installer.activated);
    }

    #[test]
    fn a_failed_install_is_reported_and_leaves_no_record() {
        let mut client = idle_client();
        client.installer.fail = Some("HTTP status: 403".into());
        let mut wire = Wire::default();
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &queued()),
            Next::Continue
        );
        let updates = wire.updates();
        assert_eq!(updates.last().unwrap()["status"], "FAILED");
        assert_eq!(
            updates.last().unwrap()["statusDetails"]["reason"],
            jobs::reason::DOWNLOAD
        );
        assert_eq!(client.store.load(), None);
        assert_eq!(client.store.load_attempts(), None);
    }

    #[test]
    fn a_download_that_keeps_dying_fails_the_job_instead_of_repeating() {
        // Each boot below is one that crashed mid-download: the count
        // survives in NVS, nothing else does.
        let store = Nvs::default();
        for attempt in 1..=jobs::MAX_DOWNLOAD_ATTEMPTS {
            let attempts = store.load_attempts();
            let next = jobs::next_attempt(attempts.as_ref(), JOB).unwrap();
            assert_eq!(next.count, attempt);
            store.save_attempts(&next).unwrap();
        }
        let mut client = client_with(store, boot("0.1.0", "ota_0"));
        let mut wire = Wire::default();
        let interrupted = offer(JOB, |e| {
            e["status"] = "IN_PROGRESS".into();
            e["statusDetails"] = json!({"phase": "downloading"});
        });
        deliver(&mut client, &mut wire, "$next/get/accepted", &interrupted);
        assert_eq!(client.installer.installs, 0);
        let updates = wire.updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0]["status"], "FAILED");
        assert_eq!(
            updates[0]["statusDetails"]["reason"],
            jobs::reason::DOWNLOAD
        );

        // Once that is on record, the count goes and the next job runs.
        deliver(
            &mut client,
            &mut wire,
            &format!("{JOB}/update/accepted"),
            b"{}",
        );
        assert_eq!(client.store.load_attempts(), None);
    }

    #[test]
    fn the_version_already_running_is_settled_without_a_download() {
        let mut client = client_with(Nvs::default(), boot("0.2.0", "ota_0"));
        let mut wire = Wire::default();
        assert_eq!(
            deliver(&mut client, &mut wire, "$next/get/accepted", &queued()),
            Next::Continue
        );
        assert_eq!(client.installer.installs, 0);
        assert_eq!(wire.updates()[0]["status"], "SUCCEEDED");
    }

    // --- refusing -----------------------------------------------------------------

    #[test]
    fn an_image_for_another_product_is_rejected_without_a_download() {
        let mut client = idle_client().with_product("gateway");
        let mut wire = Wire::default();
        // Same version as the running one: the product is checked first, so a
        // version shared between products is never taken as "already running".
        let other = offer(JOB, |e| {
            e["jobDocument"]["product"] = "vaktus".into();
            e["jobDocument"]["firmware_version"] = "firmware_v0.1.0".into();
        });
        deliver(&mut client, &mut wire, "$next/get/accepted", &other);
        assert_eq!(client.installer.installs, 0);
        let updates = wire.updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0]["status"], "REJECTED");
        assert_eq!(
            updates[0]["statusDetails"]["detail"],
            r#"the image is for product "vaktus", this device is "gateway""#
        );
    }

    #[test]
    fn an_image_for_this_product_or_none_is_installed() {
        for product in [Some("gateway"), None] {
            let mut client = idle_client().with_product("gateway");
            let mut wire = Wire::default();
            let job = offer(JOB, |e| {
                if let Some(p) = product {
                    e["jobDocument"]["product"] = p.into();
                }
            });
            deliver(&mut client, &mut wire, "$next/get/accepted", &job);
            assert_eq!(client.installer.installs, 1, "product {product:?}");
        }
    }

    #[test]
    fn without_a_product_set_any_product_is_installed() {
        let mut client = idle_client();
        let mut wire = Wire::default();
        let job = offer(JOB, |e| e["jobDocument"]["product"] = "vaktus".into());
        deliver(&mut client, &mut wire, "$next/get/accepted", &job);
        assert_eq!(client.installer.installs, 1);
    }

    #[test]
    fn a_refused_job_is_reported_rejected_instead_of_staying_queued() {
        let mut client = idle_client();
        let mut wire = Wire::default();
        let plaintext = offer(JOB, |e| {
            e["jobDocument"]["download_url"] = "http://bucket/firmware.bin".into()
        });
        deliver(&mut client, &mut wire, "$next/get/accepted", &plaintext);
        assert_eq!(client.installer.installs, 0);
        let updates = wire.updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0]["status"], "REJECTED");
        assert_eq!(
            updates[0]["statusDetails"]["detail"],
            "download_url is not https"
        );

        // Settled like any outcome: nothing else until it is on record.
        wire.clear();
        deliver(&mut client, &mut wire, "notify-next", b"{}");
        assert!(wire.published.is_empty());
        deliver(
            &mut client,
            &mut wire,
            &format!("{JOB}/update/accepted"),
            b"{}",
        );
        assert!(wire.asked_for_next());
    }

    #[test]
    fn other_operations_are_rejected_so_they_do_not_block_the_queue() {
        let mut client = idle_client();
        let mut wire = Wire::default();
        let reboot = offer(JOB, |e| e["jobDocument"]["operation"] = "reboot".into());
        deliver(&mut client, &mut wire, "$next/get/accepted", &reboot);
        let updates = wire.updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0]["status"], "REJECTED");
        assert_eq!(
            updates[0]["statusDetails"]["reason"],
            jobs::reason::OPERATION
        );
        deliver(
            &mut client,
            &mut wire,
            &format!("{JOB}/update/accepted"),
            b"{}",
        );
        assert_eq!(
            client.take_settled(),
            Some(Settled {
                job_id: JOB.into(),
                status: "REJECTED",
                reason: jobs::reason::OPERATION.into(),
            })
        );
        assert_eq!(client.take_settled(), None);
    }

    #[test]
    fn a_notification_asks_for_the_details() {
        let mut client = idle_client();
        let mut wire = Wire::default();
        deliver(&mut client, &mut wire, "notify-next", b"{}");
        assert_eq!(wire.topics(), [topic("$next/get").as_str()]);
    }

    #[test]
    fn only_this_things_jobs_topics_are_owned() {
        let client = idle_client();
        assert!(client.owns(&topic(&format!("{JOB}/get/accepted"))));
        assert!(!client.owns("$aws/things/gw-2/jobs/notify-next"));
        assert!(!client.owns("$aws/things/gw-1/shadow/name/opcua/get/accepted"));
    }
}
