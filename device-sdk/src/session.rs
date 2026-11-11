//! The device's connection to AWS IoT, with the platform's planes on it.
//!
//! One MQTT session carries:
//!
//! * **Jobs** (OTA): handled here, by the `iot-jobs` state machine;
//! * **the `platform` shadow**: reported on connect, on change and every 6 h;
//!   its `desired.telemetry.enabled` is the product's telemetry switch;
//! * **the product's own topics**: handed to the product by [`Session::poll`].
//!
//! The image is marked valid on the first CONNACK. Reconnects follow the
//! platform's backoff (`device_core::backoff`): quick retries for a network
//! failure, a minute to six hours for a refusal.

use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::Result;
use device_core::backoff::{Failure, Reconnect, HEALTHY_AFTER_S};
use device_core::nvs::{self, Identity, PLATFORM_NS};
use device_core::product::Product;
use device_core::shadow::{self, LastJob, Report, TelemetryState};
use iot_jobs::client::Next;
use iot_jobs::Keyring;

use crate::job_store::JobStore;
use crate::jobs::{JobsClient, Link, Ota};
use crate::kv::NvsKv;
use crate::mqtt::{self, Mqtt, MqttEvent};

/// How often failed Jobs subscriptions are tried again while connected.
const JOBS_RETRY: Duration = Duration::from_secs(30);
/// How long the first report waits for the shadow's desired state.
const DESIRED_WAIT: Duration = Duration::from_secs(10);

/// Connection options a product may set.
#[derive(Debug, Clone, Copy)]
pub struct ConnectOptions {
    /// MQTT input buffer. Larger messages are reassembled up to 16 KB, but a
    /// product that must see a large retained message in one piece sizes it.
    pub buffer_size: i32,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self { buffer_size: 4096 }
    }
}

/// What [`Session::poll`] hands the product.
#[derive(Debug)]
pub enum Event {
    /// (Re)connected: subscriptions are gone; make the product's again.
    Connected,
    Disconnected,
    /// A message on one of the product's topics.
    Message {
        topic: String,
        data: Vec<u8>,
    },
    /// An update is installed. Call [`crate::restart_into_update`].
    Restart,
}

/// A live session.
pub struct Session {
    product: &'static Product,
    thing: String,
    client: Mqtt,
    events: Receiver<MqttEvent>,
    backlog: VecDeque<MqttEvent>,
    jobs: JobsClient,
    jobs_started: bool,
    last_jobs_start: Instant,
    shadow: shadow::Topics,
    telemetry: bool,
    desired_known: bool,
    last_report: Option<(Report, Instant)>,
    connected_at: Option<Instant>,
    report_due_at: Option<Instant>,
    reconnect: Reconnect,
    retry_at: Option<Instant>,
    last_tick: Instant,
    boot: crate::BootInfo,
    last_job: Option<LastJob>,
    platform: NvsKv,
}

impl Session {
    /// Connects as `identity`, retrying with the platform's backoff until the
    /// first CONNACK, and marks the image valid.
    pub(crate) fn connect(
        p: &crate::Platform,
        identity: &Identity,
        opts: &ConnectOptions,
    ) -> Result<Self> {
        let product = p.product;
        let platform = NvsKv::open(&p.nvs, PLATFORM_NS)?;
        let endpoint = nvs::endpoint(&platform, product.endpoint);
        let uri = Product::broker_uri(&endpoint);
        crate::set_status(format!("connecting as {}", identity.thing_name));
        let (client, events) = Mqtt::connect(&mqtt::Settings {
            uri: &uri,
            // The device policy only lets a thing connect with its own name.
            client_id: &identity.thing_name,
            root_ca: crate::ROOT_CA,
            auth: crate::key::auth(identity),
            buffer_size: opts.buffer_size,
            auto_reconnect: false,
        })?;

        let mut reconnect = Reconnect::new();
        loop {
            match mqtt::wait_connected(&events, Duration::from_secs(60)) {
                Ok(()) => break,
                Err(e) => {
                    let failure = if e.refused {
                        Failure::Refused
                    } else {
                        Failure::Network
                    };
                    let delay = reconnect.on_failure(failure, crate::boot::random_u32());
                    log::warn!(
                        "AWS IoT connection {} ({}); next attempt in {delay} s",
                        if e.refused { "refused" } else { "failed" },
                        e.detail
                    );
                    crate::set_status(if e.refused {
                        "connection refused; backing off".to_string()
                    } else {
                        "offline; reconnecting".to_string()
                    });
                    std::thread::sleep(Duration::from_secs(delay));
                    // Drain what the failed attempt left behind.
                    while events.try_recv().is_ok() {}
                    client.reconnect()?;
                }
            }
        }
        crate::set_status(format!("online: {}", identity.thing_name));

        // This image reached AWS IoT with its identity: keep it.
        let valid = crate::boot::mark_valid();
        if let Err(e) = &valid {
            log::warn!("could not mark the firmware valid: {e:#}");
        }
        let facts = crate::boot::boot_facts(product.fw_version, &valid);

        let keyring = Keyring::from_pems(product.signing_keys.iter().map(|k| (k.id, k.pem)))
            .unwrap_or_else(|e| {
                // platform-build checked them; this cannot happen in a built
                // image, and an empty keyring only refuses signed jobs.
                log::error!("signing keyring: {e}");
                Keyring::default()
            });
        let jobs = JobsClient::new(
            &identity.thing_name,
            JobStore::new(p.nvs.clone())?,
            Ota {
                mqtt: client.pause_handle(),
            },
            facts,
        )
        .with_product(product.id)
        .with_keyring(keyring)
        .signed_only(cfg!(feature = "signed-only"));

        let now = Instant::now();
        let mut session = Self {
            product,
            thing: identity.thing_name.clone(),
            client,
            events,
            backlog: VecDeque::new(),
            jobs,
            jobs_started: false,
            last_jobs_start: now,
            shadow: shadow::Topics::new(&identity.thing_name, shadow::NAME),
            telemetry: false,
            desired_known: false,
            last_report: None,
            connected_at: None,
            report_due_at: None,
            reconnect,
            retry_at: None,
            last_tick: now,
            boot: p.boot.clone(),
            last_job: nvs::load_last_job(&platform),
            platform,
        };
        session.on_connected();
        Ok(session)
    }

    /// The thing name, which is also the MQTT client id.
    pub fn thing_name(&self) -> &str {
        &self.thing
    }

    /// The MQTT client, for the product's own topics. Every publish passes
    /// the platform's limiter.
    pub fn client(&self) -> &Mqtt {
        &self.client
    }

    /// Publishes at QoS 1 through the limiter.
    pub fn publish(&self, topic: &str, payload: &[u8]) -> Result<()> {
        self.client.publish(topic, payload)
    }

    /// The platform's telemetry switch (`platform` shadow,
    /// `desired.telemetry.enabled`; off until the platform turns it on). A
    /// product publishes telemetry only while it is on.
    pub fn telemetry_enabled(&self) -> bool {
        self.telemetry
    }

    pub fn is_connected(&self) -> bool {
        self.connected_at.is_some()
    }

    /// Waits up to `timeout` for the next event the product should see, and
    /// does the platform's periodic work. Returns `None` on a timeout or when
    /// the event was the platform's own.
    pub fn poll(&mut self, timeout: Duration) -> Option<Event> {
        self.tick();
        let event = match self.backlog.pop_front() {
            Some(e) => e,
            None => match self.events.recv_timeout(timeout) {
                Ok(e) => e,
                Err(RecvTimeoutError::Timeout) => return None,
                Err(RecvTimeoutError::Disconnected) => {
                    std::thread::sleep(timeout);
                    return None;
                }
            },
        };
        match event {
            MqttEvent::Connected => {
                log::info!("MQTT reconnected; restoring subscriptions");
                self.on_connected();
                Some(Event::Connected)
            }
            MqttEvent::Disconnected => {
                let was_connected = self.connected_at.take().is_some();
                if self.retry_at.is_none() {
                    self.schedule_retry(Failure::Network, "connection lost".into());
                }
                was_connected.then_some(Event::Disconnected)
            }
            MqttEvent::Error(e) if !e.connection => {
                // One request failed (a refused SUBSCRIBE): the connection
                // is fine.
                log::warn!("MQTT request failed: {}", e.detail);
                None
            }
            MqttEvent::Error(e) => {
                // The connection failed. While connected, esp-mqtt follows
                // with DISCONNECTED, which ends the session's connected
                // state; the error decides how long to back off.
                let failure = if e.refused {
                    Failure::Refused
                } else {
                    Failure::Network
                };
                if self.retry_at.is_none() {
                    self.schedule_retry(failure, e.detail);
                }
                None
            }
            MqttEvent::Message { topic, data } => {
                if self.jobs.owns(&topic) {
                    let next = self.jobs.handle(
                        &topic,
                        &data,
                        &mut Link {
                            client: &self.client,
                            events: &self.events,
                            backlog: &mut self.backlog,
                        },
                    );
                    self.record_settled();
                    if next == Next::Restart {
                        crate::set_status("update installed; restarting");
                        return Some(Event::Restart);
                    }
                    None
                } else if self.shadow.owns(&topic) {
                    self.on_platform_shadow(&topic, &data);
                    None
                } else {
                    Some(Event::Message { topic, data })
                }
            }
        }
    }

    fn on_connected(&mut self) {
        let now = Instant::now();
        self.connected_at = Some(now);
        self.retry_at = None;
        crate::set_status(format!("online: {}", self.thing));
        self.start_jobs();
        for topic in self.shadow.subscriptions() {
            if let Err(e) = self.client.subscribe(topic) {
                log::warn!("platform shadow: {e:#}");
            }
        }
        self.desired_known = false;
        if let Err(e) = self.client.publish(&self.shadow.get, b"") {
            log::warn!("platform shadow get: {e:#}");
        }
        // The first report waits briefly for `desired`, so it echoes the
        // telemetry switch instead of leaving a delta.
        self.report_due_at = Some(now + DESIRED_WAIT);
    }

    fn schedule_retry(&mut self, failure: Failure, detail: String) {
        let delay = self
            .reconnect
            .on_failure(failure, crate::boot::random_u32());
        log::warn!(
            "AWS IoT connection {} ({detail}); next attempt in {delay} s",
            if failure == Failure::Refused {
                "refused"
            } else {
                "lost"
            }
        );
        crate::set_status(if failure == Failure::Refused {
            "connection refused; backing off"
        } else {
            "offline; reconnecting"
        });
        self.retry_at = Some(Instant::now() + Duration::from_secs(delay));
    }

    fn start_jobs(&mut self) {
        self.last_jobs_start = Instant::now();
        let mut link = Link {
            client: &self.client,
            events: &self.events,
            backlog: &mut self.backlog,
        };
        self.jobs_started = match self.jobs.start(&mut link) {
            Ok(()) => true,
            Err(e) => {
                log::warn!("Jobs subscriptions not set up yet: {e}");
                false
            }
        };
    }

    fn on_platform_shadow(&mut self, topic: &str, data: &[u8]) {
        if topic == self.shadow.get_rejected {
            // A 404 means the shadow does not exist yet: defaults.
            log::info!(
                "platform shadow: none yet ({})",
                String::from_utf8_lossy(data)
            );
            self.desired_known = true;
            self.report_due_at = Some(Instant::now());
            return;
        }
        let delta = topic == self.shadow.update_delta;
        match shadow::parse_desired(delta, data) {
            Ok(desired) => {
                if let Some(on) = desired.telemetry_enabled {
                    if on != self.telemetry {
                        log::info!("platform: telemetry {}", if on { "on" } else { "off" });
                    }
                    self.telemetry = on;
                } else if !delta {
                    // A full document without the setting: the default.
                    self.telemetry = false;
                }
                self.desired_known = true;
                self.report_due_at = Some(Instant::now());
            }
            Err(e) => log::warn!("platform shadow: {e}"),
        }
    }

    fn record_settled(&mut self) {
        if let Some(settled) = self.jobs.take_settled() {
            let job = LastJob {
                id: settled.job_id,
                status: settled.status.to_string(),
                reason: settled.reason,
            };
            if let Err(e) = nvs::save_last_job(&mut self.platform, &job) {
                log::warn!("could not record the last job: {e}");
            }
            self.last_job = Some(job);
            self.report_due_at = Some(Instant::now());
        }
    }

    fn report(&self) -> Report {
        Report {
            contract: device_core::CONTRACT,
            product: self.product.id.to_string(),
            fw: self.product.fw_version.to_string(),
            slot: self.boot.slot.clone(),
            boot_reason: self.boot.reason.to_string(),
            boot_count_since_update: self.boot.count,
            uptime_s: crate::boot::uptime_s(),
            key_id: self
                .product
                .key_ids()
                .into_iter()
                .map(str::to_string)
                .collect(),
            last_job: self.last_job.clone(),
            telemetry: TelemetryState {
                enabled: self.telemetry,
            },
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if !self.is_connected() {
            if self.retry_at.is_some_and(|at| now >= at) {
                self.retry_at = None;
                crate::set_status("reconnecting");
                if let Err(e) = self.client.reconnect() {
                    log::warn!("{e:#}");
                    self.schedule_retry(Failure::Network, format!("{e:#}"));
                }
            }
            return;
        }
        if now.saturating_duration_since(self.last_tick) < Duration::from_secs(1) {
            return;
        }
        self.last_tick = now;

        if self
            .connected_at
            .is_some_and(|at| now.saturating_duration_since(at).as_secs() >= HEALTHY_AFTER_S)
        {
            self.reconnect.on_healthy();
        }
        if !self.jobs_started && now.saturating_duration_since(self.last_jobs_start) >= JOBS_RETRY {
            self.start_jobs();
        }
        self.jobs.tick(
            &mut Link {
                client: &self.client,
                events: &self.events,
                backlog: &mut self.backlog,
            },
            now,
        );
        self.record_settled();

        let report = self.report();
        let due = match &self.last_report {
            None => self.report_due_at.is_some_and(|at| now >= at),
            Some((last, at)) => {
                (self.report_due_at.is_some_and(|due| now >= due) && report.changed_from(last))
                    || now.saturating_duration_since(*at).as_secs() >= shadow::REPORT_EVERY_S
            }
        };
        if due {
            match self
                .client
                .publish(&self.shadow.update, &report.to_update())
            {
                Ok(()) => {
                    log::info!(
                        "platform shadow: reported {} on {} (boot {} of it, {})",
                        report.fw,
                        report.slot,
                        report.boot_count_since_update,
                        report.boot_reason
                    );
                    self.last_report = Some((report, now));
                    self.report_due_at = None;
                }
                Err(e) => log::warn!("platform shadow report: {e:#}"),
            }
        } else if self.last_report.is_some() && self.report_due_at.is_some_and(|at| now >= at) {
            // Nothing changed since the last report.
            self.report_due_at = None;
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        crate::set_status("offline");
    }
}
