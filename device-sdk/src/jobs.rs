//! AWS IoT Jobs firmware updates: the `iot-jobs` state machine (host-tested
//! there) on this device's MQTT ([`Link`]), NVS ([`JobStore`]) and OTA
//! partitions ([`Ota`]).

use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use iot_jobs::client::{self, Installer, Transport};
use iot_jobs::{Expected, InstallError};

use crate::job_store::JobStore;
use crate::mqtt::{Mqtt, MqttEvent};

pub type JobsClient = client::JobsClient<JobStore, Ota>;

/// The MQTT connection as the Jobs client sees it. Messages that arrive while
/// it waits for its own answer go to `backlog`, which the session drains
/// before reading the channel again.
pub struct Link<'a> {
    pub client: &'a Mqtt,
    pub events: &'a Receiver<MqttEvent>,
    pub backlog: &'a mut VecDeque<MqttEvent>,
}

impl Transport for Link<'_> {
    fn publish(&mut self, topic: &str, payload: &[u8]) -> Result<(), String> {
        self.client
            .publish(topic, payload)
            .map_err(|e| format!("{e:#}"))
    }

    fn subscribe(&mut self, topic: &str) -> Result<(), String> {
        self.client.subscribe(topic).map_err(|e| format!("{e:#}"))
    }

    fn unsubscribe(&mut self, topic: &str) -> Result<(), String> {
        self.client.unsubscribe(topic).map_err(|e| format!("{e:#}"))
    }

    fn wait_for(&mut self, topics: &[&str], timeout: Duration) -> Option<(String, Vec<u8>)> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.events.recv_timeout(left) {
                Ok(MqttEvent::Message { topic, data }) if topics.contains(&topic.as_str()) => {
                    return Some((topic, data));
                }
                Ok(other) => self.backlog.push_back(other),
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return None,
            }
        }
    }
}

/// How long the MQTT session gets to come back after the download before
/// the job is asked about; requests sent earlier wait in esp-mqtt's outbox.
const RESUME_GRACE: Duration = Duration::from_secs(3);

/// The OTA partitions.
///
/// The MQTT session is paused for the download: its TLS context, buffers
/// and task stack are heap an HTTPS download needs, a 16.7 KB TLS record
/// block above all, and the gateway did not have it while both ran. It is
/// started again before the job is asked whether it is still wanted.
pub struct Ota {
    pub(crate) mqtt: crate::mqtt::Pause,
}

impl Installer for Ota {
    fn install(
        &mut self,
        url: &str,
        expected: Option<&Expected>,
        before_activate: &mut dyn FnMut(&str) -> Result<(), String>,
    ) -> Result<String, InstallError> {
        let mqtt = self.mqtt;
        log::info!("OTA: pausing MQTT for the download");
        mqtt.stop();
        let mut resumed = false;
        let result = crate::ota::perform_ota(url, expected, |slot| {
            mqtt.start();
            resumed = true;
            std::thread::sleep(RESUME_GRACE);
            before_activate(slot)
        });
        if !resumed {
            mqtt.start();
        }
        result
    }
}
