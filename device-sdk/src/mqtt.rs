//! MQTT over mutual TLS, on the raw ESP-IDF `esp-mqtt` API.
//!
//! esp-idf-svc's `MqttClientConfiguration` (0.52) cannot set
//! `credentials.authentication.use_secure_element`, which a secure-element
//! device needs: its private key is in the ATECC608B, and esp-tls signs the
//! TLS handshake there (slot 0). So this wraps the few C calls itself. Events
//! are copied in the esp-mqtt task and handed over on a channel.
//!
//! Every publish of the device passes the platform's publish limiter
//! ([`device_core::limiter`]), whichever client sends it.
//!
//! esp-mqtt's own reconnect loop retries every few seconds forever, which
//! against a refusing platform is exactly the traffic the guard alarms watch
//! for. The session turns it off and reconnects with the platform's backoff
//! ([`Mqtt::reconnect`]); [`MqttEvent::Error`] says whether the platform
//! refused.

use std::ffi::{c_void, CString};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Result};
use device_core::limiter::Limiter;
use device_core::product::Limits;
use esp_idf_svc::sys::{
    esp_event_base_t, esp_mqtt_client_config_t, esp_mqtt_client_destroy, esp_mqtt_client_handle_t,
    esp_mqtt_client_init, esp_mqtt_client_publish, esp_mqtt_client_reconnect,
    esp_mqtt_client_register_event, esp_mqtt_client_start, esp_mqtt_client_subscribe_single,
    esp_mqtt_client_unsubscribe, esp_mqtt_error_type_t_MQTT_ERROR_TYPE_CONNECTION_REFUSED,
    esp_mqtt_error_type_t_MQTT_ERROR_TYPE_TCP_TRANSPORT, esp_mqtt_event_id_t_MQTT_EVENT_ANY,
    esp_mqtt_event_id_t_MQTT_EVENT_CONNECTED, esp_mqtt_event_id_t_MQTT_EVENT_DATA,
    esp_mqtt_event_id_t_MQTT_EVENT_DISCONNECTED, esp_mqtt_event_id_t_MQTT_EVENT_ERROR,
    esp_mqtt_event_t, ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED, ESP_OK,
};

/// QoS 1 for the platform's own traffic: AWS IoT does not support QoS 2.
pub const QOS1: i32 = 1;

/// Largest message reassembled from chunks. The length comes from the
/// broker, and an allocation failure inside the esp-mqtt task would abort the
/// firmware.
const MAX_MESSAGE: usize = 16 * 1024;

/// The device-wide publish limiter, set up by [`crate::Platform::init`].
static LIMITER: Mutex<Option<Limiter>> = Mutex::new(None);

pub(crate) fn init_limiter(limits: Limits) {
    if let Ok(mut l) = LIMITER.lock() {
        *l = Some(Limiter::new(limits));
    }
}

/// Admits one publish of `bytes` (see [`device_core::limiter`]).
fn admit(topic: &str, bytes: usize) -> Result<()> {
    let mut guard = LIMITER.lock().unwrap_or_else(|e| e.into_inner());
    let limiter = guard.get_or_insert_with(|| Limiter::new(Limits::DEFAULT));
    if let Err(refusal) = limiter.admit(bytes, crate::boot::now_ms()) {
        let refused = limiter.take_refused();
        // One line per burst of refusals, not one per publish.
        if refused <= 1 || refused % 50 == 0 {
            log::warn!("not publishing to {topic}: {refusal} ({refused} refused)");
        }
        bail!("{refusal}");
    }
    Ok(())
}

/// Why a connection attempt failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectError {
    /// The platform refused (CONNACK refusal, TLS handshake rejected): back
    /// off for long.
    pub refused: bool,
    /// The connection is affected (a transport error or a refused CONNECT),
    /// rather than a single request (a refused SUBSCRIBE, say).
    pub connection: bool,
    pub detail: String,
}

/// An event copied out of the esp-mqtt task.
#[derive(Debug)]
pub enum MqttEvent {
    Connected,
    Disconnected,
    Error(ConnectError),
    Message { topic: String, data: Vec<u8> },
}

/// One publish.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    pub topic: &'a str,
    pub payload: &'a [u8],
    /// 0 or 1: AWS IoT has no QoS 2.
    pub qos: i32,
    pub retain: bool,
}

/// How the client proves its identity.
pub enum Auth<'a> {
    /// Certificate and private key PEM in RAM (the claim; a soft key).
    Pem { cert: &'a str, key: &'a str },
    /// Certificate in RAM, key in the ATECC608B.
    SecureElement { cert: &'a str },
}

/// Everything a connection needs, passed by reference.
///
/// One struct rather than separate arguments: on Xtensa, a call with more
/// than six argument words (each `&str` is two) has its later arguments read
/// wrong by this toolchain.
pub struct Settings<'a> {
    /// `mqtts://host:8883`
    pub uri: &'a str,
    pub client_id: &'a str,
    pub root_ca: &'a str,
    pub auth: Auth<'a>,
    /// Input buffer; larger messages are reassembled up to 16 KB.
    pub buffer_size: i32,
    /// Let esp-mqtt reconnect by itself every 10 s (the short-lived claim
    /// connection), or leave reconnecting to the caller.
    pub auto_reconnect: bool,
}

/// What the event callback needs; boxed so its address is stable.
struct Context {
    tx: Mutex<Sender<MqttEvent>>,
    /// A message larger than the input buffer arrives in chunks; only the
    /// first carries the topic.
    partial: Mutex<Option<(String, Vec<u8>, usize)>>,
}

/// A running client. Dropping it disconnects and frees everything.
pub struct Mqtt {
    handle: esp_mqtt_client_handle_t,
    // Referenced by the client until it is destroyed.
    _context: Box<Context>,
    _strings: Vec<CString>,
}

// The handle is used from one thread at a time; esp-mqtt locks internally.
unsafe impl Send for Mqtt {}

impl Mqtt {
    /// Starts connecting. The connection comes up asynchronously: wait for
    /// [`MqttEvent::Connected`].
    pub fn connect(settings: &Settings<'_>) -> Result<(Self, Receiver<MqttEvent>)> {
        let c = |s: &str| CString::new(s).map_err(|_| anyhow::anyhow!("NUL in MQTT setting"));
        let uri = c(settings.uri)?;
        let client_id = c(settings.client_id)?;
        let root_ca = c(settings.root_ca)?;
        let (cert, key, secure_element) = match settings.auth {
            Auth::Pem { cert, key } => (c(cert)?, Some(c(key)?), false),
            Auth::SecureElement { cert } => (c(cert)?, None, true),
        };

        // SAFETY: a zeroed config is esp-mqtt's "all defaults"; every pointer
        // set below points into a CString kept alive in `_strings`.
        let mut cfg: esp_mqtt_client_config_t = unsafe { core::mem::zeroed() };
        cfg.broker.address.uri = uri.as_ptr();
        // PEM, NUL-terminated: a zero length means "up to the NUL".
        cfg.broker.verification.certificate = root_ca.as_ptr();
        cfg.credentials.client_id = client_id.as_ptr();
        cfg.credentials.authentication.certificate = cert.as_ptr();
        if let Some(key) = &key {
            cfg.credentials.authentication.key = key.as_ptr();
        }
        cfg.credentials.authentication.use_secure_element = secure_element;
        cfg.session.keepalive = 60;
        cfg.network.reconnect_timeout_ms = 10_000;
        cfg.network.timeout_ms = 20_000;
        cfg.network.disable_auto_reconnect = !settings.auto_reconnect;
        cfg.buffer.size = settings.buffer_size;
        // Room for the largest payload the limiter admits, plus the topic.
        cfg.buffer.out_size = settings.buffer_size.max(6 * 1024);
        // The TLS handshake (and with the secure element, the ATECC calls)
        // runs on this task.
        cfg.task.stack_size = 8192;

        let (tx, rx) = channel();
        let context = Box::new(Context {
            tx: Mutex::new(tx),
            partial: Mutex::new(None),
        });

        // SAFETY: `cfg` and every string it points to outlive the call; the
        // client copies what it keeps or keeps pointing at `_strings`.
        let handle = unsafe { esp_mqtt_client_init(&cfg) };
        if handle.is_null() {
            bail!("esp_mqtt_client_init failed");
        }
        let mut strings = vec![uri, client_id, root_ca, cert];
        strings.extend(key);
        let client = Self {
            handle,
            _context: context,
            _strings: strings,
        };

        let arg = &*client._context as *const Context as *mut c_void;
        // SAFETY: `arg` stays valid until `esp_mqtt_client_destroy` in Drop,
        // after which no more events are delivered.
        let err = unsafe {
            esp_mqtt_client_register_event(
                handle,
                esp_mqtt_event_id_t_MQTT_EVENT_ANY,
                Some(on_event),
                arg,
            )
        };
        if err != ESP_OK {
            bail!("esp_mqtt_client_register_event: {err}");
        }
        let err = unsafe { esp_mqtt_client_start(handle) };
        if err != ESP_OK {
            bail!("esp_mqtt_client_start: {err}");
        }
        Ok((client, rx))
    }

    /// Publishes at QoS 1, through the limiter.
    pub fn publish(&self, topic: &str, payload: &[u8]) -> Result<()> {
        self.publish_message(&Message {
            topic,
            payload,
            qos: QOS1,
            retain: false,
        })
    }

    /// Publishes with an explicit QoS and retain flag, through the limiter.
    /// One struct, not four arguments: see [`Settings`] on the Xtensa
    /// argument-register limit.
    pub fn publish_message(&self, message: &Message<'_>) -> Result<()> {
        let Message {
            topic,
            payload,
            qos,
            retain,
        } = *message;
        admit(topic, payload.len())?;
        let topic_c = CString::new(topic)?;
        // esp-mqtt reads a length of 0 as "NUL-terminated, take strlen()".
        // An empty slice's pointer is dangling (0x1): give it an empty C
        // string instead, which strlen() measures as 0.
        let data: *const core::ffi::c_char = if payload.is_empty() {
            c"".as_ptr()
        } else {
            payload.as_ptr().cast()
        };
        // SAFETY: both buffers outlive the call; esp-mqtt copies them.
        let id = unsafe {
            esp_mqtt_client_publish(
                self.handle,
                topic_c.as_ptr(),
                data,
                payload.len() as i32,
                qos,
                i32::from(retain),
            )
        };
        if id < 0 {
            bail!("publishing to {topic} failed ({id})");
        }
        Ok(())
    }

    pub fn subscribe(&self, topic: &str) -> Result<()> {
        let topic_c = CString::new(topic)?;
        // SAFETY: the string outlives the call.
        let id = unsafe { esp_mqtt_client_subscribe_single(self.handle, topic_c.as_ptr(), QOS1) };
        if id < 0 {
            bail!("subscribing to {topic} failed ({id})");
        }
        Ok(())
    }

    pub fn unsubscribe(&self, topic: &str) -> Result<()> {
        let topic_c = CString::new(topic)?;
        // SAFETY: the string outlives the call.
        let id = unsafe { esp_mqtt_client_unsubscribe(self.handle, topic_c.as_ptr()) };
        if id < 0 {
            bail!("unsubscribing from {topic} failed ({id})");
        }
        Ok(())
    }

    /// Starts one reconnection attempt (with auto-reconnect off).
    pub fn reconnect(&self) -> Result<()> {
        // SAFETY: a live handle.
        let err = unsafe { esp_mqtt_client_reconnect(self.handle) };
        if err != ESP_OK {
            bail!("esp_mqtt_client_reconnect: {err}");
        }
        Ok(())
    }
}

impl Drop for Mqtt {
    fn drop(&mut self) {
        // SAFETY: the handle came from esp_mqtt_client_init and is destroyed
        // once; this also stops the task, so the context is no longer used.
        unsafe { esp_mqtt_client_destroy(self.handle) };
    }
}

/// Waits up to `timeout` for the connection to come up. An error event ends
/// the wait early.
pub fn wait_connected(events: &Receiver<MqttEvent>, timeout: Duration) -> Result<(), ConnectError> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match events.recv_timeout(left) {
            Ok(MqttEvent::Connected) => return Ok(()),
            Ok(MqttEvent::Error(e)) if e.connection => return Err(e),
            Ok(_) => continue,
            Err(_) => {
                return Err(ConnectError {
                    refused: false,
                    connection: true,
                    detail: format!("no MQTT connection within {} s", timeout.as_secs()),
                })
            }
        }
    }
}

unsafe extern "C" fn on_event(
    arg: *mut c_void,
    _base: esp_event_base_t,
    event_id: i32,
    event_data: *mut c_void,
) {
    // SAFETY: `arg` is the boxed Context (see `connect`), `event_data` the
    // esp_mqtt_event_t esp-mqtt passes for the duration of the call.
    let ctx = unsafe { &*(arg as *const Context) };
    let send = |e| {
        if let Ok(tx) = ctx.tx.lock() {
            let _ = tx.send(e);
        }
    };
    match event_id {
        id if id == esp_mqtt_event_id_t_MQTT_EVENT_CONNECTED => send(MqttEvent::Connected),
        id if id == esp_mqtt_event_id_t_MQTT_EVENT_DISCONNECTED => send(MqttEvent::Disconnected),
        id if id == esp_mqtt_event_id_t_MQTT_EVENT_ERROR => {
            let ev = unsafe { &*(event_data as *const esp_mqtt_event_t) };
            // SAFETY: esp-mqtt sets error_handle on every error event.
            let Some(codes) = (unsafe { ev.error_handle.as_ref() }) else {
                return;
            };
            let refused = codes.error_type
                == esp_mqtt_error_type_t_MQTT_ERROR_TYPE_CONNECTION_REFUSED
                || codes.esp_tls_last_esp_err == ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED;
            let connection =
                refused || codes.error_type == esp_mqtt_error_type_t_MQTT_ERROR_TYPE_TCP_TRANSPORT;
            send(MqttEvent::Error(ConnectError {
                refused,
                connection,
                detail: format!(
                    "type {} connack {} tls 0x{:x} errno {}",
                    codes.error_type,
                    codes.connect_return_code,
                    codes.esp_tls_last_esp_err,
                    codes.esp_transport_sock_errno
                ),
            }));
        }
        id if id == esp_mqtt_event_id_t_MQTT_EVENT_DATA => {
            let ev = unsafe { &*(event_data as *const esp_mqtt_event_t) };
            let bytes = |p: *const core::ffi::c_char, n: i32| -> &[u8] {
                if p.is_null() || n <= 0 {
                    &[]
                } else {
                    unsafe { core::slice::from_raw_parts(p.cast(), n as usize) }
                }
            };
            let data = bytes(ev.data, ev.data_len);
            let total = ev.total_data_len.max(0) as usize;
            if total > MAX_MESSAGE {
                if ev.current_data_offset == 0 {
                    log::warn!("dropping a {total} B MQTT message (limit {MAX_MESSAGE} B)");
                }
                return;
            }
            let Ok(mut partial) = ctx.partial.lock() else {
                return;
            };
            if ev.current_data_offset == 0 {
                let topic = String::from_utf8_lossy(bytes(ev.topic, ev.topic_len)).into_owned();
                if data.len() >= total {
                    send(MqttEvent::Message {
                        topic,
                        data: data.to_vec(),
                    });
                    return;
                }
                let mut buf = Vec::with_capacity(total);
                buf.extend_from_slice(data);
                *partial = Some((topic, buf, total));
                return;
            }
            if let Some((_, buf, total)) = partial.as_mut() {
                buf.extend_from_slice(data);
                if buf.len() >= *total {
                    let (topic, data, _) = partial.take().expect("checked above");
                    send(MqttEvent::Message { topic, data });
                }
            }
        }
        _ => {}
    }
}
