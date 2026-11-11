//! Bench provisioning over the serial console.
//!
//! Images carry no secrets. The claim credential and Wi-Fi reach a device
//! only at the bench: `ergo commission` writes them into NVS `platform` over
//! the USB serial console, and the device erases the claim once it has its own
//! certificate. The same console tells `ergo` what to register: the MAC and
//! the device's public key.
//!
//! One line per message, ASCII, `\n`-terminated, all starting `PLATFORM `.
//! Everything else on the console (the firmware's log) is ignored by both
//! sides. Values are base64 (PEM has newlines, an SSID may have spaces), and
//! the device never echoes one back.
//!
//! Host to device:
//!
//! ```text
//! PLATFORM INFO                      -> REGISTER line, then OK INFO
//! PLATFORM SET <key> <base64 value>  -> OK SET <key> | ERR SET <why>
//! PLATFORM ERASE                     -> OK ERASE (claim, Wi-Fi, endpoint gone)
//! PLATFORM ENROL                     -> OK ENROL (try enrolment now, no backoff)
//! PLATFORM FORGET                    -> OK FORGET, then a restart without its
//!                                       identity (re-enrolment at the bench)
//! ```
//!
//! `pubkey=-` in REGISTER means the device has no P-256 key to register: a
//! gateway enrolled before the SDK holds an RSA key from
//! `CreateKeysAndCertificate`. `FORGET` drops it, and the device generates a
//! P-256 key as it comes back.
//!
//! Device to host:
//!
//! ```text
//! PLATFORM REGISTER product=<id> mac=<AA:..> thing=<MAC12> pubkey=<128 hex> fw=<X.Y.Z> enrolled=<bool>
//! PLATFORM OK <verb> [<key>]
//! PLATFORM ERR <verb> <message>
//! PLATFORM EVENT <name> [<k>=<v> ...]   e.g. EVENT enrolled thing=38182B8456F4
//! ```
//!
//! Physical access to the console is the trust boundary, as it is for
//! flashing: anyone who can type here can also reflash the board.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// Every protocol line starts with this.
pub const PREFIX: &str = "PLATFORM ";

/// Longest line the device accepts. A claim key in base64 is ~2.3 KB.
pub const MAX_LINE: usize = 8 * 1024;

/// The NVS `platform` keys the console may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Overrides the compiled-in IoT endpoint.
    Endpoint,
    /// Claim certificate PEM. Erased after enrolment.
    ClaimCert,
    /// Claim private key PEM. Erased after enrolment.
    ClaimKey,
    WifiSsid,
    WifiPsk,
}

impl Key {
    pub const ALL: [Key; 5] = [
        Key::Endpoint,
        Key::ClaimCert,
        Key::ClaimKey,
        Key::WifiSsid,
        Key::WifiPsk,
    ];

    /// The NVS key, which is also the console spelling (≤ 15 characters).
    pub fn nvs_key(self) -> &'static str {
        match self {
            Key::Endpoint => "endpoint",
            Key::ClaimCert => "claim_cert",
            Key::ClaimKey => "claim_key",
            Key::WifiSsid => "wifi_ssid",
            Key::WifiPsk => "wifi_psk",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.nvs_key() == s)
    }

    /// True for values that must never be logged or echoed.
    pub fn is_secret(self) -> bool {
        matches!(self, Key::ClaimKey | Key::WifiPsk)
    }

    /// Checks a value before the device stores it.
    pub fn validate(self, value: &str) -> Result<(), String> {
        match self {
            Key::Endpoint => {
                let ok = !value.is_empty()
                    && value.len() <= 253
                    && value
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                    && value.ends_with(".amazonaws.com");
                if !ok {
                    return Err("not an AWS IoT endpoint host name".into());
                }
            }
            Key::ClaimCert => {
                if !value.contains("-----BEGIN CERTIFICATE-----") || value.len() > 4000 {
                    return Err("not a PEM certificate".into());
                }
            }
            Key::ClaimKey => {
                if !value.contains("PRIVATE KEY-----") || value.len() > 4000 {
                    return Err("not a PEM private key".into());
                }
            }
            Key::WifiSsid => {
                if value.is_empty() || value.len() > 32 {
                    return Err("an SSID is 1-32 bytes".into());
                }
            }
            Key::WifiPsk => {
                if !(value.is_empty() || (8..=63).contains(&value.len())) {
                    return Err("a WPA2 passphrase is 8-63 characters (empty: open network)".into());
                }
            }
        }
        if value.contains('\0') {
            return Err("NUL in value".into());
        }
        Ok(())
    }
}

/// A host-to-device command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Info,
    Set { key: Key, value: String },
    Erase,
    Enrol,
    Forget,
}

impl Command {
    /// The verb, as replies name it.
    pub fn verb(&self) -> &'static str {
        match self {
            Command::Info => "INFO",
            Command::Set { .. } => "SET",
            Command::Erase => "ERASE",
            Command::Enrol => "ENROL",
            Command::Forget => "FORGET",
        }
    }

    /// The line to send (without the newline).
    pub fn encode(&self) -> String {
        match self {
            Command::Set { key, value } => {
                format!("{PREFIX}SET {} {}", key.nvs_key(), B64.encode(value))
            }
            other => format!("{PREFIX}{}", other.verb()),
        }
    }

    /// Parses a console line. `None` for a line that is not a command (log
    /// output, noise); `Some(Err)` for a malformed command, which the device
    /// answers with `ERR`.
    pub fn parse(line: &str) -> Option<Result<Command, String>> {
        let rest = line.trim_end_matches(['\r', '\n']).strip_prefix(PREFIX)?;
        let mut words = rest.split(' ');
        let verb = words.next().unwrap_or_default();
        let parsed = match verb {
            "INFO" => Ok(Command::Info),
            "ERASE" => Ok(Command::Erase),
            "ENROL" => Ok(Command::Enrol),
            "FORGET" => Ok(Command::Forget),
            "SET" => (|| {
                let key = words.next().ok_or("SET needs a key")?;
                let key = Key::parse(key).ok_or_else(|| format!("unknown key {key:?}"))?;
                let encoded = words.next().unwrap_or_default();
                let raw = B64
                    .decode(encoded)
                    .map_err(|_| "the value is not base64".to_string())?;
                let value =
                    String::from_utf8(raw).map_err(|_| "the value is not UTF-8".to_string())?;
                key.validate(&value)?;
                Ok(Command::Set { key, value })
            })(),
            other => Err(format!("unknown command {other:?}")),
        };
        Some(parsed)
    }
}

/// What the device announces for registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub product: String,
    /// `AA:BB:CC:DD:EE:FF`.
    pub mac: String,
    pub thing: String,
    /// X||Y of the P-256 public key, 128 uppercase hex digits.
    pub pubkey: String,
    pub fw: String,
    /// The device already has its own certificate.
    pub enrolled: bool,
}

/// A device-to-host line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Register(Register),
    Ok {
        verb: String,
        key: Option<String>,
    },
    Err {
        verb: String,
        message: String,
    },
    Event {
        name: String,
        fields: Vec<(String, String)>,
    },
}

impl Reply {
    /// The line to print (without the newline). Messages are kept to one line.
    pub fn encode(&self) -> String {
        match self {
            Reply::Register(r) => format!(
                "{PREFIX}REGISTER product={} mac={} thing={} pubkey={} fw={} enrolled={}",
                r.product, r.mac, r.thing, r.pubkey, r.fw, r.enrolled
            ),
            Reply::Ok { verb, key } => match key {
                Some(key) => format!("{PREFIX}OK {verb} {key}"),
                None => format!("{PREFIX}OK {verb}"),
            },
            Reply::Err { verb, message } => {
                format!("{PREFIX}ERR {verb} {}", one_line(message))
            }
            Reply::Event { name, fields } => {
                let mut line = format!("{PREFIX}EVENT {name}");
                for (k, v) in fields {
                    line.push_str(&format!(" {k}={}", v.replace([' ', '\n', '\r'], "_")));
                }
                line
            }
        }
    }

    /// Finds a reply in a console line. The prefix may be preceded by log
    /// decoration (colour codes, a partial line).
    pub fn parse(line: &str) -> Option<Reply> {
        let start = line.find(PREFIX)?;
        let rest = line[start + PREFIX.len()..].trim_end_matches(['\r', '\n']);
        let (kind, tail) = rest.split_once(' ').unwrap_or((rest, ""));
        match kind {
            "REGISTER" => {
                let fields = fields(tail);
                let get = |k: &str| {
                    fields
                        .iter()
                        .find(|(name, _)| name == k)
                        .map(|(_, v)| v.clone())
                };
                Some(Reply::Register(Register {
                    product: get("product")?,
                    mac: get("mac")?,
                    thing: get("thing")?,
                    pubkey: get("pubkey")?,
                    fw: get("fw").unwrap_or_default(),
                    enrolled: get("enrolled").as_deref() == Some("true"),
                }))
            }
            "OK" => {
                let mut words = tail.split_whitespace();
                Some(Reply::Ok {
                    verb: words.next()?.to_string(),
                    key: words.next().map(str::to_string),
                })
            }
            "ERR" => {
                let (verb, message) = tail.split_once(' ').unwrap_or((tail, ""));
                Some(Reply::Err {
                    verb: verb.to_string(),
                    message: message.to_string(),
                })
            }
            "EVENT" => {
                let (name, rest) = tail.split_once(' ').unwrap_or((tail, ""));
                Some(Reply::Event {
                    name: name.to_string(),
                    fields: fields(rest),
                })
            }
            _ => None,
        }
    }
}

fn fields(s: &str) -> Vec<(String, String)> {
    s.split_whitespace()
        .filter_map(|w| w.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(200)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    #[test]
    fn commands_round_trip() {
        let commands = [
            Command::Info,
            Command::Erase,
            Command::Enrol,
            Command::Forget,
            Command::Set {
                key: Key::ClaimCert,
                value: PEM.into(),
            },
            Command::Set {
                key: Key::WifiSsid,
                value: "my home net".into(),
            },
            Command::Set {
                key: Key::WifiPsk,
                value: String::new(),
            },
        ];
        for c in commands {
            let line = c.encode();
            assert!(!line.contains('\n'), "{line}");
            assert_eq!(Command::parse(&format!("{line}\r\n")), Some(Ok(c)));
        }
    }

    #[test]
    fn log_lines_are_not_commands() {
        assert_eq!(Command::parse("I (123) wifi: connected"), None);
        assert_eq!(Command::parse(""), None);
    }

    #[test]
    fn bad_commands_are_answered_not_ignored() {
        for line in [
            "PLATFORM FORMAT",
            "PLATFORM SET",
            "PLATFORM SET thing QUJD",
            "PLATFORM SET wifi_ssid !!!",
            "PLATFORM SET claim_key bm90IGEga2V5",
            "PLATFORM SET endpoint ZXZpbC5leGFtcGxlLmNvbQ==",
        ] {
            assert!(matches!(Command::parse(line), Some(Err(_))), "{line}");
        }
    }

    #[test]
    fn values_are_validated_per_key() {
        assert!(Key::Endpoint
            .validate("a1b2c3-ats.iot.eu-central-1.amazonaws.com")
            .is_ok());
        assert!(Key::Endpoint.validate("evil.example.com").is_err());
        assert!(Key::ClaimKey
            .validate("-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----")
            .is_ok());
        assert!(Key::WifiSsid.validate(&"x".repeat(33)).is_err());
        assert!(Key::WifiPsk.validate("short").is_err());
        assert!(Key::WifiPsk.validate("long enough").is_ok());
        assert!(Key::WifiSsid.validate("a\0b").is_err());
        assert!(Key::ClaimKey.is_secret() && Key::WifiPsk.is_secret());
        assert!(!Key::ClaimCert.is_secret());
        for k in Key::ALL {
            assert!(k.nvs_key().len() <= 15);
            assert_eq!(Key::parse(k.nvs_key()), Some(k));
        }
    }

    #[test]
    fn replies_round_trip_and_survive_log_decoration() {
        let register = Reply::Register(Register {
            product: "vaktus".into(),
            mac: "38:18:2B:84:56:F4".into(),
            thing: "38182B8456F4".into(),
            pubkey: "AB".repeat(64),
            fw: "0.9.0".into(),
            enrolled: false,
        });
        let replies = [
            register,
            Reply::Ok {
                verb: "SET".into(),
                key: Some("claim_cert".into()),
            },
            Reply::Ok {
                verb: "ERASE".into(),
                key: None,
            },
            Reply::Err {
                verb: "SET".into(),
                message: "not a PEM certificate".into(),
            },
            Reply::Event {
                name: "enrolled".into(),
                fields: vec![("thing".into(), "38182B8456F4".into())],
            },
        ];
        for r in replies {
            let line = r.encode();
            assert_eq!(Reply::parse(&line), Some(r.clone()), "{line}");
            assert_eq!(
                Reply::parse(&format!("\x1b[0;32m{line}\x1b[0m\r\n").replace("\x1b[0m", "")),
                Some(r)
            );
        }
        assert_eq!(Reply::parse("I (5) cloud: online"), None);
    }

    #[test]
    fn error_messages_stay_on_one_line() {
        let line = Reply::Err {
            verb: "SET".into(),
            message: "a\nb".into(),
        }
        .encode();
        assert_eq!(line, "PLATFORM ERR SET a b");
    }
}
