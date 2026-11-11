//! Names the platform derives from a device's MAC, and product ids.
//!
//! Frozen: the thing name is the product's declared MAC as 12 uppercase hex
//! digits, the device policy pins the MQTT client id to it, and the registry
//! keys records by the colon form. Changing either strands every device.

use std::fmt;

/// Which of the chip's MACs names the device. Part of the contract: two units
/// of the same product must use the same one, and it never changes for a
/// product, because the thing name is derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacType {
    /// The Wi-Fi station MAC (`ESP_MAC_WIFI_STA`). Vaktus.
    WifiSta,
    /// The Ethernet MAC (`ESP_MAC_ETH`). The gateway: it differs from the base
    /// MAC printed on the module.
    Eth,
}

impl MacType {
    /// Parses the `platform.toml` spelling.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "wifi_sta" => Ok(Self::WifiSta),
            "eth" => Ok(Self::Eth),
            other => Err(format!("unknown mac_type {other:?} (wifi_sta or eth)")),
        }
    }

    /// The `platform.toml` spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WifiSta => "wifi_sta",
            Self::Eth => "eth",
        }
    }
}

/// A device MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// Accepts 12 hex digits, with or without `:` or `-` separators, in any
    /// case.
    pub fn parse(s: &str) -> Result<Self, String> {
        let digits: String = s.chars().filter(|c| !matches!(c, ':' | '-')).collect();
        if digits.len() != 12 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("{s:?} is not a MAC (12 hex digits)"));
        }
        let mut mac = [0u8; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).expect("checked hex");
        }
        Ok(Self(mac))
    }

    /// The thing name: 12 uppercase hex digits, e.g. `38182B8456F4`.
    pub fn thing_name(&self) -> String {
        self.0.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// The registry key: `38:18:2B:84:56:F4`.
    pub fn colon(&self) -> String {
        self.0
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Client id of the claim connection. Distinct from the thing name, which
    /// the device policy reserves for the device's own connection; the claim
    /// policy only allows `claim-*`.
    pub fn claim_client_id(&self) -> String {
        format!("claim-{}", self.thing_name())
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.colon())
    }
}

/// True for a product id: 2-16 lowercase letters and digits, starting with a
/// letter. The same rule as the infrastructure's `products` variable, because
/// the id appears in S3 keys, job ids, rule names and resource names.
pub fn is_product_id(s: &str) -> bool {
    (2..=16).contains(&s.len())
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

/// True for a thing name the platform issues: 12 uppercase hex digits.
pub fn is_thing_name(s: &str) -> bool {
    s.len() == 12 && s.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F'))
}

/// Uppercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Parses hex (either case; `:` and whitespace ignored).
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b':')
        .collect();
    if digits.len() % 2 != 0 {
        return Err("odd number of hex digits".into());
    }
    digits
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "not hex".to_string())?;
            u8::from_str_radix(text, 16).map_err(|_| format!("{text:?} is not hex"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAKTUS: Mac = Mac([0x38, 0x18, 0x2B, 0x84, 0x56, 0xF4]);

    #[test]
    fn names_match_the_registry_template_and_policies() {
        assert_eq!(VAKTUS.thing_name(), "38182B8456F4");
        assert_eq!(VAKTUS.colon(), "38:18:2B:84:56:F4");
        assert_eq!(VAKTUS.claim_client_id(), "claim-38182B8456F4");
        assert!(is_thing_name(&VAKTUS.thing_name()));
    }

    #[test]
    fn macs_parse_in_every_spelling() {
        for s in ["38:18:2B:84:56:F4", "38-18-2b-84-56-f4", "38182B8456F4"] {
            assert_eq!(Mac::parse(s).unwrap(), VAKTUS, "{s}");
        }
        for s in ["", "38:18:2B:84:56", "38182B8456F4AA", "zz182B8456F4"] {
            assert!(Mac::parse(s).is_err(), "{s}");
        }
    }

    #[test]
    fn product_ids_follow_the_infrastructure_rule() {
        for ok in ["vaktus", "gateway", "p2", "abcdefghijklmnop"] {
            assert!(is_product_id(ok), "{ok}");
        }
        for bad in ["", "v", "Vaktus", "2fa", "my-product", "abcdefghijklmnopq"] {
            assert!(!is_product_id(bad), "{bad}");
        }
    }

    #[test]
    fn mac_types_round_trip() {
        for t in [MacType::WifiSta, MacType::Eth] {
            assert_eq!(MacType::parse(t.as_str()).unwrap(), t);
        }
        assert!(MacType::parse("base").is_err());
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0x04, 0xAB]), "04AB");
        assert_eq!(unhex("04:ab cd").unwrap(), vec![0x04, 0xAB, 0xCD]);
        assert!(unhex("abc").is_err());
        assert!(unhex("zz").is_err());
    }
}
