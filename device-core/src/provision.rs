//! AWS IoT Fleet Provisioning by claim, with a CSR: the wire formats.
//!
//! 1. Connect as `claim-<MAC12>` with the claim certificate (it may only
//!    provision, and is ACTIVE only during an enrolment window).
//! 2. `CreateCertificateFromCsr`: AWS IoT issues a certificate for the key in
//!    the CSR. No private key crosses the wire.
//! 3. `RegisterThing` on the product's template. The pre-provisioning hook
//!    approves only if this MAC is registered for the product with exactly the
//!    public key in the certificate, once, inside its enrolment window.

use serde::{Deserialize, Serialize};

use crate::ids::Mac;

/// `CreateCertificateFromCsr` request topic. `/accepted` and `/rejected`
/// answer it.
pub const CREATE_FROM_CSR_TOPIC: &str = "$aws/certificates/create-from-csr/json";

/// `RegisterThing` request topic for `template`.
pub fn register_topic(template: &str) -> String {
    format!("$aws/provisioning-templates/{template}/provision/json")
}

/// The four topics the claim connection subscribes to before asking.
pub fn answer_topics(template: &str) -> [String; 4] {
    let register = register_topic(template);
    [
        format!("{CREATE_FROM_CSR_TOPIC}/accepted"),
        format!("{CREATE_FROM_CSR_TOPIC}/rejected"),
        format!("{register}/accepted"),
        format!("{register}/rejected"),
    ]
}

/// Payload of a `CreateCertificateFromCsr` request.
pub fn create_from_csr_request(csr_pem: &str) -> Vec<u8> {
    #[derive(Serialize)]
    struct Req<'a> {
        #[serde(rename = "certificateSigningRequest")]
        csr: &'a str,
    }
    serde_json::to_vec(&Req { csr: csr_pem }).expect("serializable")
}

/// What `CreateCertificateFromCsr` answered.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct IssuedCertificate {
    /// The device certificate, for the key in the CSR.
    #[serde(rename = "certificatePem")]
    pub certificate_pem: String,
    #[serde(rename = "certificateId")]
    pub certificate_id: String,
    /// Proves ownership in `RegisterThing`; valid for one hour.
    #[serde(rename = "certificateOwnershipToken")]
    pub ownership_token: String,
}

/// Parses `.../create-from-csr/json/accepted`.
pub fn parse_issued(payload: &[u8]) -> Result<IssuedCertificate, String> {
    let issued: IssuedCertificate = serde_json::from_slice(payload)
        .map_err(|e| format!("unreadable certificate response: {e}"))?;
    if !issued.certificate_pem.contains("BEGIN CERTIFICATE") || issued.ownership_token.is_empty() {
        return Err("certificate response without a certificate or ownership token".into());
    }
    Ok(issued)
}

/// Payload of a `RegisterThing` request. No `Secret`: the device proves itself
/// with the key its certificate was issued for, which the hook compares with
/// the one registered for its MAC.
pub fn register_request(ownership_token: &str, mac: &Mac) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "certificateOwnershipToken": ownership_token,
        "parameters": {
            "SerialNumber": mac.thing_name(),
            "MacAddress": mac.colon(),
        }
    }))
    .expect("serializable")
}

/// Parses `.../provision/json/accepted` into the thing name.
pub fn parse_registered(payload: &[u8]) -> Result<String, String> {
    #[derive(Deserialize)]
    struct Resp {
        #[serde(rename = "thingName")]
        thing_name: String,
    }
    let resp: Resp = serde_json::from_slice(payload)
        .map_err(|e| format!("unreadable registration response: {e}"))?;
    if resp.thing_name.is_empty() {
        return Err("registration response without a thing name".into());
    }
    Ok(resp.thing_name)
}

/// True when a `/rejected` answer means the platform refused this device
/// (403): not registered, registered with another key or product, already
/// enrolled, or outside its window. Retrying soon will not help; the device
/// backs off for long ([`crate::backoff`]). Anything else (throttling, a
/// template error) is not about the device.
pub fn refused(payload: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Status {
        #[serde(rename = "statusCode")]
        status_code: u32,
    }
    serde_json::from_slice::<Status>(payload).is_ok_and(|s| s.status_code == 403)
}

/// A `/rejected` answer of either provisioning API, as one line.
pub fn describe_rejection(payload: &[u8]) -> String {
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Rejected {
        #[serde(rename = "statusCode")]
        status_code: u32,
        #[serde(rename = "errorCode")]
        error_code: String,
        #[serde(rename = "errorMessage")]
        error_message: String,
    }
    match serde_json::from_slice::<Rejected>(payload) {
        Ok(r) => format!("{} {}: {}", r.status_code, r.error_code, r.error_message),
        Err(_) => String::from_utf8_lossy(payload).chars().take(200).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const MAC: Mac = Mac([0x38, 0x18, 0x2B, 0x84, 0x56, 0xF4]);

    #[test]
    fn topics_match_the_claim_policy() {
        assert_eq!(
            register_topic("esp32-ztp-vaktus-fleet-template"),
            "$aws/provisioning-templates/esp32-ztp-vaktus-fleet-template/provision/json"
        );
        let answers = answer_topics("t");
        assert_eq!(
            answers[0],
            "$aws/certificates/create-from-csr/json/accepted"
        );
        assert_eq!(
            answers[3],
            "$aws/provisioning-templates/t/provision/json/rejected"
        );
    }

    #[test]
    fn the_csr_request_carries_the_pem() {
        let v: Value =
            serde_json::from_slice(&create_from_csr_request("-----BEGIN X-----\n")).unwrap();
        assert_eq!(v["certificateSigningRequest"], "-----BEGIN X-----\n");
    }

    #[test]
    fn an_issued_certificate_is_read() {
        let ok = br#"{"certificatePem":"-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n","certificateId":"abc","certificateOwnershipToken":"tok"}"#;
        let issued = parse_issued(ok).unwrap();
        assert_eq!(issued.certificate_id, "abc");
        assert_eq!(issued.ownership_token, "tok");
        assert!(parse_issued(
            br#"{"certificatePem":"x","certificateId":"a","certificateOwnershipToken":"t"}"#
        )
        .is_err());
        assert!(parse_issued(b"not json").is_err());
    }

    #[test]
    fn the_registration_sends_serial_and_mac_but_no_secret() {
        let v: Value = serde_json::from_slice(&register_request("tok", &MAC)).unwrap();
        assert_eq!(v["certificateOwnershipToken"], "tok");
        assert_eq!(v["parameters"]["SerialNumber"], "38182B8456F4");
        assert_eq!(v["parameters"]["MacAddress"], "38:18:2B:84:56:F4");
        assert!(v["parameters"].get("Secret").is_none());
        assert_eq!(
            parse_registered(br#"{"thingName":"38182B8456F4","deviceConfiguration":{}}"#).unwrap(),
            "38182B8456F4"
        );
        assert!(parse_registered(br#"{"thingName":""}"#).is_err());
    }

    #[test]
    fn only_a_403_is_a_refusal() {
        assert!(refused(
            br#"{"statusCode":403,"errorCode":"AccessDenied","errorMessage":"Access Denied"}"#
        ));
        assert!(!refused(
            br#"{"statusCode":429,"errorCode":"ThrottlingException","errorMessage":"Rate exceeded"}"#
        ));
        assert!(!refused(b"garbage"));
    }

    #[test]
    fn rejections_are_one_line() {
        assert_eq!(
            describe_rejection(br#"{"statusCode":403,"errorCode":"AccessDenied","errorMessage":"Pre-provisioning hook rejected"}"#),
            "403 AccessDenied: Pre-provisioning hook rejected"
        );
        assert_eq!(describe_rejection(b"oops"), "oops");
    }
}
