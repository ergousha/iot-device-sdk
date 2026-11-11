//! PKCS#10 certificate signing requests for a P-256 key that never leaves the
//! ATECC608B.
//!
//! AWS IoT's `CreateCertificateFromCsr` issues the device certificate for the
//! key in the CSR. The private key is in the secure element, so the CSR is put
//! together here in three steps: [`request_info`] builds the DER the signature
//! covers, the firmware has the chip sign its SHA-256 [`digest`], and
//! [`assemble`] wraps both into the final request ([`to_pem`] for the wire).
//!
//! Only what this needs is encoded: subject `CN=<name>`, an EC P-256 public
//! key, no attributes, signed ecdsa-with-SHA256 (RFC 2986, RFC 5480, RFC 5758).

use sha2::{Digest, Sha256};

/// id-ecPublicKey, 1.2.840.10045.2.1
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// prime256v1 / secp256r1, 1.2.840.10045.3.1.7
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// ecdsa-with-SHA256, 1.2.840.10045.4.3.2
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// id-at-commonName, 2.5.4.3
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0C;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
/// `[0] IMPLICIT`, constructed: the CSR's attributes.
const TAG_ATTRIBUTES: u8 = 0xA0;

/// One DER TLV.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(TAG_SEQUENCE, &parts.concat())
}

/// A DER INTEGER for an unsigned big-endian number: leading zero bytes
/// dropped, one zero byte added back when the top bit is set (or it would read
/// as negative).
fn unsigned_integer(be: &[u8]) -> Vec<u8> {
    let first = be
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(be.len().saturating_sub(1));
    let trimmed = &be[first..];
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    tlv(TAG_INTEGER, &content)
}

/// The `CertificationRequestInfo`: what the signature covers.
///
/// `public_key` is X||Y, big-endian, as an ATECC608 GenKey returns it.
pub fn request_info(common_name: &str, public_key: &[u8; 64]) -> Vec<u8> {
    let version = tlv(TAG_INTEGER, &[0]);

    let cn = sequence(&[
        &tlv(TAG_OID, OID_COMMON_NAME),
        &tlv(TAG_UTF8_STRING, common_name.as_bytes()),
    ]);
    let subject = sequence(&[&tlv(TAG_SET, &cn)]);

    let algorithm = sequence(&[&tlv(TAG_OID, OID_EC_PUBLIC_KEY), &tlv(TAG_OID, OID_P256)]);
    // No unused bits, then the uncompressed point 04||X||Y.
    let mut point = vec![0x00, 0x04];
    point.extend_from_slice(public_key);
    let spki = sequence(&[&algorithm, &tlv(TAG_BIT_STRING, &point)]);

    let attributes = tlv(TAG_ATTRIBUTES, &[]);
    sequence(&[&version, &subject, &spki, &attributes])
}

/// SHA-256 of the request info: what the secure element signs.
pub fn digest(request_info: &[u8]) -> [u8; 32] {
    Sha256::digest(request_info).into()
}

/// The complete DER `CertificationRequest`, from the request info and the
/// chip's signature over its [`digest`] (r||s, 32 bytes each, big-endian).
pub fn assemble(request_info: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let algorithm = sequence(&[&tlv(TAG_OID, OID_ECDSA_SHA256)]);
    let ecdsa_sig = sequence(&[
        &unsigned_integer(&signature[..32]),
        &unsigned_integer(&signature[32..]),
    ]);
    let mut bits = vec![0x00];
    bits.extend_from_slice(&ecdsa_sig);
    sequence(&[request_info, &algorithm, &tlv(TAG_BIT_STRING, &bits)])
}

/// PEM `CERTIFICATE REQUEST`, as `CreateCertificateFromCsr` expects it.
pub fn to_pem(der: &[u8]) -> String {
    let b64 = base64(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE REQUEST-----\n");
    for line in b64.as_bytes().chunks(64) {
        pem.push_str(core::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE REQUEST-----\n");
    pem
}

/// Standard base64 with padding (RFC 4648 §4).
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use x509_cert::der::{Decode, Encode};
    use x509_cert::request::CertReq;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32].into()).unwrap()
    }

    fn xy(key: &SigningKey) -> [u8; 64] {
        let point = key.verifying_key().to_encoded_point(false);
        point.as_bytes()[1..].try_into().unwrap()
    }

    /// What the device does, with a software key standing in for the chip.
    fn csr_signed_by(key: &SigningKey, cn: &str) -> Vec<u8> {
        let info = request_info(cn, &xy(key));
        // `sign` hashes with SHA-256, as the chip signs `digest(info)`.
        let sig: Signature = key.sign(&info);
        assemble(&info, &sig.to_bytes().into())
    }

    #[test]
    fn the_csr_parses_and_carries_the_name_and_key() {
        let key = key();
        let der = csr_signed_by(&key, "38182B8456F4");
        let req = CertReq::from_der(&der).expect("valid PKCS#10");

        assert_eq!(req.info.subject.to_string(), "CN=38182B8456F4");
        let spki = req.info.public_key.to_der().unwrap();
        let expected = p256::PublicKey::from(key.verifying_key()).to_public_key_der_bytes();
        assert_eq!(spki, expected);
        assert_eq!(
            req.algorithm.oid.to_string(),
            "1.2.840.10045.4.3.2",
            "ecdsa-with-SHA256"
        );
    }

    #[test]
    fn the_signature_verifies_over_the_request_info() {
        let key = key();
        let der = csr_signed_by(&key, "38182B8456F4");
        let req = CertReq::from_der(&der).unwrap();

        let info_der = req.info.to_der().unwrap();
        let sig = Signature::from_der(req.signature.raw_bytes()).unwrap();
        let vk = VerifyingKey::from_sec1_bytes(req.info.public_key.subject_public_key.raw_bytes())
            .unwrap();
        vk.verify(&info_der, &sig)
            .expect("signature over the request info");
    }

    #[test]
    fn the_digest_is_sha256_of_the_request_info() {
        let info = request_info("x", &xy(&key()));
        assert_eq!(digest(&info), <[u8; 32]>::from(Sha256::digest(&info)));
    }

    #[test]
    fn integers_are_minimal_and_never_negative() {
        let mut high = [0u8; 32];
        high[0] = 0x80;
        assert_eq!(unsigned_integer(&high)[..3], [0x02, 33, 0x00]);
        let mut leading_zeros = [0u8; 32];
        leading_zeros[30] = 0x01;
        leading_zeros[31] = 0x02;
        assert_eq!(unsigned_integer(&leading_zeros), [0x02, 2, 0x01, 0x02]);
        assert_eq!(unsigned_integer(&[0u8; 32]), [0x02, 1, 0x00]);
        // A signature whose r and s both need the extra byte still parses.
        let info = request_info("x", &xy(&key()));
        let der = assemble(&info, &[0xFF; 64]);
        assert!(CertReq::from_der(&der).is_ok());
    }

    #[test]
    fn long_lengths_use_the_long_form() {
        assert_eq!(tlv(0x04, &[0; 0x7F])[..2], [0x04, 0x7F]);
        assert_eq!(tlv(0x04, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(tlv(0x04, &[0; 0x100])[..4], [0x04, 0x82, 0x01, 0x00]);
    }

    #[test]
    fn pem_is_wrapped_base64() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        let pem = to_pem(&[0u8; 100]);
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----\n"));
        assert!(pem.ends_with("-----END CERTIFICATE REQUEST-----\n"));
        assert!(pem.lines().all(|l| l.len() <= 64));
    }

    trait ToDer {
        fn to_public_key_der_bytes(&self) -> Vec<u8>;
    }
    impl ToDer for p256::PublicKey {
        fn to_public_key_der_bytes(&self) -> Vec<u8> {
            use p256::pkcs8::EncodePublicKey;
            self.to_public_key_der().unwrap().as_bytes().to_vec()
        }
    }
}
