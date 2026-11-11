//! The platform's device contracts as pure logic.
//!
//! Everything here is a function of its inputs: no esp-idf, no clock, no
//! randomness, no I/O. The firmware side (`device-sdk`) moves the bytes, and
//! the owner's tool (`ergo`) speaks the other end of the same formats, so both
//! sides are tested against one definition.
//!
//! | Module | Contract (`PLATFORM.md`) |
//! |---|---|
//! | [`ids`] | thing name = MAC12, claim client id, product ids, MAC types |
//! | [`product`] | what a product build declares in `platform.toml` |
//! | [`provision`] | Fleet Provisioning by claim with a CSR |
//! | [`csr`] | PKCS#10 for a P-256 key that signs elsewhere |
//! | [`atecc`] | ATECC608B slot-0 checks before anything one-way |
//! | [`shadow`] | the `platform` named shadow, boot counter, telemetry opt-in |
//! | [`limiter`] | publish rate and size limits |
//! | [`backoff`] | retry backoff with jitter |
//! | [`console`] | bench provisioning over the serial console |
//! | [`nvs`] | frozen NVS namespaces and keys, identity records |

pub mod atecc;
pub mod backoff;
pub mod console;
pub mod csr;
pub mod ids;
pub mod limiter;
pub mod nvs;
pub mod product;
pub mod provision;
pub mod shadow;

/// The version of the device contract this crate implements. Reported in the
/// `platform` shadow and carried by manifests and job documents.
pub const CONTRACT: u32 = 1;
