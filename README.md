# iot-device-sdk

The device side of the Ergousha IoT platform
([`ergousha/iot-platform`](https://github.com/ergousha/iot-platform)): what a
product firmware needs to enrol, connect, update itself and report, and the
owner's bench tool. Products today:
[Vaktus Salât](https://github.com/ergousha/esp32-display-vaktus-salat-rust)
(ESP32 + ATECC608B) and the
[OPC UA gateway](https://github.com/ergousha/esp32-opcua-gateway-rust)
(ESP32-S3, NVS soft key).

| Crate | What it is | Runs on |
|---|---|---|
| [`iot-jobs`](iot-jobs) | AWS IoT Jobs OTA protocol: job documents, signed manifests, monotonic versions, outcome settling across the reboot | host-tested, device |
| [`device-core`](device-core) | the device contracts as pure logic: provisioning wire format, CSR, the `platform` shadow, publish limiter, backoff, serial console protocol, frozen NVS layouts | host-tested, device |
| [`device-sdk`](device-sdk) | ESP-IDF glue: MQTT (with a secure element), NVS, OTA, ATECC608B or NVS soft key, the session | device |
| [`platform-build`](platform-build) | build-script helper: `platform.toml`, `FW_VERSION`, keyring, partition check, bootloader staging | build host |
| [`nvs-image`](nvs-image) | reads an ESP-IDF NVS partition dump | host |
| [`ergo`](ergo) | the owner's CLI: `register`, `commission`, `nvs-check` | host |
| [`contract/v1`](contract/v1) | the signed-manifest test vector, made with `openssl` | — |
| [`firmware-release.yml`](.github/workflows/firmware-release.yml) | every product's release pipeline (reusable workflow) | GitHub Actions |

## What every product gets

- **No secrets in images.** The IoT endpoint and provisioning template are
  public and compiled in from the product's `platform.toml`. The claim
  credential and WiFi reach a device only at the bench, over its serial
  console (`ergo commission`), and the claim is erased as soon as the device
  has its own certificate. A build needs no AWS access.
- **Enrolment with a CSR.** The private key never leaves the device: slot 0 of
  an ATECC608B (`atecc608`), or a P-256 key generated on the device and kept in
  NVS (`nvs-soft-key`). The platform's pre-provisioning hook approves only the
  registered key, once, inside its enrolment window. Refusals back off from a
  minute to six hours, with jitter.
- **A bounded bill.** Every publish passes a limiter (10 a minute and 5 KB each
  by default, `[limits]` in `platform.toml`); reconnects follow the same
  backoff; subscriptions are the exact answers the device acts on, never
  `shadow/#`; telemetry is off until the platform switches it on.
- **OTA through AWS IoT Jobs.** Only a greater version is installed (unless the
  owner's rollback says `downgrade`); a signed manifest is verified against
  the compiled-in keyring and binds product and version; the image is hashed
  as it streams in; the new image is kept only once it reaches AWS IoT, else
  the bootloader rolls it back. Failure reasons are the contract's: `verify`,
  `sig`, `version`, `rollback`, `boot`, `download`. Unknown operations and
  other products' jobs are REJECTED. The `signed-only` feature refuses every
  unsigned job.
- **The `platform` shadow**, reported on connect, on change and every 6 h:
  `{contract, product, fw, slot, boot_reason, boot_count_since_update,
  uptime_s, key_id[], last_job, telemetry}`. Its `desired.telemetry.enabled`
  is the product's telemetry switch.

## Using it in a product

```toml
# Cargo.toml
[dependencies]
device-sdk = { git = "https://github.com/ergousha/iot-device-sdk", rev = "…", features = ["atecc608"] }
[build-dependencies]
platform-build = { git = "https://github.com/ergousha/iot-device-sdk", rev = "…" }
```

```rust
// build.rs
fn main() { platform_build::configure(); }
```

```rust
// src/main.rs
include!(concat!(env!("OUT_DIR"), "/platform.rs")); // pub const PLATFORM

device_sdk::start_rollback_guard();
let platform = device_sdk::Platform::init(&PLATFORM, nvs.clone())?; // before the network
// ... network up; platform.wifi() has the bench-provisioned WiFi
let identity = platform.identity()?;                 // stored, or enrolment
let mut session = platform.connect(&identity, &Default::default())?;
loop {
    match session.poll(Duration::from_millis(100)) {
        Some(Event::Connected) => { /* subscribe the product's own topics */ }
        Some(Event::Message { topic, data }) => { /* the product's own */ }
        Some(Event::Restart) => device_sdk::restart_into_update(),
        _ => {}
    }
}
```

`platform.toml`, with every field the build checks:

```toml
[product]
id = "vaktus"              # 2-16 lowercase letters and digits
chip = "esp32"             # must match the build target
mac_type = "wifi_sta"      # or "eth"; the thing name is this MAC (frozen)
key_storage = "atecc608"   # or "nvs-soft-key"; the device-sdk feature

[cloud]
endpoint = "xxxxxxxxxxxxxx-ats.iot.eu-central-1.amazonaws.com"
template = "esp32-ztp-vaktus-fleet-template"

[limits]                   # optional; these are the defaults
publishes_per_minute = 10
max_message_bytes = 5120

[signing]
keys = ["vaktus-a"]        # keys/vaktus-a.pub.pem

[flash]
partitions = "partitions.csv"
frozen = [{ name = "nvs", offset = 0x9000, size = 0x6000 }]
```

The `atecc608` feature needs the product to declare CryptoAuthLib with
`bindings_module = "atca"` and link with `-Wl,--wrap=atcab_release` (see
`device-sdk/src/atecc.rs` and the Vaktus repository).

## Releasing

Every merge to a product's `main` runs [`firmware-release.yml`](.github/workflows/firmware-release.yml). The product's `release.yml` only calls it, pinned by commit SHA:

```yaml
on:
  push:
    branches: [ main ]
concurrency:
  group: release-${{ github.repository }}
  cancel-in-progress: false
permissions: {}
jobs:
  release:
    uses: ergousha/iot-device-sdk/.github/workflows/firmware-release.yml@<sha> # <branch or tag>
    permissions:
      contents: write   # tag and GitHub pre-release
      id-token: write   # AWS OIDC, in the publish job only
      issues: write     # "release vX.Y.Z failed"
    with:
      flash-size: 4mb
      aws-role-arn: ${{ vars.AWS_ROLE_ARN }}
      firmware-bucket: ${{ vars.AWS_FIRMWARE_BUCKET }}
```

1. **version**: the next semver from the conventional commits since the newest `v*` tag (`feat` → minor, `fix` → patch, breaking → major, or minor below 1.0). Without a `feat:` or `fix:` nothing is released.
2. **build**, with no secrets, no AWS and no cache: `app.bin` (the OTA image), `factory.bin` (bootloader, partition table and app, for a first flash), the canonical `manifest.json` and a CycloneDX SBOM. The app must fit 90 % of an OTA slot. Both images are scanned: PEM blocks other than the Amazon root CA and `keys/*.pub.pem` fail the build, and so does any string listed in the `image-scan-forbidden` input.
3. **publish**, in Environment `release`: re-hash against the manifest, sign it with `FIRMWARE_SIGNING_KEY` (the key touches one 0600 file, shredded afterwards), check that the signature verifies with one of `keys/*.pub.pem`, tag `vX.Y.Z` and create a GitHub pre-release with the assets, then upload to `s3://<bucket>/releases/<product>/<X.Y.Z>/` with `If-None-Match: *`, `manifest.sig` last. The product's AWS role trusts only this workflow, in that Environment, for 15 minutes.
4. **notify**: on failure, an issue "release vX.Y.Z failed" (email and mobile push).

From there the platform's OTA controller verifies the signature again, runs the release on the canaries, soaks it and promotes it (iot-platform README §3).

### Signing keys

`scripts/signing-keys.sh <product checkout>` creates a product's keys once: `<id>-a` (active) and `<id>-b` (backup), both public keys in `keys/` and `platform.toml` (every image accepts both) and in SSM `/iot-platform/products/<id>/signing_keys`, the Environment `release` (main only) with `<id>-a` as its secret, and `<id>-b` to the clipboard for the password manager. No private key is written to disk. Rotating to the backup is a `gh secret set`; no Terraform.

Until a unit runs an image that has the keys, the controller sends it unsigned (v1) job documents, after checking the signature itself; from then on, signed ones. The `signed-only` feature (plan Phase 6) refuses anything unsigned.

## Commissioning a device

At the bench, with the board on USB and the owner's AWS session:

```sh
cargo run -p ergo -- commission --product vaktus --port /dev/cu.usbserial-110 \
    --wifi-ssid <ssid> --wifi-psk-env WIFI_PSK
```

`ergo` reads the MAC and public key off the console, registers them, writes
the claim (SSM `/iot-platform/claim/{cert,key}`, which the platform's OTA
controller rotates) and WiFi, activates the claim for the window only, and
waits for the enrolment; on any failure it disarms the claim, removes the record and wipes
what it wrote. `--reprovision` re-enrols an enrolled board (it forgets its
identity first). `ergo nvs-check --dump <file> --product <id>` shows what the
SDK will read from a dump of a board's `nvs` partition, never key material.

## Development

```sh
cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test
```

`device-sdk` builds only for an ESP32 target, inside a product repository
(point its dependency at a local checkout with `path = "../iot-device-sdk/device-sdk"`).

## License

MIT, see [LICENSE](LICENSE).
