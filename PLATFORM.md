# The platform contract

What a product on the Ergousha IoT platform
([`iot-platform`](https://github.com/ergousha/iot-platform)) can rely on, and
what it must do in return. A product repository links this file at the SDK
revision it pins; the README covers the crates and the release workflow in
more detail.

The platform is one owner's, for fewer than ten devices, in one AWS account
(eu-central-1), from public repositories, for about $0.3–1 a month and $0
fixed. Nothing here is multi-tenant. Its main threat is **denial of wallet**:
anything a device or a product's cloud code does must have a ceiling.

## 1. Versions

| What | Version | Pinned where |
|---|---|---|
| Platform contract | `1` (`contract` in the `platform` shadow, manifests and job documents) | here |
| SDK | the commit a product pins | product `Cargo.toml` (`rev = "<sha>"`), and `release.yml` (`firmware-release.yml@<sha>`) |
| Firmware | `X.Y.Z` semver, tag `vX.Y.Z` | made by the release workflow from conventional commits |
| ESP-IDF | `v5.5.3` | product `.cargo/config.toml` |
| Terraform | `1.17.x`, `required_version >= 1.10` | platform and product `cloud/` |

Bumping the SDK is a deliberate human click (Dependabot opens it). A bump
that changes device behaviour is a `fix:` or `feat:` commit in the product
(it releases); one that does not, `chore:` or `ci:` (it does not).

## 2. Adding a product

1. On GitHub, **Use this template** on
   [`iot-device-template`](https://github.com/ergousha/iot-device-template),
   public, under the owner's account. Clone it.
2. With the owner's AWS session and `gh` logged in:

   ```sh
   aws-vault exec <owner> -- cargo run --manifest-path ../iot-device-sdk/Cargo.toml -p ergo -- \
       product init <id> --description "<one line>" --infra ../iot-platform [--chip esp32]
   ```

   `<id>` is 2–16 lowercase letters and digits, starting with a letter. It is
   frozen: S3 prefix, job ids, rule names, registry records. `ergo product
   init`, step by step (it can be re-run after any stop):
   - sets `platform.toml` `[product]` and the build target;
   - opens the `products/<id>.json` pull request on iot-platform, merges it
     once its checks pass, and runs `terraform apply` there (you confirm the
     plan): fleet, canary and excluded groups, provisioning template,
     GitHub OIDC role, `/iot-platform/products/<id>/platform`;
   - writes the platform's facts into `platform.toml` `[cloud]`,
     `cloud/versions.tf` and the repository variables `AWS_ROLE_ARN`,
     `AWS_FIRMWARE_BUCKET`;
   - applies the repository settings and the default-branch ruleset (§11);
   - **last**, the signing keys `<id>-a` (active) and `<id>-b` (backup) and
     the Environment `release`; `<id>-b`'s private key goes to the clipboard
     once, for the password manager;
   - opens a `chore:` pull request with the changed files.
3. Merge that pull request. The first `feat:` merge after it is release
   `0.1.0`.
4. Flash a board with that release's `factory.bin` and commission it as the
   canary: `ergo commission --product <id> --port <port> --canary
   --wifi-ssid <ssid> --wifi-psk-env WIFI_PSK`. From then on every release
   reaches it, and the fleet, by itself.

## 3. Secrets

| Secret | Lives in | Reaches |
|---|---|---|
| Device private key | the device: ATECC608B slot 0 (`atecc608`) or NVS `device_id/key` (`nvs-soft-key`) | nothing; enrolment sends a CSR |
| Claim credential (shared) | SSM `/iot-platform/claim/{cert,key}`; the OTA controller rotates it | a device's NVS at the bench (`ergo commission`), erased once it has its own certificate; ACTIVE only during enrolment windows |
| Wi-Fi PSK | the owner's environment variable, then device NVS `platform` | the device at the bench, over the serial console |
| Firmware signing key `<id>-a` | Environment `release` secret `FIRMWARE_SIGNING_KEY` | the publish job only: one 0600 file, shredded |
| Signing key `<id>-b` | the owner's password manager | nothing until a rotation |
| AWS credentials | the owner's keychain (`aws-vault`) | the owner's shell; CI uses OIDC for 15 minutes |

Never in Git, images, CI logs, caches, artifacts or Terraform state. Images
carry only public things: the endpoint, the template name, the Amazon root
CA and the signing **public** keys. The release workflow's image scan fails
on any other PEM block, and on any string in `IMAGE_SCAN_FORBIDDEN` (put your
SSID there: not secret, but a sign of compiled-in Wi-Fi).

## 4. Commissioning, backoff, reprovisioning, decommissioning

- **Commissioning** is at the bench only: `ergo commission` reads the MAC and
  public key off the serial console, registers them (`enrol_by` an hour
  ahead), writes the claim and Wi-Fi, arms the claim for that window and
  waits. The device enrols with a CSR; the pre-provisioning hook approves
  only the registered key, **once**, before `enrol_by`. Any failure or
  Ctrl-C disarms the claim, deletes the record and erases the device.
- **Backoff**: a refused enrolment or connection waits 1 minute, doubling to
  6 hours, with jitter; three quick retries 10 s apart come first, and a
  connection that held 10 minutes counts as healthy again. A blank or
  refused device never hammers AWS.
- **Reprovisioning** (a lost key, an erased board, a quarantined unit): only
  `ergo commission --reprovision` at the bench. The portal has no remote
  re-arm. The controller deactivates the old certificate once the device is
  back with its new one.
- **Decommissioning**: `scripts/ota.sh decommission <id> <thing>` or the
  portal: certificates INACTIVE, detached, thing deleted. The registry record
  stays provisioned, so the board cannot enrol again without the bench.
- **Quarantine**: `scripts/ota.sh quarantine <id> <thing>` moves a device
  into the deny-all group; it is refused on its next publish or connect.

## 5. Connection

- **Endpoint**: compiled in from `platform.toml` `[cloud] endpoint` (public).
  NVS `platform/endpoint`, written by `ergo commission --endpoint`, only
  overrides it. A unit with nothing in NVS must still connect.
- **Thing name and client id**: the device's MAC of `mac_type`
  (`wifi_sta` or `eth`) as 12 upper-case hex digits, frozen per product. The
  device policy allows only client id = thing name; the claim connects as
  `claim-<MAC12>`.
- **TLS**: mutual, port 8883, Amazon Root CA 1 (in the SDK). The clock must be
  set first (SNTP): certificates have dates.
- **Rollback**: a new image is marked valid only after its first CONNACK; one
  that does not get there within 10 minutes restarts and the bootloader
  goes back to the previous image. `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`
  and the project's own bootloader (`espflash.toml`) are required.

## 6. Topics and Basic Ingest

What the device policy allows, all pinned to the device's own thing name:

| Direction | Topics |
|---|---|
| Publish | `dt/<thing>/*`, `$aws/things/<thing>/jobs/*`, `$aws/things/<thing>/shadow/*`, `$aws/rules/<id>_*` |
| Subscribe, receive | `cmd/<thing>/*`, `$aws/things/<thing>/jobs/*`, `$aws/things/<thing>/shadow/*` |

- Subscribe to the exact answers you act on (`.../update/delta`,
  `.../get/accepted`, `.../get/rejected`), **never** `shadow/#`: every
  message received is billed.
- **Basic Ingest** (`$aws/rules/<id>_<rule>`) goes straight to a rule of
  your `cloud/` without the messaging fee ($0.36 a million for rule and
  action). Prefer it for telemetry.
- The product's **named shadow** (`shadow_name`, default the product id)
  carries its configuration; the portal owner may set its desired state.
  `platform` is the SDK's shadow; never write it from product code.
- Every publish passes the SDK's limiter (§10).

## 7. The `platform` shadow

Reported by the SDK on connect, on change and every 6 hours:

```json
{"contract": 1, "product": "demo", "fw": "0.3.1", "slot": "ota_1",
 "boot_reason": "sw", "boot_count_since_update": 1, "uptime_s": 4211,
 "key_id": ["demo-a", "demo-b"], "last_job": {"id": "...", "status": "SUCCEEDED"},
 "telemetry": {"enabled": false}}
```

The boot counter is kept in NVS. The controller's soak gate reads `fw`,
`boot_count_since_update` and `boot_reason`; `key_id` tells it when signed
job documents are safe. `desired.telemetry.enabled` is the product's
telemetry switch: publish telemetry only while it is `true`, and only when a
rule of yours consumes it.

## 8. OTA

- **Manifest**: canonical JSON `{contract, factory_sha256, product, sha256,
  size, version}` (keys sorted, no whitespace), signed
  `base64(DER(ECDSA-P256-SHA256(manifest)))`. The contract's test vector is
  `contract/v1/`.
- **The device** installs only if the manifest's product and version equal
  its own product and the job's `firmware_version`; only a **greater**
  version unless the job says `downgrade: true` (an owner's rollback),
  otherwise it reports SUCCEEDED with `reason=already-newer`. It hashes the
  image as it streams, checks size and hash, then the signature against the
  compiled-in keyring (`keys/*.pub.pem` named in `platform.toml`). Downloads
  are retried on the device.
- **Failure reasons** in the job status: `verify`, `sig`, `version`,
  `rollback`, `boot` (terminal) and `download` (transient: one rerun).
  Unknown operations and other products' jobs are REJECTED.
- `signed-only` (an SDK feature, plan Phase 6) refuses unsigned job
  documents.
- Frozen once a unit is in the field: the partition rows `platform.toml`
  lists in `[flash] frozen` (`platform-build` checks them at every build),
  the NVS keys, the thing name.

## 9. The pipeline

Every merge to `main` runs the SDK's `firmware-release.yml`: version from
the conventional commits since the last `v*` tag (`feat` → minor, `fix` →
patch; nothing else releases), a build with no secrets, the signed manifest,
a GitHub pre-release, the upload to `releases/<id>/<X.Y.Z>/`. A failure opens
an issue "release vX.Y.Z failed".

The platform's OTA controller then, every 15 minutes and on each upload:
verifies the signature again; runs a canary job on `<id>-canary` (or picks
an online device as canary, with an email); waits `soak_hours` (6 by
default) for the canaries to be online with the new `fw`, booted once, and
no crash reason; promotes to a CONTINUOUS fleet job; emails "fleet on
X.Y.Z". A canary failure **halts** the version (email); a newer version
clears the halt. One failing fleet device is moved to `<id>-excluded`; two
halt the fleet job.

Overrides, from `scripts/ota.sh` or the portal: `promote`, `hold`, `resume`,
`freeze`, `rerun`, `rollback X.Y.Z` (the only downgrade, and only to a
verified version), `target <thing>`. Job-creating overrides are refused while
the guard is tripped.

## 10. Cost rules

**On the device** (the SDK does these):

- The publish limiter: 10 messages a minute and 5,120 bytes each by default
  (`[limits]` in `platform.toml`; AWS bills per 5 KB). Batch telemetry; one
  message a minute is plenty for most things.
- Reconnects and enrolment follow the backoff of §4.
- No polling: react to deltas and Jobs notifications.

**The guard** (platform): free CloudWatch alarms at 20× or more the measured
baseline, and two budgets, trip the kill switch by scope:

| Trips when | Scope |
|---|---|
| > 30 connects or > 10 hook calls in 5 min | provisioning: the claim goes INACTIVE |
| > 1,000 publishes in 5 min; budget $10 | traffic: + the platform's presence rule and **every enabled `<id>_*` rule** disabled |
| > 1,000 publishes for 30 min; budget $25 | fleet: + deny-all on every fleet group (devices go offline) |

A guard reset enables exactly the product rules the trip disabled.

**A product's `cloud/`** (optional; its own Terraform root, applied by the
owner locally; state `products/<id>/cloud.tfstate` in the platform's state
bucket; facts from SSM `/iot-platform/products/<id>/platform`). CI enforces
these with tflint and the SDK's policies (`tflint/policies`):

- the aws provider tags everything `Product = <id>`; the backend is that
  state key;
- IoT rules are named `<id>_*` (the kill switch finds them by name), tagged
  `killable = "true"`, and select explicit small fields, never `SELECT *`;
- DynamoDB tables are on-demand with an `on_demand_throughput` cap of 1–5
  writes a second (no reservation, no fixed cost);
- Lambdas have no reserved concurrency (the account limit of 10 caps them);
- log groups keep 1–3 days; Logs sinks only behind a debug variable, off by
  default;
- names are `<id>-*` (log groups `/<id>/*`).

An exception takes `# tflint-ignore: opa_deny_<rule>` with its reason.

**A product's `web/`** (optional): its own origin, never the portal's;
commands through shadow desired state; refresh on user action or at most
every 60 s while visible.

## 11. Security baseline

- Public repositories, sole write access. The default-branch ruleset: pull
  request with 0 approvals (a sole owner cannot approve their own), required
  check `Firmware CI`, linear history, no force-push or deletion.
- Workflow token read-only by default, and it cannot approve pull requests;
  fork pull requests from outside contributors need approval; secret
  scanning with push protection; Dependabot security updates with the `fix`
  prefix.
- Workflows: `pull_request` only (never `pull_request_target`,
  `workflow_run`, `issue_comment`), actions pinned by SHA, no caches in a job
  that holds a secret, zizmor on every workflow change, no self-hosted
  runners.
- Environment `release`: `main` only, holds the signing key, no reviewer:
  the signature is the gate, checked by the controller and by the device.
  The product's AWS role trusts only that Environment inside the SDK's
  release workflow, may write only `releases/<id>/*`, for 15 minutes.
- Secure Boot V2 and flash encryption are not used (irreversible eFuses);
  key binding, signing, quarantine and the limiter cover the threat.

## 12. Local development

```sh
. ~/export-esp.sh                       # espup's environment (Xtensa toolchain)
cargo build --release                   # FW_VERSION defaults to the crate version
cargo run --release                     # flash and monitor (espflash, the project's bootloader)
cargo test -p <logic crate> --target host-tuple   # host tests
```

- Point the SDK at a local checkout while changing both:
  `device-sdk = { path = "../iot-device-sdk/device-sdk", ... }` (do not
  commit it).
- A bench board: `ergo commission ...` against the real platform; `ergo
  nvs-check --dump nvs.bin --key-storage nvs-soft-key` shows what the SDK
  sees in an NVS dump.
- `cloud/`: `TFLINT_OPA_POLICY_DIR=<sdk>/tflint/policies tflint` in
  `cloud/`, then `aws-vault exec <owner> -- terraform plan`.
