//! `ergo`: the owner's bench tool for the platform's devices.
//!
//! ```sh
//! export AWS_PROFILE=...            # the owner's credentials; nothing is stored
//! # Put a device on the platform: USB cable, then
//! WIFI_PSK=... ergo commission --product vaktus --port /dev/cu.usbmodem1101 \
//!     --wifi-ssid "home net" --wifi-psk-env WIFI_PSK
//! # Only register a device whose MAC and key are known (it enrols later):
//! ergo register --product vaktus --mac 38:18:2B:84:56:F4 --public-key <128 hex>
//! # What will the SDK see in this NVS dump?
//! ergo nvs-check --dump nvs.bin --product gateway
//! # Put a repository made from iot-device-template on the platform:
//! ergo product init demo --description "Demo board" --infra ../iot-platform
//! ```
//!
//! The bench flow is described step by step in [`commission`]. Grown from the
//! gateway repository's `seed-device`, without its shared-secret path.

mod aws;
mod cloud;
mod commission;
mod nvs_check;
mod product;
mod record;
mod serial;
mod term;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, bail, Result};
use clap::{Args, Parser, Subcommand};
use device_core::console::Key;
use device_core::ids::Mac;
use device_core::nvs::IdentityLayout;
use device_core::product::KeyStorage;

use crate::cloud::Secret;
use crate::commission::CommissionOpts;
use crate::record::{
    check_product, normalise_mac, normalise_public_key, Record, DEFAULT_REGION, DEFAULT_TABLE,
    MAX_ENROL_MINUTES,
};
use crate::term::Term;

/// Longest `--wait-minutes`: the claim is never active longer than this.
const MAX_WAIT_MINUTES: u32 = 120;

#[derive(Debug, Parser)]
#[command(
    name = "ergo",
    version,
    about = "The owner's tool for the platform: new products, register, commission, inspect NVS.",
    long_about = "Bench tool for the platform's devices.\n\n\
        `commission` puts a device on the platform over its USB serial console: it registers \
        the device, writes the claim credential and Wi-Fi to it, opens the claim for a few \
        minutes and waits until the device has enrolled. `register` only writes the registry \
        record. `nvs-check` reports what the SDK will find in an NVS partition dump. \
        `product init` puts a repository made from the template on the platform.\n\n\
        AWS credentials come from the default chain (AWS_PROFILE=...). No secret is ever \
        printed or written to a file."
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Register a device in the provisioning registry (it may then enrol once).
    ///
    /// Writes {mac_address, product, public_key, allowed=true, provisioned=false,
    /// enrol_by, canary, registered_at}. Refuses to overwrite an existing record
    /// unless --reprovision.
    Register(RegisterArgs),
    /// Commission a device on the bench over its USB serial console.
    ///
    /// Checks the guard, asks the device for its MAC and key, registers it, writes
    /// the claim credential (and Wi-Fi, endpoint), activates the claim, tells the
    /// device to enrol and waits for the registry to show it enrolled. On any
    /// failure or Ctrl-C the claim is deactivated, the record deleted and the
    /// device erased.
    Commission(CommissionArgs),
    /// Report what the SDK will see in an NVS partition dump (no key material).
    ///
    /// Exits non-zero if no identity loads.
    NvsCheck(NvsCheckArgs),
    /// Products on the platform.
    #[command(subcommand)]
    Product(ProductCmd),
}

#[derive(Debug, Subcommand)]
enum ProductCmd {
    /// Put a repository made from iot-device-template on the platform.
    ///
    /// Sets the product id and chip, adds products/<id>.json to iot-platform
    /// in a pull request and applies it, writes the platform's facts into
    /// platform.toml, cloud/ and the repository variables, applies the
    /// repository settings and ruleset, and last creates the signing keys and
    /// Environment `release`. Ends with a pull request on the product. Safe
    /// to run again after a stop.
    Init(ProductInitArgs),
}

#[derive(Debug, Args)]
struct ProductInitArgs {
    /// The product id: 2-16 lowercase letters and digits, starting with a letter.
    #[arg(value_parser = parse_product)]
    id: String,
    /// One line about the product (resources, the portal).
    #[arg(long)]
    description: String,
    /// The iot-platform checkout, clean and on main.
    #[arg(long, value_name = "DIR")]
    infra: PathBuf,
    /// The product repository checkout.
    #[arg(long, value_name = "DIR", default_value = ".")]
    repo: PathBuf,
    /// esp32 or esp32s3.
    #[arg(long, default_value = "esp32s3", value_parser = product::Chip::parse)]
    chip: product::Chip,
    /// Hours a release soaks on the canaries before the fleet job.
    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u32).range(0..=168))]
    soak_hours: u32,
    /// AWS region.
    #[arg(long, default_value = DEFAULT_REGION)]
    region: String,
}

#[derive(Debug, Args)]
struct AwsArgs {
    /// DynamoDB device registry table.
    #[arg(long, default_value = DEFAULT_TABLE)]
    table: String,
    /// AWS region.
    #[arg(long, default_value = DEFAULT_REGION)]
    region: String,
}

#[derive(Debug, Args)]
struct RegisterArgs {
    /// Product the device enrols as (e.g. vaktus, gateway).
    #[arg(long, value_parser = parse_product)]
    product: String,
    /// The device's MAC as it reports it, e.g. 38:18:2B:84:56:F4 (any case, `:`/`-`/none).
    #[arg(long, value_parser = parse_mac)]
    mac: Mac,
    /// The device's P-256 public key: X||Y (128 hex) or 04||X||Y (130); `:` and spaces ignored.
    #[arg(long, value_parser = parse_public_key)]
    public_key: String,
    /// Set canary=true on the registry record.
    #[arg(long)]
    canary: bool,
    /// Minutes the device may enrol within (enrol_by), at most a week.
    #[arg(long, default_value_t = record::DEFAULT_ENROL_MINUTES,
          value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_ENROL_MINUTES)))]
    minutes: u32,
    /// Overwrite an existing record (resets provisioned=false): re-enrolment at the bench.
    #[arg(long)]
    reprovision: bool,
    #[command(flatten)]
    aws: AwsArgs,
}

#[derive(Debug, Args)]
struct CommissionArgs {
    /// Product the device must report (e.g. vaktus, gateway).
    #[arg(long, value_parser = parse_product)]
    product: String,
    /// Serial port of the device's console, e.g. /dev/cu.usbmodem1101.
    #[arg(long)]
    port: String,
    /// Serial baud rate.
    #[arg(long, default_value_t = 115_200)]
    baud: u32,
    /// Set canary=true on the registry record.
    #[arg(long)]
    canary: bool,
    /// Wi-Fi network to write to the device.
    #[arg(long, requires = "wifi_psk_env")]
    wifi_ssid: Option<String>,
    /// NAME of the environment variable holding the Wi-Fi passphrase (never the
    /// passphrase itself). An empty variable means an open network.
    #[arg(long, requires = "wifi_ssid", value_name = "VAR")]
    wifi_psk_env: Option<String>,
    /// AWS IoT endpoint override, e.g. xxxx-ats.iot.eu-central-1.amazonaws.com.
    #[arg(long, value_parser = parse_endpoint)]
    endpoint: Option<String>,
    /// Minutes the registry record allows enrolment (enrol_by).
    #[arg(long, default_value_t = record::DEFAULT_ENROL_MINUTES,
          value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_ENROL_MINUTES)))]
    minutes: u32,
    /// Re-enrol an enrolled device: it forgets its identity and its record is overwritten.
    #[arg(long)]
    reprovision: bool,
    /// Minutes to wait for enrolment once the claim is active (plus up to one more
    /// minute for the device to confirm it holds its certificate).
    #[arg(long, default_value_t = 10,
          value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_WAIT_MINUTES)))]
    wait_minutes: u32,
    #[command(flatten)]
    aws: AwsArgs,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("layout").required(true).args(["key_storage", "product"])))]
struct NvsCheckArgs {
    /// NVS partition dump (esptool.py read_flash <offset> <size> nvs.bin).
    #[arg(long)]
    dump: PathBuf,
    /// Where the product keeps its key: atecc608 or nvs-soft-key.
    #[arg(long, value_parser = parse_key_storage)]
    key_storage: Option<KeyStorage>,
    /// A known product instead of --key-storage: vaktus or gateway.
    #[arg(long)]
    product: Option<String>,
}

fn parse_product(s: &str) -> Result<String, String> {
    check_product(s).map_err(|e| e.to_string())
}
fn parse_mac(s: &str) -> Result<Mac, String> {
    normalise_mac(s).map_err(|e| e.to_string())
}
fn parse_public_key(s: &str) -> Result<String, String> {
    normalise_public_key(s).map_err(|e| e.to_string())
}
fn parse_endpoint(s: &str) -> Result<String, String> {
    Key::Endpoint.validate(s).map(|()| s.to_string())
}
fn parse_key_storage(s: &str) -> Result<KeyStorage, String> {
    KeyStorage::parse(s)
}

impl CommissionArgs {
    /// Checks what clap cannot, and reads the passphrase from the environment.
    fn opts(&self, env: impl Fn(&str) -> Option<String>) -> Result<CommissionOpts> {
        if self.wait_minutes > self.minutes {
            bail!(
                "--wait-minutes {} is longer than the record allows (--minutes {})",
                self.wait_minutes,
                self.minutes
            );
        }
        let wifi = match (&self.wifi_ssid, &self.wifi_psk_env) {
            (Some(ssid), Some(var)) => {
                Key::WifiSsid
                    .validate(ssid)
                    .map_err(|e| anyhow!("--wifi-ssid: {e}"))?;
                let psk = env(var).ok_or_else(|| {
                    anyhow!("--wifi-psk-env {var}: the environment variable {var} is not set")
                })?;
                // The message names the rule, never the value.
                Key::WifiPsk
                    .validate(&psk)
                    .map_err(|e| anyhow!("--wifi-psk-env {var}: {e}"))?;
                Some((ssid.clone(), Secret::new(psk)))
            }
            _ => None,
        };
        Ok(CommissionOpts {
            product: self.product.clone(),
            canary: self.canary,
            wifi,
            endpoint: self.endpoint.clone(),
            minutes: self.minutes,
            reprovision: self.reprovision,
            wait: Duration::from_secs(u64::from(self.wait_minutes) * 60),
            region: self.aws.region.clone(),
        })
    }
}

impl NvsCheckArgs {
    fn layout(&self) -> Result<IdentityLayout> {
        let storage = match (&self.key_storage, &self.product) {
            (Some(storage), _) => *storage,
            (None, Some(product)) => nvs_check::product_storage(product)?,
            (None, None) => bail!("--key-storage or --product is required"),
        };
        Ok(IdentityLayout::for_storage(storage))
    }
}

/// Resolves on Ctrl-C (or SIGTERM/SIGHUP). If the handler cannot be installed
/// it never resolves, rather than reporting an interrupt that did not happen.
async fn interrupted() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let term = signal(SignalKind::terminate());
        let hup = signal(SignalKind::hangup());
        if let (Ok(mut term), Ok(mut hup)) = (term, hup) {
            tokio::select! {
                r = tokio::signal::ctrl_c() => if r.is_err() { std::future::pending::<()>().await },
                _ = term.recv() => {}
                _ = hup.recv() => {}
            }
            return;
        }
    }
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

async fn run(cli: Cli) -> Result<()> {
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    let mut term = Term {
        out: &mut stdout,
        err: &mut stderr,
    };
    match cli.command {
        Cmd::Register(args) => {
            let record = Record::new(
                &args.mac,
                &args.product,
                &args.public_key,
                args.canary,
                args.minutes,
                SystemTime::now(),
            );
            let cloud = aws::Aws::connect(&args.aws.region, &args.aws.table).await?;
            commission::register(&cloud, &record, args.reprovision, &mut term).await
        }
        Cmd::Commission(args) => {
            let opts = args.opts(|var| std::env::var(var).ok())?;
            let cloud = aws::Aws::connect(&args.aws.region, &args.aws.table).await?;
            commission::commission(
                &cloud,
                || serial::SerialConsole::open(&args.port, args.baud),
                &opts,
                SystemTime::now(),
                interrupted(),
                &mut term,
            )
            .await
            .map(|_thing| ())
        }
        Cmd::Product(ProductCmd::Init(args)) => {
            let opts = product::InitOpts {
                id: args.id,
                description: args.description,
                chip: args.chip,
                soak_hours: args.soak_hours,
                repo_dir: args.repo,
                infra_dir: args.infra,
            };
            let mut ops = product::RealOps::connect(&args.region).await?;
            product::init(&mut ops, &opts, &mut term).await
        }
        Cmd::NvsCheck(args) => {
            let layout = args.layout()?;
            if nvs_check::check_dump(&args.dump, layout, term.out)? {
                Ok(())
            } else {
                bail!("no identity loads from {}", args.dump.display())
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("ergo").chain(args.iter().copied()))
    }

    const KEY: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\
                       FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210";

    #[test]
    fn the_cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn register_normalises_and_defaults() {
        let key = format!("04{}", KEY.to_lowercase());
        let cli = parse(&[
            "register",
            "--product",
            "vaktus",
            "--mac",
            "38-18-2b-84-56-f4",
            "--public-key",
            &key,
        ])
        .unwrap();
        let Cmd::Register(args) = cli.command else {
            panic!()
        };
        assert_eq!(args.mac.colon(), "38:18:2B:84:56:F4");
        assert_eq!(args.public_key, KEY);
        assert_eq!(args.minutes, 60);
        assert!(!args.reprovision && !args.canary);
        assert_eq!(args.aws.table, "esp32-ztp-device-registry");
        assert_eq!(args.aws.region, "eu-central-1");
    }

    #[test]
    fn bad_register_arguments_are_refused() {
        let base = [
            "register",
            "--mac",
            "AA:BB:CC:DD:EE:FF",
            "--public-key",
            KEY,
        ];
        let with = |extra: &[&str]| {
            let mut v: Vec<&str> = base.to_vec();
            v.extend_from_slice(extra);
            parse(&v)
        };
        assert!(with(&["--product", "vaktus"]).is_ok());
        assert!(with(&["--product", "Vaktus"]).is_err());
        assert!(with(&[]).is_err(), "--product is required");
        assert!(with(&["--product", "vaktus", "--minutes", "0"]).is_err());
        assert!(with(&["--product", "vaktus", "--minutes", "10081"]).is_err());
        assert!(with(&["--product", "vaktus", "--minutes", "10080"]).is_ok());
        assert!(parse(&[
            "register",
            "--product",
            "vaktus",
            "--mac",
            "AA:BB",
            "--public-key",
            KEY
        ])
        .is_err());
        assert!(parse(&[
            "register",
            "--product",
            "vaktus",
            "--mac",
            "AA:BB:CC:DD:EE:FF",
            "--public-key",
            "04AB"
        ])
        .is_err());
        assert!(
            with(&["--product", "vaktus", "--secret", "s"]).is_err(),
            "the shared-secret path is gone"
        );
    }

    fn commission(extra: &[&str]) -> Result<CommissionArgs, clap::Error> {
        let mut v = vec!["commission", "--product", "vaktus", "--port", "/dev/null"];
        v.extend_from_slice(extra);
        parse(&v).map(|cli| match cli.command {
            Cmd::Commission(args) => args,
            _ => unreachable!(),
        })
    }

    #[test]
    fn commission_reads_the_passphrase_from_the_environment_only() {
        let args = commission(&["--wifi-ssid", "home net", "--wifi-psk-env", "MY_PSK"]).unwrap();
        let env = |var: &str| (var == "MY_PSK").then(|| "correct horse".to_string());
        let opts = args.opts(env).unwrap();
        let (ssid, psk) = opts.wifi.unwrap();
        assert_eq!(ssid, "home net");
        assert_eq!(psk.expose(), "correct horse");
        assert_eq!(opts.wait, Duration::from_secs(600));
        assert_eq!(opts.minutes, 60);
        assert_eq!(args.baud, 115_200);

        let e = args.opts(|_| None).unwrap_err().to_string();
        assert!(e.contains("MY_PSK is not set"), "{e}");
        let e = args.opts(|_| Some("short".into())).unwrap_err().to_string();
        assert!(e.contains("8-63") && !e.contains("short\""), "{e}");
        let open = args.opts(|_| Some(String::new())).unwrap();
        assert_eq!(open.wifi.unwrap().1.expose(), "", "open network");

        assert!(
            commission(&["--wifi-ssid", "home"]).is_err(),
            "needs the variable"
        );
        assert!(
            commission(&["--wifi-psk-env", "X"]).is_err(),
            "needs the SSID"
        );
        assert!(
            commission(&["--wifi-psk", "x"]).is_err(),
            "never on the command line"
        );
    }

    #[test]
    fn commission_checks_endpoint_and_windows() {
        assert!(commission(&["--endpoint", "evil.example.com"]).is_err());
        let args = commission(&["--endpoint", "a1-ats.iot.eu-central-1.amazonaws.com"]).unwrap();
        assert!(args.opts(|_| None).unwrap().endpoint.is_some());
        assert!(commission(&["--wait-minutes", "121"]).is_err());
        let args = commission(&["--wait-minutes", "30", "--minutes", "20"]).unwrap();
        assert!(args.opts(|_| None).is_err(), "would outlive the record");
    }

    #[test]
    fn product_init_arguments() {
        let cli = parse(&[
            "product",
            "init",
            "demo",
            "--description",
            "Demo",
            "--infra",
            "../p",
        ])
        .unwrap();
        let Cmd::Product(ProductCmd::Init(args)) = cli.command else {
            panic!()
        };
        assert_eq!(args.chip, product::Chip::Esp32s3);
        assert_eq!(args.repo, PathBuf::from("."));
        assert_eq!(args.soak_hours, 6);
        assert!(parse(&[
            "product",
            "init",
            "Demo",
            "--description",
            "D",
            "--infra",
            "p"
        ])
        .is_err());
        assert!(
            parse(&["product", "init", "demo", "--infra", "p"]).is_err(),
            "needs a description"
        );
        assert!(
            parse(&["product", "init", "demo", "--description", "D"]).is_err(),
            "needs --infra"
        );
        assert!(parse(&[
            "product",
            "init",
            "demo",
            "--description",
            "D",
            "--infra",
            "p",
            "--chip",
            "esp32c3"
        ])
        .is_err());
        assert!(parse(&[
            "product",
            "init",
            "demo",
            "--description",
            "D",
            "--infra",
            "p",
            "--soak-hours",
            "169"
        ])
        .is_err());
    }

    #[test]
    fn nvs_check_needs_exactly_one_layout() {
        let layout = |extra: &[&str]| -> Result<IdentityLayout> {
            let mut v = vec!["nvs-check", "--dump", "nvs.bin"];
            v.extend_from_slice(extra);
            match parse(&v)?.command {
                Cmd::NvsCheck(args) => args.layout(),
                _ => unreachable!(),
            }
        };
        assert_eq!(
            layout(&["--product", "vaktus"]).unwrap(),
            IdentityLayout::SecureElement
        );
        assert_eq!(
            layout(&["--key-storage", "nvs-soft-key"]).unwrap(),
            IdentityLayout::SoftKey
        );
        assert_eq!(
            layout(&["--key-storage", "atecc608"]).unwrap(),
            IdentityLayout::SecureElement
        );
        assert!(layout(&[]).is_err());
        assert!(layout(&["--product", "vaktus", "--key-storage", "atecc608"]).is_err());
        assert!(layout(&["--key-storage", "tpm"]).is_err());
        assert!(layout(&["--product", "toaster"]).is_err());
    }
}
