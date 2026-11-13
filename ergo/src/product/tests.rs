use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

// ---------------------------------------------------------------------------
// Text edits
// ---------------------------------------------------------------------------

const PLATFORM_TOML: &str = r#"# header
[product]
# 2-16 lowercase letters and digits
id = "template"
chip = "esp32s3"
mac_type = "wifi_sta"
key_storage = "nvs-soft-key"

[cloud]
endpoint = "a2pw25e7ewpuwe-ats.iot.eu-central-1.amazonaws.com"
template = "esp32-ztp-template-fleet-template"

[signing]
keys = []

[flash]
partitions = "partitions.csv"
frozen = [{ name = "nvs", offset = 0x9000, size = 0x6000 }]
"#;

const CARGO_CONFIG: &str = r#"[build]
target = "xtensa-esp32s3-espidf"

[env]
MCU = "esp32s3"
ESP_IDF_VERSION = "v5.5.3"
"#;

const VERSIONS_TF: &str = r#"terraform {
  backend "s3" {
    bucket       = "esp32-ztp-tfstate-637423178579"
    key          = "products/template/cloud.tfstate"
    region       = "eu-central-1"
    use_lockfile = true
  }
}

locals {
  product = "template"
}

provider "aws" {
  region = "eu-central-1"

  default_tags {
    tags = {
      Product   = local.product
      ManagedBy = "terraform"
    }
  }
}
"#;

#[test]
fn set_toml_replaces_exactly_the_key_of_its_section() {
    let t = set_toml(PLATFORM_TOML, "product", "id", "\"demo\"").unwrap();
    assert!(t.contains("\nid = \"demo\"\n"));
    assert!(
        t.contains("template = \"esp32-ztp-template-fleet-template\""),
        "other sections untouched"
    );
    assert!(t.ends_with('\n'));
    assert_eq!(t.lines().count(), PLATFORM_TOML.lines().count());
    let t = set_toml(&t, "signing", "keys", r#"["demo-a", "demo-b"]"#).unwrap();
    assert!(t.contains(r#"keys = ["demo-a", "demo-b"]"#));
    assert!(
        set_toml(PLATFORM_TOML, "cloud", "id", "\"x\"").is_err(),
        "not in that section"
    );
    assert!(set_toml(PLATFORM_TOML, "product", "missing", "1").is_err());
    let twice = format!("{PLATFORM_TOML}[product]\nid = \"again\"\n");
    assert!(set_toml(&twice, "product", "id", "\"x\"").is_err());
    // A key that only starts like another is not it.
    let t = set_toml(PLATFORM_TOML, "cloud", "template", "\"t\"").unwrap();
    assert!(t.contains("endpoint = \"a2pw25e7ewpuwe"));
}

#[test]
fn toml_string_reads_plain_strings() {
    assert_eq!(
        toml_string(PLATFORM_TOML, "product", "id").as_deref(),
        Some("template")
    );
    assert_eq!(toml_string(PLATFORM_TOML, "cloud", "id"), None);
    assert_eq!(
        toml_string(PLATFORM_TOML, "signing", "keys"),
        None,
        "not a string"
    );
}

#[test]
fn set_hcl_keeps_alignment_and_counts() {
    let t = set_hcl(VERSIONS_TF, "key", "\"products/demo/cloud.tfstate\"", 1).unwrap();
    assert!(t.contains("    key          = \"products/demo/cloud.tfstate\"\n"));
    let t = set_hcl(&t, "region", "\"eu-west-1\"", 2).unwrap();
    assert_eq!(t.matches("\"eu-west-1\"").count(), 2);
    let t = set_hcl(&t, "product", "\"demo\"", 1).unwrap();
    assert!(t.contains("  product = \"demo\"\n"));
    assert!(t.contains("Product   = local.product"), "case matters");
    assert!(t.contains("ManagedBy = \"terraform\""));
    assert!(
        set_hcl(VERSIONS_TF, "region", "\"x\"", 1).is_err(),
        "two, not one"
    );
    assert!(set_hcl(VERSIONS_TF, "nothing", "\"x\"", 1).is_err());
}

#[test]
fn github_repository_from_remotes() {
    for url in [
        "git@github.com:ergousha/demo-firmware.git\n",
        "https://github.com/ergousha/demo-firmware",
        "https://github.com/ergousha/demo-firmware.git",
        "ssh://git@github.com/ergousha/demo-firmware.git",
    ] {
        assert_eq!(
            github_repository(url).unwrap(),
            "ergousha/demo-firmware",
            "{url}"
        );
    }
    for url in [
        "https://gitlab.com/a/b",
        "git@github.com:a",
        "git@github.com:a/b/c",
        "git@github.com:a/b;rm",
    ] {
        assert!(github_repository(url).is_err(), "{url}");
    }
}

#[test]
fn chips() {
    assert_eq!(
        Chip::parse("esp32s3").unwrap().target(),
        "xtensa-esp32s3-espidf"
    );
    assert_eq!(
        Chip::parse("esp32").unwrap().target(),
        "xtensa-esp32-espidf"
    );
    assert!(Chip::parse("esp32c3")
        .unwrap_err()
        .contains("esp32 or esp32s3"));
}

#[test]
fn product_file_has_only_what_differs_from_the_defaults() {
    let mut o = opts(Path::new("/r"), Path::new("/i"));
    let v: Value = serde_json::from_str(&product_file(&o, "ergousha/demo-firmware", 42)).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"description": "Demo board", "github_repository": "ergousha/demo-firmware", "github_repository_id": 42})
    );
    o.soak_hours = 24;
    let v: Value = serde_json::from_str(&product_file(&o, "a/b", 1)).unwrap();
    assert_eq!(v["soak_hours"], 24);
}

#[test]
fn ruleset_requires_a_pr_without_approvals_and_the_firmware_check() {
    let r = ruleset();
    let rules = r["rules"].as_array().unwrap();
    let types: Vec<&str> = rules.iter().map(|r| r["type"].as_str().unwrap()).collect();
    assert_eq!(
        types,
        [
            "deletion",
            "non_fast_forward",
            "required_linear_history",
            "pull_request",
            "required_status_checks"
        ]
    );
    assert_eq!(rules[3]["parameters"]["required_approving_review_count"], 0);
    assert_eq!(rules[3]["parameters"]["require_code_owner_review"], false);
    assert_eq!(
        rules[4]["parameters"]["required_status_checks"][0]["context"],
        REQUIRED_CHECK
    );
}

#[test]
fn signing_keys_are_p256_pairs_in_the_formats_their_readers_take() {
    use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
    let (private, public) = signing_key().unwrap();
    assert!(
        private.starts_with("-----BEGIN PRIVATE KEY-----"),
        "PKCS#8, for openssl dgst -sign"
    );
    assert!(public.starts_with("-----BEGIN PUBLIC KEY-----"));
    let secret = p256::SecretKey::from_pkcs8_pem(&private).unwrap();
    let parsed = p256::PublicKey::from_public_key_pem(&public).unwrap();
    assert_eq!(secret.public_key(), parsed);
    let (other, _) = signing_key().unwrap();
    assert_ne!(*private, *other);
}

// ---------------------------------------------------------------------------
// The flow, against a fake
// ---------------------------------------------------------------------------

const FACTS: &str = r#"{"product":"demo","region":"eu-central-1","account_id":"637423178579",
"iot_endpoint":"a2pw25e7ewpuwe-ats.iot.eu-central-1.amazonaws.com",
"provisioning_template":"esp32-ztp-demo-fleet-template","fleet_group":"esp32-ztp-demo-fleet",
"canary_group":"esp32-ztp-demo-canary","excluded_group":"esp32-ztp-demo-excluded","shadow_name":"demo",
"github_actions_role_arn":"arn:aws:iam::637423178579:role/esp32-ztp-demo-github-actions-role",
"firmware_bucket":"esp32-ztp-firmware-637423178579","cloud_state_bucket":"esp32-ztp-tfstate-637423178579",
"cloud_state_key":"products/demo/cloud.tfstate","rule_prefix":"demo_","log_retention_days":3}"#;

#[derive(Default)]
struct Fake {
    /// Every call, in order: command lines, "confirm", "ssm put <name>",
    /// "clipboard set"/"clipboard clear", "interactive <line>".
    log: Vec<String>,
    /// Inputs given on stdin, by command line.
    stdin: Vec<(String, String)>,
    params: RefCell<HashMap<String, String>>,
    infra_branch: String,
    env_secrets: String,
    answers: Vec<bool>,
    checks_pending: usize,
    clipboard: Option<String>,
}

impl Fake {
    fn new() -> Self {
        Self {
            infra_branch: "main".into(),
            answers: vec![true, true],
            checks_pending: 1,
            ..Default::default()
        }
    }

    fn index(&self, needle: &str) -> usize {
        self.log
            .iter()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no call {needle:?} in {:#?}", self.log))
    }

    fn called(&self, needle: &str) -> bool {
        self.log.iter().any(|l| l.contains(needle))
    }
}

impl Ops for Fake {
    fn run(&mut self, cmd: Cmd) -> Result<String> {
        let line = cmd.line();
        self.log.push(line.clone());
        if let Some(input) = &cmd.stdin {
            self.stdin.push((line.clone(), input.to_string()));
        }
        let out = match line.as_str() {
            "git remote get-url origin" => "git@github.com:ergousha/demo-firmware.git\n",
            "gh api repos/ergousha/demo-firmware --jq .id" => "123456\n",
            "git rev-parse --abbrev-ref HEAD" => return Ok(format!("{}\n", self.infra_branch)),
            "git status --porcelain" => "",
            "sh -c command -v pbcopy" => "/usr/bin/pbcopy\n",
            l if l.starts_with("git status --porcelain --") => " M platform.toml\n",
            l if l.starts_with("gh pr create") && l.contains("product/demo") => {
                "https://github.com/ergousha/iot-platform/pull/15\n"
            }
            l if l.starts_with("gh pr create") => {
                "https://github.com/ergousha/demo-firmware/pull/1\n"
            }
            l if l.starts_with("gh pr checks") => {
                if self.checks_pending > 0 {
                    self.checks_pending -= 1;
                    bail!("no checks reported on the 'product/demo' branch");
                }
                ""
            }
            l if l.starts_with("gh secret list") => return Ok(self.env_secrets.clone()),
            _ => "",
        };
        Ok(out.to_string())
    }

    fn run_interactive(&mut self, cmd: Cmd) -> Result<()> {
        self.log.push(format!("interactive {}", cmd.line()));
        if cmd.line() == "terraform apply" {
            self.params
                .borrow_mut()
                .insert(facts_parameter("demo"), FACTS.into());
        }
        Ok(())
    }

    fn confirm(&mut self, _question: &str) -> Result<bool> {
        self.log.push("confirm".into());
        Ok(if self.answers.is_empty() {
            false
        } else {
            self.answers.remove(0)
        })
    }

    fn pause(&mut self, _prompt: &str) -> Result<()> {
        self.log.push("pause".into());
        Ok(())
    }

    fn sleep(&mut self, _d: Duration) {}

    fn clipboard(&mut self, secret: Option<&str>) -> Result<()> {
        self.log.push(
            if secret.is_some() {
                "clipboard set"
            } else {
                "clipboard clear"
            }
            .into(),
        );
        self.clipboard = secret.map(str::to_string);
        Ok(())
    }

    async fn parameter(&self, name: &str) -> Result<Option<String>> {
        Ok(self.params.borrow().get(name).cloned())
    }

    async fn create_parameter(&self, name: &str, value: &str, _description: &str) -> Result<()> {
        let mut params = self.params.borrow_mut();
        if params.contains_key(name) {
            bail!("{name} exists");
        }
        params.insert(name.into(), value.into());
        Ok(())
    }
}

struct Dirs {
    root: PathBuf,
    repo: PathBuf,
    infra: PathBuf,
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn dirs() -> Dirs {
    static N: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "ergo-product-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let repo = root.join("repo");
    let infra = root.join("infra");
    for d in [
        repo.join(".cargo"),
        repo.join("cloud"),
        infra.join("products"),
    ] {
        std::fs::create_dir_all(d).unwrap();
    }
    std::fs::write(repo.join("platform.toml"), PLATFORM_TOML).unwrap();
    std::fs::write(repo.join(".cargo/config.toml"), CARGO_CONFIG).unwrap();
    std::fs::write(repo.join("cloud/versions.tf"), VERSIONS_TF).unwrap();
    Dirs { root, repo, infra }
}

fn opts(repo: &Path, infra: &Path) -> InitOpts {
    InitOpts {
        id: "demo".into(),
        description: "Demo board".into(),
        chip: Chip::Esp32,
        soak_hours: 6,
        repo_dir: repo.to_path_buf(),
        infra_dir: infra.to_path_buf(),
    }
}

async fn run(fake: &mut Fake, o: &InitOpts) -> (Result<()>, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let r = {
        let mut term = Term {
            out: &mut out,
            err: &mut err,
        };
        init(fake, o, &mut term).await
    };
    let text = String::from_utf8(out).unwrap() + &String::from_utf8(err).unwrap();
    (r, text)
}

#[tokio::test]
async fn a_fresh_template_goes_on_the_platform_with_the_environment_last() {
    let d = dirs();
    let o = opts(&d.repo, &d.infra);
    let mut fake = Fake::new();
    let (r, text) = run(&mut fake, &o).await;
    r.unwrap();

    // The product's files.
    let platform = std::fs::read_to_string(d.repo.join("platform.toml")).unwrap();
    assert!(
        platform.contains("id = \"demo\"\nchip = \"esp32\"\n"),
        "{platform}"
    );
    assert!(platform.contains("template = \"esp32-ztp-demo-fleet-template\""));
    assert!(platform.contains(r#"keys = ["demo-a", "demo-b"]"#));
    let cargo = std::fs::read_to_string(d.repo.join(".cargo/config.toml")).unwrap();
    assert!(
        cargo.contains("target = \"xtensa-esp32-espidf\"") && cargo.contains("MCU = \"esp32\"")
    );
    let tf = std::fs::read_to_string(d.repo.join("cloud/versions.tf")).unwrap();
    assert!(tf.contains("\"products/demo/cloud.tfstate\"") && tf.contains("product = \"demo\""));
    for k in ["demo-a", "demo-b"] {
        let pem = std::fs::read_to_string(d.repo.join(format!("keys/{k}.pub.pem"))).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }
    let product: Value =
        serde_json::from_str(&std::fs::read_to_string(d.infra.join("products/demo.json")).unwrap())
            .unwrap();
    assert_eq!(product["github_repository_id"], 123456);

    // The order: platform PR merged, then apply, then the facts, settings,
    // and only then keys and the Environment; the clipboard last.
    let merge = fake.index("gh pr merge https://github.com/ergousha/iot-platform/pull/15 --merge");
    let apply = fake.index("interactive terraform apply");
    let vars = fake.index("gh variable set AWS_ROLE_ARN");
    let ruleset = fake.index("/rulesets --input -");
    let env = fake.index("environments/release --input -");
    let secret = fake.index("gh secret set FIRMWARE_SIGNING_KEY");
    let clip = fake.index("clipboard set");
    let pr = fake.index("gh pr create --base main --head chore/platform-demo");
    assert!(
        merge < apply
            && apply < vars
            && vars < ruleset
            && ruleset < env
            && env < secret
            && secret < clip
            && clip < pr
    );
    assert!(fake.index("clipboard clear") > fake.index("pause"));
    assert!(fake.clipboard.is_none(), "cleared");
    assert!(fake.called("gh variable set AWS_FIRMWARE_BUCKET --repo ergousha/demo-firmware --body esp32-ztp-firmware-637423178579"));

    // SSM has both public keys; the secret went on stdin only.
    let keys: Value =
        serde_json::from_str(&fake.params.borrow()[&signing_keys_parameter("demo")]).unwrap();
    assert!(keys["demo-a"].as_str().unwrap().contains("PUBLIC KEY"));
    assert!(keys["demo-b"].as_str().unwrap().contains("PUBLIC KEY"));
    let (_, key) = fake
        .stdin
        .iter()
        .find(|(l, _)| l.starts_with("gh secret set"))
        .unwrap();
    assert!(key.starts_with("-----BEGIN PRIVATE KEY-----"));
    assert!(
        !fake.log.iter().any(|l| l.contains("PRIVATE")),
        "no key on a command line"
    );
    assert!(!text.contains("PRIVATE KEY-----"), "no key printed");
    assert!(!platform.contains("PRIVATE"));
}

#[tokio::test]
async fn a_second_run_changes_nothing_that_is_done() {
    let d = dirs();
    let o = opts(&d.repo, &d.infra);
    let mut fake = Fake::new();
    run(&mut fake, &o).await.0.unwrap();
    let params = fake.params.take();

    let mut again = Fake::new();
    again.params = RefCell::new(params);
    again.env_secrets = "FIRMWARE_SIGNING_KEY\n".into();
    std::fs::write(d.infra.join("products/demo.json"), "{}").unwrap();
    let (r, text) = run(&mut again, &o).await;
    r.unwrap();
    assert!(
        !again.called("terraform"),
        "the platform knows the product: {:#?}",
        again.log
    );
    assert!(!again.called("gh secret set") && !again.called("clipboard"));
    assert!(!again.called("gh pr create --base main --head product/"));
    assert!(
        text.contains("signing keys demo-a and demo-b exist"),
        "{text}"
    );
}

#[tokio::test]
async fn a_half_made_key_set_stops_with_what_to_remove() {
    let d = dirs();
    let o = opts(&d.repo, &d.infra);
    let mut fake = Fake::new();
    fake.params
        .borrow_mut()
        .insert(facts_parameter("demo"), FACTS.into());
    fake.params
        .borrow_mut()
        .insert(signing_keys_parameter("demo"), "{}".into());
    let (r, _) = run(&mut fake, &o).await;
    let e = format!("{:#}", r.unwrap_err());
    assert!(
        e.contains("half-made") && e.contains("aws ssm delete-parameter"),
        "{e}"
    );
    assert!(!fake.called("gh secret set") && !fake.called("environments/release"));
}

#[tokio::test]
async fn declining_the_apply_stops_before_any_key_exists() {
    let d = dirs();
    let o = opts(&d.repo, &d.infra);
    let mut fake = Fake::new();
    fake.answers = vec![true, false]; // merge yes, apply no
    let (r, _) = run(&mut fake, &o).await;
    assert!(format!("{:#}", r.unwrap_err()).contains("before terraform apply"));
    assert!(!fake.called("interactive terraform apply"));
    assert!(fake.params.borrow().is_empty());
    assert!(!d.repo.join("keys").exists());
}

#[tokio::test]
async fn refuses_another_product_and_a_dirty_or_wrong_platform_checkout() {
    let d = dirs();
    let o = opts(&d.repo, &d.infra);

    let mut fake = Fake::new();
    fake.infra_branch = "feature".into();
    let (r, _) = run(&mut fake, &o).await;
    assert!(format!("{:#}", r.unwrap_err()).contains("not main"));

    std::fs::write(
        d.repo.join("platform.toml"),
        PLATFORM_TOML.replace("id = \"template\"", "id = \"vaktus\""),
    )
    .unwrap();
    let (r, _) = run(&mut Fake::new(), &o).await;
    assert!(format!("{:#}", r.unwrap_err()).contains("is product \"vaktus\""));

    let mut bad = o.clone();
    bad.id = "Demo".into();
    assert!(run(&mut Fake::new(), &bad).await.0.is_err());
}
