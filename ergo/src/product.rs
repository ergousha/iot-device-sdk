//! `ergo product init`: puts a repository made from the template
//! (`ergousha/iot-device-template`) on the platform (plan §8).
//!
//! 1. **Checks**: a valid product id; the product checkout is a GitHub
//!    repository still carrying the template's product (or this product,
//!    on a re-run); the iot-platform checkout is clean on `main`; `pbcopy`
//!    exists for the backup key.
//! 2. **The product's own files**: `platform.toml` (`[product] id, chip`),
//!    `.cargo/config.toml` (build target, `MCU`).
//! 3. **The platform**: `products/<id>.json` in a pull request on
//!    iot-platform, merged once its checks pass, then `terraform apply` in
//!    that checkout (Terraform shows the plan and asks). Skipped once SSM
//!    `/iot-platform/products/<id>/platform` exists.
//! 4. **From the platform's facts**: `platform.toml` `[cloud]`, the backend,
//!    region and `local.product` of `cloud/versions.tf`, and the repository variables
//!    `AWS_ROLE_ARN` and `AWS_FIRMWARE_BUCKET`.
//! 5. **Repository settings** (plan §3.4): read-only workflow token that
//!    cannot approve, fork-PR approval for all outside contributors, secret
//!    scanning with push protection, Dependabot security updates, and a
//!    ruleset on the default branch (PR with 0 approvals, check
//!    `Firmware CI`, linear history, no force-push or deletion).
//! 6. **Signing keys and Environment `release`, last**, so no release can
//!    run before AWS is ready: `<id>-a` (active) and `<id>-b` (offline
//!    backup), public keys to SSM `signing_keys` and `keys/` and
//!    `platform.toml`, Environment `release` (main only) with `<id>-a` as
//!    `FIRMWARE_SIGNING_KEY`, and `<id>-b` to the clipboard once. No private
//!    key is written to disk, printed or put on a command line.
//! 7. **A pull request** on the product with those files (`chore:`, which
//!    releases nothing). The first `feat:` merge after it is release 0.1.0.
//!
//! Every step checks what is already there, so a run that stopped half-way
//! can be repeated. The one exception is a half-made key set (SSM, `keys/`
//! and the Environment secret disagree): that needs a look, and the error
//! says what to remove.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::record::check_product;
use crate::term::Term;

/// The product id a fresh template repository carries.
pub const TEMPLATE_PRODUCT: &str = "template";
/// The check the default-branch ruleset requires (the template's ci.yml).
pub const REQUIRED_CHECK: &str = "Firmware CI";

/// Chips the template builds for (Xtensa, Espressif's `esp` toolchain).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chip {
    Esp32,
    Esp32s3,
}

impl Chip {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "esp32" => Ok(Self::Esp32),
            "esp32s3" => Ok(Self::Esp32s3),
            _ => Err(format!(
                "{s:?}: the template builds for esp32 or esp32s3 (other chips need their own toolchain setup)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Esp32 => "esp32",
            Self::Esp32s3 => "esp32s3",
        }
    }

    pub fn target(self) -> &'static str {
        match self {
            Self::Esp32 => "xtensa-esp32-espidf",
            Self::Esp32s3 => "xtensa-esp32s3-espidf",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InitOpts {
    pub id: String,
    pub description: String,
    pub chip: Chip,
    pub soak_hours: u32,
    /// The product repository checkout (made from the template).
    pub repo_dir: PathBuf,
    /// An iot-platform checkout, on `main`, with its Terraform initialised
    /// or initialisable (the owner's AWS session).
    pub infra_dir: PathBuf,
}

/// `/iot-platform/products/<id>/platform`, written by the platform's
/// Terraform (ssm.tf).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct PlatformFacts {
    pub product: String,
    pub region: String,
    pub iot_endpoint: String,
    pub provisioning_template: String,
    pub github_actions_role_arn: String,
    pub firmware_bucket: String,
    pub cloud_state_bucket: String,
    pub cloud_state_key: String,
}

pub fn facts_parameter(id: &str) -> String {
    format!("/iot-platform/products/{id}/platform")
}

pub fn signing_keys_parameter(id: &str) -> String {
    format!("/iot-platform/products/{id}/signing_keys")
}

/// One external command. `stdin` carries anything secret: it never appears
/// in the arguments (which a process listing shows).
#[derive(Clone)]
pub struct Cmd {
    pub program: &'static str,
    pub args: Vec<String>,
    pub dir: PathBuf,
    pub stdin: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.line())?;
        if self.stdin.is_some() {
            f.write_str(" <stdin>")?;
        }
        Ok(())
    }
}

impl Cmd {
    pub fn new(program: &'static str, dir: &Path, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(|a| a.to_string()).collect(),
            dir: dir.to_path_buf(),
            stdin: None,
        }
    }

    pub fn stdin(mut self, input: &str) -> Self {
        self.stdin = Some(Zeroizing::new(input.to_string()));
        self
    }

    /// The command as text, without its input.
    pub fn line(&self) -> String {
        std::iter::once(self.program.to_string())
            .chain(self.args.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Everything `init` does outside its own process. [`RealOps`] is the real
/// one; the tests use a fake.
#[allow(async_fn_in_trait)]
pub trait Ops {
    /// Runs `cmd` and returns its stdout; fails on a non-zero exit.
    fn run(&mut self, cmd: Cmd) -> Result<String>;
    /// Runs `cmd` on the terminal (Terraform's plan and prompt).
    fn run_interactive(&mut self, cmd: Cmd) -> Result<()>;
    fn confirm(&mut self, question: &str) -> Result<bool>;
    /// Waits for the owner (Enter).
    fn pause(&mut self, prompt: &str) -> Result<()>;
    fn sleep(&mut self, d: Duration);
    /// Puts `secret` on the clipboard (`None` clears it).
    fn clipboard(&mut self, secret: Option<&str>) -> Result<()>;
    async fn parameter(&self, name: &str) -> Result<Option<String>>;
    /// Creates a String parameter; fails if it exists.
    async fn create_parameter(&self, name: &str, value: &str, description: &str) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Text edits: pure, and tested.
// ---------------------------------------------------------------------------

/// Sets `key = <literal>` in `[section]` of a TOML file, keeping every other
/// line. The key must be there exactly once, on its own line (the template
/// keeps comments on lines of their own).
pub fn set_toml(text: &str, section: &str, key: &str, literal: &str) -> Result<String> {
    let mut current = String::new();
    let mut found = 0;
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            current = trimmed
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or_default()
                .trim()
                .to_string();
        }
        if current == section && assigns(trimmed, key) {
            found += 1;
            let indent = &line[..line.len() - line.trim_start().len()];
            out.push(format!("{indent}{key} = {literal}"));
        } else {
            out.push(line.to_string());
        }
    }
    match found {
        1 => Ok(join_lines(out, text)),
        0 => bail!("no `{key} = ...` line in [{section}]"),
        n => bail!("{n} `{key} = ...` lines in [{section}]"),
    }
}

/// Sets every `key = ...` attribute line of an HCL file to `literal`,
/// keeping its indentation and alignment; exactly `expected` must exist.
pub fn set_hcl(text: &str, key: &str, literal: &str, expected: usize) -> Result<String> {
    let mut found = 0;
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if assigns(trimmed, key) {
            found += 1;
            let indent = &line[..line.len() - trimmed.len()];
            let eq = trimmed.find('=').expect("assigns() saw it");
            let lhs = &trimmed[..eq]; // the key and its alignment spaces
            out.push(format!("{indent}{lhs}= {literal}"));
        } else {
            out.push(line.to_string());
        }
    }
    if found != expected {
        bail!("expected {expected} `{key} = ...` line(s), found {found}");
    }
    Ok(join_lines(out, text))
}

fn assigns(trimmed: &str, key: &str) -> bool {
    trimmed
        .strip_prefix(key)
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

fn join_lines(lines: Vec<String>, original: &str) -> String {
    let mut s = lines.join("\n");
    if original.ends_with('\n') {
        s.push('\n');
    }
    s
}

pub fn quoted(s: &str) -> String {
    serde_json::to_string(s).expect("a string serialises")
}

/// The value of `key` in `[section]`, if it is a plain string.
pub fn toml_string(text: &str, section: &str, key: &str) -> Option<String> {
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            current = trimmed
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_string();
        } else if current == section && assigns(trimmed, key) {
            let value = trimmed.split_once('=')?.1.trim();
            return serde_json::from_str::<String>(value).ok();
        }
    }
    None
}

/// `owner/name` from a GitHub remote URL.
pub fn github_repository(url: &str) -> Result<String> {
    let url = url.trim();
    let path = url
        .strip_prefix("git@github.com:")
        .or_else(|| url.strip_prefix("https://github.com/"))
        .or_else(|| url.strip_prefix("ssh://git@github.com/"))
        .ok_or_else(|| anyhow!("{url} is not a GitHub remote"))?;
    let repo = path.trim_end_matches('/').trim_end_matches(".git");
    let ok = repo.split('/').count() == 2
        && repo.split('/').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        });
    if !ok {
        bail!("cannot tell the GitHub repository from {url}");
    }
    Ok(repo.to_string())
}

/// `products/<id>.json` for the platform repository.
pub fn product_file(o: &InitOpts, repository: &str, repository_id: u64) -> String {
    let mut v = serde_json::json!({
        "description": o.description,
        "github_repository": repository,
        "github_repository_id": repository_id,
    });
    if o.soak_hours != 6 {
        v["soak_hours"] = o.soak_hours.into();
    }
    let mut s = serde_json::to_string_pretty(&v).expect("JSON");
    s.push('\n');
    s
}

/// The default-branch ruleset (plan §3.4).
pub fn ruleset() -> Value {
    serde_json::json!({
        "name": "main",
        "target": "branch",
        "enforcement": "active",
        "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
        "rules": [
            { "type": "deletion" },
            { "type": "non_fast_forward" },
            { "type": "required_linear_history" },
            { "type": "pull_request", "parameters": {
                "required_approving_review_count": 0,
                "dismiss_stale_reviews_on_push": false,
                "require_code_owner_review": false,
                "require_last_push_approval": false,
                "required_review_thread_resolution": false
            }},
            { "type": "required_status_checks", "parameters": {
                "strict_required_status_checks_policy": false,
                "required_status_checks": [ { "context": REQUIRED_CHECK } ]
            }}
        ]
    })
}

/// A P-256 key pair: the private key as PKCS#8 PEM (what `openssl dgst
/// -sign` in the release workflow reads), the public key as SPKI PEM (what
/// `keys/*.pub.pem`, the OTA controller and the device keyring read).
pub fn signing_key() -> Result<(Zeroizing<String>, String)> {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    let secret = loop {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|e| anyhow!("no randomness: {e}"))?;
        // Almost every 32-byte string is a valid scalar; retry the rest.
        if let Ok(key) = p256::SecretKey::from_slice(bytes.as_ref()) {
            break key;
        }
    };
    let private = secret
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| anyhow!("encoding the private key: {e}"))?;
    let public = secret
        .public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| anyhow!("encoding the public key: {e}"))?;
    Ok((Zeroizing::new(private.to_string()), public))
}

// ---------------------------------------------------------------------------
// The flow.
// ---------------------------------------------------------------------------

fn read(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

fn write(path: &Path, text: &str) -> Result<()> {
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

/// Edits `path` in place with `f`; returns whether it changed.
fn edit(path: &Path, f: impl FnOnce(&str) -> Result<String>) -> Result<bool> {
    let before = read(path)?;
    let after = f(&before).with_context(|| path.display().to_string())?;
    if after != before {
        write(path, &after)?;
    }
    Ok(after != before)
}

pub async fn init<O: Ops>(ops: &mut O, o: &InitOpts, term: &mut Term<'_>) -> Result<()> {
    check_product(&o.id)?;
    let id = o.id.as_str();
    let repo_dir = o.repo_dir.as_path();
    let infra_dir = o.infra_dir.as_path();

    // --- 1. checks -------------------------------------------------------
    let repo = github_repository(&ops.run(Cmd::new(
        "git",
        repo_dir,
        &["remote", "get-url", "origin"],
    ))?)?;
    let platform_toml = repo_dir.join("platform.toml");
    let current = toml_string(&read(&platform_toml)?, "product", "id")
        .ok_or_else(|| anyhow!("platform.toml has no [product] id"))?;
    if current != TEMPLATE_PRODUCT && current != id {
        bail!(
            "{} is product {current:?}, not a fresh template ({TEMPLATE_PRODUCT:?}) or {id:?}",
            repo_dir.display()
        );
    }
    let repo_id: u64 = ops
        .run(Cmd::new(
            "gh",
            repo_dir,
            &["api", &format!("repos/{repo}"), "--jq", ".id"],
        ))?
        .trim()
        .parse()
        .context("the repository's numeric id")?;
    let infra_branch = ops.run(Cmd::new(
        "git",
        infra_dir,
        &["rev-parse", "--abbrev-ref", "HEAD"],
    ))?;
    if infra_branch.trim() != "main" {
        bail!(
            "{} is on {}, not main",
            infra_dir.display(),
            infra_branch.trim()
        );
    }
    if !ops
        .run(Cmd::new("git", infra_dir, &["status", "--porcelain"]))?
        .trim()
        .is_empty()
    {
        bail!("{} has uncommitted changes", infra_dir.display());
    }
    ops.run(Cmd::new("sh", repo_dir, &["-c", "command -v pbcopy"]))
        .context("pbcopy (macOS) is needed for the backup signing key")?;
    term.say(format!(
        "product {id} ({}), repository {repo} (id {repo_id}), platform {}",
        o.chip.as_str(),
        infra_dir.display()
    ));

    // --- 2. the product's own files ---------------------------------------
    edit(&platform_toml, |t| {
        let t = set_toml(t, "product", "id", &quoted(id))?;
        set_toml(&t, "product", "chip", &quoted(o.chip.as_str()))
    })?;
    edit(&repo_dir.join(".cargo/config.toml"), |t| {
        let t = set_toml(t, "build", "target", &quoted(o.chip.target()))?;
        set_toml(&t, "env", "MCU", &quoted(o.chip.as_str()))
    })?;
    term.say("platform.toml and .cargo/config.toml: product and chip set");

    // --- 3. the platform ---------------------------------------------------
    let facts = match ops.parameter(&facts_parameter(id)).await? {
        Some(json) => {
            term.say(format!(
                "{} exists: the platform knows {id}",
                facts_parameter(id)
            ));
            json
        }
        None => {
            platform_pull_request(ops, o, &repo, repo_id, term)?;
            if !ops.confirm(&format!(
                "Run `terraform apply` in {} now (it shows the plan and asks again)?",
                infra_dir.display()
            ))? {
                bail!("stopped before terraform apply; run `ergo product init` again to go on");
            }
            ops.run(Cmd::new("terraform", infra_dir, &["init", "-input=false"]))?;
            ops.run_interactive(Cmd::new("terraform", infra_dir, &["apply"]))
                .context("terraform apply")?;
            ops.parameter(&facts_parameter(id)).await?.ok_or_else(|| {
                anyhow!(
                    "terraform apply ran but {} is still missing",
                    facts_parameter(id)
                )
            })?
        }
    };
    let facts: PlatformFacts = serde_json::from_str(&facts)
        .with_context(|| format!("{} is not the expected JSON", facts_parameter(id)))?;
    if facts.product != id {
        bail!("{} names product {}", facts_parameter(id), facts.product);
    }

    // --- 4. from the platform's facts --------------------------------------
    edit(&platform_toml, |t| {
        let t = set_toml(t, "cloud", "endpoint", &quoted(&facts.iot_endpoint))?;
        set_toml(
            &t,
            "cloud",
            "template",
            &quoted(&facts.provisioning_template),
        )
    })?;
    edit(&repo_dir.join("cloud/versions.tf"), |t| {
        let t = set_hcl(t, "bucket", &quoted(&facts.cloud_state_bucket), 1)?;
        let t = set_hcl(&t, "key", &quoted(&facts.cloud_state_key), 1)?;
        let t = set_hcl(&t, "region", &quoted(&facts.region), 2)?;
        set_hcl(&t, "product", &quoted(id), 1)
    })?;
    for (name, value) in [
        ("AWS_ROLE_ARN", &facts.github_actions_role_arn),
        ("AWS_FIRMWARE_BUCKET", &facts.firmware_bucket),
    ] {
        ops.run(Cmd::new(
            "gh",
            repo_dir,
            &["variable", "set", name, "--repo", &repo, "--body", value],
        ))?;
    }
    term.say("platform.toml [cloud], cloud/versions.tf and the repository variables set");

    // --- 5. repository settings ---------------------------------------------
    settings(ops, repo_dir, &repo)?;
    term.say(format!(
        "repository settings and the default-branch ruleset (check {REQUIRED_CHECK:?}) applied"
    ));

    // --- 6. signing keys and Environment release, last ---------------------
    keys(ops, o, &repo, term).await?;

    // --- 7. the pull request --------------------------------------------------
    product_pull_request(ops, o, term)
}

/// `products/<id>.json` on iot-platform: a branch, a pull request, merged
/// once its checks pass; then the checkout is back on an up-to-date main.
fn platform_pull_request<O: Ops>(
    ops: &mut O,
    o: &InitOpts,
    repo: &str,
    repo_id: u64,
    term: &mut Term<'_>,
) -> Result<()> {
    let id = o.id.as_str();
    let dir = o.infra_dir.as_path();
    ops.run(Cmd::new("git", dir, &["pull", "--ff-only"]))?;
    let file = dir.join("products").join(format!("{id}.json"));
    if file.exists() {
        term.say(format!("{} is on main already", file.display()));
        return Ok(());
    }
    let branch = format!("product/{id}");
    ops.run(Cmd::new("git", dir, &["switch", "-c", &branch]))?;
    write(&file, &product_file(o, repo, repo_id))?;
    let rel = format!("products/{id}.json");
    let title = format!("feat: product {id}");
    ops.run(Cmd::new("git", dir, &["add", &rel]))?;
    ops.run(Cmd::new("git", dir, &["commit", "-q", "-m", &title]))?;
    ops.run(Cmd::new("git", dir, &["push", "-u", "origin", &branch]))?;
    let body = format!(
        "Adds product `{id}` ({}), firmware from `{repo}`. Opened by `ergo product init`.",
        o.description
    );
    let url = ops.run(Cmd::new(
        "gh",
        dir,
        &[
            "pr", "create", "--base", "main", "--head", &branch, "--title", &title, "--body", &body,
        ],
    ))?;
    let url = url.trim().to_string();
    term.say(format!("opened {url}; waiting for its checks"));
    // Checks register a few seconds after the PR opens.
    let mut attempt = 0;
    loop {
        ops.sleep(Duration::from_secs(10));
        match ops.run(Cmd::new(
            "gh",
            dir,
            &["pr", "checks", &url, "--watch", "--fail-fast"],
        )) {
            Ok(_) => break,
            Err(e) if attempt < 5 && format!("{e:#}").contains("no checks reported") => {
                attempt += 1
            }
            Err(e) => return Err(e.context(format!("the checks of {url}"))),
        }
    }
    if !ops.confirm(&format!("Checks passed. Merge {url}?"))? {
        bail!("{url} is open and unmerged; merge it, then run `ergo product init` again");
    }
    ops.run(Cmd::new(
        "gh",
        dir,
        &["pr", "merge", &url, "--merge", "--delete-branch"],
    ))?;
    ops.run(Cmd::new("git", dir, &["switch", "main"]))?;
    ops.run(Cmd::new("git", dir, &["pull", "--ff-only"]))?;
    term.say(format!("merged {url}"));
    Ok(())
}

fn settings<O: Ops>(ops: &mut O, dir: &Path, repo: &str) -> Result<()> {
    let api = |method: &str, path: &str, body: Value| {
        Cmd::new(
            "gh",
            dir,
            &[
                "api",
                "-X",
                method,
                &format!("repos/{repo}{path}"),
                "--input",
                "-",
            ],
        )
        .stdin(&body.to_string())
    };
    ops.run(api(
        "PUT",
        "/actions/permissions/workflow",
        serde_json::json!({"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false}),
    ))?;
    ops.run(api(
        "PUT",
        "/actions/permissions/fork-pr-contributor-approval",
        serde_json::json!({"approval_policy": "all_external_contributors"}),
    ))?;
    ops.run(api(
        "PATCH",
        "",
        serde_json::json!({"security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
            "secret_scanning_push_protection": {"status": "enabled"}
        }}),
    ))?;
    ops.run(Cmd::new(
        "gh",
        dir,
        &[
            "api",
            "-X",
            "PUT",
            &format!("repos/{repo}/vulnerability-alerts"),
        ],
    ))?;
    ops.run(Cmd::new(
        "gh",
        dir,
        &[
            "api",
            "-X",
            "PUT",
            &format!("repos/{repo}/automated-security-fixes"),
        ],
    ))?;
    let names = ops.run(Cmd::new(
        "gh",
        dir,
        &["api", &format!("repos/{repo}/rulesets"), "--jq", ".[].name"],
    ))?;
    if !names.lines().any(|n| n.trim() == "main") {
        ops.run(api("POST", "/rulesets", ruleset()))?;
    }
    Ok(())
}

async fn keys<O: Ops>(ops: &mut O, o: &InitOpts, repo: &str, term: &mut Term<'_>) -> Result<()> {
    let id = o.id.as_str();
    let dir = o.repo_dir.as_path();
    let parameter = signing_keys_parameter(id);
    let ids = [format!("{id}-a"), format!("{id}-b")];
    let paths: Vec<PathBuf> = ids
        .iter()
        .map(|k| dir.join("keys").join(format!("{k}.pub.pem")))
        .collect();

    let in_ssm = ops.parameter(&parameter).await?.is_some();
    let in_repo = paths.iter().all(|p| p.exists());
    let secrets = ops
        .run(Cmd::new(
            "gh",
            dir,
            &[
                "secret", "list", "--env", "release", "--repo", repo, "--json", "name", "--jq",
                ".[].name",
            ],
        ))
        .unwrap_or_default(); // no Environment yet
    let in_env = secrets.lines().any(|n| n.trim() == "FIRMWARE_SIGNING_KEY");
    match (in_ssm, in_repo, in_env) {
        (true, true, true) => {
            term.say(format!("signing keys {} and {} exist (SSM, keys/, Environment release)", ids[0], ids[1]));
            return Ok(());
        }
        (false, false, false) => {}
        _ => bail!(
            "a half-made key set: SSM {parameter} {}, keys/{id}-*.pub.pem {}, Environment release secret {}. \
             Nothing has been signed with it yet: remove what exists (aws ssm delete-parameter --name {parameter}; \
             rm keys/{id}-*.pub.pem; gh secret delete FIRMWARE_SIGNING_KEY --env release) and run again",
            yes(in_ssm),
            yes(in_repo),
            yes(in_env)
        ),
    }

    let (private_a, public_a) = signing_key()?;
    let (private_b, public_b) = signing_key()?;

    // SSM first: the controller must know the keys before a release is signed.
    let value = serde_json::json!({ &ids[0]: public_a, &ids[1]: public_b }).to_string();
    ops.create_parameter(
        &parameter,
        &value,
        &format!(
            "Firmware-signing public keys of {id} (key id -> PEM). Read by the OTA controller."
        ),
    )
    .await?;
    std::fs::create_dir_all(dir.join("keys"))?;
    write(&paths[0], &public_a)?;
    write(&paths[1], &public_b)?;
    edit(&dir.join("platform.toml"), |t| {
        set_toml(
            t,
            "signing",
            "keys",
            &format!("[{}, {}]", quoted(&ids[0]), quoted(&ids[1])),
        )
    })?;
    term.say(format!(
        "public keys {} and {}: SSM {parameter}, keys/, platform.toml",
        ids[0], ids[1]
    ));

    // Environment release: deployments from main only, no reviewers (the
    // signature is the gate, plan decision B). Created last.
    let env = format!("repos/{repo}/environments/release");
    ops.run(
        Cmd::new("gh", dir, &["api", "-X", "PUT", &env, "--input", "-"]).stdin(
            &serde_json::json!({"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}})
                .to_string(),
        ),
    )?;
    let policies = ops.run(Cmd::new(
        "gh",
        dir,
        &[
            "api",
            &format!("{env}/deployment-branch-policies"),
            "--jq",
            ".branch_policies[].name",
        ],
    ))?;
    if !policies.lines().any(|n| n.trim() == "main") {
        ops.run(Cmd::new(
            "gh",
            dir,
            &[
                "api",
                "-X",
                "POST",
                &format!("{env}/deployment-branch-policies"),
                "-f",
                "name=main",
                "-f",
                "type=branch",
            ],
        ))?;
    }
    ops.run(
        Cmd::new(
            "gh",
            dir,
            &[
                "secret",
                "set",
                "FIRMWARE_SIGNING_KEY",
                "--env",
                "release",
                "--repo",
                repo,
            ],
        )
        .stdin(&private_a),
    )?;
    drop(private_a);
    term.say(format!(
        "Environment release: main only, FIRMWARE_SIGNING_KEY = {}",
        ids[0]
    ));

    ops.clipboard(Some(&private_b))?;
    drop(private_b);
    let cleared = ops.pause(&format!(
        "The PRIVATE key of {} (the offline backup) is on the clipboard. Paste it into the password \
         manager as \"{} firmware signing key\", then press Enter to clear the clipboard.",
        ids[1], ids[1]
    ));
    ops.clipboard(None)?;
    cleared?;
    term.say("clipboard cleared");
    Ok(())
}

fn yes(b: bool) -> &'static str {
    if b {
        "exists"
    } else {
        "is missing"
    }
}

/// Commits the files `init` changed on a branch and opens the pull request.
fn product_pull_request<O: Ops>(ops: &mut O, o: &InitOpts, term: &mut Term<'_>) -> Result<()> {
    let id = o.id.as_str();
    let dir = o.repo_dir.as_path();
    let files = [
        "platform.toml",
        ".cargo/config.toml",
        "cloud/versions.tf",
        "keys",
    ];
    let changed = ops.run(Cmd::new(
        "git",
        dir,
        &[
            "status",
            "--porcelain",
            "--",
            files[0],
            files[1],
            files[2],
            files[3],
        ],
    ))?;
    if changed.trim().is_empty() {
        term.say(format!("{id} is on the platform; nothing left to commit"));
        return Ok(());
    }
    let branch = format!("chore/platform-{id}");
    let title = format!("chore: put {id} on the platform");
    ops.run(Cmd::new("git", dir, &["switch", "-c", &branch]))?;
    ops.run(Cmd::new(
        "git",
        dir,
        &["add", "--", files[0], files[1], files[2], files[3]],
    ))?;
    ops.run(Cmd::new("git", dir, &["commit", "-q", "-m", &title]))?;
    ops.run(Cmd::new("git", dir, &["push", "-u", "origin", &branch]))?;
    let body = format!(
        "`ergo product init {id}`: product id and chip, the platform's endpoint and template, the \
         cloud/ backend, and the signing public keys `{id}-a` and `{id}-b`. `chore:`, so it releases nothing."
    );
    let url = ops.run(Cmd::new(
        "gh",
        dir,
        &[
            "pr", "create", "--base", "main", "--head", &branch, "--title", &title, "--body", &body,
        ],
    ))?;
    term.say(format!("opened {}", url.trim()));
    term.say(format!(
        "Next: merge it once \"{REQUIRED_CHECK}\" passes (squash or rebase: history is linear). \
         The first feat: merge after it is release 0.1.0; then flash a board with factory.bin and \
         `ergo commission --product {id} --canary ...`."
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// The real thing.
// ---------------------------------------------------------------------------

pub struct RealOps {
    ssm: aws_sdk_ssm::Client,
}

impl RealOps {
    pub async fn connect(region: &str) -> Result<Self> {
        let config = aws_config::from_env()
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;
        Ok(Self {
            ssm: aws_sdk_ssm::Client::new(&config),
        })
    }
}

fn command(cmd: &Cmd) -> std::process::Command {
    let mut c = std::process::Command::new(cmd.program);
    c.args(&cmd.args).current_dir(&cmd.dir);
    c
}

impl Ops for RealOps {
    fn run(&mut self, cmd: Cmd) -> Result<String> {
        use std::io::Write;
        use std::process::Stdio;
        let mut c = command(&cmd);
        c.stdin(if cmd.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        let mut child = c
            .spawn()
            .with_context(|| format!("starting {}", cmd.program))?;
        if let Some(input) = &cmd.stdin {
            let mut stdin = child.stdin.take().expect("piped");
            stdin.write_all(input.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            // The arguments, never the input: secrets travel on stdin only.
            bail!(
                "`{}` failed ({}): {}",
                cmd.line(),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn run_interactive(&mut self, cmd: Cmd) -> Result<()> {
        let status = command(&cmd)
            .status()
            .with_context(|| format!("starting {}", cmd.program))?;
        if !status.success() {
            bail!("`{}` failed ({status})", cmd.line());
        }
        Ok(())
    }

    fn confirm(&mut self, question: &str) -> Result<bool> {
        let mut answer = String::new();
        eprint!("{question} [y/N] ");
        std::io::stdin().read_line(&mut answer)?;
        Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
    }

    fn pause(&mut self, prompt: &str) -> Result<()> {
        let mut line = String::new();
        eprint!("{prompt} ");
        std::io::stdin().read_line(&mut line)?;
        Ok(())
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }

    fn clipboard(&mut self, secret: Option<&str>) -> Result<()> {
        self.run(Cmd::new("pbcopy", Path::new("."), &[]).stdin(secret.unwrap_or("")))
            .map(|_| ())
    }

    async fn parameter(&self, name: &str) -> Result<Option<String>> {
        use aws_sdk_ssm::operation::get_parameter::GetParameterError;
        match self.ssm.get_parameter().name(name).send().await {
            Ok(out) => Ok(out.parameter().and_then(|p| p.value()).map(str::to_string)),
            Err(e) => match e.as_service_error() {
                Some(GetParameterError::ParameterNotFound(_)) => Ok(None),
                _ => Err(anyhow!("{}", aws_sdk_ssm::error::DisplayErrorContext(e)))
                    .with_context(|| format!("SSM GetParameter {name}")),
            },
        }
    }

    async fn create_parameter(&self, name: &str, value: &str, description: &str) -> Result<()> {
        self.ssm
            .put_parameter()
            .name(name)
            .value(value)
            .description(description)
            .r#type(aws_sdk_ssm::types::ParameterType::String)
            .overwrite(false)
            .send()
            .await
            .map_err(|e| anyhow!("{}", aws_sdk_ssm::error::DisplayErrorContext(e)))
            .with_context(|| format!("SSM PutParameter {name}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
