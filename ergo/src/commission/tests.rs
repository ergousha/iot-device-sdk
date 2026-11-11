//! The commission flow against a fake cloud and a simulated device, in paused
//! time: every 3 s / 5 s / minutes-long wait runs instantly.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::UNIX_EPOCH;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use super::*;
use crate::cloud::ClaimCredential;

const MAC: &str = "38:18:2B:84:56:F4";
const THING: &str = "38182B8456F4";
const CERT_ID: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const CLAIM_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIBclaim\n-----END CERTIFICATE-----\n";
const CLAIM_KEY: &str =
    "-----BEGIN EC PRIVATE KEY-----\nTOPSECRETCLAIMKEYMATERIAL\n-----END EC PRIVATE KEY-----\n";
const PSK: &str = "psk-very-secret-42";
const ENDPOINT: &str = "a1b2c3-ats.iot.eu-central-1.amazonaws.com";

fn key1() -> String {
    "AB".repeat(64)
}
fn key2() -> String {
    "CD".repeat(64)
}

// ---- the fake cloud --------------------------------------------------------

struct FakeCloud {
    calls: RefCell<Vec<String>>,
    guard: String,
    exists: bool,
    /// `get_provisioned` returns true from this poll on (1-based).
    provisioned_from_poll: Option<usize>,
    polls: Cell<usize>,
    poll_fails: bool,
    arm_fails: bool,
    disarm_fails: bool,
    delete_result: Delete,
    put: RefCell<Option<(Record, bool)>>,
}

impl Default for FakeCloud {
    fn default() -> Self {
        Self {
            calls: RefCell::default(),
            guard: r#"{"tripped":false}"#.into(),
            exists: false,
            provisioned_from_poll: Some(2),
            polls: Cell::new(0),
            poll_fails: false,
            arm_fails: false,
            disarm_fails: false,
            delete_result: Delete::Deleted,
            put: RefCell::default(),
        }
    }
}

impl FakeCloud {
    fn log(&self, call: impl Into<String>) {
        self.calls.borrow_mut().push(call.into());
    }
    fn calls(&self) -> Vec<String> {
        // Polls are collapsed: how many depends on timing.
        let mut calls: Vec<String> = Vec::new();
        for c in self.calls.borrow().iter() {
            if c == "poll" && calls.last().map(String::as_str) == Some("poll") {
                continue;
            }
            calls.push(c.clone());
        }
        calls
    }
    fn armed(&self) -> bool {
        self.calls.borrow().iter().any(|c| c.starts_with("arm"))
    }
}

impl Cloud for FakeCloud {
    async fn guard_state(&self) -> Result<String> {
        self.log("guard");
        Ok(self.guard.clone())
    }
    async fn put_record(&self, record: &Record, overwrite: bool) -> Result<Put> {
        self.log(format!("put {} overwrite={overwrite}", record.mac));
        if self.exists && !overwrite {
            return Ok(Put::AlreadyRegistered);
        }
        *self.put.borrow_mut() = Some((record.clone(), overwrite));
        Ok(Put::Written)
    }
    async fn get_provisioned(&self, mac: &str) -> Result<Option<bool>> {
        assert_eq!(mac, MAC);
        self.log("poll");
        if self.poll_fails {
            bail!("DynamoDB GetItem: throttled");
        }
        self.polls.set(self.polls.get() + 1);
        Ok(Some(
            self.provisioned_from_poll
                .is_some_and(|n| self.polls.get() >= n),
        ))
    }
    async fn delete_record_if_unprovisioned(&self, mac: &str) -> Result<Delete> {
        self.log(format!("delete {mac}"));
        Ok(self.delete_result)
    }
    async fn claim_credential(&self) -> Result<ClaimCredential> {
        self.log("claim");
        Ok(ClaimCredential {
            certificate_pem: CLAIM_CERT.into(),
            private_key: Secret::new(CLAIM_KEY.into()),
        })
    }
    async fn claim_policy_targets(&self) -> Result<Vec<String>> {
        self.log("targets");
        Ok(vec![format!(
            "arn:aws:iot:eu-central-1:123456789012:cert/{CERT_ID}"
        )])
    }
    async fn set_claim_active(&self, cert_id: &str, active: bool) -> Result<()> {
        assert_eq!(cert_id, CERT_ID);
        self.log(if active { "arm" } else { "disarm" });
        if (active && self.arm_fails) || (!active && self.disarm_fails) {
            bail!("IoT UpdateCertificate: AccessDenied");
        }
        Ok(())
    }
}

// ---- the simulated device --------------------------------------------------

/// Answers the console protocol like the firmware does.
struct Device {
    sent: Rc<RefCell<Vec<String>>>,
    inbox: VecDeque<String>,
    product: String,
    pubkey: String,
    enrolled: bool,
    /// INFOs ignored before answering (booting).
    deaf_for: usize,
    /// Never answers anything.
    silent: bool,
    /// Answers `SET` of this key with ERR.
    refuse: Option<Key>,
    /// Reports `EVENT enrolled` after ENROL.
    reports_enrolled: bool,
    /// Key after FORGET.
    new_pubkey: String,
}

impl Device {
    fn new(sent: &Rc<RefCell<Vec<String>>>) -> Self {
        Self {
            sent: sent.clone(),
            inbox: VecDeque::new(),
            product: "vaktus".into(),
            pubkey: key1(),
            enrolled: false,
            deaf_for: 0,
            silent: false,
            refuse: None,
            reports_enrolled: true,
            new_pubkey: key2(),
        }
    }

    fn reply(&mut self, reply: Reply) {
        // Log decoration, as the firmware's logger adds it.
        self.inbox
            .push_back(format!("I (42) console: {}", reply.encode()));
    }

    fn register(&self) -> Reply {
        Reply::Register(Register {
            product: self.product.clone(),
            mac: MAC.into(),
            thing: THING.into(),
            pubkey: self.pubkey.clone(),
            fw: "0.9.0".into(),
            enrolled: self.enrolled,
        })
    }
}

fn ok(verb: &str, key: Option<&str>) -> Reply {
    Reply::Ok {
        verb: verb.into(),
        key: key.map(str::to_string),
    }
}

impl Console for Device {
    fn send_line(&mut self, line: &str) -> Result<()> {
        self.sent.borrow_mut().push(line.to_string());
        if self.silent {
            return Ok(());
        }
        self.inbox.push_back("I (40) wifi: some log line".into());
        match Command::parse(line)
            .expect("a command")
            .expect("well formed")
        {
            Command::Info if self.deaf_for > 0 => self.deaf_for -= 1,
            Command::Info => {
                let register = self.register();
                self.reply(register);
                self.reply(ok("INFO", None));
            }
            Command::Set { key, .. } if Some(key) == self.refuse => self.reply(Reply::Err {
                verb: "SET".into(),
                message: "nvs: no space".into(),
            }),
            Command::Set { key, .. } => self.reply(ok("SET", Some(key.nvs_key()))),
            Command::Erase => self.reply(ok("ERASE", None)),
            Command::Enrol => {
                self.reply(ok("ENROL", None));
                self.reply(Reply::Event {
                    name: "provisioning".into(),
                    fields: vec![("step".into(), "csr".into())],
                });
                if self.reports_enrolled {
                    self.reply(Reply::Event {
                        name: "enrolled".into(),
                        fields: vec![("thing".into(), THING.into())],
                    });
                }
            }
            Command::Forget => {
                self.reply(ok("FORGET", None));
                // Restarting: deaf for a while, then a new key, unenrolled.
                self.inbox
                    .push_back("ets Jun  8 2016 00:22:57 rst:0xc".into());
                self.deaf_for = 4;
                self.enrolled = false;
                self.pubkey = self.new_pubkey.clone();
            }
        }
        Ok(())
    }

    async fn read_line(&mut self, timeout: Duration) -> Result<Option<String>> {
        if let Some(line) = self.inbox.pop_front() {
            return Ok(Some(line));
        }
        tokio::time::sleep(timeout).await;
        Ok(None)
    }
}

// ---- running the flow ------------------------------------------------------

fn opts() -> CommissionOpts {
    CommissionOpts {
        product: "vaktus".into(),
        canary: false,
        wifi: Some(("home net".into(), Secret::new(PSK.into()))),
        endpoint: Some(ENDPOINT.into()),
        minutes: 60,
        reprovision: false,
        wait: Duration::from_secs(10 * 60),
        region: "eu-central-1".into(),
    }
}

struct Run {
    result: Result<String>,
    out: String,
    err: String,
    sent: Vec<String>,
    opened: bool,
}

impl Run {
    /// The verbs (and SET keys) sent to the device, in order.
    fn verbs(&self) -> Vec<String> {
        self.sent
            .iter()
            .map(|l| {
                let words: Vec<&str> = l.split(' ').collect();
                match words[1] {
                    "SET" => format!("SET {}", words[2]),
                    verb => verb.to_string(),
                }
            })
            .collect()
    }

    fn error(&self) -> String {
        format!("{:#}", self.result.as_ref().unwrap_err())
    }

    /// No secret, in clear or as it travels to the device, in anything a
    /// person or a log could see.
    fn assert_no_secrets(&self) {
        let shown = format!(
            "{}\n{}\n{}",
            self.out,
            self.err,
            match &self.result {
                Ok(thing) => thing.clone(),
                Err(e) => format!("{e:#} {e:?}"),
            }
        );
        for secret in [
            CLAIM_KEY.to_string(),
            "TOPSECRETCLAIMKEYMATERIAL".to_string(),
            B64.encode(CLAIM_KEY),
            PSK.to_string(),
            B64.encode(PSK),
        ] {
            assert!(!shown.contains(&secret), "{secret:?} leaked into:\n{shown}");
        }
    }
}

async fn attempt_with(
    cloud: &FakeCloud,
    device: impl FnOnce(&Rc<RefCell<Vec<String>>>) -> Device,
    opts: CommissionOpts,
    interrupt: impl Future<Output = ()>,
) -> Run {
    let sent = Rc::new(RefCell::new(Vec::new()));
    let device = device(&sent);
    let opened = Cell::new(false);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let result = {
        let mut term = Term {
            out: &mut out,
            err: &mut err,
        };
        commission(
            cloud,
            || {
                opened.set(true);
                Ok(device)
            },
            &opts,
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            interrupt,
            &mut term,
        )
        .await
    };
    let run = Run {
        result,
        out: String::from_utf8(out).unwrap(),
        err: String::from_utf8(err).unwrap(),
        sent: sent.borrow().clone(),
        opened: opened.get(),
    };
    run.assert_no_secrets();
    run
}

async fn attempt(cloud: &FakeCloud, device: impl FnOnce(&mut Device)) -> Run {
    attempt_with(
        cloud,
        |sent| {
            let mut d = Device::new(sent);
            device(&mut d);
            d
        },
        opts(),
        std::future::pending(),
    )
    .await
}

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

const ALL_WRITES: [&str; 6] = [
    "INFO",
    "SET claim_cert",
    "SET claim_key",
    "SET wifi_ssid",
    "SET wifi_psk",
    "SET endpoint",
];

// ---- tests -----------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn the_happy_path_enrols_and_closes_the_claim() {
    let cloud = FakeCloud::default();
    let run = attempt(&cloud, |_| {}).await;
    assert_eq!(run.result.as_deref().unwrap(), THING);
    assert_eq!(
        cloud.calls(),
        strings(&[
            "guard",
            &format!("put {MAC} overwrite=false"),
            "claim",
            "guard",
            "targets",
            "arm",
            "poll",
            "disarm"
        ])
    );
    let mut expected = strings(&ALL_WRITES);
    expected.push("ENROL".into());
    assert_eq!(run.verbs(), expected, "no ERASE: the device keeps Wi-Fi");

    let (record, overwrite) = cloud.put.borrow().clone().unwrap();
    assert!(!overwrite);
    assert_eq!(record.mac, MAC);
    assert_eq!(record.product, "vaktus");
    assert_eq!(record.public_key, key1());
    assert_eq!(record.enrol_by, 1_700_000_000 + 3600);

    // The values did reach the device, encoded by the protocol.
    assert!(run.sent.contains(
        &Command::Set {
            key: Key::ClaimKey,
            value: CLAIM_KEY.into()
        }
        .encode()
    ));
    assert!(run.sent.contains(
        &Command::Set {
            key: Key::WifiPsk,
            value: PSK.into()
        }
        .encode()
    ));
    assert!(
        run.out.contains(&format!("{THING} enrolled")),
        "{}",
        run.out
    );
    assert!(run.out.contains("INACTIVE again"), "{}", run.out);
    assert!(
        run.err
            .contains("PLATFORM EVENT enrolled thing=38182B8456F4"),
        "events are echoed: {}",
        run.err
    );
    assert!(!run.err.contains("wifi: some log line"), "logs are not");
}

#[tokio::test(start_paused = true)]
async fn optional_writes_are_skipped() {
    let cloud = FakeCloud::default();
    let mut o = opts();
    o.wifi = None;
    o.endpoint = None;
    let run = attempt_with(&cloud, Device::new, o, std::future::pending()).await;
    assert!(run.result.is_ok());
    assert_eq!(
        run.verbs(),
        strings(&["INFO", "SET claim_cert", "SET claim_key", "ENROL"])
    );
}

#[tokio::test(start_paused = true)]
async fn a_booting_board_is_asked_again() {
    let cloud = FakeCloud::default();
    let run = attempt(&cloud, |d| d.deaf_for = 3).await;
    assert!(run.result.is_ok(), "{}", run.error());
    assert_eq!(run.verbs().iter().filter(|v| *v == "INFO").count(), 4);
}

#[tokio::test(start_paused = true)]
async fn a_silent_port_times_out_before_touching_aws() {
    let cloud = FakeCloud::default();
    let run = attempt(&cloud, |d| d.silent = true).await;
    assert!(run.error().contains("no REGISTER"), "{}", run.error());
    assert_eq!(run.verbs().len(), 10, "INFO every 3 s for 30 s");
    assert_eq!(cloud.calls(), strings(&["guard"]));
}

#[tokio::test(start_paused = true)]
async fn the_wrong_product_stops_before_anything_is_written() {
    let cloud = FakeCloud::default();
    let run = attempt(&cloud, |d| d.product = "gateway".into()).await;
    assert!(run.error().contains("\"gateway\""), "{}", run.error());
    assert_eq!(cloud.calls(), strings(&["guard"]));
    assert_eq!(run.verbs(), strings(&["INFO"]), "no ERASE: nothing written");
}

#[tokio::test(start_paused = true)]
async fn an_enrolled_device_stops_without_reprovision() {
    let cloud = FakeCloud::default();
    let run = attempt(&cloud, |d| d.enrolled = true).await;
    assert!(run.error().contains("already enrolled"), "{}", run.error());
    assert!(run.error().contains("--reprovision"));
    assert_eq!(cloud.calls(), strings(&["guard"]));
    assert_eq!(run.verbs(), strings(&["INFO"]), "and is not made to FORGET");
}

#[tokio::test(start_paused = true)]
async fn reprovision_forgets_and_registers_the_new_key() {
    let cloud = FakeCloud::default();
    let mut o = opts();
    o.reprovision = true;
    let run = attempt_with(
        &cloud,
        |sent| {
            let mut d = Device::new(sent);
            d.enrolled = true;
            d.pubkey = "-".into(); // a legacy RSA identity
            d
        },
        o,
        std::future::pending(),
    )
    .await;
    assert_eq!(run.result.as_deref().unwrap(), THING, "{}", run.err);
    let verbs = run.verbs();
    assert_eq!(&verbs[..2], ["INFO", "FORGET"]);
    let infos_after = verbs[2..].iter().take_while(|v| *v == "INFO").count();
    assert_eq!(infos_after, 5, "asked until the restarted device answers");
    let (record, overwrite) = cloud.put.borrow().clone().unwrap();
    assert!(overwrite, "--reprovision overwrites the old record");
    assert_eq!(record.public_key, key2(), "the key reported after FORGET");
    assert_eq!(
        cloud.calls()[..2],
        strings(&["guard", &format!("put {MAC} overwrite=true")])
    );
}

#[tokio::test(start_paused = true)]
async fn a_device_without_a_p256_key_is_not_registered() {
    let cloud = FakeCloud::default();
    let run = attempt(&cloud, |d| d.pubkey = "-".into()).await;
    assert!(run.error().contains("pubkey=-"), "{}", run.error());
    assert_eq!(cloud.calls(), strings(&["guard"]));

    let cloud = FakeCloud::default();
    let run = attempt(&cloud, |d| d.pubkey = "AB".repeat(65)).await;
    assert!(run.error().contains("128 hex"), "{}", run.error());
    assert_eq!(cloud.calls(), strings(&["guard"]));
}

#[tokio::test(start_paused = true)]
async fn a_tripped_guard_never_opens_the_port_or_arms() {
    let cloud = FakeCloud {
        guard: r#"{"tripped":true,"reason":"spend"}"#.into(),
        ..FakeCloud::default()
    };
    let run = attempt(&cloud, |_| {}).await;
    assert!(run.error().contains("guard is tripped"), "{}", run.error());
    assert!(!run.opened);
    assert!(!cloud.armed());
    assert_eq!(cloud.calls(), strings(&["guard"]));
}

#[tokio::test(start_paused = true)]
async fn an_existing_record_is_left_alone() {
    let cloud = FakeCloud {
        exists: true,
        ..FakeCloud::default()
    };
    let run = attempt(&cloud, |_| {}).await;
    assert!(
        run.error().contains("already registered"),
        "{}",
        run.error()
    );
    assert!(run.error().contains("--reprovision"));
    assert_eq!(
        cloud.calls(),
        strings(&["guard", &format!("put {MAC} overwrite=false")]),
        "not deleted: this run did not write it"
    );
    assert_eq!(run.verbs(), strings(&["INFO"]));
}

#[tokio::test(start_paused = true)]
async fn a_refused_set_erases_the_device_and_deletes_the_record() {
    let cloud = FakeCloud::default();
    let run = attempt(&cloud, |d| d.refuse = Some(Key::WifiPsk)).await;
    assert!(
        run.error()
            .contains("refused SET wifi_psk: ERR SET nvs: no space"),
        "{}",
        run.error()
    );
    assert_eq!(
        cloud.calls(),
        strings(&[
            "guard",
            &format!("put {MAC} overwrite=false"),
            "claim",
            &format!("delete {MAC}")
        ]),
        "the claim was never armed, so there is nothing to disarm"
    );
    assert_eq!(
        run.verbs(),
        strings(&[
            "INFO",
            "SET claim_cert",
            "SET claim_key",
            "SET wifi_ssid",
            "SET wifi_psk",
            "ERASE"
        ])
    );
}

#[tokio::test(start_paused = true)]
async fn waiting_too_long_disarms_deletes_and_erases() {
    let cloud = FakeCloud {
        provisioned_from_poll: None,
        ..FakeCloud::default()
    };
    let run = attempt(&cloud, |d| d.reports_enrolled = false).await;
    assert!(
        run.error().contains("did not enrol within 10 min"),
        "{}",
        run.error()
    );
    assert_eq!(
        cloud.calls(),
        strings(&[
            "guard",
            &format!("put {MAC} overwrite=false"),
            "claim",
            "guard",
            "targets",
            "arm",
            "poll",
            "disarm",
            &format!("delete {MAC}")
        ])
    );
    assert_eq!(
        cloud.polls.get(),
        121,
        "every 5 s for 10 min, and once at the deadline"
    );
    assert_eq!(run.verbs().last().unwrap(), "ERASE");
}

#[tokio::test(start_paused = true)]
async fn a_failing_step_after_arming_still_disarms() {
    let cloud = FakeCloud {
        poll_fails: true,
        ..FakeCloud::default()
    };
    let run = attempt(&cloud, |_| {}).await;
    assert!(run.error().contains("throttled"), "{}", run.error());
    let calls = cloud.calls();
    assert_eq!(
        calls[calls.len() - 3..],
        strings(&["poll", "disarm", &format!("delete {MAC}")])
    );
    assert_eq!(run.verbs().last().unwrap(), "ERASE");
}

#[tokio::test(start_paused = true)]
async fn a_failed_activation_is_still_undone() {
    let cloud = FakeCloud {
        arm_fails: true,
        ..FakeCloud::default()
    };
    let run = attempt(&cloud, |_| {}).await;
    assert!(run.error().contains("AccessDenied"), "{}", run.error());
    let calls = cloud.calls();
    assert_eq!(
        calls[calls.len() - 3..],
        strings(&["arm", "disarm", &format!("delete {MAC}")])
    );
}

#[tokio::test(start_paused = true)]
async fn ctrl_c_disarms_deletes_and_erases() {
    let cloud = FakeCloud {
        provisioned_from_poll: None,
        ..FakeCloud::default()
    };
    let run = attempt_with(
        &cloud,
        |sent| {
            let mut d = Device::new(sent);
            d.reports_enrolled = false;
            d
        },
        opts(),
        tokio::time::sleep(Duration::from_secs(20)),
    )
    .await;
    assert_eq!(run.error(), "interrupted");
    let calls = cloud.calls();
    assert_eq!(
        calls[calls.len() - 3..],
        strings(&["poll", "disarm", &format!("delete {MAC}")])
    );
    assert!(cloud.polls.get() < 10);
    assert_eq!(run.verbs().last().unwrap(), "ERASE");
}

#[tokio::test(start_paused = true)]
async fn ctrl_c_before_arming_cleans_up_what_was_written() {
    let cloud = FakeCloud::default();
    let run = attempt_with(
        &cloud,
        |sent| {
            let mut d = Device::new(sent);
            d.deaf_for = 100;
            d
        },
        opts(),
        tokio::time::sleep(Duration::from_secs(10)),
    )
    .await;
    assert_eq!(run.error(), "interrupted");
    assert_eq!(cloud.calls(), strings(&["guard"]), "nothing to undo");
    assert!(run.verbs().iter().all(|v| v == "INFO"));
}

#[tokio::test(start_paused = true)]
async fn a_failed_disarm_prints_the_command_to_run() {
    let cloud = FakeCloud {
        disarm_fails: true,
        ..FakeCloud::default()
    };
    let run = attempt(&cloud, |_| {}).await;
    let command = format!(
        "aws iot update-certificate --certificate-id {CERT_ID} --new-status INACTIVE --region eu-central-1"
    );
    assert!(run.err.contains(&command), "{}", run.err);
    assert!(
        run.error()
            .contains("enrolled, but the claim is still ACTIVE"),
        "{}",
        run.error()
    );
    assert!(run.error().contains(&command));
}

#[tokio::test(start_paused = true)]
async fn approval_without_the_device_event_waits_the_grace_period() {
    let cloud = FakeCloud::default();
    let start = Instant::now();
    let run = attempt(&cloud, |d| d.reports_enrolled = false).await;
    assert_eq!(run.result.as_deref().unwrap(), THING);
    assert!(run.err.contains("did not report"), "{}", run.err);
    assert!(Instant::now() - start >= ENROLLED_GRACE);
    assert_eq!(cloud.calls().last().unwrap(), "disarm");
}

#[tokio::test(start_paused = true)]
async fn a_last_moment_enrolment_is_left_alone() {
    let cloud = FakeCloud {
        provisioned_from_poll: None,
        delete_result: Delete::Provisioned,
        ..FakeCloud::default()
    };
    let run = attempt(&cloud, |d| d.reports_enrolled = false).await;
    assert!(run.result.is_err());
    assert!(run.err.contains("enrolled after all"), "{}", run.err);
    assert_eq!(
        run.verbs().last().unwrap(),
        "ENROL",
        "an enrolled device keeps its Wi-Fi"
    );
}

#[tokio::test(start_paused = true)]
async fn an_invalid_value_is_refused_before_the_first_set() {
    let cloud = FakeCloud::default();
    let mut o = opts();
    o.wifi = Some(("home".into(), Secret::new("short".into())));
    let run = attempt_with(&cloud, Device::new, o, std::future::pending()).await;
    assert!(
        run.error().contains("wifi_psk is not valid"),
        "{}",
        run.error()
    );
    assert!(!run.error().contains("short\""));
    assert_eq!(run.verbs(), strings(&["INFO"]));
    assert_eq!(cloud.calls().last().unwrap(), &format!("delete {MAC}"));
}

#[tokio::test]
async fn register_writes_once_unless_overwriting() {
    let record = Record::new(
        &Mac::parse(MAC).unwrap(),
        "vaktus",
        &key1(),
        true,
        60,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    );
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut term = Term {
        out: &mut out,
        err: &mut err,
    };
    let cloud = FakeCloud::default();
    register(&cloud, &record, false, &mut term).await.unwrap();
    let exists = FakeCloud {
        exists: true,
        ..FakeCloud::default()
    };
    let e = register(&exists, &record, false, &mut term)
        .await
        .unwrap_err();
    assert!(e
        .to_string()
        .contains("already registered; use --reprovision"));
    register(&exists, &record, true, &mut term).await.unwrap();
    assert!(exists.put.borrow().as_ref().unwrap().1);
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("38:18:2B:84:56:F4 registered as product vaktus (canary)"));
    assert!(out.contains("2023-11-14T23:13:20Z"));
}
