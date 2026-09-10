//! Selected-node lifecycle mechanism observer; never customer API retention
//! qualification. Use a fresh private state directory and an explicitly
//! unprotected clean-team mission fixture. No network peers are configured.
//!
//! Required flag/value pairs: --state, --mission-bundle, --output, --mode,
//! --ttl-ms, --payload-bytes, --sample-every, --deadline-seconds, --topic,
//! --scope, --operation-prefix, --source-commit, --binary-sha256,
//! --config-sha256. Modes: small (requires --count 1..10000),
//! small-byte-capacity (requires --count 1..10000; durable byte-edge fixture),
//! The requested million-retired and candidate-capacity modes are disabled:
//! they retain a feasibility-failure receipt before state creation because
//! custody authority stops at 262,144 unique Events and this API cannot bind
//! aliases. Their requested limit identities remain separate in receipts.

use aster_node::{
    MutableSourceInterests, NodeApplication, NodeConfig, NodeOperatorOutputPolicy, RunningNode,
    SelectedForwardingConfig,
    application::{
        ApplicationErrorKind, EventPublishOptions, EventPublishRequest, Priority, Scope,
        SelectedEventHandle, Topic,
    },
    audit_store_event_operations,
    mission::UnprotectedReferenceMission,
    start_node_with_forwarding_and_output_policy,
};
use aster_redb_store::{EventOperationAuditState, EventOperationLimits, EventOperationStats};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs::{self, File, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::time::{sleep, timeout};

type Failure = Box<dyn Error + Send + Sync>;
type Result<T> = std::result::Result<T, Failure>;

fn unique_event_feasible(count: u64) -> bool {
    count <= aster_redb_store::MAX_CUSTODY_RETIREMENTS
}

#[derive(Debug)]
struct ObservedFailure {
    phase: &'static str,
    reason: &'static str,
}
impl std::fmt::Display for ObservedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.phase, self.reason)
    }
}
impl Error for ObservedFailure {}

fn safe_reason(error: &Failure) -> &'static str {
    if let Some(e) = error.downcast_ref::<ObservedFailure>() {
        return e.reason;
    }
    if let Some(e) = error.downcast_ref::<aster_node::application::ApplicationError>() {
        return match e.kind() {
            ApplicationErrorKind::OperationCapacity => "operation_capacity",
            ApplicationErrorKind::ResourceLimit => "resource_limit",
            ApplicationErrorKind::StateUnavailable => "state_unavailable",
            ApplicationErrorKind::Integrity => "integrity",
            ApplicationErrorKind::RequestRejected => "request_rejected",
            ApplicationErrorKind::UnauthorizedOrRevoked => "unauthorized_or_revoked",
            ApplicationErrorKind::Conflict => "operation_conflict",
            ApplicationErrorKind::ExpiredOrRetired => "expired_or_retired",
            ApplicationErrorKind::InvalidRequest => "invalid_request",
            ApplicationErrorKind::PolicyUnsettled => "policy_unsettled",
            ApplicationErrorKind::Provisioning => "provisioning",
            _ => "unknown_application_error",
        };
    }
    if error.is::<std::io::Error>() {
        return "io";
    }
    "state_unavailable"
}

fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok {
        return Ok(());
    }
    let reason = match reason {
        "exact retry changed durable result"
        | "exact replay changed original result"
        | "new operation replayed" => "unexpected_replay",
        "changed intent did not conflict" => "unexpected_conflict",
        "ordinary boundary not reached" | "first new key did not reject at capacity" => {
            "capacity_boundary"
        }
        "operation audit failed" => "integrity",
        _ => "invariant",
    };
    Err(ObservedFailure {
        phase: "validation",
        reason,
    }
    .into())
}

#[derive(Clone)]
struct Workload {
    mode: &'static str,
    ordinary: u64,
    limits: EventOperationLimits,
    finite: bool,
}
impl Workload {
    fn new(mode: &str, count: Option<u64>) -> Result<Self> {
        let (name, ordinary, records, bytes, reserve, finite) = match (mode, count) {
            ("small", Some(n @ 1..=10_000)) => ("small", n, n + 2, 201_326_592, 2, true),
            ("small-byte-capacity", Some(n @ 1..=10_000)) => {
                ("small-byte-capacity", n, n + 102, (n + 2) * 162, 2, false)
            }
            ("million-retired", None) => (
                "million-retired",
                1_000_000,
                1_010_000,
                201_326_592,
                10_000,
                true,
            ),
            ("candidate-capacity", None) => (
                "candidate-capacity",
                990_000,
                1_000_000,
                201_326_592,
                10_000,
                true,
            ),
            _ => return Err("invalid workload mode/count".into()),
        };
        Ok(Self {
            mode: name,
            ordinary,
            limits: EventOperationLimits::new(records, bytes, reserve)?,
            finite,
        })
    }
}

struct Options {
    state: PathBuf,
    mission: PathBuf,
    output: PathBuf,
    workload: Workload,
    ttl_ms: u64,
    payload_bytes: usize,
    sample_every: u64,
    deadline: Duration,
    topic: Topic,
    scope: Scope,
    prefix: String,
    commit: String,
    binary_hash: String,
    config_hash: String,
}

fn options(args: &[String]) -> Result<Options> {
    require(args.len().is_multiple_of(2), "invalid arguments")?;
    let mut fields = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        require(
            !pair[1].is_empty() && fields.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "invalid arguments",
        )?;
    }
    for key in fields.keys() {
        require(
            matches!(
                *key,
                "--state"
                    | "--mission-bundle"
                    | "--output"
                    | "--mode"
                    | "--count"
                    | "--ttl-ms"
                    | "--payload-bytes"
                    | "--sample-every"
                    | "--deadline-seconds"
                    | "--topic"
                    | "--scope"
                    | "--operation-prefix"
                    | "--source-commit"
                    | "--binary-sha256"
                    | "--config-sha256"
            ),
            "unknown argument",
        )?;
    }
    let get = |key| {
        fields
            .get(key)
            .copied()
            .ok_or_else(|| Failure::from("missing argument"))
    };
    let number = |key, max| -> Result<u64> {
        let value: u64 = get(key)?.parse()?;
        require(value > 0 && value <= max, "argument out of bounds")?;
        Ok(value)
    };
    let workload = Workload::new(
        get("--mode")?,
        fields.get("--count").map(|v| v.parse()).transpose()?,
    )?;
    let prefix = get("--operation-prefix")?;
    require(
        prefix.len() <= 128
            && prefix
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-_.".contains(&v)),
        "invalid operation prefix",
    )?;
    for (name, length) in [
        ("--source-commit", 40),
        ("--binary-sha256", 64),
        ("--config-sha256", 64),
    ] {
        let value = get(name)?;
        require(
            value.len() == length
                && value
                    .bytes()
                    .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v)),
            "invalid provenance digest",
        )?;
    }
    let state = PathBuf::from(get("--state")?);
    let mission = PathBuf::from(get("--mission-bundle")?);
    let output = PathBuf::from(get("--output")?);
    require(
        [&state, &mission, &output].iter().all(|p| p.is_absolute())
            && output != mission
            && output != state
            && state != mission,
        "invalid path",
    )?;
    Ok(Options {
        state,
        mission,
        output,
        workload,
        ttl_ms: number("--ttl-ms", 60_000)?,
        payload_bytes: number("--payload-bytes", 65_536)? as usize,
        sample_every: number("--sample-every", 1_000_000)?,
        deadline: Duration::from_secs(number("--deadline-seconds", 604_800)?),
        topic: Topic::new(get("--topic")?)?,
        scope: Scope::new(get("--scope")?)?,
        prefix: prefix.into(),
        commit: get("--source-commit")?.into(),
        binary_hash: get("--binary-sha256")?.into(),
        config_hash: get("--config-sha256")?.into(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn operation_key(prefix: &str, index: u64) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"aster/ledger-scale/key/v1\0");
    h.update((prefix.len() as u16).to_be_bytes());
    h.update(prefix.as_bytes());
    h.update(index.to_be_bytes());
    h.finalize().to_vec()
}

fn publication(o: &Options, index: u64, tombstone: bool) -> EventPublishRequest {
    EventPublishRequest {
        operation_key: operation_key(&o.prefix, index),
        predecessor: None,
        topic: o.topic.clone(),
        scope: o.scope.clone(),
        priority: Priority::Routine,
        logical_key: b"ledger-scale/v1".to_vec(),
        payload: if tombstone {
            Vec::new()
        } else {
            vec![0x61; o.payload_bytes]
        },
        tombstone,
    }
}
fn changed_publication(o: &Options, index: u64) -> EventPublishRequest {
    let mut p = publication(o, index, false);
    p.payload[0] ^= 1;
    p
}
fn same_publication(
    original: &aster_node::application::EventPublishResult,
    replay: &aster_node::application::EventPublishResult,
) -> bool {
    let mut expected = original.clone();
    expected.inserted = false;
    expected == *replay
}
fn lifetime(o: &Options) -> Result<EventPublishOptions> {
    Ok(if o.workload.finite {
        EventPublishOptions::finite_ttl_ms(o.ttl_ms)?
    } else {
        EventPublishOptions::durable()
    })
}

// At most four indices and four original results are retained. SplitMix's integer
// mixing is for reproducible sampling only, not randomness or cryptography.
fn samples(n: u64) -> Vec<u64> {
    if n == 0 {
        return Vec::new();
    }
    let mut z = n.wrapping_add(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
    z ^= z >> 31;
    let mut selected = vec![0, n / 2, n - 1, z % n];
    selected.sort_unstable();
    selected.dedup();
    selected
}

#[derive(Default)]
struct Receipt {
    originals: BTreeMap<u64, aster_node::application::EventPublishResult>,
    started_ms: u128,
    ended_ms: u128,
    elapsed_ms: u128,
    startup_ms: u128,
    shutdown_ms: u128,
    created: u64,
    retired: u64,
    exact_active: u64,
    exact_result_matches: u64,
    exact_retired: u64,
    conflicts: u64,
    capacity_rejected: u64,
    emergency_accepted: u64,
    final_stats: EventOperationStats,
    restarted: bool,
    restart_ms: u128,
    audit_complete: bool,
    audit_ms: u128,
    audit_scanned: u64,
    status_samples: u64,
    status_max_us: u128,
    failure: &'static str,
    phase: &'static str,
}

impl Receipt {
    // Every interpolated string below is a fixed enum label or lowercase hex.
    // No user text, IDs, paths, payloads, or operation bytes enter this encoder.
    fn json(&self, o: &Options) -> String {
        let config = format!(
            "{{\"mode\":\"{}\",\"ordinary_target\":{},\"record_limit\":{},\"byte_limit\":{},\"emergency_reserve\":{},\"finite_ttl\":{},\"ttl_ms\":{},\"payload_bytes\":{},\"sample_every\":{},\"deadline_seconds\":{},\"topic_sha256\":\"{}\",\"scope_sha256\":\"{}\",\"operation_prefix_sha256\":\"{}\"}}",
            o.workload.mode,
            o.workload.ordinary,
            o.workload.limits.max_records(),
            o.workload.limits.max_logical_bytes(),
            o.workload.limits.emergency_reserve(),
            o.workload.finite,
            o.ttl_ms,
            o.payload_bytes,
            o.sample_every,
            o.deadline.as_secs(),
            digest(o.topic.as_str().as_bytes()),
            digest(o.scope.as_str().as_bytes()),
            digest(o.prefix.as_bytes())
        );
        format!(
            concat!(
                "{{\"schema\":\"aster-event-operation-ledger-scale/v1\",\"claim\":\"selected-rust-node-mechanism-observation\",\"qualification\":false,",
                "\"customer_api_retention\":\"unavailable_public_rpc_has_no_ttl\",\"provisioning\":\"unprotected_clean_team_fixture\",",
                "\"alias_64_65\":\"unavailable_selected_api_has_no_alias_binding\",\"key_algorithm\":\"sha256:aster/ledger-scale/key/v1:u16be-prefix-length:prefix:u64be-index\",",
                "\"sampling\":\"at_most_four_original_results_at_planned_early_middle_late_splitmix64_indices\",\"custody_unique_event_ceiling\":262144,\"long_unique_event_lifetimes\":\"blocked_7d_at_1hz_and_2d_at_5hz\",\"source_commit_supplied\":\"{}\",\"binary_sha256_supplied\":\"{}\",\"config_sha256_supplied\":\"{}\",",
                "\"workload\":{},\"workload_sha256\":\"{}\",\"started_unix_ms\":{},\"ended_unix_ms\":{},\"elapsed_ms\":{},\"startup_ms\":{},\"shutdown_ms\":{},\"failure\":\"{}\",\"failure_phase\":\"{}\",\"request_disposition\":\"{}\",\"ledger_counts_observation\":\"last_successful_status\",",
                "\"created_ordinary\":{},\"retired_ordinary\":{},\"exact_active_probes\":{},\"exact_retired_probes\":{},\"exact_full_result_matches\":{},\"changed_intent_conflicts\":{},\"first_new_key_rejections\":{},\"emergency_tombstones_accepted\":{},",
                "\"records_total\":{},\"records_active\":{},\"records_retired\":{},\"reverse_rows\":{},\"logical_bytes\":{},",
                "\"clean_restart\":{},\"restart_ms\":{},\"offline_audit_complete\":{},\"audit_ms\":{},\"audit_scanned\":{},\"status_samples\":{},\"status_max_us\":{}}}\n"
            ),
            o.commit,
            o.binary_hash,
            o.config_hash,
            config,
            digest(config.as_bytes()),
            self.started_ms,
            self.ended_ms,
            self.elapsed_ms,
            self.startup_ms,
            self.shutdown_ms,
            self.failure,
            self.phase,
            if self.phase == "feasibility" {
                "not_started_feasibility_blocked"
            } else if self.failure == "none" {
                "observation_completed"
            } else {
                "observation_failed"
            },
            self.created,
            self.retired,
            self.exact_active,
            self.exact_retired,
            self.exact_result_matches,
            self.conflicts,
            self.capacity_rejected,
            self.emergency_accepted,
            self.final_stats.records_total,
            self.final_stats.records_active,
            self.final_stats.records_retired,
            self.final_stats.reverse_rows,
            self.final_stats.logical_bytes,
            self.restarted,
            self.restart_ms,
            self.audit_complete,
            self.audit_ms,
            self.audit_scanned,
            self.status_samples,
            self.status_max_us
        )
    }
}

async fn sample_status(
    events: &SelectedEventHandle,
    r: &mut Receipt,
) -> Result<aster_node::application::SelectedEventStatus> {
    let began = Instant::now();
    let status = events.status().await?;
    r.status_samples += 1;
    r.status_max_us = r.status_max_us.max(began.elapsed().as_micros());
    require(
        status.event_operation_audit.state != EventOperationAuditState::Failed,
        "operation audit failed",
    )?;
    r.final_stats = status.event_operation_capacity.stats;
    r.retired = r.final_stats.records_retired;
    Ok(status)
}

async fn probe(
    events: &SelectedEventHandle,
    o: &Options,
    n: u64,
    r: &mut Receipt,
    retired: bool,
) -> Result<()> {
    let before = sample_status(events, r)
        .await?
        .event_operation_capacity
        .stats
        .records_total;
    for (i, original) in r.originals.clone().into_iter().filter(|(i, _)| *i < n) {
        match events
            .publish_with_options(publication(o, i, false), lifetime(o)?)
            .await
        {
            Ok(value) => {
                require(
                    !retired && same_publication(&original, &value),
                    "exact retry changed durable result",
                )?;
                r.exact_active += 1;
                r.exact_result_matches += 1;
            }
            Err(e) if o.workload.finite && e.kind() == ApplicationErrorKind::ExpiredOrRetired => {
                r.exact_retired += 1;
            }
            Err(e) => return Err(e.into()),
        }
        let changed = events
            .publish_with_options(changed_publication(o, i), lifetime(o)?)
            .await;
        require(
            changed.is_err_and(|e| e.kind() == ApplicationErrorKind::Conflict),
            "changed intent did not conflict",
        )?;
        r.conflicts += 1;
    }
    require(
        sample_status(events, r)
            .await?
            .event_operation_capacity
            .stats
            .records_total
            == before,
        "probes created operations",
    )
}

async fn start(o: &Options) -> Result<RunningNode> {
    Ok(start_node_with_forwarding_and_output_policy(
        NodeConfig {
            state: o.state.clone(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            mission: UnprotectedReferenceMission::load(&o.mission).map_err(|_| {
                ObservedFailure {
                    phase: "startup",
                    reason: "provisioning",
                }
            })?,
            peers: Vec::new(),
            mutable_interests: MutableSourceInterests::default(),
            sync_interval: Duration::from_secs(300),
            run_for: None,
            application: NodeApplication::Relay,
        },
        SelectedForwardingConfig::default().with_operation_limits(o.workload.limits),
        NodeOperatorOutputPolicy::CustomerSafe,
    )
    .await?)
}

async fn exercise(events: &SelectedEventHandle, o: &Options, r: &mut Receipt) -> Result<()> {
    require(
        sample_status(events, r)
            .await?
            .event_operation_capacity
            .stats
            .records_total
            == 0,
        "state is not fresh",
    )?;
    let selected = samples(o.workload.ordinary);
    for i in 0..o.workload.ordinary {
        r.phase = "publication";
        let published = events
            .publish_with_options(publication(o, i, false), lifetime(o)?)
            .await?;
        require(published.inserted, "new operation replayed")?;
        r.created += 1;
        if selected.contains(&i) {
            r.originals.insert(i, published.clone());
        }
        if r.created.is_multiple_of(o.sample_every) || r.created == o.workload.ordinary {
            r.phase = "probe";
            match events
                .publish_with_options(publication(o, i, false), lifetime(o)?)
                .await
            {
                Ok(replay) => {
                    require(
                        same_publication(&published, &replay),
                        "exact replay changed original result",
                    )?;
                    r.exact_result_matches += 1;
                }
                Err(e)
                    if o.workload.finite && e.kind() == ApplicationErrorKind::ExpiredOrRetired =>
                {
                    r.exact_retired += 1;
                }
                Err(e) => return Err(e.into()),
            }
            probe(events, o, r.created, r, false).await?;
        }
    }
    r.phase = "capacity";
    require(
        sample_status(events, r)
            .await?
            .event_operation_capacity
            .ordinary_remaining
            == 0,
        "ordinary boundary not reached",
    )?;
    let rejected = events
        .publish_with_options(publication(o, o.workload.ordinary, false), lifetime(o)?)
        .await;
    require(
        rejected.is_err_and(|e| e.kind() == ApplicationErrorKind::OperationCapacity),
        "first new key did not reject at capacity",
    )?;
    r.capacity_rejected = 1;
    let emergency = events
        .publish(publication(o, o.workload.ordinary + 1, true))
        .await?;
    require(
        emergency.inserted,
        "emergency tombstone was not newly accepted",
    )?;
    r.emergency_accepted = 1;
    if o.workload.finite {
        r.phase = "retirement";
        loop {
            let stats = sample_status(events, r)
                .await?
                .event_operation_capacity
                .stats;
            if stats.records_retired == r.created {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
    r.phase = "probe";
    probe(events, o, r.created, r, o.workload.finite).await?;
    require(
        r.final_stats.records_total == r.created + 1,
        "unexpected ledger growth",
    )
}

fn unix_ms() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

async fn run_workload(o: &Options) -> Result<Receipt> {
    let began = Instant::now();
    let wall_start = unix_ms();
    let mut r = Receipt {
        started_ms: wall_start.as_ref().copied().unwrap_or(0),
        failure: "none",
        phase: "preflight",
        ..Default::default()
    };
    if wall_start.is_err() {
        r.phase = "clock";
        r.failure = "wall_clock_unavailable";
        return finish_observation(r, began);
    }
    // Do not create state or load provisioning for a known impossible run.
    if !unique_event_feasible(o.workload.ordinary) {
        r.phase = "feasibility";
        r.failure = "custody_ceiling_alias_unavailable";
        return finish_observation(r, began);
    }
    let preflight = (|| -> Result<()> {
        private_directory(o.state.parent().ok_or("invalid state")?)?;
        if !fs::symlink_metadata(&o.state).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            return Err(ObservedFailure {
                phase: "preflight",
                reason: "state_exists",
            }
            .into());
        }
        fs::DirBuilder::new().mode(0o700).create(&o.state)?;
        Ok(())
    })();
    if let Err(e) = preflight {
        r.failure = safe_reason(&e);
        return finish_observation(r, began);
    }
    r.phase = "startup";
    let startup = Instant::now();
    let started = start(o).await;
    r.startup_ms = startup.elapsed().as_millis();
    let running = match started {
        Ok(node) => node,
        Err(e) => {
            r.failure = safe_reason(&e);
            return finish_observation(r, began);
        }
    };
    let events = running.selected_events();
    match timeout(o.deadline, exercise(&events, o, &mut r)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => r.failure = safe_reason(&e),
        Err(_) => r.failure = "workload_deadline",
    }
    drop(events);
    let shutdown = Instant::now();
    if let Err(e) = running.shutdown().await {
        r.phase = "shutdown";
        r.failure = safe_reason(&e.into());
    }
    r.shutdown_ms = shutdown.elapsed().as_millis();
    if r.failure == "none" {
        r.phase = "restart";
        let restart = Instant::now();
        match start(o).await {
            Ok(reopened) => {
                r.restart_ms = restart.elapsed().as_millis();
                r.phase = "restart_probe";
                let events = reopened.selected_events();
                match timeout(
                    Duration::from_secs(30),
                    probe(&events, o, r.created, &mut r, o.workload.finite),
                )
                .await
                {
                    Ok(Ok(())) => r.restarted = true,
                    Ok(Err(e)) => r.failure = safe_reason(&e),
                    Err(_) => r.failure = "deadline",
                }
                drop(events);
                if reopened.shutdown().await.is_err() {
                    r.phase = "restart_shutdown";
                    r.failure = "state_unavailable";
                }
            }
            Err(e) => {
                r.restart_ms = restart.elapsed().as_millis();
                r.failure = safe_reason(&e);
            }
        }
    }
    if r.failure == "none" {
        r.phase = "offline_audit";
        let audit = Instant::now();
        match audit_store_event_operations(&o.state) {
            Ok(p) => {
                r.audit_scanned = p.scanned;
                r.audit_complete = p.scanned == p.total;
                if !r.audit_complete {
                    r.failure = "integrity";
                }
            }
            Err(_) => r.failure = "integrity",
        };
        r.audit_ms = audit.elapsed().as_millis();
    }
    if r.failure == "none" {
        r.phase = "complete";
    }
    finish_observation(r, began)
}

fn finish_observation(mut r: Receipt, began: Instant) -> Result<Receipt> {
    match unix_ms() {
        Ok(value) => r.ended_ms = value,
        Err(_) => {
            if r.failure == "none" {
                r.phase = "clock";
                r.failure = "wall_clock_unavailable";
            }
        }
    }
    r.elapsed_ms = began.elapsed().as_millis();
    Ok(r)
}

struct AtomicOutput {
    file: File,
    temporary: PathBuf,
    destination: PathBuf,
    directory: fs::Metadata,
}
impl AtomicOutput {
    fn prepare(path: &Path) -> Result<Self> {
        let parent = path.parent().ok_or("invalid output")?;
        private_directory(parent)?;
        require(
            fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "output already exists",
        )?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce)?;
        let temporary = parent.join(format!(".ledger-scale-{}.tmp", hex(&nonce)));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        Ok(Self {
            file,
            temporary,
            destination: path.to_path_buf(),
            directory: fs::symlink_metadata(parent)?,
        })
    }
    fn valid_stage(&self) -> Result<()> {
        let parent = self.destination.parent().ok_or("invalid output")?;
        private_directory(parent)?;
        let directory = fs::symlink_metadata(parent)?;
        require(
            directory.dev() == self.directory.dev() && directory.ino() == self.directory.ino(),
            "output directory changed",
        )?;
        let opened = self.file.metadata()?;
        let named = fs::symlink_metadata(&self.temporary)?;
        require(
            named.is_file()
                && named.mode() & 0o777 == 0o600
                && named.uid() == rustix::process::geteuid().as_raw()
                && named.nlink() == 1
                && opened.dev() == named.dev()
                && opened.ino() == named.ino(),
            "output staging changed",
        )
    }
    fn finish(&mut self, bytes: &[u8]) -> Result<()> {
        self.valid_stage()?;
        self.file.write_all(bytes)?;
        self.file.sync_all()?;
        self.valid_stage()?;
        fs::hard_link(&self.temporary, &self.destination)?;
        fs::remove_file(&self.temporary)?;
        File::open(self.destination.parent().ok_or("invalid output")?)?.sync_all()?;
        Ok(())
    }
}
impl Drop for AtomicOutput {
    fn drop(&mut self) {
        if self.valid_stage().is_ok() {
            let _ = fs::remove_file(&self.temporary);
        }
    }
}
fn private_directory(path: &Path) -> Result<()> {
    require(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "directory must be canonical",
    )?;
    let m = fs::symlink_metadata(path)?;
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        let sticky_tmp =
            ancestor == Path::new("/tmp") && metadata.uid() == 0 && metadata.mode() & 0o1000 != 0;
        require(
            metadata.is_dir()
                && (metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw())
                && (metadata.mode() & 0o022 == 0 || sticky_tmp),
            "unsafe writable directory ancestor",
        )?;
    }
    // rustix's safe wrapper provides the process uid without unsafe code.
    require(
        m.is_dir() && m.mode() & 0o077 == 0 && m.uid() == rustix::process::geteuid().as_raw(),
        "directory must be private and owned",
    )
}

async fn run(args: &[String]) -> Result<()> {
    let o = options(args).map_err(|_| ObservedFailure {
        phase: "arguments",
        reason: "invalid_arguments",
    })?;
    let mut output = AtomicOutput::prepare(&o.output).map_err(|_| ObservedFailure {
        phase: "output",
        reason: "invalid_output",
    })?;
    let receipt = run_workload(&o).await?;
    persist_receipt(&mut output, &receipt, &o)?;
    if receipt.failure != "none" {
        return Err(ObservedFailure {
            phase: receipt.phase,
            reason: receipt.failure,
        }
        .into());
    }
    Ok(())
}

fn persist_receipt(output: &mut AtomicOutput, receipt: &Receipt, o: &Options) -> Result<()> {
    output.finish(receipt.json(o).as_bytes()).map_err(|_| {
        ObservedFailure {
            phase: "output",
            reason: "output_commit_failed",
        }
        .into()
    })
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run(&env::args().skip(1).collect::<Vec<_>>()).await {
        let phase = error
            .downcast_ref::<ObservedFailure>()
            .map_or("observation", |e| e.phase);
        eprintln!(
            "{{\"status\":\"error\",\"phase\":\"{}\",\"reason\":\"{}\"}}",
            phase,
            safe_reason(&error)
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_receipt_write_error_is_safe_typed_and_never_partial() {
        let root = TestRoot::new();
        let o = fixture_options(&root.0);
        let mut output = AtomicOutput::prepare(&o.output).unwrap();
        output.file = File::open(&output.temporary).unwrap();
        let r = Receipt {
            failure: "provisioning",
            phase: "startup",
            ..Default::default()
        };
        let error = persist_receipt(&mut output, &r, &o).unwrap_err();
        let safe = error.downcast_ref::<ObservedFailure>().unwrap();
        assert_eq!(safe.phase, "output");
        assert_eq!(safe.reason, "output_commit_failed");
        assert!(!o.output.exists());
        assert!(!error.to_string().contains(root.0.to_str().unwrap()));
    }

    #[test]
    fn unique_event_lifetime_feasibility_rejects_custody_ceiling() {
        assert!(unique_event_feasible(262_144));
        for count in [262_145, 604_800, 864_000, 990_000, 1_000_000] {
            assert!(!unique_event_feasible(count));
        }
    }

    #[tokio::test]
    async fn startup_failure_and_large_mode_blocker_have_atomic_receipts() {
        for mode in ["small", "candidate-capacity", "million-retired"] {
            let root = TestRoot::new();
            let mut o = fixture_options(&root.0);
            if mode != "small" {
                o.workload = Workload::new(mode, None).unwrap();
            }
            assert!(run(&cli_args(&o)).await.is_err());
            let receipt = fs::read_to_string(&o.output).expect("failure receipt missing");
            assert!(receipt.contains("\"qualification\":false"));
            if mode == "small" {
                assert!(receipt.contains("\"failure_phase\":\"startup\""));
                assert!(receipt.contains("\"failure\":\"provisioning\""));
            } else {
                assert!(receipt.contains("\"failure\":\"custody_ceiling_alias_unavailable\""));
                assert!(!o.state.exists());
            }
            assert!(!receipt.contains(o.mission.to_str().unwrap()));
        }
    }

    #[tokio::test]
    async fn workload_failure_receipt_distinguishes_policy_rejection() {
        let root = TestRoot::new();
        let mut o = fixture_options(&root.0);
        provision(&o);
        o.topic = Topic::new("unprovisioned.topic").unwrap();
        assert!(run(&cli_args(&o)).await.is_err());
        let receipt = fs::read_to_string(&o.output).unwrap();
        assert!(receipt.contains("\"failure_phase\":\"publication\""));
        assert!(receipt.contains("\"failure\":\"request_rejected\""));
    }

    #[tokio::test]
    async fn older_active_probe_rejects_changed_original_result() {
        let root = TestRoot::new();
        let mut o = fixture_options(&root.0);
        o.workload = Workload::new("small-byte-capacity", Some(4)).unwrap();
        provision(&o);
        fs::DirBuilder::new().mode(0o700).create(&o.state).unwrap();
        let running = start(&o).await.unwrap();
        let events = running.selected_events();
        let mut original = events.publish(publication(&o, 0, false)).await.unwrap();
        original.acceptance_marker += 1;
        let mut r = Receipt::default();
        r.originals.insert(0, original);
        let result = probe(&events, &o, 1, &mut r, false).await;
        drop(events);
        running.shutdown().await.unwrap();
        assert!(
            result.is_err(),
            "older active replay accepted a changed marker"
        );
    }

    fn cli_args(o: &Options) -> Vec<String> {
        let pairs = [
            ("--state", o.state.to_str().unwrap().to_owned()),
            ("--mission-bundle", o.mission.to_str().unwrap().to_owned()),
            ("--output", o.output.to_str().unwrap().to_owned()),
            ("--mode", o.workload.mode.into()),
            ("--ttl-ms", o.ttl_ms.to_string()),
            ("--payload-bytes", o.payload_bytes.to_string()),
            ("--sample-every", o.sample_every.to_string()),
            ("--deadline-seconds", o.deadline.as_secs().to_string()),
            ("--topic", o.topic.as_str().into()),
            ("--scope", o.scope.as_str().into()),
            ("--operation-prefix", o.prefix.clone()),
            ("--source-commit", o.commit.clone()),
            ("--binary-sha256", o.binary_hash.clone()),
            ("--config-sha256", o.config_hash.clone()),
        ];
        let mut args = pairs
            .into_iter()
            .flat_map(|(k, v)| [k.into(), v])
            .collect::<Vec<_>>();
        if o.workload.mode.starts_with("small") {
            args.extend(["--count".into(), o.workload.ordinary.to_string()]);
        }
        args
    }

    #[tokio::test]
    async fn selected_api_same_intent_new_keys_create_distinct_events_not_aliases() {
        let root = TestRoot::new();
        let mut o = fixture_options(&root.0);
        o.ttl_ms = 60_000;
        o.workload.limits = EventOperationLimits::new(512, 201_326_592, 2).unwrap();
        provision(&o);
        fs::DirBuilder::new().mode(0o700).create(&o.state).unwrap();
        let running = start(&o).await.unwrap();
        let events = running.selected_events();
        let first = events
            .publish_with_options(publication(&o, 0, false), lifetime(&o).unwrap())
            .await
            .unwrap();
        let second = events
            .publish_with_options(publication(&o, 1, false), lifetime(&o).unwrap())
            .await
            .unwrap();
        let status = events.status().await.unwrap();
        drop(events);
        running.shutdown().await.unwrap();
        assert!(first.inserted && second.inserted);
        assert!(first.id != second.id);
        assert_eq!(status.event_operation_capacity.stats.records_total, 2);
    }

    #[test]
    fn output_rejects_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = TestRoot::new();
        let child = root.0.join("private");
        fs::DirBuilder::new().mode(0o700).create(&child).unwrap();
        fs::set_permissions(&root.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(AtomicOutput::prepare(&child.join("receipt.json")).is_err());
    }

    #[test]
    fn output_rejects_staging_substitution() {
        let root = TestRoot::new();
        let destination = root.0.join("receipt.json");
        let mut out = AtomicOutput::prepare(&destination).unwrap();
        fs::rename(&out.temporary, root.0.join("old.tmp")).unwrap();
        std::os::unix::fs::symlink("target", &out.temporary).unwrap();
        assert!(out.finish(b"{}").is_err());
        assert!(!destination.exists());
    }

    #[test]
    fn output_rejects_swapped_parent_directory() {
        let root = TestRoot::new();
        let child = root.0.join("private");
        fs::DirBuilder::new().mode(0o700).create(&child).unwrap();
        let mut out = AtomicOutput::prepare(&child.join("receipt.json")).unwrap();
        fs::rename(&child, root.0.join("old")).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&child).unwrap();
        fs::write(&out.temporary, b"substitution").unwrap();
        assert!(out.finish(b"{}").is_err());
    }

    #[test]
    fn replay_evidence_requires_every_original_result_field() {
        use aster_node::application::{EventId, EventPublishResult};
        let original = EventPublishResult {
            id: EventId::from_bytes([1; 32]),
            publisher: [2; 32],
            publisher_counter: 3,
            event_sequence: 4,
            priority: Priority::Routine,
            ttl_ms: Some(5),
            acceptance_marker: 6,
            inserted: true,
        };
        let mut replay = original.clone();
        replay.inserted = false;
        assert!(same_publication(&original, &replay));
        for field in 0..8 {
            let mut changed = replay.clone();
            match field {
                0 => changed.id = EventId::from_bytes([9; 32]),
                1 => changed.publisher = [9; 32],
                2 => changed.publisher_counter += 1,
                3 => changed.event_sequence += 1,
                4 => changed.priority = Priority::Flash,
                5 => changed.ttl_ms = None,
                6 => changed.acceptance_marker += 1,
                _ => changed.inserted = true,
            }
            assert!(
                !same_publication(&original, &changed),
                "changed replay field accepted"
            );
        }
    }

    #[test]
    fn arguments_reject_colliding_paths_and_invalid_or_conflicting_limits() {
        let base = [
            "--state",
            "/private/state",
            "--mission-bundle",
            "/private/mission",
            "--output",
            "/private/result.json",
            "--mode",
            "small",
            "--count",
            "6",
            "--ttl-ms",
            "1",
            "--payload-bytes",
            "256",
            "--sample-every",
            "3",
            "--deadline-seconds",
            "20",
            "--topic",
            "load.events",
            "--scope",
            "test/load",
            "--operation-prefix",
            "fixture",
            "--source-commit",
            &"a".repeat(40),
            "--binary-sha256",
            &"b".repeat(64),
            "--config-sha256",
            &"c".repeat(64),
        ]
        .map(String::from)
        .to_vec();
        assert!(options(&base).is_ok());
        for (flag, value) in [
            ("--output", "/private/state"),
            ("--state", "/private/mission"),
            ("--ttl-ms", "0"),
            ("--ttl-ms", "60001"),
            ("--sample-every", "0"),
            ("--payload-bytes", "65537"),
            ("--count", "18446744073709551616"),
            ("--deadline-seconds", "0"),
            ("--mode", "candidate-capacity"),
            ("--source-commit", "secret"),
            ("--operation-prefix", "invalid prefix"),
        ] {
            let mut args = base.clone();
            let i = args.iter().position(|v| v == flag).unwrap();
            args[i + 1] = value.into();
            assert!(
                options(&args).is_err(),
                "invalid arguments accepted: {flag}"
            );
        }
        let mut duplicate = base.clone();
        duplicate.extend(["--count".into(), "6".into()]);
        assert!(options(&duplicate).is_err());
    }

    #[test]
    fn modes_keep_million_retirement_separate_from_candidate_capacity() {
        let million = Workload::new("million-retired", None).unwrap();
        assert_eq!(million.ordinary, 1_000_000);
        assert_eq!(million.limits.max_records(), 1_010_000);
        assert_eq!(million.limits.emergency_reserve(), 10_000);
        let candidate = Workload::new("candidate-capacity", None).unwrap();
        assert_eq!(candidate.ordinary, 990_000);
        assert_eq!(candidate.limits, EventOperationLimits::DEFAULT);
        assert!(Workload::new("million-retired", Some(5)).is_err());
        assert!(Workload::new("small", Some(0)).is_err());
        assert!(Workload::new("small", Some(10_001)).is_err());
        assert!(Workload::new("unknown", None).is_err());
    }

    #[test]
    fn deterministic_sampling_is_unique_bounded_and_covers_age_ranges() {
        assert_eq!(samples(1), vec![0]);
        for n in [2, 3, 10, 10_000, 1_000_000] {
            let s = samples(n);
            assert!(s.len() <= 4);
            assert!(s.contains(&0) && s.contains(&(n / 2)) && s.contains(&(n - 1)));
            assert!(s.iter().all(|i| *i < n));
            assert!(s.windows(2).all(|w| w[0] < w[1]));
            assert_eq!(s, samples(n));
        }
    }

    #[test]
    fn derivation_preserves_intent_and_separates_keys_and_changed_probes() {
        let o = fixture_options(std::path::Path::new("/unused"));
        let original = publication(&o, 7, false);
        let retry = publication(&o, 7, false);
        assert_eq!(original, retry);
        assert_ne!(
            original.operation_key,
            publication(&o, 8, false).operation_key
        );
        assert_eq!(original.operation_key.len(), 32);
        assert_eq!(original.payload.len(), 256);
        assert_eq!(original.topic, Topic::new("load.events").unwrap());
        assert_eq!(original.scope, Scope::new("test/load").unwrap());
        let changed = changed_publication(&o, 7);
        assert_eq!(original.operation_key, changed.operation_key);
        assert_ne!(original.payload, changed.payload);
        let emergency = publication(&o, 8, true);
        assert!(emergency.tombstone && emergency.payload.is_empty());
    }

    #[test]
    fn output_never_replaces_existing_or_exposes_partial_receipt() {
        let root = TestRoot::new();
        let path = root.0.join("receipt.json");
        let mut output = AtomicOutput::prepare(&path).unwrap();
        assert!(!path.exists());
        std::fs::write(&path, b"prior").unwrap();
        assert!(output.finish(b"new").is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"prior");
        assert!(AtomicOutput::prepare(&path).is_err());
        let path2 = root.0.join("complete.json");
        AtomicOutput::prepare(&path2)
            .unwrap()
            .finish(b"{}\n")
            .unwrap();
        assert_eq!(std::fs::read(path2).unwrap(), b"{}\n");
    }

    #[tokio::test]
    async fn selected_api_small_retirement_capacity_restart_and_audit() {
        // A skipped custody pass, forgotten conflict probe, or capacity/restart
        // result counted without checking it fails this real selected-node run.
        let root = TestRoot::new();
        let o = fixture_options(&root.0);
        provision(&o);
        let r = run_workload(&o).await.unwrap();
        assert_eq!(r.created, 6);
        assert_eq!(r.retired, 6);
        assert_eq!(r.emergency_accepted, 1);
        assert_eq!(r.capacity_rejected, 1);
        assert_eq!(r.final_stats.records_total, 7);
        assert_eq!(r.final_stats.records_active, 1);
        assert_eq!(r.final_stats.records_retired, 6);
        assert!(r.exact_retired > 0 && r.conflicts > 0);
        assert!(r.restarted && r.audit_complete);
        assert_eq!(r.audit_scanned, 8);
        let encoded = r.json(&o);
        assert!(encoded.starts_with("{\"schema\":\"aster-event-operation-ledger-scale/v1\""));
        for secret in [
            o.prefix.as_str(),
            o.state.to_str().unwrap(),
            o.mission.to_str().unwrap(),
            "test/load",
            "load.events",
        ] {
            assert!(!encoded.contains(secret), "unsanitized input in receipt");
        }
        assert!(encoded.contains("\"qualification\":false"));
        assert!(
            encoded.contains("\"alias_64_65\":\"unavailable_selected_api_has_no_alias_binding\"")
        );
        assert!(!encoded.contains(&hex(&operation_key(&o.prefix, 0))));
        assert_eq!(encoded, r.json(&o));
        println!("{encoded}");
    }

    #[tokio::test]
    async fn selected_api_byte_boundary_uses_durable_rows_and_emergency_bytes() {
        let root = TestRoot::new();
        let mut o = fixture_options(&root.0);
        o.workload = Workload::new("small-byte-capacity", Some(4)).unwrap();
        provision(&o);
        let r = run_workload(&o).await.unwrap();
        assert_eq!(r.failure, "none");
        assert_eq!(r.created, 4);
        assert_eq!(r.retired, 0);
        assert_eq!(r.capacity_rejected, 1);
        assert_eq!(r.emergency_accepted, 1);
        assert_eq!(r.final_stats.logical_bytes, 810);
        assert_eq!(r.final_stats.records_active, 5);
        assert!(r.exact_result_matches > 0);
        assert!(r.restarted && r.audit_complete);
    }

    #[tokio::test]
    async fn deadline_retains_failed_observation_and_does_not_claim_restart_or_audit() {
        let root = TestRoot::new();
        let mut o = fixture_options(&root.0);
        o.ttl_ms = 60_000;
        o.deadline = Duration::from_millis(100);
        provision(&o);
        let r = run_workload(&o).await.unwrap();
        assert_eq!(r.failure, "workload_deadline");
        assert!(!r.restarted && !r.audit_complete);
        assert!(r.created <= 6);
        assert_eq!(r.retired, 0);
    }

    fn fixture_options(root: &std::path::Path) -> Options {
        Options {
            state: root.join("state"),
            mission: root.join("mission.bundle"),
            output: root.join("receipt.json"),
            workload: Workload::new("small", Some(6)).unwrap(),
            ttl_ms: 1,
            payload_bytes: 256,
            sample_every: 3,
            deadline: Duration::from_secs(20),
            topic: Topic::new("load.events").unwrap(),
            scope: Scope::new("test/load").unwrap(),
            prefix: "PRIVATE_OPERATION_PREFIX".into(),
            commit: "a".repeat(40),
            binary_hash: "b".repeat(64),
            config_hash: "c".repeat(64),
        }
    }

    fn provision(o: &Options) {
        use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
        let access =
            ProvisioningAccess::member(o.scope.clone(), vec![1], vec![o.topic.clone()]).unwrap();
        let mut p = ReferenceProvisioner::from_seed([0x73; 32]).unwrap();
        let bytes = p.issue_node(1, &[access]).unwrap().to_bytes().unwrap();
        UnprotectedReferenceMission::persist(&o.mission, bytes).unwrap();
    }

    struct TestRoot(std::path::PathBuf);
    impl TestRoot {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt as _;
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).unwrap();
            let path =
                std::env::temp_dir().join(format!("aster-ledger-scale-test-{}", hex(&nonce)));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
}
