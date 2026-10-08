//! Clean Room — Privileged.
//! Numbered publication lifecycle observer; no customer or physical qualification.
//! Requires a fresh private state directory and an unprotected fixture mission.
//! --client-namespace configures ten fixed producer slots, never one client per
//! publication. Journals retain one full intent per slot. V2 observations replace
//! the old arbitrary-key ledger experiment without relabeling its v1 receipts.

use aster_node::publication_journal as numbered;
use aster_node::{
    MutableSourceInterests, NodeApplication, NodeConfig, NodeOperatorOutputPolicy, RunningNode,
    SelectedForwardingConfig,
    application::{
        ApplicationError, ApplicationErrorKind, CommittedEventContent, NumberedEventPublishOutcome,
        Priority, Scope, SelectedEventHandle, Topic,
    },
    mission::UnprotectedReferenceMission,
    start_node_with_forwarding_and_output_policy,
};
use aster_redb_store::{EventOperationLimits, Store};
use serde::Serialize;
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
fn require(ok: bool, reason: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
        let (mode, ordinary, finite, bytes) = match (mode, count) {
            ("small", Some(count @ 1..=10_000)) => ("small", count, true, 201_326_592),
            // Ten 32-byte clients plus eight results use 2,954 logical bytes.
            // Four spare ordinary bytes leave the ninth result outside the
            // ordinary budget; two reserved emergency rows retain a tombstone.
            ("small-byte-capacity", Some(count @ 1..=10_000)) => {
                ("small-byte-capacity", count, false, 3_282)
            }
            ("million-retired", None) => ("million-retired", 1_000_000, true, 201_326_592),
            ("candidate-capacity", None) => ("candidate-capacity", 990_000, true, 201_326_592),
            _ => return Err("invalid workload mode/count".into()),
        };
        Ok(Self {
            mode,
            ordinary,
            finite,
            limits: EventOperationLimits::new(20, bytes, 2)?,
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
                    | "--client-namespace"
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
    let prefix = get("--client-namespace")?;
    require(
        prefix.len() <= 128
            && prefix
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"-_.".contains(&v)),
        "invalid client namespace",
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

async fn start(o: &Options) -> Result<RunningNode> {
    Ok(start_node_with_forwarding_and_output_policy(
        NodeConfig {
            state: o.state.clone(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            mission: UnprotectedReferenceMission::load(&o.mission)
                .map_err(|_| Failure::from("provisioning unavailable"))?,
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

#[derive(Serialize)]
struct Receipt {
    schema: &'static str,
    publication_model: &'static str,
    qualification: bool,
    claim: &'static str,
    mode: &'static str,
    requested_events: u64,
    source_commit: String,
    binary_sha256: String,
    config_sha256: String,
    configured_clients: u64,
    created: u64,
    exact_retries: u64,
    conflicts: u64,
    capacity_rejected: u64,
    emergency_accepted: u64,
    repaired_original: u64,
    retired_receipts: u64,
    peak_results: u64,
    peak_record_rows: u64,
    peak_logical_bytes: u64,
    final_results: u64,
    final_clients: u64,
    final_reverse_rows: u64,
    final_logical_bytes: u64,
    restarted: bool,
    offline_numbered_audit: bool,
    started_ms: u128,
    elapsed_ms: u128,
    phase: &'static str,
    failure: &'static str,
}
impl Receipt {
    fn new(o: &Options) -> Self {
        Self {
            schema: "aster-event-operation-ledger-scale/v2",
            publication_model: "numbered-v1",
            qualification: false,
            claim: "selected-rust-node-numbered-lifecycle-observation",
            mode: o.workload.mode,
            requested_events: o.workload.ordinary,
            source_commit: o.commit.clone(),
            binary_sha256: o.binary_hash.clone(),
            config_sha256: o.config_hash.clone(),
            configured_clients: 10,
            created: 0,
            exact_retries: 0,
            conflicts: 0,
            capacity_rejected: 0,
            emergency_accepted: 0,
            repaired_original: 0,
            retired_receipts: 0,
            peak_results: 0,
            peak_record_rows: 0,
            peak_logical_bytes: 0,
            final_results: 0,
            final_clients: 0,
            final_reverse_rows: 0,
            final_logical_bytes: 0,
            restarted: false,
            offline_numbered_audit: false,
            started_ms: 0,
            elapsed_ms: 0,
            phase: "preflight",
            failure: "none",
        }
    }
    fn json(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        Ok(bytes)
    }
}
fn client(o: &Options, slot: usize) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"aster/native-numbered-observer/client/v1\0");
    hash.update((o.prefix.len() as u16).to_be_bytes());
    hash.update(o.prefix.as_bytes());
    hash.update([slot as u8]);
    hash.finalize().to_vec()
}
fn intent(o: &Options, index: u64, tombstone: bool) -> numbered::Intent {
    numbered::Intent {
        predecessor: None,
        topic: o.topic.as_str().into(),
        scope: o.scope.as_str().into(),
        priority: Priority::Routine as u8,
        logical_key: format!("observer/{index}").into_bytes(),
        payload: if tombstone {
            Vec::new()
        } else {
            vec![0x61; o.payload_bytes]
        },
        tombstone,
        ttl_ms: if o.workload.finite && !tombstone {
            Some(o.ttl_ms)
        } else {
            None
        },
    }
}
fn journal_path(o: &Options, slot: usize) -> PathBuf {
    o.state.join(format!("publication-slot-{slot}.redb"))
}
async fn open_journals(
    o: &Options,
    events: &SelectedEventHandle,
    initialize: bool,
) -> Result<Vec<numbered::Journal>> {
    let mut journals = Vec::new();
    for slot in 0..10 {
        let path = journal_path(o, slot);
        let id = client(o, slot);
        if initialize {
            numbered::Journal::initialize(&path, &id)?;
        }
        let mut journal = numbered::Journal::open(&path, &id)?;
        journal
            .recover(&mut numbered::Backend::Live(events))
            .await?;
        journals.push(journal);
    }
    Ok(journals)
}
async fn sample_status(events: &SelectedEventHandle, r: &mut Receipt) -> Result<()> {
    let status = events.status().await?;
    let stats = status.event_operation_capacity.numbered_stats;
    require(
        stats.clients == 10 && stats.reverse_edges == stats.outstanding_results,
        "numbered accounting",
    )?;
    require(
        status.event_operation_capacity.stats.records_total == 0,
        "ordinary publication ledger must remain empty",
    )?;
    r.peak_results = r.peak_results.max(stats.outstanding_results);
    r.peak_record_rows = r
        .peak_record_rows
        .max(stats.clients + stats.outstanding_results);
    r.peak_logical_bytes = r.peak_logical_bytes.max(stats.logical_bytes);
    r.final_results = stats.outstanding_results;
    r.final_clients = stats.clients;
    r.final_reverse_rows = stats.reverse_edges;
    r.final_logical_bytes = stats.logical_bytes;
    Ok(())
}
fn kind(error: &Failure) -> Option<ApplicationErrorKind> {
    error
        .downcast_ref::<ApplicationError>()
        .map(ApplicationError::kind)
}
fn immutable(original: &NumberedEventPublishOutcome, replay: &NumberedEventPublishOutcome) -> bool {
    !replay.inserted
        && original.result.sequence == replay.result.sequence
        && original.result.receipt == replay.result.receipt
}
async fn probe(
    journal: &mut numbered::Journal,
    events: &SelectedEventHandle,
    original: &NumberedEventPublishOutcome,
    r: &mut Receipt,
) -> Result<()> {
    let retained = journal.pending().ok_or("probe intent missing")?.1.clone();
    let replay = journal
        .publish(&mut numbered::Backend::Live(events), retained.clone())
        .await?;
    require(
        immutable(original, &replay),
        "exact replay changed immutable receipt",
    )?;
    r.exact_retries += 1;
    let mut changed = retained;
    changed.payload[0] ^= 1;
    let error = journal
        .probe_changed(&mut numbered::Backend::Live(events), &changed)
        .await
        .err()
        .ok_or("changed intent accepted")?;
    require(
        kind(&error) == Some(ApplicationErrorKind::Conflict),
        "changed intent conflict missing",
    )?;
    r.conflicts += 1;
    Ok(())
}
async fn exercise(events: &SelectedEventHandle, o: &Options, r: &mut Receipt) -> Result<()> {
    let mut journals = open_journals(o, events, true).await?;
    let selected = samples(o.workload.ordinary);
    let mut worker = 0;
    for index in 0..o.workload.ordinary {
        r.phase = "publication";
        let slot = if let Some(slot) = selected.iter().position(|sample| *sample == index) {
            slot
        } else {
            let slot = 4 + worker % 4;
            worker += 1;
            slot
        };
        let outcome = journals[slot]
            .publish(
                &mut numbered::Backend::Live(events),
                intent(o, index, false),
            )
            .await?;
        require(outcome.inserted, "new sequence replayed")?;
        r.created += 1;
        if index.is_multiple_of(o.sample_every) || selected.contains(&index) {
            probe(&mut journals[slot], events, &outcome, r).await?;
        }
        if slot >= 4 {
            journals[slot]
                .acknowledge(&mut numbered::Backend::Live(events))
                .await?;
        }
        sample_status(events, r).await?;
    }
    // Fill the configured eight publication slots, retaining at most one
    // original intent per fixed producer. These are separate capacity probes.
    let mut originals = Vec::new();
    for (slot, journal) in journals[..8].iter_mut().enumerate() {
        let retained = journal
            .pending()
            .map(|(_, intent)| intent.clone())
            .unwrap_or_else(|| intent(o, o.workload.ordinary + slot as u64, false));
        let outcome = journal
            .publish(&mut numbered::Backend::Live(events), retained)
            .await?;
        originals.push(outcome);
    }
    sample_status(events, r).await?;
    require(r.final_results == 8, "capacity slots not full")?;
    r.phase = "capacity";
    let rejected = intent(o, o.workload.ordinary + 8, false);
    let error = journals[8]
        .publish(&mut numbered::Backend::Live(events), rejected.clone())
        .await
        .err()
        .ok_or("ordinary capacity did not reject")?;
    require(
        kind(&error) == Some(ApplicationErrorKind::OperationCapacity),
        "ordinary capacity classification",
    )?;
    r.capacity_rejected = 1;
    let emergency = journals[9]
        .publish(
            &mut numbered::Backend::Live(events),
            intent(o, o.workload.ordinary + 9, true),
        )
        .await?;
    require(emergency.inserted, "reserved tombstone did not commit")?;
    r.emergency_accepted = 1;
    sample_status(events, r).await?;
    journals[9]
        .acknowledge(&mut numbered::Backend::Live(events))
        .await?;
    if o.workload.finite {
        r.phase = "retirement";
        sleep(Duration::from_millis(o.ttl_ms.saturating_add(50))).await;
    }
    for slot in 0..8 {
        let retained = journals[slot]
            .pending()
            .ok_or("retained intent missing")?
            .1
            .clone();
        let replay = journals[slot]
            .publish(&mut numbered::Backend::Live(events), retained)
            .await?;
        require(
            immutable(&originals[slot], &replay),
            "retirement changed receipt",
        )?;
        if o.workload.finite {
            require(
                matches!(replay.result.content, CommittedEventContent::Retired(_)),
                "receipt did not survive retirement",
            )?;
            r.retired_receipts += 1;
        }
        probe(&mut journals[slot], events, &originals[slot], r).await?;
    }
    // Explicitly free one result, then retry the exact preserved failed input.
    // No abandonment, new client identity, or sequence reuse is hidden here.
    journals[4]
        .acknowledge(&mut numbered::Backend::Live(events))
        .await?;
    let repaired = journals[8]
        .publish(&mut numbered::Backend::Live(events), rejected)
        .await?;
    require(
        repaired.inserted && repaired.result.sequence.get() == 1,
        "capacity repair changed original operation",
    )?;
    r.repaired_original = 1;
    journals[8]
        .acknowledge(&mut numbered::Backend::Live(events))
        .await?;
    drop(journals);
    Ok(())
}
fn safe_reason(error: &Failure) -> &'static str {
    match kind(error) {
        Some(ApplicationErrorKind::RequestRejected) => "request_rejected",
        Some(ApplicationErrorKind::UnauthorizedOrRevoked) => "unauthorized_or_revoked",
        Some(ApplicationErrorKind::OperationCapacity) => "operation_capacity",
        _ => "observation_failed",
    }
}
async fn run_workload(o: &Options) -> Result<Receipt> {
    let began = Instant::now();
    let mut r = Receipt::new(o);
    r.started_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    if o.workload.ordinary > aster_redb_store::MAX_CUSTODY_RETIREMENTS {
        r.phase = "feasibility";
        r.failure = "custody_ceiling_alias_unavailable";
        return Ok(r);
    }
    private_directory(o.state.parent().ok_or("state parent missing")?)?;
    require(
        fs::symlink_metadata(&o.state)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound),
        "state must be fresh",
    )?;
    fs::DirBuilder::new().mode(0o700).create(&o.state)?;
    r.phase = "startup";
    let running = match start(o).await {
        Ok(node) => node,
        Err(error) => {
            r.failure = safe_reason(&error);
            return Ok(r);
        }
    };
    let events = running.selected_events();
    match timeout(o.deadline, exercise(&events, o, &mut r)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => r.failure = safe_reason(&error),
        Err(_) => r.failure = "workload_deadline",
    };
    drop(events);
    running.shutdown().await?;
    if r.failure == "none" {
        r.phase = "restart";
        let reopened = start(o).await?;
        let events = reopened.selected_events();
        let mut journals = open_journals(o, &events, false).await?;
        for journal in &mut journals {
            if let Some((_, retained)) = journal.pending() {
                let retained = retained.clone();
                let replay = journal
                    .publish(&mut numbered::Backend::Live(&events), retained)
                    .await?;
                require(
                    !replay.inserted,
                    "restart duplicated a retained publication",
                )?;
                r.exact_retries += 1;
                journal
                    .acknowledge(&mut numbered::Backend::Live(&events))
                    .await?;
            }
        }
        sample_status(&events, &mut r).await?;
        require(
            r.final_results == 0 && r.final_reverse_rows == 0 && r.final_clients == 10,
            "acknowledgement did not release result headroom",
        )?;
        r.restarted = true;
        drop(journals);
        drop(events);
        reopened.shutdown().await?;
        // Read-only inspection runs numbered table/result/reverse authority audits.
        Store::inspect_existing(o.state.join("mesh.redb"))?;
        r.offline_numbered_audit = true;
        r.phase = "complete";
    }
    r.elapsed_ms = began.elapsed().as_millis();
    Ok(r)
}
async fn run(args: &[String]) -> Result<()> {
    let o = options(args)?;
    let mut output = AtomicOutput::prepare(&o.output)?;
    let receipt = run_workload(&o).await?;
    output.finish(&receipt.json()?)?;
    require(
        receipt.failure == "none",
        "observer retained a failure receipt",
    )
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run(&env::args().skip(1).collect::<Vec<_>>()).await {
        eprintln!(
            "numbered publication observer failed: {}",
            safe_reason(&error)
        );
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn byte_capacity_repair_restart_and_bounded_result_cleanup() {
        let root = TestRoot::new();
        let mut o = fixture_options(&root.0);
        o.workload = Workload::new("small-byte-capacity", Some(12)).unwrap();
        provision(&o);
        let r = run_workload(&o).await.unwrap();
        assert_eq!(r.failure, "none");
        assert_eq!(r.created, 12);
        assert_eq!(r.capacity_rejected, 1);
        assert_eq!(r.emergency_accepted, 1);
        assert_eq!(r.repaired_original, 1);
        assert_eq!(r.peak_results, 9);
        assert_eq!(r.peak_record_rows, 19);
        assert_eq!(r.final_clients, 10);
        assert_eq!(r.final_results, 0);
        assert_eq!(r.final_reverse_rows, 0);
        assert_eq!(r.final_logical_bytes, 1130);
        assert!(r.restarted && r.offline_numbered_audit);
        let encoded = String::from_utf8(r.json().unwrap()).unwrap();
        for secret in [
            o.prefix.as_str(),
            o.state.to_str().unwrap(),
            o.mission.to_str().unwrap(),
            "test/load",
            "load.events",
        ] {
            assert!(!encoded.contains(secret));
        }
        assert!(encoded.contains("\"qualification\":false"));
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn finite_retirement_keeps_receipts_through_restart_and_acknowledgement() {
        let root = TestRoot::new();
        let o = fixture_options(&root.0);
        provision(&o);
        let r = run_workload(&o).await.unwrap();
        assert_eq!(r.failure, "none");
        assert_eq!(r.retired_receipts, 8);
        assert_eq!(r.repaired_original, 1);
        assert!(r.restarted && r.offline_numbered_audit);
        assert_eq!(r.final_results, 0);
    }
    #[tokio::test]
    async fn deadline_preserves_pending_journals_without_claiming_success() {
        let root = TestRoot::new();
        let mut o = fixture_options(&root.0);
        o.workload = Workload::new("small-byte-capacity", Some(100)).unwrap();
        o.deadline = Duration::ZERO;
        provision(&o);
        let r = run_workload(&o).await.unwrap();
        assert_eq!(r.failure, "workload_deadline");
        assert!(!r.restarted && !r.offline_numbered_audit);
    }
    #[tokio::test]
    async fn impossible_large_modes_refuse_before_state_or_provisioning() {
        for mode in ["million-retired", "candidate-capacity"] {
            let root = TestRoot::new();
            let mut o = fixture_options(&root.0);
            o.workload = Workload::new(mode, None).unwrap();
            let r = run_workload(&o).await.unwrap();
            assert_eq!(r.failure, "custody_ceiling_alias_unavailable");
            assert!(!o.state.exists());
            assert!(!o.mission.exists());
        }
    }
    #[test]
    fn output_refuses_existing_file_and_substituted_stage() {
        let root = TestRoot::new();
        let path = root.0.join("receipt.json");
        let mut output = AtomicOutput::prepare(&path).unwrap();
        fs::remove_file(&output.temporary).unwrap();
        fs::write(&output.temporary, b"substituted").unwrap();
        assert!(output.finish(b"{}\n").is_err());
        assert!(!path.exists());
        fs::write(&path, b"original").unwrap();
        assert!(AtomicOutput::prepare(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original");
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
            let path = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("aster-ledger-scale-test-{}", hex(&nonce)));
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
