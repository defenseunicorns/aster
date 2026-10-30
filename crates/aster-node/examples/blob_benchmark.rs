//! Real selected-stack Blob benchmark; production defaults, synthetic identities.
//! See docs/validation/blob-benchmark.md for timing boundaries and reproduction.
use aster_iroh::{EndpointId, ExpectedPeer};
use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
use aster_node::{
    BlobDepotLimits, MissionExpectedPeer, MutableSourceInterests, NodeConfig, NodeIdentity,
    SelectedForwardingConfig, SourceInterestSelector,
    application::{
        ApplicationErrorKind, BlobPublishOptions, BlobPublishRequest, BlobPublishStreamRequest,
        BlobReadPageRequest, BlobReadRequest, MAX_SELECTED_BLOB_PAGE_BYTES,
        MAX_SELECTED_BLOB_STREAM_BYTES, Priority, Scope, Topic,
    },
    mission::UnprotectedReferenceMission,
    start_node_with_forwarding,
};
use aster_redb_store::Store;
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};
use zeroize::Zeroizing;
type E = Box<dyn Error + Send + Sync>;
struct Participant {
    state: PathBuf,
    mission: UnprotectedReferenceMission,
    carrier: EndpointId,
}

#[cfg(unix)]
fn create_owner_only_directory(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_owner_only_directory(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)
}

fn participant(root: &Path, name: &str, bytes: Vec<u8>) -> Result<Participant, E> {
    let dir = root.join(name);
    create_owner_only_directory(&dir)?;
    let state = dir.join("state");
    create_owner_only_directory(&state)?;
    let mission = UnprotectedReferenceMission::persist(dir.join("mission.bundle"), bytes)?;
    let carrier = NodeIdentity::load_or_create(&state)?.id();
    Ok(Participant {
        state,
        mission,
        carrier,
    })
}
fn config(
    p: &Participant,
    bind: SocketAddr,
    peer: Option<(&Participant, SocketAddr)>,
    topic: &Topic,
    scope: &Scope,
) -> NodeConfig {
    let mut c = NodeConfig::new(p.state.clone(), bind, p.mission.clone());
    if let Some((r, address)) = peer {
        c.peers = vec![MissionExpectedPeer {
            carrier: ExpectedPeer {
                id: r.carrier,
                address,
            },
            mission: r.mission.identity(),
        }];
        c.mutable_interests =
            MutableSourceInterests::default().with_blob(vec![SourceInterestSelector::new(
                topic.clone(),
                scope.clone(),
                false,
            )]);
    }
    assert_eq!(c.sync_interval, Duration::from_millis(500));
    c
}

fn forwarding(total_len: u64) -> Result<SelectedForwardingConfig, E> {
    let max_bytes = total_len
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(256 * 1024 * 1024))
        .ok_or("benchmark Blob depot byte limit overflow")?;
    let max_chunks = total_len
        .div_ceil(64 * 1024)
        .checked_mul(2)
        .and_then(|chunks| chunks.checked_add(1024))
        .ok_or("benchmark Blob depot chunk limit overflow")?;
    Ok(
        SelectedForwardingConfig::default().with_blob_depot_limits(BlobDepotLimits::new(
            max_bytes.max(1),
            max_chunks.max(1),
            4,
        )?),
    )
}
fn receipt(name: &str, r: &aster_node::NodeReceipt) {
    println!(
        "BENCH_RECEIPT {{\"node\":\"{name}\",\"contacts\":{},\"direct_contacts\":{},\"relay_contacts\":{},\"unknown_path_contacts\":{},\"contact_errors\":{},\"blobs\":{},\"pending_blobs\":{},\"blob_ranges_fetched\":{},\"blob_bytes_fetched\":{},\"committed_chunks\":{},\"network_staging_bytes\":{}}}",
        r.contacts,
        r.direct_contacts,
        r.relay_contacts,
        r.unknown_path_contacts,
        r.contact_errors,
        r.blobs,
        r.pending_blobs,
        r.blob_ranges_fetched,
        r.blob_bytes_fetched,
        r.blob_committed_chunks,
        r.blob_network_staging_bytes
    );
}

fn transfer_is_pending(kind: ApplicationErrorKind) -> bool {
    matches!(
        kind,
        ApplicationErrorKind::NotFound
            | ApplicationErrorKind::RequestRejected
            | ApplicationErrorKind::UnauthorizedOrRevoked
            | ApplicationErrorKind::PolicyUnsettled
    )
}

fn fixture_bytes(offset: u64, len: usize) -> Vec<u8> {
    // SplitMix64's bijective output permutation over a counter, not randomness
    // for credentials. Distinct aligned words/chunks avoid a repetitive Blob
    // workload while keeping the source reproducible and seek-independent.
    (offset..offset + len as u64)
        .map(|position| {
            let mut word = (position / 8).wrapping_add(0x9e3779b97f4a7c15);
            word = (word ^ (word >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            word = (word ^ (word >> 27)).wrapping_mul(0x94d049bb133111eb);
            word ^= word >> 31;
            (word >> ((position % 8) * 8)) as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn benchmark_directories_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let path = std::env::temp_dir().join(format!(
            "aster-blob-benchmark-directory-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir(&path);

        create_owner_only_directory(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        fs::remove_dir(&path).unwrap();

        assert_eq!(mode, 0o700);
    }

    #[test]
    fn receiver_absence_is_pending_until_reconciliation_completes() {
        assert!(transfer_is_pending(ApplicationErrorKind::NotFound));
        assert!(!transfer_is_pending(ApplicationErrorKind::Integrity));
    }

    #[test]
    fn all_live_size_chunks_are_distinct_and_generation_is_seek_independent() {
        let words: std::collections::BTreeSet<_> = (0..1024)
            .map(|chunk| fixture_bytes(chunk * 65536, 8))
            .collect();
        assert_eq!(words.len(), 1024);
        assert_eq!(fixture_bytes(3, 29), fixture_bytes(0, 32)[3..]);
    }

    #[test]
    fn source_chunks_do_not_repeat_at_the_old_pattern_period() {
        assert!(
            fixture_bytes(0, 65536) != fixture_bytes(251 * 65536, 65536),
            "large-size fixture must not repeat chunks"
        );
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<(), E> {
    let args: Vec<_> = std::env::args().collect();
    let root = PathBuf::from(&args[1]);
    let len: u64 = args[2].parse()?;
    let deadline: u64 = args[3].parse()?;
    create_owner_only_directory(&root)?;
    let topic = Topic::new("benchmark.blob")?;
    let scope = Scope::new("test/blob-benchmark")?;
    let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed)?;
    let mut prov = ReferenceProvisioner::from_seed(seed)?;
    let publisher = participant(
        &root,
        "publisher",
        prov.issue_node(1, std::slice::from_ref(&access))?
            .to_bytes()?,
    )?;
    let receiver = participant(
        &root,
        "receiver",
        prov.issue_node(2, std::slice::from_ref(&access))?
            .to_bytes()?,
    )?;
    let source = root.join("source.bin");
    let mut file = File::create(&source)?;
    let mut hash = Sha256::new();
    let mut offset = 0u64;
    let generation = Instant::now();
    while offset < len {
        let n = (len - offset).min(1024 * 1024) as usize;
        let bytes = fixture_bytes(offset, n);
        file.write_all(&bytes)?;
        hash.update(&bytes);
        offset += n as u64;
    }
    file.sync_all()?;
    drop(file);
    let expected: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "BENCH_SOURCE {{\"bytes\":{len},\"sha256\":\"{expected}\",\"generation_ns\":{},\"max_stream_blob_bytes\":{MAX_SELECTED_BLOB_STREAM_BYTES},\"sync_interval_ms\":500,\"tokio_workers\":2}}",
        generation.elapsed().as_nanos()
    );
    if len > MAX_SELECTED_BLOB_STREAM_BYTES {
        return Err("benchmark source exceeds the selected streaming protocol limit".into());
    }
    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let peerless = start_node_with_forwarding(
        config(&publisher, local, None, &topic, &scope),
        forwarding(len)?,
    )
    .await?;
    let total = Instant::now();
    let publication_start = Instant::now();
    let mut upload = peerless
        .selected_blobs()
        .open_publish_stream(BlobPublishStreamRequest {
            publication: BlobPublishRequest {
                operation_key: b"benchmark-once".to_vec(),
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Priority,
                media_type: Some("application/octet-stream".into()),
                schema_id: b"benchmark-v1".to_vec(),
            },
            options: BlobPublishOptions::durable(),
            total_len: len,
        })
        .await?;
    let mut source_file = File::open(&source)?;
    let mut offset = upload.durable_offset();
    source_file.seek(SeekFrom::Start(offset))?;
    while offset < len {
        let chunk_len = usize::try_from((len - offset).min(1024 * 1024))?;
        let mut bytes = Zeroizing::new(vec![0_u8; chunk_len]);
        source_file.read_exact(&mut bytes)?;
        let progress = upload.write(offset, bytes).await?;
        offset = progress.accepted_offset;
    }
    let published = upload.finish().await?;
    let publication_ns = publication_start.elapsed().as_nanos();
    assert_eq!(published.total_len, len);
    assert!(published.inserted);
    println!(
        "BENCH_PUBLICATION {{\"bytes\":{len},\"publication_ns\":{publication_ns},\"blob_id\":\"{}\"}}",
        published.id
    );
    let r = peerless.shutdown().await?;
    assert_eq!(r.blobs, 1);
    receipt("publisher_peerless", &r);
    let a = UdpSocket::bind(local)?;
    let b = UdpSocket::bind(local)?;
    let pa = a.local_addr()?;
    let ra = b.local_addr()?;
    drop((a, b));
    println!(
        "BENCH_PATH {{\"publisher_bind\":\"{pa}\",\"receiver_bind\":\"{ra}\",\"transport\":\"direct Iroh QUIC\"}}"
    );
    let transfer = Instant::now();
    let pc = config(&publisher, pa, Some((&receiver, ra)), &topic, &scope);
    let rc = config(&receiver, ra, Some((&publisher, pa)), &topic, &scope);
    let (p, r) = if publisher.carrier > receiver.carrier {
        let p = start_node_with_forwarding(pc, forwarding(len)?).await?;
        let r = start_node_with_forwarding(rc, forwarding(len)?).await?;
        (p, r)
    } else {
        let r = start_node_with_forwarding(rc, forwarding(len)?).await?;
        let p = start_node_with_forwarding(pc, forwarding(len)?).await?;
        (p, r)
    };
    let request = BlobReadRequest {
        id: published.id,
        topic: topic.clone(),
        scope: scope.clone(),
    };
    let h = r.selected_blobs();
    let publisher_events = p.selected_events();
    let receiver_events = r.selected_events();
    let mut last = Instant::now();
    let mut content_visible = false;
    let mut transfer_until_visible_ns = None;
    let mut publish_to_visible_ns = None;
    let completed=timeout(Duration::from_secs(deadline),async {
  loop {
   if !content_visible { match h.read_page(BlobReadPageRequest{blob:request.clone(),offset:0,max_bytes:1}).await {
    Ok(page)=>{
     assert_eq!(page.total_len,len);
     assert_eq!(page.id,published.id);
     content_visible=true;
     transfer_until_visible_ns=Some(transfer.elapsed().as_nanos());
     publish_to_visible_ns=Some(total.elapsed().as_nanos());
    },
    Err(e) if transfer_is_pending(e.kind())=>{},
    Err(e)=>break Err(Box::new(e) as E),
   }}
   let (publisher_status, receiver_status) = tokio::join!(publisher_events.status(), receiver_events.status());
   let publisher_status = publisher_status?;
   let receiver_status = receiver_status?;
   // Offline peers and slow durable-store reopen can outlive one carrier
   // attempt. The runtime retries them; keep the cumulative failures visible
   // in progress/final receipts and let authenticated settlement or the
   // overall deadline decide the benchmark outcome.
   if content_visible && publisher_status.authenticated_contacts > 0 && receiver_status.authenticated_contacts > 0 { break Ok::<(),E>(()); }
  if last.elapsed()>=Duration::from_secs(10){println!("BENCH_PROGRESS {{\"elapsed_ns\":{},\"content_visible\":{},\"publisher_authenticated_contacts\":{},\"receiver_authenticated_contacts\":{},\"publisher_failed_contacts\":{},\"receiver_failed_contacts\":{}}}",transfer.elapsed().as_nanos(),content_visible,publisher_status.authenticated_contacts,receiver_status.authenticated_contacts,publisher_status.failed_contact_attempts,receiver_status.failed_contact_attempts);last=Instant::now();}
  sleep(Duration::from_millis(20)).await;
 }
 }).await;
    let settled_ns = transfer.elapsed().as_nanos();
    let publish_to_settled_ns = total.elapsed().as_nanos();
    if let Ok(outcome) = &completed {
        assert!(outcome.is_ok(), "transfer failed: {outcome:?}");
    }
    // The readiness loop includes terminal contact accounting, so shutdown
    // cannot truncate profile-5 settlement after content becomes visible.
    let connected_shutdown = Instant::now();
    let (pr, rr) = tokio::join!(p.shutdown(), r.shutdown());
    let connected_shutdown_ns = connected_shutdown.elapsed().as_nanos();
    let pr = pr?;
    let rr = rr?;
    drop(h);
    receipt("publisher_connected", &pr);
    receipt("receiver_connected", &rr);
    for rec in [&pr, &rr] {
        assert!(rec.direct_contacts > 0);
        assert_eq!(rec.direct_contacts, rec.contacts);
        assert_eq!(rec.relay_contacts, 0);
        assert_eq!(rec.unknown_path_contacts, 0);
    }
    let durable_inspection = Instant::now();
    let store = Store::open_for_mission(
        receiver.state.join("mesh.redb"),
        receiver.mission.mission_authority_id(),
    )?;
    let stats = store.blob_stats()?;
    println!(
        "BENCH_DURABLE {{\"publications\":{},\"pending_sources\":{},\"committed_chunks\":{},\"network_staging_bytes\":{},\"carrier_prefixes\":{}}}",
        stats.publications,
        stats.pending_sources,
        stats.committed_chunks,
        stats.network_staging_bytes,
        stats.carrier_prefixes
    );
    if completed.is_err() {
        drop(store);
        println!(
            "BENCH_RESULT {{\"status\":\"transfer_timeout\",\"bytes\":{len},\"source_sha256\":\"{expected}\",\"publication_ns\":{publication_ns},\"transfer_ns\":null,\"transfer_observed_ns\":{settled_ns},\"verification_ns\":null,\"total_ns\":{},\"fetched_carrier_bytes\":{},\"pending_sources\":{}}}",
            total.elapsed().as_nanos(),
            rr.blob_bytes_fetched,
            stats.pending_sources
        );
        return Ok(());
    }
    assert_eq!(stats.publications, 1);
    assert_eq!(stats.pending_sources, 0);
    assert_eq!(stats.carrier_prefixes, 0);
    assert_eq!(stats.network_staging_bytes, 0);
    drop(store);
    let durable_inspection_ns = durable_inspection.elapsed().as_nanos();
    let transfer_ns = transfer.elapsed().as_nanos();
    let verification = Instant::now();
    let restart = Instant::now();
    let reopened = start_node_with_forwarding(
        config(&receiver, local, None, &topic, &scope),
        forwarding(len)?,
    )
    .await?;
    let restart_ns = restart.elapsed().as_nanos();
    let handle = reopened.selected_blobs();
    let download_verification = Instant::now();
    let mut offset = 0;
    let mut digest = Sha256::new();
    let mut pages = 0;
    loop {
        let page = handle
            .read_page(BlobReadPageRequest {
                blob: request.clone(),
                offset,
                max_bytes: MAX_SELECTED_BLOB_PAGE_BYTES,
            })
            .await?;
        assert_eq!(page.id, published.id);
        assert_eq!(page.total_len, len);
        assert_eq!(page.publisher, published.publisher);
        assert_eq!(page.offset, offset);
        assert!(!page.is_empty());
        assert!(page.len() <= MAX_SELECTED_BLOB_PAGE_BYTES);
        digest.update(page.as_bytes());
        offset = page.next_offset();
        pages += 1;
        if page.complete {
            break;
        }
    }
    let actual: String = digest
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(offset, len);
    assert_eq!(actual, expected);
    let download_verification_ns = download_verification.elapsed().as_nanos();
    let verification_ns = verification.elapsed().as_nanos();
    let total_ns = total.elapsed().as_nanos();
    let final_receipt = reopened.shutdown().await?;
    receipt("receiver_reopened", &final_receipt);
    assert_eq!(final_receipt.blobs, 1);
    assert_eq!(final_receipt.contacts, 0);
    println!(
        "BENCH_RESULT {{\"status\":\"complete\",\"bytes\":{len},\"verified_bytes\":{offset},\"pages\":{pages},\"source_sha256\":\"{expected}\",\"receiver_sha256\":\"{actual}\",\"publication_ns\":{publication_ns},\"transfer_until_visible_ns\":{},\"transfer_until_ready_ns\":{settled_ns},\"publish_to_visible_ns\":{},\"publish_to_settled_ns\":{publish_to_settled_ns},\"connected_shutdown_ns\":{connected_shutdown_ns},\"durable_inspection_ns\":{durable_inspection_ns},\"transfer_ns\":{transfer_ns},\"restart_ns\":{restart_ns},\"download_verification_ns\":{download_verification_ns},\"verification_ns\":{verification_ns},\"total_ns\":{total_ns}}}",
        transfer_until_visible_ns.expect("complete transfer became visible"),
        publish_to_visible_ns.expect("complete transfer became visible"),
    );
    Ok(())
}
