//! Test-only observation of committed Blob prefixes; never a transport policy.
use super::{BlobCarrierObjectId, BlobTransferId, ContentVerifiedBlobEnvelope, NodeId};
use std::{
    collections::BTreeMap,
    future::Future,
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};
use tokio::time::{Instant, sleep, sleep_until};

// Receiver, source publisher, publication counter, content identity.
type Key = (NodeId, NodeId, u64, [u8; 32]);
type Ranges = BTreeMap<(BlobTransferId, BlobCarrierObjectId), (u64, u64)>;
static OBSERVERS: LazyLock<Mutex<BTreeMap<Key, Arc<Mutex<Progress>>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

#[derive(Clone, Debug)]
struct Progress {
    started: Instant,
    last_advance: Instant,
    ranges: Ranges,
}

impl Progress {
    fn new(now: Instant) -> Self {
        Self {
            started: now,
            last_advance: now,
            ranges: BTreeMap::new(),
        }
    }

    fn record(
        &mut self,
        source: BlobTransferId,
        object: BlobCarrierObjectId,
        prefix: u64,
        total: u64,
        now: Instant,
    ) {
        assert!(
            prefix <= total,
            "durable Blob prefix exceeds carrier length"
        );
        let old = self.ranges.entry((source, object)).or_insert((0, total));
        assert_eq!(old.1, total, "durable Blob carrier length changed");
        assert!(prefix >= old.0, "durable Blob prefix regressed");
        if prefix > old.0 {
            old.0 = prefix;
            self.last_advance = now;
        }
    }

    fn failure(&self, now: Instant, stall: Duration, absolute: Duration) -> Option<&'static str> {
        if now >= self.started + absolute {
            Some("absolute deadline exceeded")
        } else if now >= self.last_advance + stall {
            Some("durable progress stalled")
        } else {
            None
        }
    }

    fn diagnostic(&self, now: Instant, reason: &str, last_probe: &str) -> String {
        let retained: u64 = self.ranges.values().map(|(prefix, _)| prefix).sum();
        let known_total: u64 = self.ranges.values().map(|(_, total)| total).sum();
        let completed = self
            .ranges
            .values()
            .filter(|(prefix, total)| prefix == total)
            .count();
        format!(
            "{reason}; elapsed={:?}; idle={:?}; durable_bytes={retained}; known_carrier_bytes={known_total}; completed_carriers={completed}/{}; prefixes={:?}; last_probe={last_probe}",
            now.duration_since(self.started),
            now.duration_since(self.last_advance),
            self.ranges.len(),
            self.ranges.values().collect::<Vec<_>>()
        )
    }
}

pub(super) struct Observer {
    key: Key,
    progress: Arc<Mutex<Progress>>,
}

impl Observer {
    pub(super) fn assert_carriers_complete(&self) {
        let progress = self.progress.lock().expect("Blob progress");
        assert!(
            !progress.ranges.is_empty(),
            "no durable Blob progress observed"
        );
        assert!(
            progress
                .ranges
                .values()
                .all(|(prefix, total)| prefix == total),
            "application completed before observed carrier prefixes: {:?}",
            progress.ranges
        );
    }

    pub(super) fn install(
        receiver: NodeId,
        publisher: NodeId,
        counter: u64,
        blob: [u8; 32],
    ) -> Self {
        let key = (receiver, publisher, counter, blob);
        let progress = Arc::new(Mutex::new(Progress::new(Instant::now())));
        assert!(
            OBSERVERS
                .lock()
                .expect("Blob observers")
                .insert(key, progress.clone())
                .is_none(),
            "duplicate Blob progress observer"
        );
        Self { key, progress }
    }

    /// `Ok(None)` means exact application content is available. Pending probes
    /// return a diagnostic; unexpected application errors terminate immediately.
    pub(super) async fn wait<F, Fut>(
        &self,
        stall: Duration,
        absolute: Duration,
        mut probe: F,
    ) -> Result<(), String>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<Option<String>, String>>,
    {
        let mut last_probe = "no completed application/status probe".to_owned();
        loop {
            let snapshot = self.progress.lock().expect("Blob progress").clone();
            let now = Instant::now();
            if let Some(reason) = snapshot.failure(now, stall, absolute) {
                return Err(snapshot.diagnostic(now, reason, &last_probe));
            }
            let deadline = (snapshot.started + absolute).min(snapshot.last_advance + stall);
            tokio::select! {
                biased;
                _ = sleep_until(deadline) => continue,
                result = probe() => {
                    let snapshot = self.progress.lock().expect("Blob progress").clone();
                    let now = Instant::now();
                    if let Some(reason) = snapshot.failure(now, stall, absolute) {
                        return Err(snapshot.diagnostic(now, reason, &last_probe));
                    }
                    match result {
                        Ok(None) => return Ok(()),
                        Ok(Some(detail)) => last_probe = detail,
                        Err(error) => return Err(snapshot.diagnostic(now, "unexpected application/status error", &error)),
                    }
                }
            }
            // The next iteration checks both deadlines even if probes or the
            // actor stop responding. Progress alone never moves the absolute cap.
            sleep(
                Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
            )
            .await;
        }
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        OBSERVERS.lock().expect("Blob observers").remove(&self.key);
    }
}

pub(super) fn record(
    receiver: NodeId,
    blob: &ContentVerifiedBlobEnvelope,
    status: super::BlobCarrierPrefixStatus,
) {
    let key = (
        receiver,
        blob.publisher(),
        blob.dot().counter,
        *blob.blob_id().as_bytes(),
    );
    record_key(
        key,
        status.source(),
        status.object(),
        status.prefix_len(),
        status.total_len(),
    );
}

fn record_key(
    key: Key,
    source: BlobTransferId,
    object: BlobCarrierObjectId,
    prefix: u64,
    total: u64,
) {
    let observer = OBSERVERS.lock().expect("Blob observers").get(&key).cloned();
    if let Some(observer) = observer {
        observer.lock().expect("Blob progress").record(
            source,
            object,
            prefix,
            total,
            Instant::now(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ids() -> (BlobTransferId, BlobCarrierObjectId) {
        let mut object = [7; 33];
        object[0] = 2;
        (
            BlobTransferId::new([8; 32]),
            BlobCarrierObjectId::new(object).expect("object"),
        )
    }
    #[test]
    fn duplicate_ranges_do_not_reset_stall_and_progress_never_resets_absolute_deadline() {
        let start = Instant::now();
        let mut progress = Progress::new(start);
        let (source, object) = ids();
        let stall = Duration::from_secs(10);
        let cap = Duration::from_secs(25);
        progress.record(source, object, 10, 100, start + Duration::from_secs(8));
        progress.record(source, object, 10, 100, start + Duration::from_secs(17));
        assert_eq!(
            progress.failure(start + Duration::from_secs(18), stall, cap),
            Some("durable progress stalled")
        );
        progress.record(source, object, 20, 100, start + Duration::from_secs(18));
        assert_eq!(
            progress.failure(start + Duration::from_secs(24), stall, cap),
            None
        );
        progress.record(source, object, 30, 100, start + Duration::from_secs(24));
        assert_eq!(
            progress.failure(start + cap, stall, cap),
            Some("absolute deadline exceeded")
        );
    }
    #[test]
    fn observer_ignores_other_receivers_and_publications_and_unregisters() {
        let receiver = [71; 32];
        let publisher = [72; 32];
        let observer = Observer::install(receiver, publisher, 1, [73; 32]);
        let key = observer.key;
        let (source, object) = ids();
        record_key((publisher, publisher, 1, [73; 32]), source, object, 10, 100);
        record_key((receiver, publisher, 2, [73; 32]), source, object, 10, 100);
        assert!(observer.progress.lock().unwrap().ranges.is_empty());
        record_key(key, source, object, 10, 100);
        assert_eq!(observer.progress.lock().unwrap().ranges.len(), 1);
        drop(observer);
        assert!(!OBSERVERS.lock().unwrap().contains_key(&key));
    }
    #[tokio::test]
    async fn unresponsive_probe_is_bounded_and_reports_stall() {
        let observer = Observer::install([74; 32], [75; 32], 1, [76; 32]);
        let error = observer
            .wait(Duration::from_millis(20), Duration::from_secs(10), || {
                std::future::pending::<Result<Option<String>, String>>()
            })
            .await
            .expect_err("stalled probe");
        assert!(error.contains("durable progress stalled"));
        assert!(error.contains("durable_bytes=0"));
    }
    #[tokio::test]
    async fn unresponsive_probe_is_bounded_by_absolute_deadline_too() {
        let observer = Observer::install([80; 32], [81; 32], 1, [82; 32]);
        let error = observer
            .wait(Duration::from_secs(10), Duration::from_millis(20), || {
                std::future::pending::<Result<Option<String>, String>>()
            })
            .await
            .expect_err("absolute cap");
        assert!(error.contains("absolute deadline exceeded"));
    }

    #[tokio::test]
    async fn unexpected_error_is_not_retried_and_includes_last_progress() {
        let observer = Observer::install([77; 32], [78; 32], 1, [79; 32]);
        let (source, object) = ids();
        record_key(observer.key, source, object, 10, 100);
        let error = observer
            .wait(Duration::from_secs(10), Duration::from_secs(20), || async {
                Err("integrity failure".to_owned())
            })
            .await
            .expect_err("fatal error");
        assert!(error.contains("integrity failure"));
        assert!(error.contains("durable_bytes=10"));
    }
}
