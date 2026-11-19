use std::time::Duration;

use aster_ble_linux::FixedRole;
use aster_node::{
    AutomaticEventAttemptOutcome, ContactDisposition, ContactOutcome,
    RunningAutomaticEventTransportHandle,
};
use futures::future::BoxFuture;
use tokio::task::JoinHandle;

use super::EventScheduleExit;

pub(super) const EVENT_CONTACT_CADENCE: Duration = Duration::from_secs(60);
const EVENT_RETRY_INITIAL: Duration = Duration::from_secs(5);
const EVENT_RETRY_BASE_MAX: Duration = Duration::from_secs(48);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScheduleAction {
    After(Duration),
    Reselect,
    Park,
}

pub(super) fn spawn_event_schedule(
    automatic: RunningAutomaticEventTransportHandle,
    peer: aster_mesh::NodeId,
    role: FixedRole,
) -> Option<JoinHandle<EventScheduleExit>> {
    matches!(role, FixedRole::Initiator).then(|| tokio::spawn(run_event_schedule(automatic, peer)))
}

async fn run_event_schedule(
    automatic: RunningAutomaticEventTransportHandle,
    peer: aster_mesh::NodeId,
) -> EventScheduleExit {
    run_event_schedule_with(peer, move |peer| {
        let automatic = automatic.clone();
        Box::pin(async move { automatic.run_peer_attempt(peer).await })
    })
    .await
}

async fn run_event_schedule_with(
    peer: aster_mesh::NodeId,
    mut run_attempt: impl FnMut(aster_mesh::NodeId) -> BoxFuture<'static, AutomaticEventAttemptOutcome>,
) -> EventScheduleExit {
    let mut failures = 0_u32;
    loop {
        let result = match run_attempt(peer).await {
            AutomaticEventAttemptOutcome::Completed(result) => result,
            AutomaticEventAttemptOutcome::AdmissionClosed => {
                return EventScheduleExit::AdmissionClosed;
            }
            AutomaticEventAttemptOutcome::PeerUnavailable => {
                return EventScheduleExit::PeerUnavailable;
            }
        };
        match next_delay(peer, &mut failures, result) {
            ScheduleAction::After(delay) => tokio::time::sleep(delay).await,
            ScheduleAction::Reselect => {}
            ScheduleAction::Park => std::future::pending::<()>().await,
        }
    }
}

fn next_delay(
    peer: aster_mesh::NodeId,
    failures: &mut u32,
    result: Result<(), ContactOutcome>,
) -> ScheduleAction {
    match result {
        Ok(()) => {
            *failures = 0;
            ScheduleAction::After(EVENT_CONTACT_CADENCE)
        }
        Err(outcome) => match outcome.disposition() {
            ContactDisposition::RetryLater => {
                *failures = failures.saturating_add(1);
                ScheduleAction::After(retry_delay(peer, *failures))
            }
            ContactDisposition::Reselect => ScheduleAction::Reselect,
            ContactDisposition::Suppress
            | ContactDisposition::Terminal
            | ContactDisposition::Cancelled => ScheduleAction::Park,
        },
    }
}

fn retry_delay(peer: aster_mesh::NodeId, failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(4);
    let base = EVENT_RETRY_INITIAL
        .checked_mul(1_u32 << shift)
        .unwrap_or(EVENT_RETRY_BASE_MAX)
        .min(EVENT_RETRY_BASE_MAX);
    let mut peer_prefix = [0_u8; 8];
    peer_prefix.copy_from_slice(&peer[..8]);
    let seed =
        u64::from_le_bytes(peer_prefix) ^ u64::from(failures).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    let base_millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    let jitter_window = base_millis / 4;
    Duration::from_millis(base_millis.saturating_add(seed % (jitter_window + 1)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::btle::{ActiveBtleRuntime, BtleRuntimeOwner, BtleRuntimeOwnerError};
    #[cfg(feature = "sdk-test-support")]
    use crate::runtime::btle::{BtleRuntimeStartup, unavailable_owner};
    use aster_node::{
        ContactDisposition, EventAdapterControl, EventAdapterSnapshot, EventAdapterState,
        EventAttemptReceiver, EventPeerEligibility, EventTransportKind, RunningNode,
    };
    use futures::FutureExt as _;
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };
    use tokio::task::{AbortHandle, JoinHandle};

    const PEER: aster_mesh::NodeId = [0x22; 32];

    struct ControlledAttempt {
        peer: aster_mesh::NodeId,
        result: tokio::sync::oneshot::Sender<Result<(), ContactOutcome>>,
        observed: tokio::sync::oneshot::Receiver<()>,
    }

    impl ControlledAttempt {
        async fn finish(self, result: Result<(), ContactOutcome>) {
            self.result.send(result).expect("live schedule attempt");
            self.observed.await.expect("schedule observed completion");
            tokio::task::yield_now().await;
        }
    }

    fn controlled_schedule(
        peer: aster_mesh::NodeId,
    ) -> (
        JoinHandle<EventScheduleExit>,
        tokio::sync::mpsc::UnboundedReceiver<ControlledAttempt>,
    ) {
        let (request, requests) = tokio::sync::mpsc::unbounded_channel();
        let schedule = tokio::spawn(run_event_schedule_with(peer, move |peer| {
            let request = request.clone();
            Box::pin(async move {
                let (result, result_receiver) = tokio::sync::oneshot::channel();
                let (observed, observed_receiver) = tokio::sync::oneshot::channel();
                assert!(
                    request
                        .send(ControlledAttempt {
                            peer,
                            result,
                            observed: observed_receiver,
                        })
                        .is_ok(),
                    "controlled attempt receiver"
                );
                let result = result_receiver.await.expect("controlled attempt result");
                let _ = observed.send(());
                AutomaticEventAttemptOutcome::Completed(result)
            }) as BoxFuture<'static, AutomaticEventAttemptOutcome>
        }));
        (schedule, requests)
    }

    fn test_state(label: &str) -> PathBuf {
        static NEXT_STATE: AtomicU64 = AtomicU64::new(1);
        let state = std::env::temp_dir().join(format!(
            "aster-btle-event-schedule-{label}-{}-{}",
            std::process::id(),
            NEXT_STATE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&state).expect("test state root");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))
                .expect("owner-only test state root");
        }
        state
    }

    async fn start_test_node(label: &str) -> (PathBuf, RunningNode) {
        let state = test_state(label);
        let mission = aster_node::mission::UnprotectedReferenceMission::from_bytes(
            include_bytes!("../../../../../bindings/testdata/non-production-provisioning.bundle")
                .to_vec(),
        )
        .expect("test mission");
        let node =
            aster_node::start_transport_neutral_node(aster_node::TransportNeutralNodeConfig {
                state: state.clone(),
                mission,
                mutable_interests: aster_node::MutableSourceInterests::default(),
                sync_interval: Duration::from_secs(60),
                run_for: None,
                application: aster_node::NodeApplication::Relay,
            })
            .await
            .expect("transport-neutral node");
        (state, node)
    }

    struct ScheduleFixture {
        state: PathBuf,
        node: RunningNode,
        automatic: aster_node::RunningAutomaticEventTransportHandle,
        schedule: Option<JoinHandle<EventScheduleExit>>,
        control: EventAdapterControl,
        attempts: EventAttemptReceiver,
    }

    impl ScheduleFixture {
        async fn new() -> Self {
            let (state, node) = start_test_node("fixture").await;
            let automatic = node.automatic_event_transports();
            let (control, attempts) = automatic
                .register(EventAdapterSnapshot::new(
                    EventTransportKind::BLE_L2CAP_V1,
                    1,
                    EventAdapterState::Available,
                    true,
                    10,
                ))
                .expect("test adapter");
            automatic
                .replace_eligibility(vec![EventPeerEligibility::provisioned_exact_peer(
                    node.selected_events().mission_authority(),
                    PEER,
                    EventTransportKind::BLE_L2CAP_V1,
                    true,
                    1,
                    0,
                    None,
                )])
                .expect("install exact peer");
            let schedule = spawn_event_schedule(automatic.clone(), PEER, FixedRole::Initiator);
            Self {
                state,
                node,
                automatic,
                schedule,
                control,
                attempts,
            }
        }

        async fn shutdown(mut self) {
            if let Some(mut schedule) = self.schedule.take() {
                schedule.abort();
                let _ = (&mut schedule).await;
            }
            drop(self.attempts);
            drop(self.control);
            self.node.shutdown().await.expect("test node shutdown");
            std::fs::remove_dir_all(self.state).expect("test state cleanup");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn success_rearms_sixty_seconds_after_completion_not_start() {
        let (schedule, mut requests) = controlled_schedule(PEER);
        let first = requests.recv().await.expect("first live attempt");
        assert_eq!(first.peer, PEER);

        tokio::time::advance(Duration::from_secs(17)).await;
        let completed = tokio::time::Instant::now();
        first.finish(Ok(())).await;

        tokio::time::advance(Duration::from_millis(59_999)).await;
        assert!(requests.recv().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(1)).await;
        let second = requests.recv().await.expect("post-success attempt");
        assert_eq!(second.peer, PEER);
        assert_eq!(
            tokio::time::Instant::now() - completed,
            EVENT_CONTACT_CADENCE
        );

        drop(second);
        schedule.abort();
        let _ = schedule.await;
    }

    #[tokio::test(start_paused = true)]
    async fn retry_later_uses_bounded_deterministic_jitter() {
        let retry = Err(ContactOutcome::admission_busy());
        let mut failures = 0;
        let mut delays = Vec::new();
        for expected_failure in 1..=5 {
            let ScheduleAction::After(delay) = next_delay(PEER, &mut failures, retry) else {
                panic!("retry-later outcome must schedule a delay");
            };
            let shift = (expected_failure - 1).min(4);
            let base = EVENT_RETRY_INITIAL
                .checked_mul(1_u32 << shift)
                .expect("bounded retry base")
                .min(EVENT_RETRY_BASE_MAX);
            assert!(delay >= base);
            assert!(delay <= base + base / 4);
            delays.push(delay);
        }
        assert_eq!(failures, 5);

        let mut repeated_failures = 0;
        let repeated = (0..5)
            .map(|_| {
                let ScheduleAction::After(delay) = next_delay(PEER, &mut repeated_failures, retry)
                else {
                    panic!("retry-later outcome must schedule a delay");
                };
                delay
            })
            .collect::<Vec<_>>();
        assert_eq!(repeated, delays, "jitter must be deterministic per peer");

        let peer_delays = [[0x33; 32], [0x44; 32], [0x55; 32]].map(|peer| {
            let mut failures = 0;
            let ScheduleAction::After(delay) = next_delay(peer, &mut failures, retry) else {
                panic!("retry-later outcome must schedule a delay");
            };
            assert!(delay >= EVENT_RETRY_INITIAL);
            assert!(delay <= EVENT_RETRY_INITIAL + EVENT_RETRY_INITIAL / 4);
            delay
        });
        assert!(
            peer_delays.iter().any(|delay| *delay != delays[0]),
            "peer identity must influence retry jitter"
        );

        let (schedule, mut requests) = controlled_schedule(PEER);
        requests
            .recv()
            .await
            .expect("first live retry attempt")
            .finish(retry)
            .await;
        tokio::time::advance(delays[0] - Duration::from_millis(1)).await;
        assert!(requests.recv().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(
            requests.recv().await.expect("jittered retry attempt").peer,
            PEER
        );

        schedule.abort();
        let _ = schedule.await;
    }

    #[tokio::test(start_paused = true)]
    async fn reselect_submits_one_fresh_event_driven_request_without_sleep_polling() {
        let mut fixture = ScheduleFixture::new().await;
        let first = fixture.attempts.recv().await.expect("initial attempt");
        let outcome = first.fail_carrier_open();
        assert_eq!(outcome.disposition(), ContactDisposition::Reselect);
        // No await has yielded to the schedule yet: publish Unavailable before
        // it observes completion and submits the one replacement request.
        assert!(
            fixture
                .control
                .publish_availability(EventAdapterSnapshot::new(
                    EventTransportKind::BLE_L2CAP_V1,
                    2,
                    EventAdapterState::Unavailable,
                    true,
                    10,
                ))
        );
        tokio::task::yield_now().await;

        tokio::time::advance(Duration::from_secs(3_600)).await;
        assert!(fixture.attempts.recv().now_or_never().is_none());
        assert!(
            fixture
                .control
                .publish_availability(EventAdapterSnapshot::new(
                    EventTransportKind::BLE_L2CAP_V1,
                    3,
                    EventAdapterState::Available,
                    true,
                    10,
                ))
        );
        let selected = fixture.attempts.recv().await.expect("held fresh request");
        assert_eq!(selected.peer(), PEER);
        assert!(fixture.attempts.recv().now_or_never().is_none());

        drop(selected);
        fixture.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn suppression_and_terminal_park_schedule_but_leave_owner_alive() {
        let mut fixture = ScheduleFixture::new().await;
        let mut attempt = fixture.attempts.recv().await.expect("initial attempt");
        fixture
            .automatic
            .replace_eligibility(Vec::new())
            .expect("withdraw exact authority");
        let suppressed = attempt.revocation_outcome().await;
        assert_eq!(suppressed.disposition(), ContactDisposition::Suppress);
        attempt.finish_revoked();
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3_600)).await;
        assert!(fixture.attempts.recv().now_or_never().is_none());
        assert!(!fixture.schedule.as_ref().expect("schedule").is_finished());
        assert!(
            fixture
                .control
                .publish_availability(EventAdapterSnapshot::new(
                    EventTransportKind::BLE_L2CAP_V1,
                    2,
                    EventAdapterState::Available,
                    true,
                    10,
                ))
        );

        let (terminal_schedule, mut terminal_requests) = controlled_schedule(PEER);
        terminal_requests
            .recv()
            .await
            .expect("terminal live attempt")
            .finish(Err(ContactOutcome::admission_closed()))
            .await;
        tokio::time::advance(Duration::from_secs(3_600)).await;
        assert!(terminal_requests.recv().now_or_never().is_none());
        assert!(!terminal_schedule.is_finished());

        let terminal_abort = terminal_schedule.abort_handle();
        let (terminal_owner, terminal_cancelled, _signal, terminal_dropped) =
            cleanup_owner(terminal_abort);
        let mut terminal_active = ActiveBtleRuntime::new(
            Some(Box::new(terminal_owner)),
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );
        terminal_active.schedule = Some(terminal_schedule);
        assert!(!terminal_active.is_terminal());
        terminal_active
            .begin_cleanup()
            .expect("terminal cleanup")
            .await
            .expect("terminal cleanup task")
            .expect("terminal cleanup result");
        assert!(terminal_cancelled.load(Ordering::Acquire));
        assert!(terminal_dropped.load(Ordering::Acquire));
        fixture.shutdown().await;
    }

    struct CleanupOwner {
        schedule: AbortHandle,
        cancelled: Arc<AtomicBool>,
        cancelled_signal: Arc<tokio::sync::Notify>,
        dropped: Arc<AtomicBool>,
        _completion_guard: tokio::sync::watch::Sender<bool>,
        completion: tokio::sync::watch::Receiver<bool>,
    }

    impl Drop for CleanupOwner {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl BtleRuntimeOwner for CleanupOwner {
        fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
            self.completion.clone()
        }

        fn cancel(&self) {
            assert!(
                self.schedule.is_finished(),
                "owner cancelled before Event schedule joined"
            );
            self.cancelled.store(true, Ordering::Release);
            self.cancelled_signal.notify_one();
        }

        fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
            Box::pin(async move {
                assert!(self.cancelled.load(Ordering::Acquire));
                drop(self);
                Ok(())
            })
        }
    }

    fn cleanup_owner(
        schedule: AbortHandle,
    ) -> (
        CleanupOwner,
        Arc<AtomicBool>,
        Arc<tokio::sync::Notify>,
        Arc<AtomicBool>,
    ) {
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancelled_signal = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let (completion_guard, completion) = tokio::sync::watch::channel(false);
        (
            CleanupOwner {
                schedule,
                cancelled: cancelled.clone(),
                cancelled_signal: cancelled_signal.clone(),
                dropped: dropped.clone(),
                _completion_guard: completion_guard,
                completion,
            },
            cancelled,
            cancelled_signal,
            dropped,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_exits_only_during_owner_cleanup() {
        let mut fixture = ScheduleFixture::new().await;
        let attempt = fixture.attempts.recv().await.expect("initial attempt");
        let cancelled_outcome = attempt.cancel_carrier_open();
        assert_eq!(
            cancelled_outcome.disposition(),
            ContactDisposition::Cancelled
        );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(3_600)).await;
        assert!(fixture.attempts.recv().now_or_never().is_none());

        let schedule = fixture.schedule.take().expect("initiator schedule");
        let schedule_abort = schedule.abort_handle();
        let (owner, cancelled, _cancelled_signal, dropped) = cleanup_owner(schedule_abort.clone());
        let mut active = ActiveBtleRuntime::new(
            Some(Box::new(owner)),
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );
        active.schedule = Some(schedule);

        let cleanup = active.begin_cleanup().expect("live schedule cleanup");
        assert!(!cancelled.load(Ordering::Acquire));
        cleanup
            .await
            .expect("cleanup result task")
            .expect("joined schedule and owner");
        assert!(schedule_abort.is_finished());
        assert!(cancelled.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));

        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn admission_closed_schedule_keeps_monitoring_owner_until_clean_completion() {
        let mut fixture = ScheduleFixture::new().await;
        fixture.node.close_transport_admission();
        let schedule = fixture.schedule.take().expect("initiator schedule");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !schedule.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("schedule observes closed admission");

        let schedule_abort = schedule.abort_handle();
        let (owner, cancelled, _cancelled_signal, dropped) = cleanup_owner(schedule_abort);
        let owner_completion = owner._completion_guard.clone();
        let mut active = ActiveBtleRuntime::new(
            Some(Box::new(owner)),
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );
        active.schedule = Some(schedule);

        assert!(active.wait_terminal().now_or_never().is_none());
        assert!(active.schedule.is_none());
        assert!(!active.is_terminal());

        owner_completion.send_replace(true);
        tokio::time::timeout(Duration::from_secs(1), active.wait_terminal())
            .await
            .expect("owner completion must terminate monitoring");
        assert!(active.is_terminal());
        active
            .begin_cleanup()
            .expect("closed-admission cleanup")
            .await
            .expect("cleanup result task")
            .expect("normal schedule exit remains a clean shutdown");
        assert!(cancelled.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));

        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn cleanup_rejects_schedule_exit_for_missing_current_peer() {
        let mut fixture = ScheduleFixture::new().await;
        fixture
            .automatic
            .replace_eligibility(Vec::new())
            .expect("remove current peer while admission stays open");
        let schedule = fixture.schedule.take().expect("initiator schedule");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !schedule.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("schedule observes missing peer");

        let schedule_abort = schedule.abort_handle();
        let (owner, cancelled, _cancelled_signal, dropped) = cleanup_owner(schedule_abort);
        let mut active = ActiveBtleRuntime::new(
            Some(Box::new(owner)),
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );
        active.schedule = Some(schedule);

        assert_eq!(
            active
                .begin_cleanup()
                .expect("missing-peer cleanup")
                .await
                .expect("cleanup result task"),
            Err(BtleRuntimeOwnerError::Cleanup)
        );
        assert!(cancelled.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));

        fixture.shutdown().await;
    }

    #[tokio::test]
    async fn unexpected_schedule_exit_marks_active_runtime_terminal() {
        let (entered, entered_observer) = tokio::sync::oneshot::channel();
        let (release, release_observer) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered);
        let mut release_observer = Some(release_observer);
        let schedule = tokio::spawn(run_event_schedule_with(PEER, move |_peer| {
            let entered = entered.take();
            let release_observer = release_observer.take();
            Box::pin(async move {
                if let Some(entered) = entered {
                    let _ = entered.send(());
                }
                if let Some(release_observer) = release_observer {
                    let _ = release_observer.await;
                }
                AutomaticEventAttemptOutcome::PeerUnavailable
            }) as BoxFuture<'static, AutomaticEventAttemptOutcome>
        }));
        let schedule_abort = schedule.abort_handle();
        let (owner, _cancelled, _cancelled_signal, _dropped) = cleanup_owner(schedule_abort);
        let mut active = ActiveBtleRuntime::new(
            Some(Box::new(owner)),
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );
        active.schedule = Some(schedule);
        entered_observer.await.expect("attempt source entered");
        release.send(()).expect("release attempt source");

        active.wait_terminal().await;
        assert!(active.is_terminal());
        assert_eq!(
            active
                .begin_cleanup()
                .expect("failed schedule cleanup")
                .await
                .expect("cleanup result task"),
            Err(BtleRuntimeOwnerError::Cleanup)
        );
    }

    #[tokio::test]
    async fn drop_joins_schedule_before_owner_cancellation() {
        let schedule = tokio::spawn(std::future::pending::<EventScheduleExit>());
        let schedule_abort = schedule.abort_handle();
        let (owner, cancelled, cancelled_signal, dropped) = cleanup_owner(schedule_abort.clone());
        let mut active = ActiveBtleRuntime::new(
            Some(Box::new(owner)),
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );
        active.schedule = Some(schedule);

        drop(active);
        tokio::time::timeout(Duration::from_secs(1), cancelled_signal.notified())
            .await
            .expect("drop cleanup cancelled owner");
        assert!(schedule_abort.is_finished());
        assert!(cancelled.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));
    }

    #[test]
    fn drop_outside_entered_runtime_retains_cleanup_custody() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("cleanup runtime");
        let (active, schedule_abort, cancelled, cancelled_signal, dropped) = {
            let _entered = runtime.enter();
            let schedule = tokio::spawn(std::future::pending::<EventScheduleExit>());
            let schedule_abort = schedule.abort_handle();
            let (owner, cancelled, cancelled_signal, dropped) =
                cleanup_owner(schedule_abort.clone());
            let mut active = ActiveBtleRuntime::new(
                Some(Box::new(owner)),
                None,
                #[cfg(feature = "sdk-test-support")]
                None,
                #[cfg(feature = "sdk-test-support")]
                None,
            );
            active.schedule = Some(schedule);
            (active, schedule_abort, cancelled, cancelled_signal, dropped)
        };

        assert!(tokio::runtime::Handle::try_current().is_err());
        drop(active);
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(1), cancelled_signal.notified())
                .await
                .expect("captured runtime cancelled owner");
        });

        assert!(schedule_abort.is_finished());
        assert!(cancelled.load(Ordering::Acquire));
        assert!(dropped.load(Ordering::Acquire));
    }

    #[cfg(feature = "sdk-test-support")]
    struct ListenerArtifactProvider(Option<Vec<u8>>);

    #[cfg(feature = "sdk-test-support")]
    impl aster_host::DiscoveryCredentialArtifactProvider for ListenerArtifactProvider {
        fn load_bounded_artifact(
            &mut self,
        ) -> Result<
            aster_host::BoundedDiscoveryCredentialArtifact,
            aster_host::DiscoveryCredentialError,
        > {
            aster_host::BoundedDiscoveryCredentialArtifact::from_zeroizing(zeroize::Zeroizing::new(
                self.0
                    .take()
                    .ok_or(aster_host::DiscoveryCredentialError::ArtifactUnavailable)?,
            ))
        }
    }

    #[cfg(feature = "sdk-test-support")]
    struct ListenerClock;

    #[cfg(feature = "sdk-test-support")]
    impl aster_host::TrustedClock for ListenerClock {
        fn sample(
            &mut self,
        ) -> Result<aster_host::TrustedClockSample, aster_host::DiscoveryCredentialError> {
            Ok(aster_host::TrustedClockSample::new(
                1_800_000_010,
                std::time::Instant::now(),
            ))
        }
    }

    #[cfg(feature = "sdk-test-support")]
    fn listener_peer(local: aster_mesh::NodeId) -> aster_mesh::NodeId {
        let mut peer = local;
        let mut lowered = false;
        for byte in peer.iter_mut().rev() {
            if *byte > 0 {
                *byte -= 1;
                lowered = true;
                break;
            }
            *byte = 0xff;
        }
        assert!(lowered, "test mission identity must admit a lower peer");
        peer
    }

    #[cfg(feature = "sdk-test-support")]
    fn listener_policy(
        state: &std::path::Path,
        peer: aster_mesh::NodeId,
    ) -> crate::config::ValidatedBtlePolicy {
        use std::os::unix::fs::PermissionsExt as _;

        let peer = peer
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let config_path = state.join("listener-config.json");
        let config = serde_json::json!({
            "schema_version": 1,
            "state": { "directory": state },
            "application": { "listen": "127.0.0.1:8181" },
            "health": { "listen": "127.0.0.1:8182" },
            "mesh": {
                "bind": "127.0.0.1:8183",
                "sync_interval_ms": 500,
                "emission_policy": "normal",
                "peers": []
            },
            "credentials": {
                "client_token_file": "/run/aster-agent/client-token",
                "mission_secret_ref_file": "/run/aster-agent/mission-ref",
                "mission_load_id": "11".repeat(32)
            },
            "storage": {
                "max_items": 4_161,
                "max_payload_bytes": 17_891_328,
                "operations": {
                    "max_records": 1_000_000,
                    "max_logical_bytes": 201_326_592,
                    "emergency_reserve": 10_000
                }
            },
            "btle": {
                "peer": peer,
                "deployment_scope_id": "42".repeat(32),
                "policy": "rostered",
                "emission_policy": "normal",
                "priority": 100,
                "credential": "aster-btle-roster"
            }
        });
        std::fs::write(
            &config_path,
            serde_json::to_vec(&config).expect("listener config"),
        )
        .expect("write listener config");
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect listener config");
        let validated = crate::config::load_and_validate_config(&config_path)
            .expect("validated listener config");
        std::fs::remove_file(config_path).expect("listener config cleanup");
        *validated
            .runtime()
            .btle_policy()
            .expect("listener BTLE policy")
    }

    #[cfg(feature = "sdk-test-support")]
    fn listener_prepared(
        state: &std::path::Path,
    ) -> aster_host::PreparedDiscoveryCredential<ListenerArtifactProvider, ListenerClock> {
        use std::{fs::OpenOptions, os::unix::fs::PermissionsExt as _};

        let authority_path = state.join("listener-authority.lock");
        std::fs::write(&authority_path, []).expect("listener authority checkpoint");
        std::fs::set_permissions(&authority_path, std::fs::Permissions::from_mode(0o600))
            .expect("protect listener authority checkpoint");
        let authority = OpenOptions::new()
            .read(true)
            .write(true)
            .open(authority_path)
            .expect("open listener authority checkpoint");
        let mut artifact = Vec::with_capacity(109);
        artifact.extend_from_slice(b"ASTRBD02");
        artifact.extend_from_slice(&1_u64.to_be_bytes());
        artifact.push(1);
        artifact.extend_from_slice(&1_800_000_000_u64.to_be_bytes());
        artifact.extend_from_slice(&1_800_000_060_u64.to_be_bytes());
        artifact.extend_from_slice(&0_u64.to_be_bytes());
        artifact.extend_from_slice(&[0x42; 32]);
        artifact.extend_from_slice(&7_u32.to_be_bytes());
        artifact.extend_from_slice(&[0x11; 32]);
        aster_host::prepare_discovery_credential_for_test(
            ListenerArtifactProvider(Some(artifact)),
            ListenerClock,
            [0x42; 32],
            state,
            authority,
        )
        .expect("prepared listener credential")
    }

    #[cfg(feature = "sdk-test-support")]
    #[tokio::test(start_paused = true)]
    async fn listener_role_never_spawns_an_outbound_schedule() {
        let (state, node) = start_test_node("listener").await;
        let peer = listener_peer(node.selected_events().identity());
        let policy = listener_policy(&state, peer);
        let prepared = listener_prepared(&state);
        let role_seen = Arc::new(AtomicBool::new(false));
        let role_observer = role_seen.clone();
        let (startup, automatic_observer) =
            BtleRuntimeStartup::automatic_linux_with_test_supervisor(
                prepared,
                policy,
                &state,
                move |config, _contacts, registration| {
                    assert_eq!(config.role(), FixedRole::Listener);
                    role_observer.store(true, Ordering::Release);
                    let (_, adapter, attempts) = registration.into_parts();
                    Ok(unavailable_owner(adapter, attempts, ()))
                },
            )
            .expect("listener startup composition");
        let mut active = startup.start(&node).expect("listener runtime");
        let _automatic = automatic_observer.await.expect("automatic observer");
        active.install_eligibility().expect("listener eligibility");

        assert!(role_seen.load(Ordering::Acquire));
        assert!(active.schedule.is_none());
        assert!(active.eligibility.is_none());

        active
            .begin_cleanup()
            .expect("listener cleanup")
            .await
            .expect("listener cleanup task")
            .expect("listener cleanup result");
        node.shutdown().await.expect("listener node shutdown");
        std::fs::remove_dir_all(state).expect("listener state cleanup");
    }
}
