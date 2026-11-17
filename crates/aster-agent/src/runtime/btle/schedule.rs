use std::time::Duration;

use aster_ble_linux::FixedRole;
use aster_node::{ContactDisposition, ContactOutcome, RunningAutomaticEventTransportHandle};
use tokio::task::JoinHandle;

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
) -> Option<JoinHandle<()>> {
    matches!(role, FixedRole::Initiator)
        .then(|| tokio::spawn(run_event_schedule(automatic, peer)))
}

async fn run_event_schedule(
    automatic: RunningAutomaticEventTransportHandle,
    peer: aster_mesh::NodeId,
) {
    let mut failures = 0_u32;
    loop {
        let Some(result) = automatic.run_peer_attempt(peer).await else {
            return;
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
    use aster_node::{
        ContactDisposition, EventAdapterControl, EventAdapterSnapshot, EventAdapterState,
        EventAttemptReceiver, EventPeerEligibility, EventTransportKind, RunningNode,
    };
    use futures::{FutureExt as _, future::BoxFuture};
    use std::{
        path::PathBuf,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        time::Duration,
    };
    use tokio::task::{AbortHandle, JoinHandle};

    const PEER: aster_mesh::NodeId = [0xff; 32];

    struct ScheduleFixture {
        state: PathBuf,
        node: RunningNode,
        automatic: aster_node::RunningAutomaticEventTransportHandle,
        schedule: Option<JoinHandle<()>>,
        control: EventAdapterControl,
        attempts: EventAttemptReceiver,
    }

    impl ScheduleFixture {
        async fn new(role: FixedRole) -> Self {
            static NEXT_STATE: AtomicU64 = AtomicU64::new(1);
            let state = std::env::temp_dir().join(format!(
                "aster-btle-event-schedule-{}-{}",
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
            let mission = aster_node::mission::UnprotectedReferenceMission::from_bytes(
                include_bytes!(
                    "../../../../../bindings/testdata/non-production-provisioning.bundle"
                )
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
            let schedule = spawn_event_schedule(automatic.clone(), PEER, role);
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
        let peer = [0x22; 32];
        let started = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_secs(17)).await;
        let completed = tokio::time::Instant::now();
        let mut failures = 4;

        let ScheduleAction::After(delay) = next_delay(peer, &mut failures, Ok(())) else {
            panic!("success must rearm the Event schedule");
        };
        assert_eq!(delay, EVENT_CONTACT_CADENCE);
        assert_eq!(failures, 0);

        let sleeper = tokio::spawn(tokio::time::sleep_until(completed + delay));
        tokio::task::yield_now().await;
        tokio::time::advance(delay - Duration::from_millis(1)).await;
        assert!(!sleeper.is_finished());
        tokio::time::advance(Duration::from_millis(1)).await;
        sleeper.await.expect("success deadline task");
        assert_eq!(tokio::time::Instant::now() - completed, delay);
        assert_eq!(
            tokio::time::Instant::now() - started,
            delay + Duration::from_secs(17)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retry_later_uses_bounded_deterministic_jitter() {
        let peer = [0x22; 32];
        let mut first_failures = 0;
        let mut repeated_failures = 0;
        let retry = Err(aster_node::ContactOutcome::admission_busy());

        let first = next_delay(peer, &mut first_failures, retry);
        let repeated = next_delay(peer, &mut repeated_failures, retry);
        assert_eq!(first, repeated);
        assert!(matches!(
            first,
            ScheduleAction::After(delay)
                if (Duration::from_secs(5)..=Duration::from_millis(6_250)).contains(&delay)
        ));

        let mut failures = 4;
        let capped = next_delay(peer, &mut failures, retry);
        assert!(matches!(
            capped,
            ScheduleAction::After(delay)
                if (Duration::from_secs(48)..=Duration::from_secs(60)).contains(&delay)
        ));
        assert_eq!(failures, 5);
    }

    #[tokio::test(start_paused = true)]
    async fn reselect_submits_one_fresh_event_driven_request_without_sleep_polling() {
        let mut fixture = ScheduleFixture::new(FixedRole::Initiator).await;
        let first = fixture.attempts.recv().await.expect("initial attempt");
        let completed_at = tokio::time::Instant::now();

        let outcome = first.fail_carrier_open();
        assert_eq!(outcome.disposition(), ContactDisposition::Reselect);
        let second = fixture.attempts.recv().await.expect("fresh reselected attempt");
        assert_eq!(tokio::time::Instant::now(), completed_at);
        assert_eq!(second.peer(), PEER);
        assert!(fixture.attempts.recv().now_or_never().is_none());

        drop(second);
        fixture.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn suppression_and_terminal_park_schedule_but_leave_owner_alive() {
        let mut fixture = ScheduleFixture::new(FixedRole::Initiator).await;
        let mut attempt = fixture.attempts.recv().await.expect("initial attempt");
        fixture
            .automatic
            .replace_eligibility(Vec::new())
            .expect("withdraw exact authority");
        let suppressed = attempt.revocation_outcome().await;
        assert_eq!(suppressed.disposition(), ContactDisposition::Suppress);
        let mut failures = 0;
        assert_eq!(
            next_delay(PEER, &mut failures, Err(suppressed)),
            ScheduleAction::Park
        );
        attempt.finish_revoked(suppressed);

        assert_eq!(
            next_delay(
                PEER,
                &mut failures,
                Err(aster_node::ContactOutcome::admission_closed())
            ),
            ScheduleAction::Park
        );
        tokio::task::yield_now().await;
        assert!(
            !fixture
                .schedule
                .as_ref()
                .expect("initiator schedule")
                .is_finished()
        );
        assert!(fixture.control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            2,
            EventAdapterState::Available,
            true,
            10,
        )));

        fixture.shutdown().await;
    }

    struct CleanupOwner {
        schedule: AbortHandle,
        cancelled: Arc<AtomicBool>,
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
            self.cancelled.store(true, Ordering::Release);
        }

        fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
            Box::pin(async move {
                assert!(self.schedule.is_finished(), "owner joined before Event schedule");
                drop(self);
                Ok(())
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_exits_only_during_owner_cleanup() {
        let mut fixture = ScheduleFixture::new(FixedRole::Initiator).await;
        let attempt = fixture.attempts.recv().await.expect("initial attempt");
        let cancelled_outcome = attempt.cancel_carrier_open();
        assert_eq!(cancelled_outcome.disposition(), ContactDisposition::Cancelled);
        let mut failures = 0;
        assert_eq!(
            next_delay(PEER, &mut failures, Err(cancelled_outcome)),
            ScheduleAction::Park
        );

        let schedule = fixture.schedule.take().expect("initiator schedule");
        let schedule_abort = schedule.abort_handle();
        let cancelled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let (completion_guard, completion) = tokio::sync::watch::channel(false);
        let owner = CleanupOwner {
            schedule: schedule_abort.clone(),
            cancelled: cancelled.clone(),
            dropped: dropped.clone(),
            _completion_guard: completion_guard,
            completion,
        };
        let mut active = ActiveBtleRuntime::new(
            Some(Box::new(owner)),
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
            #[cfg(feature = "sdk-test-support")]
            None,
        );
        active.schedule = Some(schedule);
        assert!(!schedule_abort.is_finished());

        let cleanup = active.begin_cleanup().expect("live schedule cleanup");
        assert!(cancelled.load(Ordering::Acquire));
        cleanup
            .await
            .expect("cleanup result task")
            .expect("joined schedule and owner");
        assert!(schedule_abort.is_finished());
        assert!(dropped.load(Ordering::Acquire));

        fixture.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn listener_role_never_spawns_an_outbound_schedule() {
        let mut fixture = ScheduleFixture::new(FixedRole::Listener).await;

        assert!(fixture.schedule.is_none());
        assert!(fixture.attempts.recv().now_or_never().is_none());
        assert!(fixture.control.publish_availability(EventAdapterSnapshot::new(
            EventTransportKind::BLE_L2CAP_V1,
            2,
            EventAdapterState::Available,
            true,
            10,
        )));

        fixture.shutdown().await;
    }
}
