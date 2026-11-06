use crate::{ValidatedLinkConfig, policy::LifecycleCancellation};
use bluer::ErrorKind;
use std::{fmt, future::Future, pin::Pin, sync::Arc};
use tokio::time::timeout;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerAclState {
    Absent,
    Disconnected,
    Connected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerAclObservation {
    State(PeerAclState),
    Unavailable,
    TimedOut,
    Cancelled,
}

impl fmt::Display for PeerAclObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::State(PeerAclState::Absent) => "absent",
            Self::State(PeerAclState::Disconnected) => "disconnected",
            Self::State(PeerAclState::Connected) => "connected",
            Self::Unavailable => "unavailable",
            Self::TimedOut => "timeout",
            Self::Cancelled => "cancelled",
        })
    }
}

pub(crate) type PeerAclFuture<'a> = Pin<Box<dyn Future<Output = PeerAclObservation> + Send + 'a>>;

pub(crate) trait PeerAclObserver: Send + Sync {
    fn observe<'a>(
        &'a self,
        link: &'a ValidatedLinkConfig,
        cancellation: &'a LifecycleCancellation,
    ) -> PeerAclFuture<'a>;
}

type PeerAclProbeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<bool>, PeerAclProbeError>> + Send + 'a>>;

trait PeerAclProbe: Send + Sync {
    fn probe<'a>(&'a self, link: &'a ValidatedLinkConfig) -> PeerAclProbeFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PeerAclProbeError {
    Absent,
    Unavailable,
}

pub(crate) struct BluezPeerAclObserver {
    probe: Arc<dyn PeerAclProbe>,
}

impl BluezPeerAclObserver {
    pub(crate) fn new() -> Self {
        Self {
            probe: Arc::new(BluezPeerAclProbe),
        }
    }

    #[cfg(test)]
    fn with_probe(probe: Arc<dyn PeerAclProbe>) -> Self {
        Self { probe }
    }
}

impl PeerAclObserver for BluezPeerAclObserver {
    fn observe<'a>(
        &'a self,
        link: &'a ValidatedLinkConfig,
        cancellation: &'a LifecycleCancellation,
    ) -> PeerAclFuture<'a> {
        Box::pin(async move {
            tokio::select! {
                biased;
                () = cancellation.cancelled() => PeerAclObservation::Cancelled,
                result = timeout(link.open_timeout(), self.probe.probe(link)) => match result {
                    Err(_) => PeerAclObservation::TimedOut,
                    Ok(Err(PeerAclProbeError::Unavailable)) => PeerAclObservation::Unavailable,
                    Ok(Err(PeerAclProbeError::Absent)) | Ok(Ok(None)) => {
                        PeerAclObservation::State(PeerAclState::Absent)
                    }
                    Ok(Ok(Some(false))) => {
                        PeerAclObservation::State(PeerAclState::Disconnected)
                    }
                    Ok(Ok(Some(true))) => PeerAclObservation::State(PeerAclState::Connected),
                }
            }
        })
    }
}

struct BluezPeerAclProbe;

impl PeerAclProbe for BluezPeerAclProbe {
    fn probe<'a>(&'a self, link: &'a ValidatedLinkConfig) -> PeerAclProbeFuture<'a> {
        Box::pin(async move {
            let session = bluer::Session::new()
                .await
                .map_err(|_| PeerAclProbeError::Unavailable)?;
            let adapter = session
                .adapter(link.adapter_name())
                .map_err(|_| PeerAclProbeError::Unavailable)?;
            let addresses = adapter
                .device_addresses()
                .await
                .map_err(|_| PeerAclProbeError::Unavailable)?;
            if !addresses.contains(&link.peer_address()) {
                return Ok(None);
            }
            let device = adapter
                .device(link.peer_address())
                .map_err(classify_bluer_error)?;
            device
                .is_connected()
                .await
                .map(Some)
                .map_err(classify_bluer_error)
        })
    }
}

fn classify_bluer_error(error: bluer::Error) -> PeerAclProbeError {
    match error.kind {
        ErrorKind::DoesNotExist | ErrorKind::NotFound => PeerAclProbeError::Absent,
        _ => PeerAclProbeError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LinkConfig, RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES};
    use bluer::{Address, AddressType, ErrorKind, InternalErrorKind};
    use std::{
        future::pending,
        str::FromStr,
        sync::{Arc, Mutex},
        time::Duration,
    };

    fn address(value: &str) -> Address {
        Address::from_str(value).expect("test Bluetooth address")
    }

    fn link() -> crate::ValidatedLinkConfig {
        LinkConfig {
            adapter_name: "hci7".to_owned(),
            local_address: address("02:00:00:00:00:01"),
            local_address_type: AddressType::LeRandom,
            peer_address: address("02:00:00:00:00:02"),
            peer_address_type: AddressType::LePublic,
            psm: 0x0081,
            maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
            maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
            open_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(30),
        }
        .validate()
        .expect("test link configuration")
    }

    struct FakeProbe {
        result: Mutex<Option<Result<Option<bool>, PeerAclProbeError>>>,
    }

    impl PeerAclProbe for FakeProbe {
        fn probe<'a>(&'a self, _link: &'a crate::ValidatedLinkConfig) -> PeerAclProbeFuture<'a> {
            let result = self.result.lock().unwrap().take().unwrap();
            Box::pin(async move { result })
        }
    }

    async fn observe(result: Result<Option<bool>, PeerAclProbeError>) -> PeerAclObservation {
        BluezPeerAclObserver::with_probe(Arc::new(FakeProbe {
            result: Mutex::new(Some(result)),
        }))
        .observe(&link(), &crate::policy::LifecycleCancellation::new())
        .await
    }

    #[tokio::test]
    async fn classifies_absent_disconnected_and_connected_peer_acl() {
        assert_eq!(
            observe(Ok(None)).await,
            PeerAclObservation::State(PeerAclState::Absent)
        );
        assert_eq!(
            observe(Ok(Some(false))).await,
            PeerAclObservation::State(PeerAclState::Disconnected)
        );
        assert_eq!(
            observe(Ok(Some(true))).await,
            PeerAclObservation::State(PeerAclState::Connected)
        );
    }

    #[test]
    fn maps_missing_device_permission_and_dbus_errors_to_closed_categories() {
        let missing = bluer::Error {
            kind: ErrorKind::DoesNotExist,
            message: "sensitive missing-device detail".to_owned(),
        };
        let unauthorized = bluer::Error {
            kind: ErrorKind::NotAuthorized,
            message: "sensitive permission detail".to_owned(),
        };
        let daemon_loss = bluer::Error {
            kind: ErrorKind::Internal(InternalErrorKind::DBusConnectionLost),
            message: "sensitive D-Bus detail".to_owned(),
        };

        assert_eq!(classify_bluer_error(missing), PeerAclProbeError::Absent);
        assert_eq!(
            classify_bluer_error(unauthorized),
            PeerAclProbeError::Unavailable
        );
        assert_eq!(
            classify_bluer_error(daemon_loss),
            PeerAclProbeError::Unavailable
        );
    }

    #[tokio::test]
    async fn diagnostic_output_never_contains_probe_or_locator_details() {
        let observation = observe(Err(PeerAclProbeError::Unavailable)).await;

        assert_eq!(observation, PeerAclObservation::Unavailable);
        assert_eq!(observation.to_string(), "unavailable");
        assert!(!observation.to_string().contains("hci7"));
        assert!(!observation.to_string().contains("02:00"));
    }

    struct PendingProbe;

    impl PeerAclProbe for PendingProbe {
        fn probe<'a>(&'a self, _link: &'a crate::ValidatedLinkConfig) -> PeerAclProbeFuture<'a> {
            Box::pin(pending())
        }
    }

    #[tokio::test]
    async fn cancellation_ends_a_stuck_observation() {
        let observer = BluezPeerAclObserver::with_probe(Arc::new(PendingProbe));
        let cancellation = crate::policy::LifecycleCancellation::new();
        cancellation.cancel();

        assert_eq!(
            observer.observe(&link(), &cancellation).await,
            PeerAclObservation::Cancelled
        );
    }

    #[tokio::test(start_paused = true)]
    async fn link_deadline_bounds_a_stuck_observation() {
        let observer = BluezPeerAclObserver::with_probe(Arc::new(PendingProbe));
        let cancellation = crate::policy::LifecycleCancellation::new();

        assert_eq!(
            observer.observe(&link(), &cancellation).await,
            PeerAclObservation::TimedOut
        );
    }
}
