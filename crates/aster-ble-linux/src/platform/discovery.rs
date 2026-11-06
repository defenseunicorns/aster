use crate::{
    ASTER_ROSTER_BEACON_V1_BYTES, ASTER_ROSTER_SERVICE_UUID, CanonicalLocator,
    CanonicalLocatorError, DriverError, ValidatedControllerConfig,
};
use bluer::{Address, AddressType};
use std::{fmt, future::Future, pin::Pin};
use tokio::sync::mpsc;

pub(crate) const DISCOVERY_OBSERVATION_QUEUE_CAPACITY: usize = 64;

pub(crate) type PlatformFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, DriverError>> + Send + 'a>>;
pub(crate) type TerminationFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

#[derive(Clone, Copy)]
enum BoundedRecord {
    Exact([u8; ASTER_ROSTER_BEACON_V1_BYTES]),
    WrongLength,
}

/// One bounded live Service Data observation from the owned scan.
#[derive(Clone, Copy)]
pub(crate) struct DiscoveryObservation {
    locator: CanonicalLocator,
    record: BoundedRecord,
}

impl DiscoveryObservation {
    pub(crate) fn new(
        address: Address,
        address_type: AddressType,
        record: &[u8],
    ) -> Result<Self, DiscoveryObservationError> {
        let locator = CanonicalLocator::new(address, address_type).map_err(
            |CanonicalLocatorError::NonLeAddress| DiscoveryObservationError::NonLeLocator,
        )?;
        let record = record
            .try_into()
            .map(BoundedRecord::Exact)
            .unwrap_or(BoundedRecord::WrongLength);
        Ok(Self { locator, record })
    }

    pub(crate) const fn locator(&self) -> CanonicalLocator {
        self.locator
    }

    pub(crate) fn record(&self) -> &[u8] {
        match &self.record {
            BoundedRecord::Exact(record) => record,
            BoundedRecord::WrongLength => &[],
        }
    }
}

impl fmt::Debug for DiscoveryObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DiscoveryObservation([REDACTED])")
    }
}

/// Closed translation failure before an observation enters the bounded queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DiscoveryObservationError {
    NonLeLocator,
}

/// Exact private service UUID and authenticated record advertised together.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RosterAdvertisement {
    record: [u8; ASTER_ROSTER_BEACON_V1_BYTES],
}

impl fmt::Debug for RosterAdvertisement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RosterAdvertisement([REDACTED])")
    }
}

impl RosterAdvertisement {
    pub(crate) const fn new(record: [u8; ASTER_ROSTER_BEACON_V1_BYTES]) -> Self {
        Self { record }
    }

    pub(crate) const fn service_uuid(&self) -> [u8; 16] {
        ASTER_ROSTER_SERVICE_UUID
    }

    pub(crate) const fn record(&self) -> &[u8; ASTER_ROSTER_BEACON_V1_BYTES] {
        &self.record
    }
}

pub(crate) trait OwnedAdvertisement: Send {
    fn stop(self: Box<Self>) -> PlatformFuture<'static, ()>;
    fn terminated(&mut self) -> TerminationFuture<'_>;
}

pub(crate) trait OwnedScan: Send {
    fn stop(self: Box<Self>) -> PlatformFuture<'static, ()>;
    fn terminated(&mut self) -> TerminationFuture<'_>;
}

pub(crate) struct StartedScan {
    owner: Box<dyn OwnedScan>,
    observations: mpsc::Receiver<DiscoveryObservation>,
}

impl StartedScan {
    pub(crate) const fn new(
        owner: Box<dyn OwnedScan>,
        observations: mpsc::Receiver<DiscoveryObservation>,
    ) -> Self {
        Self {
            owner,
            observations,
        }
    }

    pub(crate) fn into_parts(self) -> (Box<dyn OwnedScan>, mpsc::Receiver<DiscoveryObservation>) {
        (self.owner, self.observations)
    }
}

pub(crate) trait DiscoveryPlatform: Send + Sync {
    fn start_advertisement<'a>(
        &'a self,
        controller: &'a ValidatedControllerConfig,
        advertisement: RosterAdvertisement,
    ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>>;

    fn start_scan<'a>(
        &'a self,
        controller: &'a ValidatedControllerConfig,
    ) -> PlatformFuture<'a, StartedScan>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ContactLimits, ControllerConfig, DiscoveryCredential, DiscoveryGeneration, DiscoverySecret,
        LeasedDiscoveryCredentialSet, RING1_MAXIMUM_EXCHANGE_BYTES, RING1_MAXIMUM_FRAME_BYTES,
        RosteredAdapterConfig, RosteredDiscoveryConfig, RosteredSupervisorConfig,
        ValidatedRosteredSupervisorConfig,
    };
    use bluer::{Address, AddressType};
    use std::{
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };
    use tokio::sync::{Notify, mpsc};

    fn config() -> ValidatedRosteredSupervisorConfig {
        let credentials = LeasedDiscoveryCredentialSet::new(
            DiscoveryCredential::new(
                DiscoveryGeneration::new(7).unwrap(),
                DiscoverySecret::new([0x42; 32]).unwrap(),
            ),
            None,
            Instant::now() + Duration::from_secs(60),
        )
        .unwrap();
        RosteredAdapterConfig::Enabled(RosteredSupervisorConfig {
            controller: ControllerConfig {
                adapter_name: "hci7".to_owned(),
                local_address: Address::new([2, 0, 0, 0, 0, 1]),
                local_address_type: AddressType::LeRandom,
            },
            discovery: RosteredDiscoveryConfig { credentials },
            local_mission_id: [0x11; 32],
            peer_mission_id: [0x22; 32],
            contact_cadence: Duration::from_secs(60),
            contact_limits: ContactLimits {
                maximum_frame_bytes: RING1_MAXIMUM_FRAME_BYTES,
                maximum_exchange_bytes: RING1_MAXIMUM_EXCHANGE_BYTES,
                open_timeout: Duration::from_secs(5),
                operation_timeout: Duration::from_secs(30),
            },
        })
        .validate()
        .unwrap()
        .unwrap()
    }

    struct FakeOwner {
        stopped: Arc<AtomicBool>,
        terminated: Arc<Notify>,
    }

    impl OwnedAdvertisement for FakeOwner {
        fn stop(self: Box<Self>) -> PlatformFuture<'static, ()> {
            Box::pin(async move {
                self.stopped.store(true, Ordering::Release);
                Ok(())
            })
        }

        fn terminated(&mut self) -> TerminationFuture<'_> {
            Box::pin(async move { self.terminated.notified().await })
        }
    }

    impl OwnedScan for FakeOwner {
        fn stop(self: Box<Self>) -> PlatformFuture<'static, ()> {
            Box::pin(async move {
                self.stopped.store(true, Ordering::Release);
                Ok(())
            })
        }

        fn terminated(&mut self) -> TerminationFuture<'_> {
            Box::pin(async move { self.terminated.notified().await })
        }
    }

    struct FakePlatform {
        advertisement: Mutex<Option<RosterAdvertisement>>,
        sender: Mutex<Option<mpsc::Sender<DiscoveryObservation>>>,
        advertisement_stopped: Arc<AtomicBool>,
        advertisement_terminated: Arc<Notify>,
        scan_stopped: Arc<AtomicBool>,
        scan_terminated: Arc<Notify>,
    }

    impl DiscoveryPlatform for FakePlatform {
        fn start_advertisement<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
            advertisement: RosterAdvertisement,
        ) -> PlatformFuture<'a, Box<dyn OwnedAdvertisement>> {
            *self.advertisement.lock().unwrap() = Some(advertisement);
            let owner = FakeOwner {
                stopped: self.advertisement_stopped.clone(),
                terminated: self.advertisement_terminated.clone(),
            };
            Box::pin(async move { Ok(Box::new(owner) as Box<dyn OwnedAdvertisement>) })
        }

        fn start_scan<'a>(
            &'a self,
            _controller: &'a ValidatedControllerConfig,
        ) -> PlatformFuture<'a, StartedScan> {
            let (sender, receiver) = mpsc::channel(DISCOVERY_OBSERVATION_QUEUE_CAPACITY);
            *self.sender.lock().unwrap() = Some(sender);
            let owner = FakeOwner {
                stopped: self.scan_stopped.clone(),
                terminated: self.scan_terminated.clone(),
            };
            Box::pin(async move {
                Ok(StartedScan::new(
                    Box::new(owner) as Box<dyn OwnedScan>,
                    receiver,
                ))
            })
        }
    }

    #[test]
    fn observation_translation_is_canonical_and_bounds_service_data() {
        let public = DiscoveryObservation::new(
            Address::new([2, 0, 0, 0, 0, 1]),
            AddressType::LePublic,
            &[0x55; 40],
        )
        .unwrap();
        let random = DiscoveryObservation::new(
            Address::new([2, 0, 0, 0, 0, 2]),
            AddressType::LeRandom,
            &[0x66; 40],
        )
        .unwrap();
        assert_eq!(public.locator().address_type(), AddressType::LePublic);
        assert_eq!(random.locator().address_type(), AddressType::LeRandom);
        assert_eq!(public.record(), &[0x55; 40]);
        assert_eq!(
            DiscoveryObservation::new(Address::new([1; 6]), AddressType::BrEdr, &[0; 40])
                .unwrap_err(),
            DiscoveryObservationError::NonLeLocator
        );

        let oversized = DiscoveryObservation::new(
            Address::new([2, 0, 0, 0, 0, 3]),
            AddressType::LeRandom,
            &[0x77; 41],
        )
        .unwrap();
        assert!(oversized.record().is_empty());
    }

    #[tokio::test]
    async fn fake_platform_preserves_exact_advertisement_queue_and_owned_stop() {
        let platform = FakePlatform {
            advertisement: Mutex::new(None),
            sender: Mutex::new(None),
            advertisement_stopped: Arc::new(AtomicBool::new(false)),
            advertisement_terminated: Arc::new(Notify::new()),
            scan_stopped: Arc::new(AtomicBool::new(false)),
            scan_terminated: Arc::new(Notify::new()),
        };
        let record = [0x55; 40];
        let advertisement = RosterAdvertisement::new(record);
        let mut owned_advertisement = platform
            .start_advertisement(config().controller(), advertisement)
            .await
            .unwrap();
        assert_eq!(
            platform
                .advertisement
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .service_uuid(),
            ASTER_ROSTER_SERVICE_UUID
        );
        assert_eq!(
            platform
                .advertisement
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .record(),
            &record
        );
        let debug = format!("{advertisement:?}");
        assert_eq!(debug, "RosterAdvertisement([REDACTED])");
        assert!(!debug.contains("55"));
        platform.advertisement_terminated.notify_one();
        owned_advertisement.terminated().await;
        owned_advertisement.stop().await.unwrap();
        assert!(platform.advertisement_stopped.load(Ordering::Acquire));

        let started_scan = platform.start_scan(config().controller()).await.unwrap();
        let (mut owned_scan, _receiver) = started_scan.into_parts();
        let sender = platform.sender.lock().unwrap().take().unwrap();
        for index in 0..DISCOVERY_OBSERVATION_QUEUE_CAPACITY {
            sender
                .try_send(
                    DiscoveryObservation::new(
                        Address::new([2, 0, 0, 0, 0, index as u8]),
                        AddressType::LeRandom,
                        &[index as u8; 40],
                    )
                    .unwrap(),
                )
                .unwrap();
        }
        assert!(matches!(
            sender.try_send(
                DiscoveryObservation::new(
                    Address::new([2, 0, 0, 0, 0, 99]),
                    AddressType::LeRandom,
                    &[0x99; 40],
                )
                .unwrap()
            ),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        platform.scan_terminated.notify_one();
        owned_scan.terminated().await;
        owned_scan.stop().await.unwrap();
        assert!(platform.scan_stopped.load(Ordering::Acquire));
    }
}
