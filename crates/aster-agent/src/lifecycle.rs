//! Process lifecycle decisions shared by the agent's public listeners.

use std::{
    error::Error,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

use tokio::sync::watch;

use crate::credentials::CredentialGeneration;

pub(crate) fn credential_generation_hex(generation: CredentialGeneration) -> String {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in generation.as_bytes() {
        encoded.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

/// The lifecycle phase of one agent process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleState {
    Starting,
    Ready,
    Draining,
    Stopped,
    Failed,
}

impl LifecycleState {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Starting,
            1 => Self::Ready,
            2 => Self::Draining,
            3 => Self::Stopped,
            4 => Self::Failed,
            _ => unreachable!("the lifecycle state is private and validated"),
        }
    }

    const fn permits(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Starting, Self::Ready | Self::Failed)
                | (Self::Ready, Self::Draining | Self::Failed)
                | (Self::Draining, Self::Stopped | Self::Failed)
                | (Self::Stopped, Self::Stopped)
                | (Self::Failed, Self::Failed)
        )
    }
}

/// A fixed, non-sensitive category for a terminal service failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureReason {
    /// The process could not complete local initialization.
    Startup,
    /// A running local service failed.
    Runtime,
    /// The process could not drain or stop cleanly.
    Shutdown,
    /// A caller did not provide a more specific fixed category.
    Unspecified,
}

/// A lifecycle endpoint whose status can be observed without exposing details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthEndpoint {
    /// The process is alive while starting, ready, or draining.
    Live,
    /// The process is ready only after initialization completes.
    Ready,
}

/// The status-only outcome for a health endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HealthDecision {
    /// The endpoint may answer successfully.
    Healthy,
    /// The endpoint may answer with an unavailable status.
    Unhealthy,
    /// The endpoint is no longer served after the process stops.
    Absent,
}

impl HealthDecision {
    /// Returns the HTTP status for an active health listener.
    pub const fn status(self) -> Option<u16> {
        match self {
            Self::Healthy => Some(200),
            Self::Unhealthy => Some(503),
            Self::Absent => None,
        }
    }
}

/// A rejected lifecycle transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleError {
    current: LifecycleState,
    requested: LifecycleState,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (self.current, self.requested);
        formatter.write_str("lifecycle transition is not permitted")
    }
}

impl Error for LifecycleError {}

/// Shared, process-local lifecycle status.
#[derive(Clone)]
pub struct ServiceStatus {
    state: Arc<AtomicU8>,
    failure: Arc<Mutex<Option<FailureReason>>>,
    changes: Arc<watch::Sender<LifecycleState>>,
}

impl ServiceStatus {
    /// Creates the initial status for a process that has not completed startup.
    pub fn starting() -> Self {
        let (changes, _) = watch::channel(LifecycleState::Starting);
        Self {
            state: Arc::new(AtomicU8::new(LifecycleState::Starting as u8)),
            failure: Arc::new(Mutex::new(None)),
            changes: Arc::new(changes),
        }
    }

    /// Returns the current lifecycle phase.
    pub fn state(&self) -> LifecycleState {
        LifecycleState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Returns the fixed failure category, if the process has failed.
    pub fn failure_reason(&self) -> Option<FailureReason> {
        *self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Moves to a permitted next state.
    pub fn transition(&self, next: LifecycleState) -> Result<(), LifecycleError> {
        if next == LifecycleState::Failed {
            return self.fail(FailureReason::Unspecified);
        }

        self.transition_without_failure(next)
    }

    /// Moves to the failed state while retaining only a fixed public category.
    pub fn fail(&self, reason: FailureReason) -> Result<(), LifecycleError> {
        let mut failure = self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = self.state();
        if !current.permits(LifecycleState::Failed) {
            return Err(LifecycleError {
                current,
                requested: LifecycleState::Failed,
            });
        }
        if current == LifecycleState::Failed {
            return Ok(());
        }

        self.state
            .compare_exchange(
                current as u8,
                LifecycleState::Failed as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|observed| LifecycleError {
                current: LifecycleState::from_u8(observed),
                requested: LifecycleState::Failed,
            })?;
        *failure = Some(reason);
        let _ = self.changes.send(LifecycleState::Failed);
        Ok(())
    }

    /// Decides the externally visible, detail-free result for one endpoint.
    pub fn health(&self, endpoint: HealthEndpoint) -> HealthDecision {
        match (self.state(), endpoint) {
            (LifecycleState::Stopped, _) => HealthDecision::Absent,
            (LifecycleState::Failed, _) => HealthDecision::Unhealthy,
            (
                LifecycleState::Starting | LifecycleState::Ready | LifecycleState::Draining,
                HealthEndpoint::Live,
            ) => HealthDecision::Healthy,
            (LifecycleState::Ready, HealthEndpoint::Ready) => HealthDecision::Healthy,
            (LifecycleState::Starting | LifecycleState::Draining, HealthEndpoint::Ready) => {
                HealthDecision::Unhealthy
            }
        }
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<LifecycleState> {
        self.changes.subscribe()
    }

    fn transition_without_failure(&self, next: LifecycleState) -> Result<(), LifecycleError> {
        let mut current = self.state();
        loop {
            if !current.permits(next) {
                return Err(LifecycleError {
                    current,
                    requested: next,
                });
            }
            if current == next {
                return Ok(());
            }

            match self.state.compare_exchange(
                current as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    let _ = self.changes.send(next);
                    return Ok(());
                }
                Err(observed) => current = LifecycleState::from_u8(observed),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn assert_health(state: LifecycleState, live: u16, ready: u16) {
        let status = ServiceStatus::starting();
        for next in match state {
            LifecycleState::Starting => &[][..],
            LifecycleState::Ready => &[LifecycleState::Ready],
            LifecycleState::Draining => &[LifecycleState::Ready, LifecycleState::Draining],
            LifecycleState::Stopped => &[
                LifecycleState::Ready,
                LifecycleState::Draining,
                LifecycleState::Stopped,
            ],
            LifecycleState::Failed => &[LifecycleState::Failed],
        } {
            status
                .transition(*next)
                .expect("legal lifecycle transition");
        }
        assert_eq!(status.health(HealthEndpoint::Live).status(), Some(live));
        assert_eq!(status.health(HealthEndpoint::Ready).status(), Some(ready));
    }

    #[test]
    fn lifecycle_health_matrix_is_exact() {
        assert_health(LifecycleState::Starting, 200, 503);
        assert_health(LifecycleState::Ready, 200, 200);
        assert_health(LifecycleState::Draining, 200, 503);
        assert_health(LifecycleState::Failed, 503, 503);
    }

    #[test]
    fn lifecycle_allows_only_approved_transitions() {
        let status = ServiceStatus::starting();
        assert_eq!(status.state(), LifecycleState::Starting);
        assert!(status.transition(LifecycleState::Draining).is_err());
        status
            .transition(LifecycleState::Ready)
            .expect("starting becomes ready");
        assert!(status.transition(LifecycleState::Stopped).is_err());
        status
            .transition(LifecycleState::Draining)
            .expect("ready begins draining");
        status
            .transition(LifecycleState::Stopped)
            .expect("draining becomes stopped");
        assert_eq!(status.health(HealthEndpoint::Live), HealthDecision::Absent);
        assert!(status.transition(LifecycleState::Ready).is_err());
    }

    #[test]
    fn failure_reason_is_fixed_and_not_an_error_chain() {
        let status = ServiceStatus::starting();
        status
            .fail(FailureReason::Startup)
            .expect("starting may fail");
        assert_eq!(status.state(), LifecycleState::Failed);
        assert_eq!(status.failure_reason(), Some(FailureReason::Startup));
    }

    #[test]
    fn every_declared_transition_pair_has_its_declared_result() {
        let states = [
            LifecycleState::Starting,
            LifecycleState::Ready,
            LifecycleState::Draining,
            LifecycleState::Stopped,
            LifecycleState::Failed,
        ];
        for current in states {
            for next in states {
                let status = status_at(current);
                let expected = matches!(
                    (current, next),
                    (
                        LifecycleState::Starting,
                        LifecycleState::Ready | LifecycleState::Failed
                    ) | (
                        LifecycleState::Ready,
                        LifecycleState::Draining | LifecycleState::Failed
                    ) | (
                        LifecycleState::Draining,
                        LifecycleState::Stopped | LifecycleState::Failed
                    ) | (LifecycleState::Stopped, LifecycleState::Stopped)
                        | (LifecycleState::Failed, LifecycleState::Failed)
                );
                assert_eq!(
                    status.transition(next).is_ok(),
                    expected,
                    "{current:?} -> {next:?}"
                );
            }
        }
    }

    #[test]
    fn concurrent_terminal_self_observation_succeeds() {
        let status = status_at(LifecycleState::Draining);
        let barrier = Arc::new(Barrier::new(33));
        let mut workers = Vec::new();
        for _ in 0..32 {
            let status = status.clone();
            let barrier = barrier.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                status.transition(LifecycleState::Stopped)
            }));
        }
        barrier.wait();
        for worker in workers {
            worker
                .join()
                .expect("worker does not panic")
                .expect("terminal transition or self-observation");
        }
        assert_eq!(status.state(), LifecycleState::Stopped);
    }

    fn status_at(state: LifecycleState) -> ServiceStatus {
        let status = ServiceStatus::starting();
        match state {
            LifecycleState::Starting => {}
            LifecycleState::Ready => status.transition(LifecycleState::Ready).expect("ready"),
            LifecycleState::Draining => {
                status.transition(LifecycleState::Ready).expect("ready");
                status
                    .transition(LifecycleState::Draining)
                    .expect("draining");
            }
            LifecycleState::Stopped => {
                status.transition(LifecycleState::Ready).expect("ready");
                status
                    .transition(LifecycleState::Draining)
                    .expect("draining");
                status.transition(LifecycleState::Stopped).expect("stopped");
            }
            LifecycleState::Failed => status.transition(LifecycleState::Failed).expect("failed"),
        }
        status
    }
}
