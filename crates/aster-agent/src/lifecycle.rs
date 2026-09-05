//! Process lifecycle decisions shared by the agent's public listeners.

use std::{
    error::Error,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

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
}

impl ServiceStatus {
    /// Creates the initial status for a process that has not completed startup.
    pub fn starting() -> Self {
        Self {
            state: Arc::new(AtomicU8::new(LifecycleState::Starting as u8)),
            failure: Arc::new(Mutex::new(None)),
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

    fn transition_without_failure(&self, next: LifecycleState) -> Result<(), LifecycleError> {
        let current = self.state();
        if !current.permits(next) {
            return Err(LifecycleError {
                current,
                requested: next,
            });
        }
        if current == next {
            return Ok(());
        }

        self.state
            .compare_exchange(
                current as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|observed| LifecycleError {
                current: LifecycleState::from_u8(observed),
                requested: next,
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
}
