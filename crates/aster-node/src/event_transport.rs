//! Closed outcomes shared by Event transport admission and selection.

use std::{error::Error, fmt};

/// Last trusted transition reached by one Event contact attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactStage {
    /// The candidate has not opened a carrier contact.
    Candidate,
    /// The adapter is opening the carrier contact.
    CarrierOpen,
    /// The carrier is open but the mission transcript is not authenticated.
    MissionHandshake,
    /// The exact expected mission peer has authenticated.
    AuthenticatedSession,
}

/// Authority scope affected by one contact outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactScope {
    /// One unauthenticated transient carrier locator.
    Locator,
    /// One locally observed adapter lifecycle epoch.
    AdapterEpoch,
    /// The exact mission peer authenticated by the completed transcript.
    ExpectedPeer,
    /// The authenticated mission session.
    Mission,
    /// Local or authenticated mission policy.
    Policy,
    /// Only this scheduled attempt.
    Attempt,
}

/// Trusted source of the outcome's scope classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactProvenance {
    /// Local admission or cancellation state.
    Local,
    /// Local adapter lifecycle state.
    Adapter,
    /// Remote or ambiguous evidence observed before mission authentication.
    UnauthenticatedRemote,
    /// A completed transcript authenticating the exact expected mission peer.
    AuthenticatedMission,
}

/// Scheduler action authorized by one terminal contact outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactDisposition {
    /// End the operation without an automatic retry.
    Terminal,
    /// Keep durable work pending for a later independently selected operation.
    RetryLater,
    /// Wake selection because local evidence proves this carrier is unavailable.
    Reselect,
    /// Suppress authenticated peer, mission, or policy work until authority changes.
    Suppress,
    /// Preserve caller cancellation as cancellation.
    Cancelled,
}

/// Sanitized closed reason for one contact outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactReason {
    /// Contact admission is closed.
    AdmissionClosed,
    /// The bounded contact lane is occupied.
    AdmissionBusy,
    /// The node actor cannot receive another command.
    ActorUnavailable,
    /// The node actor stopped before contact completion.
    ActorStopped,
    /// The contact caller cancelled its response wait.
    CallerCancelled,
    /// Local adapter state proves carrier opening is unavailable.
    CarrierUnavailable,
    /// An established carrier was interrupted.
    TransportInterrupted,
    /// A bounded carrier or session deadline elapsed.
    TransportTimeout,
    /// The authenticated mission identity differed from the expected identity.
    IdentityMismatch,
    /// The mission transcript failed authentication before exact peer admission.
    AuthenticationFailed,
    /// Authenticated policy rejected or invalidated the session.
    PolicyRejected,
    /// Authenticated protocol or integrity processing rejected the session.
    ProtocolViolation,
    /// A local invariant failed and the node cannot safely retry the contact.
    LocalInvariant,
}

/// Closed terminal result for one Event contact attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactOutcome {
    stage: ContactStage,
    scope: ContactScope,
    provenance: ContactProvenance,
    disposition: ContactDisposition,
    reason: ContactReason,
}

impl ContactOutcome {
    /// Creates the fixed local outcome for closed node admission.
    pub const fn admission_closed() -> Self {
        Self::local_admission(ContactDisposition::Terminal, ContactReason::AdmissionClosed)
    }

    /// Creates the fixed local outcome for an occupied bounded admission lane.
    pub const fn admission_busy() -> Self {
        Self::local_admission(ContactDisposition::RetryLater, ContactReason::AdmissionBusy)
    }

    /// Creates the fixed local outcome for an unavailable node actor mailbox.
    pub const fn actor_unavailable() -> Self {
        Self::local_admission(
            ContactDisposition::RetryLater,
            ContactReason::ActorUnavailable,
        )
    }

    /// Creates the fixed local outcome for actor loss before completion.
    pub const fn actor_stopped() -> Self {
        Self::local_admission(ContactDisposition::Terminal, ContactReason::ActorStopped)
    }

    /// Creates the fixed local outcome for a proven unavailable adapter epoch.
    #[allow(dead_code)] // Consumed by the automatic attempt ticket in Task 2.
    pub(crate) const fn carrier_open_unavailable() -> Self {
        Self {
            stage: ContactStage::CarrierOpen,
            scope: ContactScope::AdapterEpoch,
            provenance: ContactProvenance::Adapter,
            disposition: ContactDisposition::Reselect,
            reason: ContactReason::CarrierUnavailable,
        }
    }

    pub(crate) const fn caller_cancelled(stage: ContactStage) -> Self {
        Self {
            stage,
            scope: ContactScope::Attempt,
            provenance: ContactProvenance::Local,
            disposition: ContactDisposition::Cancelled,
            reason: ContactReason::CallerCancelled,
        }
    }

    pub(crate) const fn pre_auth_remote(reason: ContactReason) -> Self {
        Self {
            stage: ContactStage::MissionHandshake,
            scope: ContactScope::Locator,
            provenance: ContactProvenance::UnauthenticatedRemote,
            disposition: ContactDisposition::RetryLater,
            reason,
        }
    }

    pub(crate) const fn pre_auth_transport(
        scope: ContactScope,
        provenance: ContactProvenance,
        disposition: ContactDisposition,
        reason: ContactReason,
    ) -> Self {
        debug_assert!(matches!(
            scope,
            ContactScope::AdapterEpoch | ContactScope::Attempt
        ));
        debug_assert!(matches!(
            provenance,
            ContactProvenance::Adapter | ContactProvenance::UnauthenticatedRemote
        ));
        Self {
            stage: ContactStage::MissionHandshake,
            scope,
            provenance,
            disposition,
            reason,
        }
    }

    pub(crate) const fn authenticated_session(
        scope: ContactScope,
        disposition: ContactDisposition,
        reason: ContactReason,
    ) -> Self {
        debug_assert!(matches!(
            scope,
            ContactScope::ExpectedPeer
                | ContactScope::Mission
                | ContactScope::Policy
                | ContactScope::Attempt
        ));
        Self {
            stage: ContactStage::AuthenticatedSession,
            scope,
            provenance: ContactProvenance::AuthenticatedMission,
            disposition,
            reason,
        }
    }

    pub(crate) const fn authenticated_transport(
        scope: ContactScope,
        provenance: ContactProvenance,
        disposition: ContactDisposition,
        reason: ContactReason,
    ) -> Self {
        debug_assert!(matches!(
            scope,
            ContactScope::AdapterEpoch | ContactScope::Attempt
        ));
        debug_assert!(matches!(
            provenance,
            ContactProvenance::Adapter | ContactProvenance::AuthenticatedMission
        ));
        Self {
            stage: ContactStage::AuthenticatedSession,
            scope,
            provenance,
            disposition,
            reason,
        }
    }

    pub(crate) const fn local_invariant(stage: ContactStage) -> Self {
        Self {
            stage,
            scope: ContactScope::Attempt,
            provenance: ContactProvenance::Local,
            disposition: ContactDisposition::Terminal,
            reason: ContactReason::LocalInvariant,
        }
    }

    pub(crate) const fn local_policy(stage: ContactStage) -> Self {
        Self {
            stage,
            scope: ContactScope::Policy,
            provenance: ContactProvenance::Local,
            disposition: ContactDisposition::RetryLater,
            reason: ContactReason::PolicyRejected,
        }
    }

    const fn local_admission(disposition: ContactDisposition, reason: ContactReason) -> Self {
        Self {
            stage: ContactStage::Candidate,
            scope: ContactScope::Attempt,
            provenance: ContactProvenance::Local,
            disposition,
            reason,
        }
    }

    /// Returns the last trusted transition reached by the attempt.
    pub const fn stage(&self) -> ContactStage {
        self.stage
    }

    /// Returns the authority scope affected by the outcome.
    pub const fn scope(&self) -> ContactScope {
        self.scope
    }

    /// Returns the trusted provenance of the scope classification.
    pub const fn provenance(&self) -> ContactProvenance {
        self.provenance
    }

    /// Returns the scheduler disposition authorized by the outcome.
    pub const fn disposition(&self) -> ContactDisposition {
        self.disposition
    }

    /// Returns the sanitized closed reason.
    pub const fn reason(&self) -> ContactReason {
        self.reason
    }

    /// Returns whether this exact outcome authorizes immediate adapter reselection.
    pub const fn permits_reselection(&self) -> bool {
        matches!(self.disposition, ContactDisposition::Reselect)
    }
}

impl fmt::Display for ContactOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Event contact {:?} at {:?} ({:?}/{:?})",
            self.reason, self.stage, self.scope, self.disposition
        )
    }
}

impl Error for ContactOutcome {}
