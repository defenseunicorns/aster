use std::time::Duration;

use aster_node::application::{ApplicationError, ApplicationErrorKind};
use connectrpc::{ConnectError, ErrorCode, ErrorDetail};

use crate::api;

const PUBLIC_ERROR_DETAIL_TYPE: &str = "aster.application.v1alpha1.PublicErrorDetail";

/// Fixed public RPC operation names accepted by the error contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicOperation {
    Unspecified,
    GetStatus,
    PublishEvent,
    PublishEvents,
    PublishNumberedEvents,
    BeginEventPublicationSession,
    CompleteEventPublicationRecovery,
    PublishNumberedEvent,
    AbandonEventPublication,
    AcknowledgeEventPublicationResult,
    QueryEvents,
    CreateEventSubscription,
    ListEventSubscriptions,
    PollEvents,
    StreamEvents,
    AcknowledgeEvent,
    DeleteEventSubscription,
    QueryEventGaps,
}

impl PublicOperation {
    /// Returns the stable public operation spelling carried in error details.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::GetStatus => "get_status",
            Self::PublishEvent => "publish_event",
            Self::PublishEvents => "publish_events",
            Self::PublishNumberedEvents => "publish_numbered_events",
            Self::BeginEventPublicationSession => "begin_event_publication_session",
            Self::CompleteEventPublicationRecovery => "complete_event_publication_recovery",
            Self::PublishNumberedEvent => "publish_numbered_event",
            Self::AbandonEventPublication => "abandon_event_publication",
            Self::AcknowledgeEventPublicationResult => "acknowledge_event_publication_result",
            Self::QueryEvents => "query_events",
            Self::CreateEventSubscription => "create_event_subscription",
            Self::ListEventSubscriptions => "list_event_subscriptions",
            Self::PollEvents => "poll_events",
            Self::StreamEvents => "stream_events",
            Self::AcknowledgeEvent => "acknowledge_event",
            Self::DeleteEventSubscription => "delete_event_subscription",
            Self::QueryEventGaps => "query_event_gaps",
        }
    }

    const fn from_application(operation: &str) -> Option<Self> {
        match operation.as_bytes() {
            b"status" => Some(Self::GetStatus),
            b"publish" => Some(Self::PublishEvent),
            b"begin_publication_session" => Some(Self::BeginEventPublicationSession),
            b"complete_publication_recovery" => Some(Self::CompleteEventPublicationRecovery),
            b"publish_numbered" => Some(Self::PublishNumberedEvent),
            b"abandon_publication" => Some(Self::AbandonEventPublication),
            b"acknowledge_publication_result" => Some(Self::AcknowledgeEventPublicationResult),
            b"query" => Some(Self::QueryEvents),
            b"subscribe" => Some(Self::CreateEventSubscription),
            b"list_subscriptions" => Some(Self::ListEventSubscriptions),
            b"poll" => Some(Self::PollEvents),
            b"acknowledge" => Some(Self::AcknowledgeEvent),
            b"unsubscribe" => Some(Self::DeleteEventSubscription),
            b"gaps" => Some(Self::QueryEventGaps),
            _ => None,
        }
    }
}

impl api::PublicErrorReason {
    const fn public_message(self) -> &'static str {
        match self {
            Self::MalformedInput => "request is malformed",
            Self::UnsupportedValue => "request contains an unsupported value",
            Self::OperationKeyConflict => "operation key conflicts with an existing request",
            Self::MissingDurableObject => "durable object is unavailable",
            Self::FailedPrecondition => "operation precondition is not satisfied",
            Self::Deadline => "operation deadline exceeded",
            Self::ResourceExhaustion => "resource limit reached",
            Self::OperationCapacityExhausted => "durable operation capacity exhausted",
            Self::SessionFenced => "publication session is fenced",
            Self::SequenceGap => "publication sequence has a gap",
            Self::SequenceRetired => "publication sequence is retired",
            Self::RecoveryRequired => "publication recovery is required",
            Self::LegacyStateRequiresFreshStore => {
                "legacy publication state requires a fresh store"
            }
            Self::Draining => "service is draining",
            Self::StateUnavailable => "service state is unavailable",
            Self::AuthenticationFailed => "authentication failed",
            Self::Internal | Self::Unspecified => "internal service error",
        }
    }
}

/// Recognizes only the closed message vocabulary emitted by this module.
#[cfg(feature = "server")]
pub(crate) fn is_public_error_message(message: &str) -> bool {
    use api::PublicErrorReason as R;
    [
        R::MalformedInput,
        R::UnsupportedValue,
        R::OperationKeyConflict,
        R::MissingDurableObject,
        R::FailedPrecondition,
        R::Deadline,
        R::ResourceExhaustion,
        R::OperationCapacityExhausted,
        R::SessionFenced,
        R::SequenceGap,
        R::SequenceRetired,
        R::RecoveryRequired,
        R::LegacyStateRequiresFreshStore,
        R::Draining,
        R::StateUnavailable,
        R::AuthenticationFailed,
        R::Internal,
    ]
    .iter()
    .any(|reason| message == reason.public_message())
}

/// Creates one bounded public error without retaining caller-provided text.
pub fn public_error(
    code: ErrorCode,
    reason: api::PublicErrorReason,
    operation: PublicOperation,
    retryable: bool,
    retry_delay: Option<Duration>,
) -> ConnectError {
    let detail = public_error_detail(reason, operation, retryable, retry_delay);
    ConnectError::new(code, reason.public_message())
        .with_detail(ErrorDetail::from_message(PUBLIC_ERROR_DETAIL_TYPE, &detail))
}

pub(crate) fn public_error_detail(
    reason: api::PublicErrorReason,
    operation: PublicOperation,
    retryable: bool,
    retry_delay: Option<Duration>,
) -> api::PublicErrorDetail {
    api::PublicErrorDetail {
        reason: reason.into(),
        operation: operation.as_str().to_owned(),
        retryable,
        retry_delay_ms: retry_delay.and_then(bounded_millis),
        ..Default::default()
    }
}

fn bounded_millis(delay: Duration) -> Option<u32> {
    delay.as_millis().try_into().ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PublicErrorMapping {
    code: ErrorCode,
    reason: api::PublicErrorReason,
    operation: PublicOperation,
    retryable: bool,
    retry_delay: Option<Duration>,
}

fn application_error_mapping(kind: ApplicationErrorKind, operation: &str) -> PublicErrorMapping {
    let Some(operation) = PublicOperation::from_application(operation) else {
        return PublicErrorMapping {
            code: ErrorCode::Internal,
            reason: api::PublicErrorReason::Internal,
            operation: PublicOperation::Unspecified,
            retryable: false,
            retry_delay: None,
        };
    };
    let (code, reason, retryable) = match kind {
        ApplicationErrorKind::InvalidRequest => (
            ErrorCode::InvalidArgument,
            api::PublicErrorReason::MalformedInput,
            false,
        ),
        ApplicationErrorKind::RequestRejected | ApplicationErrorKind::UnauthorizedOrRevoked => (
            ErrorCode::PermissionDenied,
            api::PublicErrorReason::FailedPrecondition,
            false,
        ),
        ApplicationErrorKind::PolicyUnsettled => (
            ErrorCode::Unavailable,
            api::PublicErrorReason::FailedPrecondition,
            false,
        ),
        ApplicationErrorKind::Conflict => (
            ErrorCode::Aborted,
            api::PublicErrorReason::OperationKeyConflict,
            false,
        ),
        ApplicationErrorKind::SessionFenced => (
            ErrorCode::Aborted,
            api::PublicErrorReason::SessionFenced,
            false,
        ),
        ApplicationErrorKind::SequenceGap => (
            ErrorCode::FailedPrecondition,
            api::PublicErrorReason::SequenceGap,
            false,
        ),
        ApplicationErrorKind::SequenceRetired => (
            ErrorCode::NotFound,
            api::PublicErrorReason::SequenceRetired,
            false,
        ),
        ApplicationErrorKind::RecoveryRequired => (
            ErrorCode::FailedPrecondition,
            api::PublicErrorReason::RecoveryRequired,
            false,
        ),
        ApplicationErrorKind::LegacyState => (
            ErrorCode::FailedPrecondition,
            api::PublicErrorReason::LegacyStateRequiresFreshStore,
            false,
        ),
        ApplicationErrorKind::ExpiredOrRetired => (
            ErrorCode::NotFound,
            api::PublicErrorReason::MissingDurableObject,
            false,
        ),
        ApplicationErrorKind::ResourceLimit => (
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::ResourceExhaustion,
            true,
        ),
        ApplicationErrorKind::OperationCapacity => (
            ErrorCode::ResourceExhausted,
            api::PublicErrorReason::OperationCapacityExhausted,
            false,
        ),
        ApplicationErrorKind::StateUnavailable => (
            ErrorCode::Unavailable,
            api::PublicErrorReason::StateUnavailable,
            true,
        ),
        ApplicationErrorKind::Integrity => {
            (ErrorCode::DataLoss, api::PublicErrorReason::Internal, false)
        }
        ApplicationErrorKind::Provisioning => (
            ErrorCode::FailedPrecondition,
            api::PublicErrorReason::FailedPrecondition,
            false,
        ),
        _ => (ErrorCode::Internal, api::PublicErrorReason::Internal, false),
    };
    PublicErrorMapping {
        code,
        reason,
        operation,
        retryable,
        retry_delay: None,
    }
}

/// Converts the selected-node error taxonomy without exposing its text or source.
pub fn connect_application_error(error: ApplicationError) -> ConnectError {
    let mapping = application_error_mapping(error.kind(), error.operation());
    public_error(
        mapping.code,
        mapping.reason,
        mapping.operation,
        mapping.retryable,
        mapping.retry_delay,
    )
}

pub(crate) fn public_application_error_detail(
    error: ApplicationError,
    operation: PublicOperation,
) -> api::PublicErrorDetail {
    let mapping = application_error_mapping(error.kind(), error.operation());
    public_error_detail(
        mapping.reason,
        operation,
        mapping.retryable,
        mapping.retry_delay,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aster_node::application::ApplicationErrorKind;
    use buffa::Message as _;
    use connectrpc::{ConnectError, ErrorCode};

    use super::*;
    use crate::api;

    const DETAIL_TYPE: &str = "aster.application.v1alpha1.PublicErrorDetail";

    fn decode_base64(value: &str) -> Vec<u8> {
        fn sextet(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => panic!("invalid base64 fixture"),
            }
        }

        let mut decoded = Vec::new();
        for chunk in value.as_bytes().chunks(4) {
            let a = sextet(chunk[0]);
            let b = sextet(chunk[1]);
            decoded.push((a << 2) | (b >> 4));
            if chunk.len() > 2 && chunk[2] != b'=' {
                let c = sextet(chunk[2]);
                decoded.push((b << 4) | (c >> 2));
                if chunk.len() > 3 && chunk[3] != b'=' {
                    decoded.push((c << 6) | sextet(chunk[3]));
                }
            }
        }
        decoded
    }

    fn decoded_detail(error: &ConnectError) -> api::PublicErrorDetail {
        assert_eq!(error.details.len(), 1);
        let detail = &error.details[0];
        assert_eq!(detail.type_url, DETAIL_TYPE);
        assert!(detail.debug.is_none());
        let wire = decode_base64(detail.value.as_deref().expect("encoded detail"));
        api::PublicErrorDetail::decode_from_slice(&wire).expect("valid public detail")
    }

    fn assert_detail(
        error: ConnectError,
        reason: api::PublicErrorReason,
        operation: &str,
        retryable: bool,
        retry_delay_ms: Option<u32>,
    ) {
        let detail = decoded_detail(&error);
        assert_eq!(detail.reason, reason);
        assert_eq!(detail.operation, operation);
        assert_eq!(detail.retryable, retryable);
        assert_eq!(detail.retry_delay_ms, retry_delay_ms);
    }

    #[test]
    fn internal_failure_never_exposes_source_text() {
        let error = public_error(
            ErrorCode::Internal,
            api::PublicErrorReason::Internal,
            PublicOperation::PublishEvent,
            false,
            None,
        );
        assert_eq!(error.code, ErrorCode::Internal);
        assert_eq!(error.message.as_deref(), Some("internal service error"));
        assert_detail(
            error,
            api::PublicErrorReason::Internal,
            "publish_event",
            false,
            None,
        );
    }

    #[test]
    fn every_application_error_kind_has_one_stable_public_mapping() {
        let cases = [
            (
                ApplicationErrorKind::InvalidRequest,
                ErrorCode::InvalidArgument,
                api::PublicErrorReason::MalformedInput,
                false,
            ),
            (
                ApplicationErrorKind::RequestRejected,
                ErrorCode::PermissionDenied,
                api::PublicErrorReason::FailedPrecondition,
                false,
            ),
            (
                ApplicationErrorKind::UnauthorizedOrRevoked,
                ErrorCode::PermissionDenied,
                api::PublicErrorReason::FailedPrecondition,
                false,
            ),
            (
                ApplicationErrorKind::PolicyUnsettled,
                ErrorCode::Unavailable,
                api::PublicErrorReason::FailedPrecondition,
                false,
            ),
            (
                ApplicationErrorKind::Conflict,
                ErrorCode::Aborted,
                api::PublicErrorReason::OperationKeyConflict,
                false,
            ),
            (
                ApplicationErrorKind::ExpiredOrRetired,
                ErrorCode::NotFound,
                api::PublicErrorReason::MissingDurableObject,
                false,
            ),
            (
                ApplicationErrorKind::ResourceLimit,
                ErrorCode::ResourceExhausted,
                api::PublicErrorReason::ResourceExhaustion,
                true,
            ),
            (
                ApplicationErrorKind::OperationCapacity,
                ErrorCode::ResourceExhausted,
                api::PublicErrorReason::OperationCapacityExhausted,
                false,
            ),
            (
                ApplicationErrorKind::StateUnavailable,
                ErrorCode::Unavailable,
                api::PublicErrorReason::StateUnavailable,
                true,
            ),
            (
                ApplicationErrorKind::Integrity,
                ErrorCode::DataLoss,
                api::PublicErrorReason::Internal,
                false,
            ),
            (
                ApplicationErrorKind::Provisioning,
                ErrorCode::FailedPrecondition,
                api::PublicErrorReason::FailedPrecondition,
                false,
            ),
        ];

        for (kind, code, reason, retryable) in cases {
            let mapping = application_error_mapping(kind, "publish");
            assert_eq!(mapping.code, code, "{kind:?}");
            assert_eq!(mapping.reason, reason, "{kind:?}");
            assert_eq!(mapping.operation, PublicOperation::PublishEvent, "{kind:?}");
            assert_eq!(mapping.retryable, retryable, "{kind:?}");
            assert_eq!(mapping.retry_delay, None, "{kind:?}");
        }
    }

    #[test]
    fn numbered_publication_rejection_has_public_permission_mapping() {
        let mapping =
            application_error_mapping(ApplicationErrorKind::RequestRejected, "publish_numbered");
        assert_eq!(mapping.code, ErrorCode::PermissionDenied);
        assert_eq!(mapping.reason, api::PublicErrorReason::FailedPrecondition);
        assert_eq!(mapping.operation, PublicOperation::PublishNumberedEvent);
        let error = public_error(
            mapping.code,
            mapping.reason,
            mapping.operation,
            mapping.retryable,
            mapping.retry_delay,
        );
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_detail(
            error,
            api::PublicErrorReason::FailedPrecondition,
            "publish_numbered_event",
            false,
            None,
        );
    }

    #[test]
    fn application_operation_names_are_translated_through_a_closed_allowlist() {
        let cases = [
            ("status", PublicOperation::GetStatus, "get_status"),
            ("publish", PublicOperation::PublishEvent, "publish_event"),
            ("query", PublicOperation::QueryEvents, "query_events"),
            (
                "subscribe",
                PublicOperation::CreateEventSubscription,
                "create_event_subscription",
            ),
            ("poll", PublicOperation::PollEvents, "poll_events"),
            (
                "acknowledge",
                PublicOperation::AcknowledgeEvent,
                "acknowledge_event",
            ),
            (
                "unsubscribe",
                PublicOperation::DeleteEventSubscription,
                "delete_event_subscription",
            ),
            ("gaps", PublicOperation::QueryEventGaps, "query_event_gaps"),
        ];

        for (internal, operation, public) in cases {
            assert_eq!(PublicOperation::from_application(internal), Some(operation));
            assert_eq!(operation.as_str(), public);
        }

        assert_eq!(
            PublicOperation::from_application("payload=/private/key"),
            None
        );
        let mapping =
            application_error_mapping(ApplicationErrorKind::InvalidRequest, "payload=/private/key");
        assert_eq!(mapping.code, ErrorCode::Internal);
        assert_eq!(mapping.reason, api::PublicErrorReason::Internal);
        assert_eq!(mapping.operation, PublicOperation::Unspecified);
        assert!(!mapping.retryable);
    }

    #[test]
    fn retry_delay_is_present_only_when_whole_milliseconds_fit_the_public_bound() {
        assert_detail(
            public_error(
                ErrorCode::Unavailable,
                api::PublicErrorReason::StateUnavailable,
                PublicOperation::GetStatus,
                true,
                Some(Duration::from_millis(u64::from(u32::MAX))),
            ),
            api::PublicErrorReason::StateUnavailable,
            "get_status",
            true,
            Some(u32::MAX),
        );
        assert_detail(
            public_error(
                ErrorCode::Unavailable,
                api::PublicErrorReason::StateUnavailable,
                PublicOperation::GetStatus,
                true,
                Some(Duration::from_millis(u64::from(u32::MAX) + 1)),
            ),
            api::PublicErrorReason::StateUnavailable,
            "get_status",
            true,
            None,
        );
    }
}
