//! Evaluation-only Android LE L2CAP validator adapter.

#![forbid(unsafe_code)]

mod config;
mod receipt;
mod session;

pub use config::{
    MAX_MISSION_BUNDLE_BYTES, ValidatorConfig, ValidatorError, ValidatorErrorCategory,
};
pub use receipt::{ValidationReceipt, validate_ring1_receipt};
pub use session::{PhaseSink, RunId, RunOutcome, RunRegistry, SessionEvent, ValidatorPhase};
