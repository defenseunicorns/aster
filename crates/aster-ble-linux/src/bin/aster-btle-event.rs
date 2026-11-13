//! Evaluation-only unattended Linux Event lifecycle; not a daemon.

#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("aster-btle-event: Linux BlueZ is required");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
include!("aster_btle_event_linux.rs");
