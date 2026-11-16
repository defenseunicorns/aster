//! Evaluation-only fixed-role Linux CoC harness; not a daemon or protocol endpoint.

#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("aster-btle-ring1: Linux BlueZ is required");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
include!("aster_btle_ring1_linux.rs");
