use std::{
    env,
    io::{Read as _, Write as _},
    net::TcpStream,
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};

use aster_agent::config::load_and_validate_compose_config;

const DEFAULT_CONFIG: &str = "/etc/aster/agent.json";
const DEADLINE: Duration = Duration::from_secs(2);
const MAX_RESPONSE: usize = 4096;

fn main() -> ExitCode {
    match execute() {
        Ok(()) => {
            println!("HEALTH status=ready");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("ERROR {message}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<(), &'static str> {
    let config = parse_config_path(env::args().skip(1))?;
    let address = load_and_validate_compose_config(&config)
        .map_err(|_| "health configuration is invalid")?
        .runtime()
        .health();
    let mut stream = TcpStream::connect_timeout(&address, DEADLINE)
        .map_err(|_| "health endpoint is unavailable")?;
    stream
        .set_read_timeout(Some(DEADLINE))
        .map_err(|_| "health endpoint is unavailable")?;
    stream
        .set_write_timeout(Some(DEADLINE))
        .map_err(|_| "health endpoint is unavailable")?;
    stream
        .write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(|_| "health endpoint is unavailable")?;
    let mut response = Vec::with_capacity(512);
    stream
        .take((MAX_RESPONSE + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|_| "health endpoint is unavailable")?;
    if response.len() > MAX_RESPONSE {
        return Err("health response is invalid");
    }
    let line_end = response
        .windows(2)
        .position(|pair| pair == b"\r\n")
        .ok_or("health response is invalid")?;
    if &response[..line_end] != b"HTTP/1.1 200 OK" {
        return Err("health status is not ready");
    }
    Ok(())
}

fn parse_config_path(mut arguments: impl Iterator<Item = String>) -> Result<PathBuf, &'static str> {
    let path = match (arguments.next(), arguments.next(), arguments.next()) {
        (None, None, None) => PathBuf::from(DEFAULT_CONFIG),
        (Some(flag), Some(path), None) if flag == "--config" => PathBuf::from(path),
        _ => return Err("invalid invocation"),
    };
    if !path.is_absolute() {
        return Err("invalid invocation");
    }
    Ok(path)
}
