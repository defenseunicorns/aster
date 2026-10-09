use std::{
    env,
    fs::{Metadata, OpenOptions},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
    process::ExitCode,
};

use aster_agent::{
    ClientToken,
    config::{ValidatedComposeAgentConfig, validate_compose_config_bytes},
    credentials::{CredentialGeneration, StartupCredentials},
    runtime::{AgentExit, AgentSignal, TokenReloadPolicy, run_customer_agent_with_credentials},
};
use aster_compose_credentials::{
    ComposeActivation, ComposeProvisioningLoader, read_client_token_file,
};
use sha2::{Digest as _, Sha256};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
const MAX_CONFIG_BYTES: usize = 256 * 1024;

enum Invocation {
    CheckConfig(PathBuf),
    Run(PathBuf),
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("ERROR runtime initialization failed");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(Some(exit)) => ExitCode::from(exit_code(exit)),
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<Option<AgentExit>, BoxError> {
    std::hint::black_box(aster_compose_credentials::PROVIDER_CONTRACT);
    match parse_invocation(env::args().skip(1))? {
        Invocation::CheckConfig(path) => {
            let _config = load_digest_bound_config(&path)?;
            let (credentials, mut loader) = load_compose_credentials()?;
            loader.load_with_reason(credentials.mission_load(), credentials.mission_reference())?;
            Ok(None)
        }
        Invocation::Run(path) => {
            let config = load_digest_bound_config(&path)?;
            let (credentials, mut loader) = load_compose_credentials()?;
            let signals = translated_signals()?;
            Ok(Some(
                run_customer_agent_with_credentials(
                    config.into_runtime(),
                    credentials,
                    &mut loader,
                    signals,
                    TokenReloadPolicy::Disabled,
                )
                .await?,
            ))
        }
    }
}

fn load_digest_bound_config(path: &Path) -> Result<ValidatedComposeAgentConfig, BoxError> {
    let encoded =
        env::var("ASTER_AGENT_CONFIG_SHA256").map_err(|_| "configuration digest is required")?;
    let expected = decode_config_digest(&encoded)?;
    let bytes = read_bounded_config(path)?;
    let actual = Sha256::digest(&bytes);
    if actual[..] != expected {
        return Err("configuration digest does not match".into());
    }
    Ok(validate_compose_config_bytes(&bytes)?)
}

fn read_bounded_config(path: &Path) -> Result<Vec<u8>, BoxError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "configuration file is invalid")?;
    let before = file
        .metadata()
        .map_err(|_| "configuration file is invalid")?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_CONFIG_BYTES as u64 {
        return Err("configuration file is invalid".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize + 1);
    (&mut file)
        .take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "configuration file is invalid")?;
    let after = file
        .metadata()
        .map_err(|_| "configuration file is invalid")?;
    if bytes.len() > MAX_CONFIG_BYTES || !same_config_metadata(&before, &after) {
        return Err("configuration file is invalid".into());
    }
    Ok(bytes)
}

fn same_config_metadata(before: &Metadata, after: &Metadata) -> bool {
    before.is_file()
        && after.is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn decode_config_digest(encoded: &str) -> Result<[u8; 32], BoxError> {
    if encoded.len() != 64 {
        return Err("configuration digest is invalid".into());
    }
    let mut digest = [0_u8; 32];
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (digest_nibble(pair[0])? << 4) | digest_nibble(pair[1])?;
    }
    Ok(digest)
}

fn digest_nibble(byte: u8) -> Result<u8, BoxError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("configuration digest is invalid".into()),
    }
}

fn parse_invocation(arguments: impl Iterator<Item = String>) -> Result<Invocation, BoxError> {
    let arguments = arguments.collect::<Vec<_>>();
    match arguments.as_slice() {
        [flag, path] if flag == "--check-config" => {
            Ok(Invocation::CheckConfig(PathBuf::from(path)))
        }
        [flag, path] if flag == "--config" => Ok(Invocation::Run(PathBuf::from(path))),
        _ => Err("expected exactly --config PATH or --check-config PATH".into()),
    }
}

fn load_compose_credentials() -> Result<(StartupCredentials, ComposeProvisioningLoader), BoxError> {
    let token_envelope = read_client_token_file()?;
    let activation = ComposeActivation::from_fixed_file()?;
    let mut token_bytes = token_envelope.into_token_for_activation(&activation)?;
    let token = ClientToken::from_bytes(std::mem::take(&mut *token_bytes))?;
    let generation = CredentialGeneration::new(*activation.generation().as_bytes());
    let credentials = StartupCredentials::new(
        token,
        activation.secret_ref().clone(),
        activation.operation(),
        Some(generation),
    );
    let loader = ComposeProvisioningLoader::from_fixed_file(activation)?;
    Ok((credentials, loader))
}

const fn exit_code(exit: AgentExit) -> u8 {
    match exit {
        AgentExit::Clean => 0,
        AgentExit::Failed(_) => 1,
        AgentExit::Forced => 2,
    }
}

#[cfg(unix)]
fn translated_signals() -> Result<tokio::sync::mpsc::Receiver<AgentSignal>, BoxError> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        loop {
            let translated = tokio::select! {
                received = hangup.recv() => received.map(|()| AgentSignal::Hangup),
                received = interrupt.recv() => received.map(|()| AgentSignal::Terminate),
                received = terminate.recv() => received.map(|()| AgentSignal::Terminate),
            };
            let Some(translated) = translated else {
                return;
            };
            if sender.send(translated).await.is_err() {
                return;
            }
        }
    });
    Ok(receiver)
}

#[cfg(not(unix))]
fn translated_signals() -> Result<tokio::sync::mpsc::Receiver<AgentSignal>, BoxError> {
    let (sender, receiver) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = sender.send(AgentSignal::Terminate).await;
        }
    });
    Ok(receiver)
}
