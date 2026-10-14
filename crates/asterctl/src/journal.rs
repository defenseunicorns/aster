use aster_agent::sdk::{NumberedEventSdkError, PublicationJournal};
use std::path::PathBuf;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Identity {
    pub path: PathBuf,
    pub client_id: Vec<u8>,
}

impl Identity {
    pub fn set_option(&mut self, name: &str, value: String) -> Result<(), &'static str> {
        match name {
            "--journal" => {
                if value.is_empty() {
                    return Err("publication journal path must not be empty");
                }
                self.path = value.into();
            }
            "--client-id" => {
                if !(1..=64).contains(&value.len()) {
                    return Err("publication client ID must contain 1–64 UTF-8 bytes");
                }
                self.client_id = value.into_bytes();
            }
            _ => unreachable!("publication identity option"),
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.path.as_os_str().is_empty() {
            return Err("--journal is required; explicitly initialize it with publication-init");
        }
        if self.client_id.is_empty() {
            return Err("--client-id is required; use the journal's stable application identity");
        }
        Ok(())
    }

    pub fn initialize(&self) -> Result<(), String> {
        PublicationJournal::initialize(&self.path, &self.client_id).map_err(describe_error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    Initialize,
    Recover,
    Show,
    Retry,
    Abandon,
    Acknowledge,
}

pub fn describe_error(error: NumberedEventSdkError) -> String {
    match error {
        // Remote text is untrusted and may contain credentials. Only expose
        // the fixed protocol code, matching the CLI's other RPC diagnostics.
        NumberedEventSdkError::Transport(error) => {
            crate::client::describe_rpc_error("Numbered publication", error.code)
        }
        NumberedEventSdkError::Journal(message) => format!("publication journal: {message}"),
        NumberedEventSdkError::Protocol(message) => format!("publication protocol: {message}"),
    }
}
