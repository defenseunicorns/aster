use crate::{api, auth::Token, client, validation};
use std::{future::Future, net::SocketAddr, time::Duration};

pub const HELP: &str = "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] blob-status
                --publication-id ID --topic TOPIC --scope SCOPE [--wait] [--poll-ms N]

Inspect receiver-local durable Blob publication state.

OPTIONS:
      --publication-id ID  Publication ID as Base64-encoded 32 bytes (required)
      --topic TOPIC        Exact Blob topic (required)
      --scope SCOPE        Exact Blob scope (required)
      --wait               Poll until available, retired, or the client deadline
      --poll-ms N          Poll interval, 100–60000 ms (default: 1000; requires --wait)
      --help               Show this help

See asterctl --help for global options.
Status is local, durable, and transport-neutral; it does not imply remote delivery.
";

const DEFAULT_POLL_MS: u64 = 1_000;

#[derive(Debug, PartialEq)]
pub struct Status {
    publication_id: Vec<u8>,
    topic: String,
    scope: String,
    wait: bool,
    poll_ms: u64,
    poll_explicit: bool,
}

impl Default for Status {
    fn default() -> Self {
        Self {
            publication_id: Vec::new(),
            topic: String::new(),
            scope: String::new(),
            wait: false,
            poll_ms: DEFAULT_POLL_MS,
            poll_explicit: false,
        }
    }
}

impl Status {
    pub fn set_option(&mut self, name: &str, value: String) -> Result<(), &'static str> {
        match name {
            "--publication-id" => {
                let publication_id = validation::identity(&value)
                    .filter(|bytes| bytes.iter().any(|byte| *byte != 0))
                    .ok_or("publication ID must be a nonzero Base64-encoded 32-byte ID")?;
                self.publication_id = publication_id;
            }
            "--topic" => {
                validation::topic(&value)?;
                self.topic = value;
            }
            "--scope" => {
                validation::scope(&value)?;
                self.scope = value;
            }
            "--poll-ms" => {
                self.poll_ms = value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit())
                    .then(|| value.parse::<u64>().ok())
                    .flatten()
                    .filter(|value| (100..=60_000).contains(value))
                    .ok_or("poll interval must be an integer from 100 to 60000 milliseconds")?;
                self.poll_explicit = true;
            }
            _ => unreachable!("Blob status option"),
        }
        Ok(())
    }

    pub fn set_wait(&mut self) {
        self.wait = true;
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.publication_id.is_empty() {
            return Err("--publication-id is required; see blob-status --help");
        }
        if self.topic.is_empty() {
            return Err("--topic is required; see blob-status --help");
        }
        if self.scope.is_empty() {
            return Err("--scope is required; see blob-status --help");
        }
        if self.poll_explicit && !self.wait {
            return Err("--poll-ms requires --wait");
        }
        Ok(())
    }

    pub fn into_parts(self) -> (api::InspectBlobPublicationRequest, bool, Duration) {
        (
            api::InspectBlobPublicationRequest {
                publication_id: self.publication_id,
                topic: self.topic,
                scope: self.scope,
                ..Default::default()
            },
            self.wait,
            Duration::from_millis(self.poll_ms),
        )
    }
}

pub struct Error {
    message: String,
    last: Option<api::InspectBlobPublicationResponse>,
}

impl Error {
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn last(&self) -> Option<&api::InspectBlobPublicationResponse> {
        self.last.as_ref()
    }
}

pub async fn run(
    address: SocketAddr,
    token: &Token,
    request: api::InspectBlobPublicationRequest,
    wait: bool,
    poll: Duration,
    timeout: Duration,
) -> Result<api::InspectBlobPublicationResponse, Error> {
    let client = client::query_client(address, token, timeout);
    wait_with_deadline(
        move || {
            let client = client.clone();
            let request = request.clone();
            async move { client::inspect_blob_publication(&client, request).await }
        },
        wait,
        poll,
        timeout,
    )
    .await
}

async fn wait_with_deadline<Inspect, InspectFuture>(
    mut inspect: Inspect,
    wait: bool,
    poll: Duration,
    timeout: Duration,
) -> Result<api::InspectBlobPublicationResponse, Error>
where
    Inspect: FnMut() -> InspectFuture,
    InspectFuture: Future<Output = Result<api::InspectBlobPublicationResponse, String>>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last = None;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(deadline_error(last));
        }
        let response = tokio::time::timeout(remaining, inspect())
            .await
            .map_err(|_| deadline_error(last.clone()))?
            .map_err(|message| Error {
                message,
                last: last.clone(),
            })?;
        if last
            .as_ref()
            .is_some_and(|previous| !progress_is_monotonic(previous, &response))
        {
            return Err(Error {
                message: "InspectBlobPublication failed: status regressed or totals changed"
                    .to_owned(),
                last,
            });
        }
        let phase = response.phase.as_known().expect("validated phase");
        last = Some(response.clone());
        if !wait || phase == api::BlobPublicationPhase::Available {
            return Ok(response);
        }
        if phase == api::BlobPublicationPhase::ExpiredOrRetired {
            return Err(Error {
                message: "Blob publication expired or was retired".to_owned(),
                last,
            });
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(deadline_error(last));
        }
        tokio::time::sleep(poll.min(remaining)).await;
    }
}

fn progress_is_monotonic(
    previous: &api::InspectBlobPublicationResponse,
    current: &api::InspectBlobPublicationResponse,
) -> bool {
    if previous.publication_id != current.publication_id {
        return false;
    }
    let previous_phase = previous.phase.as_known().expect("validated phase");
    let current_phase = current.phase.as_known().expect("validated phase");
    if matches!(current_phase, api::BlobPublicationPhase::ExpiredOrRetired) {
        return true;
    }
    if previous_phase == api::BlobPublicationPhase::Missing {
        return true;
    }
    previous.plaintext_total_bytes == current.plaintext_total_bytes
        && previous.transfer_total_bytes == current.transfer_total_bytes
        && previous.total_units == current.total_units
        && previous.durable_plaintext_bytes <= current.durable_plaintext_bytes
        && previous.durable_transfer_bytes <= current.durable_transfer_bytes
        && previous.durable_units <= current.durable_units
        && phase_rank(previous_phase) <= phase_rank(current_phase)
}

const fn phase_rank(phase: api::BlobPublicationPhase) -> u8 {
    match phase {
        api::BlobPublicationPhase::Unspecified => 0,
        api::BlobPublicationPhase::Missing => 1,
        api::BlobPublicationPhase::AwaitingData => 2,
        api::BlobPublicationPhase::Receiving => 3,
        api::BlobPublicationPhase::ReadyToFinalize => 4,
        api::BlobPublicationPhase::Available => 5,
        api::BlobPublicationPhase::ExpiredOrRetired => 6,
    }
}

fn deadline_error(last: Option<api::InspectBlobPublicationResponse>) -> Error {
    let final_state = last
        .as_ref()
        .and_then(|response| response.phase.as_known())
        .map_or("none", phase_name);
    Error {
        message: format!(
            "InspectBlobPublication deadline exceeded; final observed state: {final_state}"
        ),
        last,
    }
}

fn phase_name(phase: api::BlobPublicationPhase) -> &'static str {
    match phase {
        api::BlobPublicationPhase::Unspecified => "unspecified",
        api::BlobPublicationPhase::Missing => "missing",
        api::BlobPublicationPhase::AwaitingData => "awaiting-data",
        api::BlobPublicationPhase::Receiving => "receiving",
        api::BlobPublicationPhase::ReadyToFinalize => "ready-to-finalize",
        api::BlobPublicationPhase::Available => "available",
        api::BlobPublicationPhase::ExpiredOrRetired => "expired-or-retired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    fn response(phase: api::BlobPublicationPhase) -> api::InspectBlobPublicationResponse {
        api::InspectBlobPublicationResponse {
            publication_id: vec![1; 32],
            phase: phase.into(),
            blob_id: (phase == api::BlobPublicationPhase::Available).then(|| vec![2; 32]),
            ..Default::default()
        }
    }

    #[test]
    fn wait_retirement_stops_without_another_poll() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let responses = Arc::new(Mutex::new(VecDeque::from([
            response(api::BlobPublicationPhase::Receiving),
            response(api::BlobPublicationPhase::ExpiredOrRetired),
            response(api::BlobPublicationPhase::Available),
        ])));
        let result = runtime.block_on(wait_with_deadline(
            {
                let calls = Arc::clone(&calls);
                let responses = Arc::clone(&responses);
                move || {
                    calls.fetch_add(1, Ordering::Relaxed);
                    let response = responses.lock().unwrap().pop_front().unwrap();
                    async move { Ok(response) }
                }
            },
            true,
            Duration::from_millis(1),
            Duration::from_secs(1),
        ));
        let error = result.expect_err("retirement must be terminal");
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            error.last().unwrap().phase,
            api::BlobPublicationPhase::ExpiredOrRetired
        );
    }

    #[test]
    fn wait_deadline_contains_final_state() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let result = runtime.block_on(wait_with_deadline(
            {
                let calls = Arc::clone(&calls);
                move || {
                    let call = calls.fetch_add(1, Ordering::Relaxed);
                    async move {
                        if call == 0 {
                            Ok(response(api::BlobPublicationPhase::Receiving))
                        } else {
                            std::future::pending().await
                        }
                    }
                }
            },
            true,
            Duration::from_millis(1),
            Duration::from_millis(20),
        ));
        let error = result.expect_err("global deadline must stop polling");
        assert!(error.message().contains("final observed state: receiving"));
        assert_eq!(
            error.last().unwrap().phase,
            api::BlobPublicationPhase::Receiving
        );
    }

    #[test]
    fn wait_rejects_counter_regression_and_changed_totals() {
        let previous = api::InspectBlobPublicationResponse {
            publication_id: vec![1; 32],
            phase: api::BlobPublicationPhase::Receiving.into(),
            plaintext_total_bytes: 100,
            durable_plaintext_bytes: 50,
            transfer_total_bytes: 120,
            durable_transfer_bytes: 60,
            total_units: 10,
            durable_units: 5,
            ..Default::default()
        };
        assert!(!progress_is_monotonic(
            &previous,
            &api::InspectBlobPublicationResponse {
                durable_plaintext_bytes: 49,
                ..previous.clone()
            }
        ));
        assert!(!progress_is_monotonic(
            &previous,
            &api::InspectBlobPublicationResponse {
                plaintext_total_bytes: 101,
                ..previous.clone()
            }
        ));
        assert!(progress_is_monotonic(
            &previous,
            &api::InspectBlobPublicationResponse {
                phase: api::BlobPublicationPhase::ReadyToFinalize.into(),
                durable_plaintext_bytes: 100,
                durable_transfer_bytes: 120,
                durable_units: 10,
                ..previous.clone()
            }
        ));
    }
}
