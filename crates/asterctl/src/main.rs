mod args;
mod auth;
mod client;
mod journal;
mod operation_key;
mod output;
mod publish;
mod query;
mod subscribe;
mod validation;

use aster_agent::proto::aster::application::v1alpha1 as api;
use std::{
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    process::ExitCode,
    time::Duration,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            let _ = writeln!(io::stderr().lock(), "asterctl: {message}");
            ExitCode::from(code)
        }
    }
}

fn run() -> Result<(), (u8, String)> {
    let command = args::parse(std::env::args_os().skip(1)).map_err(|e| (2, e))?;
    let text = match command {
        args::Command::SubscriptionsHelp => {
            return write_output(
                "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] subscriptions\n\nList Event subscriptions.\nGlobal options: see asterctl --help.\n",
            );
        }
        args::Command::UnsubscribeHelp => {
            return write_output(
                "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] unsubscribe SUBSCRIPTION_ID\n\nRemove an Event subscription using its Base64 32-byte ID.\nGlobal options: see asterctl --help.\n",
            );
        }
        args::Command::Help => return write_output(args::HELP),
        args::Command::PublishHelp => return write_output(publish::HELP),
        args::Command::QueryHelp => return write_output(query::HELP),
        args::Command::SubscribeHelp => return write_output(subscribe::HELP),
        args::Command::Status(options) => {
            let rpc = RpcContext::new(options)?;
            let response = rpc
                .runtime
                .block_on(client::status(rpc.address, &rpc.token, rpc.timeout))
                .map_err(|e| (1, e))?;
            output::status(&response, rpc.json)
                .map_err(|_| (1, "cannot format GetStatus response".to_owned()))?
        }
        args::Command::Subscriptions(options) => {
            let rpc = RpcContext::new(options)?;
            let response = rpc
                .runtime
                .block_on(client::subscriptions(rpc.address, &rpc.token, rpc.timeout))
                .map_err(|e| (1, e))?;
            output::subscriptions(&response, rpc.json).map_err(|_| {
                (
                    1,
                    "cannot format ListEventSubscriptions response".to_owned(),
                )
            })?
        }
        args::Command::Unsubscribe(options, subscription_id) => {
            let rpc = RpcContext::new(options)?;
            let response = rpc
                .runtime
                .block_on(client::unsubscribe(
                    rpc.address,
                    &rpc.token,
                    subscription_id,
                    rpc.timeout,
                ))
                .map_err(|e| (1, e.describe_unsubscribe()))?;
            output::unsubscribe(&response, rpc.json).map_err(|_| {
                (
                    1,
                    "cannot format DeleteEventSubscription response".to_owned(),
                )
            })?
        }
        args::Command::Publish(options, publication) => {
            let rpc = RpcContext::new(options)?;
            let sdk = client::publication_sdk(
                rpc.address,
                &rpc.token,
                rpc.timeout,
                &publication.identity,
            )
            .map_err(|e| (1, e))?;
            let stdin = io::stdin();
            if publication.reads_stdin() && stdin.is_terminal() {
                let mut stderr = io::stderr().lock();
                stderr
                    .write_all(b"Reading payload from stdin.\nEnter your message, then press Ctrl-D on an empty line to send.\nPress Ctrl-C to cancel.\n")
                    .and_then(|()| stderr.flush())
                    .map_err(|_| {
                        (
                            1,
                            "cannot write stdin instructions; request not sent".to_owned(),
                        )
                    })?;
            }
            let (request, _identity) = publication
                .into_request(stdin.lock())
                .map_err(|e| (1, e.to_owned()))?;
            let result = rpc.runtime.block_on(async {
                let report = sdk.recover().await.map_err(journal::describe_error)?;
                if report.operations.iter().any(|operation| operation.state == aster_agent::sdk::RecoveredState::Pending) {
                    return Err("journal contains pending work; use publication-recover, then publication-retry or publication-abandon before publishing a new intent".to_owned());
                }
                let sequence = sdk.journal_publication(request).map_err(journal::describe_error)?;
                writeln!(io::stderr().lock(), "asterctl: operation-sequence={sequence}").and_then(|()| io::stderr().lock().flush()).map_err(|_| format!("cannot announce sequence {sequence}; intent remains journaled and was not sent"))?;
                sdk.publish_journaled(sequence).await.map_err(|error| format!("{}; sequence {sequence} remains journaled; use publication-recover before retrying", journal::describe_error(error)))
            }).map_err(|e| (1, e))?;
            output::numbered_publication(&result, rpc.json)
                .map_err(|_| (1, "cannot format committed publication result".to_owned()))?
        }
        args::Command::PublicationInitialize(identity) => {
            identity.initialize().map_err(|e| (1, e))?;
            "Publication journal initialized.\n".to_owned()
        }
        args::Command::PublicationAction(options, identity, action, sequence) => {
            let rpc = RpcContext::new(options)?;
            let sdk = client::publication_sdk(rpc.address, &rpc.token, rpc.timeout, &identity)
                .map_err(|e| (1, e))?;
            rpc.runtime.block_on(async {
                if action == journal::Action::Show {
                    let intent = sdk.journaled_intent(sequence.expect("validated sequence")).map_err(journal::describe_error)?.ok_or_else(|| "sequence has no retained journaled intent".to_owned())?;
                    return serde_json::to_string_pretty(&intent).map(|text| text + "\n").map_err(|_| "cannot format journaled intent".to_owned());
                }
                let report = sdk.recover().await.map_err(journal::describe_error)?;
                match action {
                    journal::Action::Recover => {
                        let operations = report.operations.into_iter().map(|operation| match operation.state {
                            aster_agent::sdk::RecoveredState::Pending => serde_json::json!({"operationSequence": operation.sequence.to_string(), "state": "pending"}),
                            aster_agent::sdk::RecoveredState::Committed(result) => serde_json::json!({"operationSequence": operation.sequence.to_string(), "state": "committed", "result": result}),
                            aster_agent::sdk::RecoveredState::Retired => serde_json::json!({"operationSequence": operation.sequence.to_string(), "state": "retired"}),
                        }).collect::<Vec<_>>();
                        serde_json::to_string_pretty(&serde_json::json!({"session": report.session.to_string(), "allocatedThrough": report.allocated_through.to_string(), "operations": operations})).map(|text| text + "\n").map_err(|_| "cannot format recovery report".to_owned())
                    }
                    journal::Action::Retry => {
                        let result = sdk.publish_journaled(sequence.expect("validated sequence")).await.map_err(journal::describe_error)?;
                        output::numbered_publication(&result, rpc.json).map_err(|_| "cannot format committed publication result".to_owned())
                    }
                    journal::Action::Abandon => {
                        sdk.abandon(sequence.expect("validated sequence")).await.map_err(journal::describe_error)?;
                        Ok("Unadmitted sequence permanently abandoned.\n".to_owned())
                    }
                    journal::Action::Acknowledge => {
                        sdk.acknowledge(sequence.expect("validated sequence")).await.map_err(journal::describe_error)?;
                        Ok("Committed publication result acknowledged.\n".to_owned())
                    }
                    journal::Action::Show => unreachable!("local inspection already returned"),
                    journal::Action::Initialize => unreachable!("initialization does not use RPC"),
                }
            }).map_err(|e| (1, e))?
        }
        args::Command::Query(options, query) => {
            let rpc = RpcContext::new(options)?;
            return match rpc.runtime.block_on(query::run(
                rpc.address,
                &rpc.token,
                query,
                rpc.timeout,
                rpc.json,
                io::stdout().lock(),
            )) {
                Ok(()) => Ok(()),
                Err(query::Error::Output(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
                    Ok(())
                }
                Err(query::Error::Output(_)) => Err((1, "cannot write output".to_owned())),
                Err(query::Error::Rpc(error)) => Err((1, error)),
            };
        }
        args::Command::Subscribe(options, subscription) => {
            let rpc = RpcContext::new(options)?;
            let (request, key) = subscription.into_request().map_err(|e| (1, e.to_owned()))?;
            announce_key(&key)?;
            let response = rpc
                .runtime
                .block_on(client::subscribe(
                    rpc.address,
                    &rpc.token,
                    request,
                    rpc.timeout,
                ))
                .map_err(|e| (1, e.describe("CreateEventSubscription", &key)))?;
            output::subscribe(&response, &key.value, rpc.json).map_err(|_| {
                (
                    1,
                    "cannot format CreateEventSubscription response".to_owned(),
                )
            })?
        }
    };
    write_output(&text)
}

struct RpcContext {
    runtime: tokio::runtime::Runtime,
    address: SocketAddr,
    token: auth::Token,
    timeout: Duration,
    json: bool,
}

impl RpcContext {
    fn new(options: args::Options) -> Result<Self, (u8, String)> {
        let token = match options.token {
            args::TokenSource::Plain(token) => token,
            args::TokenSource::File(path) => {
                auth::Token::load(&path).map_err(|e| (1, e.to_owned()))?
            }
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| (1, "cannot initialize RPC runtime".to_owned()))?;
        Ok(Self {
            runtime,
            address: SocketAddr::new(options.host, options.port),
            token,
            timeout: options.timeout,
            json: options.json,
        })
    }
}

fn announce_key(key: &operation_key::Key) -> Result<(), (u8, String)> {
    key.announce(io::stderr().lock()).map_err(|_| {
        (
            1,
            "cannot write operation key to stderr; request not sent".to_owned(),
        )
    })
}

fn write_output(text: &str) -> Result<(), (u8, String)> {
    match io::stdout().lock().write_all(text.as_bytes()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(_) => Err((1, "cannot write output".to_owned())),
    }
}
