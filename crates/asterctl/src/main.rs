mod args;
mod auth;
mod client;
mod operation_key;
mod output;
mod publish;
mod query;
mod subscribe;
mod validation;

mod proto {
    connectrpc::include_generated!();
}

use proto::aster::application::v1alpha1 as api;
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
            let (request, key) = publication
                .into_request(stdin.lock())
                .map_err(|e| (1, e.to_owned()))?;
            announce_key(&key)?;
            let response = rpc
                .runtime
                .block_on(client::publish(
                    rpc.address,
                    &rpc.token,
                    request,
                    rpc.timeout,
                ))
                .map_err(|e| (1, e.describe("PublishEvent", &key)))?;
            output::publish(&response, &key.value, rpc.json)
                .map_err(|_| (1, "cannot format PublishEvent response".to_owned()))?
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
