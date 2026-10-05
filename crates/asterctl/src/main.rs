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
    let subscriptions = matches!(&command, args::Command::Subscriptions(_));
    let (options, publication, query, subscription) = match command {
        args::Command::SubscriptionsHelp => {
            return write_output(
                "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] subscriptions\n\nList Event subscriptions.\nGlobal options: see asterctl --help.\n",
            );
        }
        args::Command::Help => return write_output(args::HELP),
        args::Command::PublishHelp => return write_output(publish::HELP),
        args::Command::QueryHelp => return write_output(query::HELP),
        args::Command::SubscribeHelp => return write_output(subscribe::HELP),
        args::Command::Status(options) | args::Command::Subscriptions(options) => {
            (options, None, None, None)
        }
        args::Command::Publish(options, publication) => (options, Some(publication), None, None),
        args::Command::Query(options, query) => (options, None, Some(query), None),
        args::Command::Subscribe(options, subscription) => {
            (options, None, None, Some(subscription))
        }
    };
    let token = match options.token {
        args::TokenSource::Plain(token) => token,
        args::TokenSource::File(path) => auth::Token::load(&path).map_err(|e| (1, e.to_owned()))?,
    };
    let request = publication
        .map(|publication| {
            let stdin = io::stdin();
            if publication.reads_stdin() && stdin.is_terminal() {
                let mut stderr = io::stderr().lock();
                stderr
                    .write_all(b"Reading payload from stdin.\nEnter your message, then press Ctrl-D on an empty line to send.\nPress Ctrl-C to cancel.\n")
                    .and_then(|()| stderr.flush())
                    .map_err(|_| "cannot write stdin instructions; request not sent")?;
            }
            publication.into_request(stdin.lock())
        })
        .transpose()
        .map_err(|e| (1, e.to_owned()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| (1, "cannot initialize RPC runtime".to_owned()))?;
    let address = SocketAddr::new(options.host, options.port);
    if let Some(query) = query {
        return match runtime.block_on(query::run(
            address,
            &token,
            query,
            options.timeout,
            options.json,
            io::stdout().lock(),
        )) {
            Ok(()) => Ok(()),
            Err(query::Error::Output(error)) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            Err(query::Error::Output(_)) => Err((1, "cannot write output".to_owned())),
            Err(query::Error::Rpc(error)) => Err((1, error)),
        };
    }
    let text = if subscriptions {
        let response = runtime
            .block_on(client::subscriptions(address, &token, options.timeout))
            .map_err(|e| (1, e))?;
        output::subscriptions(&response, options.json).map_err(|_| {
            (
                1,
                "cannot format ListEventSubscriptions response".to_owned(),
            )
        })?
    } else if let Some(subscription) = subscription {
        let (request, key) = subscription.into_request().map_err(|e| (1, e.to_owned()))?;
        announce_key(&key)?;
        let response = runtime
            .block_on(client::subscribe(address, &token, request, options.timeout))
            .map_err(|e| (1, e.describe("CreateEventSubscription", &key)))?;
        let text = output::subscribe(&response, &key.value, options.json).map_err(|_| {
            (
                1,
                "cannot format CreateEventSubscription response".to_owned(),
            )
        })?;
        return write_output(&text);
    } else if let Some((request, key)) = request {
        announce_key(&key)?;
        let response = runtime
            .block_on(client::publish(address, &token, request, options.timeout))
            .map_err(|e| (1, e.describe("PublishEvent", &key)))?;
        output::publish(&response, &key.value, options.json)
            .map_err(|_| (1, "cannot format PublishEvent response".to_owned()))?
    } else {
        let response = runtime
            .block_on(client::status(address, &token, options.timeout))
            .map_err(|e| (1, e))?;
        output::status(&response, options.json)
            .map_err(|_| (1, "cannot format GetStatus response".to_owned()))?
    };
    write_output(&text)
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
