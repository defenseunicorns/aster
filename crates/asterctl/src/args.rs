use crate::auth::Token;
use crate::publish::Publication;
use crate::query::Query;
use crate::subscribe::Subscription;
use std::{
    ffi::OsString,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    time::Duration,
};

pub const HELP: &str =
    "Usage: asterctl (--token TOKEN | --token-file PATH) [OPTIONS] [COMMAND [ARGS...]]
       asterctl --help

Introspect and control Aster nodes through a running Aster agent.

COMMANDS:
  status            Display node status (default)
  publish           Publish an Event
  query             Query stored Events
  subscribe         Create an Event subscription
  subscriptions     List Event subscriptions

OPTIONS:
  -h, --host IP          Loopback agent IP address (default: 127.0.0.1)
  -p, --port PORT        Aster node RPC port (default: 8181)
      --timeout SECONDS Client RPC timeout, 1–86400 seconds (default: 10)
                        Agent-side deadlines may be shorter (currently at most 30s)
  -j, --json             Print output in JSON (when possible)
  -t, --token TOKEN      Aster node API token as plain text
      --token-file PATH  Read the agent API token from a file
      --help             Show this help
";

#[derive(Debug, PartialEq)]
pub enum TokenSource {
    Plain(Token),
    File(PathBuf),
}

#[derive(Debug, PartialEq)]
pub struct Options {
    pub host: IpAddr,
    pub port: u16,
    pub timeout: Duration,
    pub json: bool,
    pub token: TokenSource,
}

#[derive(Debug, PartialEq)]
pub enum Command {
    Help,
    PublishHelp,
    QueryHelp,
    SubscribeHelp,
    SubscriptionsHelp,
    Status(Options),
    Subscriptions(Options),
    Publish(Options, Box<Publication>),
    Query(Options, Query),
    Subscribe(Options, Subscription),
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut host = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut port = 8181;
    let mut timeout = crate::client::DEFAULT_TIMEOUT;
    let mut json = false;
    let mut token = None;
    let mut status = false;
    let mut subscriptions = false;
    let mut publication: Option<Publication> = None;
    let mut query: Option<Query> = None;
    let mut subscription: Option<Subscription> = None;
    let mut positional = false;
    let mut command_options = std::collections::HashSet::new();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let arg = arg.to_str().ok_or("invalid argument; see --help")?;
        if positional
            || (!arg.starts_with('-') && (publication.is_some() || subscription.is_some()))
        {
            if let Some(publication) = &mut publication {
                publication.set_message(arg)?;
            } else if let Some(subscription) = &mut subscription {
                subscription.set_topic(arg)?;
            } else {
                return Err("unexpected argument; see --help".into());
            }
            continue;
        }
        let (name, inline) = arg
            .split_once('=')
            .map_or((arg, None), |(name, value)| (name, Some(value)));
        match name {
            "--help" => {
                if inline.is_some() {
                    return Err("--help does not take a value".into());
                }
                return Ok(if publication.is_some() {
                    Command::PublishHelp
                } else if query.is_some() {
                    Command::QueryHelp
                } else if subscription.is_some() {
                    Command::SubscribeHelp
                } else if subscriptions {
                    Command::SubscriptionsHelp
                } else {
                    Command::Help
                });
            }
            "subscriptions" if inline.is_none() && !status && query.is_none() && !subscriptions => {
                subscriptions = true;
            }
            "status" if inline.is_none() && !status && query.is_none() && !subscriptions => {
                status = true
            }
            "publish" if inline.is_none() && !status && query.is_none() && !subscriptions => {
                publication = Some(Publication::default())
            }
            "query" if inline.is_none() && !status && query.is_none() && !subscriptions => {
                query = Some(Query::default())
            }
            "subscribe" if inline.is_none() && !status && query.is_none() && !subscriptions => {
                subscription = Some(Subscription::default())
            }
            "--" if inline.is_none() && (publication.is_some() || subscription.is_some()) => {
                positional = true
            }
            "-j" | "--json" => {
                if inline.is_some() {
                    return Err(format!("{name} does not take a value"));
                }
                json = true;
            }
            "-h" | "--host" | "-p" | "--port" | "--timeout" | "-t" | "--token" | "--token-file" => {
                let value = option_value(name, inline, &mut args)?;
                match name {
                    "-h" | "--host" => {
                        host = value
                            .to_str()
                            .and_then(|s| s.parse().ok())
                            .ok_or("host must be an IPv4 or IPv6 address")?;
                    }
                    "-p" | "--port" => {
                        port = value
                            .to_str()
                            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
                            .and_then(|s| s.parse().ok())
                            .filter(|p| *p != 0)
                            .ok_or("port must be an integer from 1 to 65535")?;
                    }
                    "--timeout" => {
                        let seconds = value
                            .to_str()
                            .filter(|s| s.bytes().all(|b| b.is_ascii_digit()))
                            .and_then(|s| s.parse::<u64>().ok())
                            .filter(|s| (1..=86400).contains(s))
                            .ok_or("timeout must be an integer from 1 to 86400 seconds")?;
                        timeout = Duration::from_secs(seconds);
                    }
                    _ => {
                        if token.is_some() {
                            return Err("specify exactly one of --token or --token-file".into());
                        }
                        token = Some(if name == "--token-file" {
                            if value.is_empty() {
                                return Err("token file path must not be empty".into());
                            }
                            TokenSource::File(value.into())
                        } else {
                            TokenSource::Plain(Token::parse(
                                value.into_string().map_err(|_| "token must be ASCII")?,
                            )?)
                        });
                    }
                }
            }
            "--topic" | "--scope" | "--priority" | "--logical-key" | "--predecessor"
            | "--ttl-ms" | "--tombstone" | "--operation-key"
                if publication.is_some() =>
            {
                if !command_options.insert(name.to_owned()) {
                    return Err(format!("{name} must not be repeated"));
                }
                let publication = publication.as_mut().expect("publish command");
                if name == "--tombstone" {
                    if inline.is_some() {
                        return Err("--tombstone does not take a value".into());
                    }
                    publication.request.tombstone = true;
                } else {
                    let value = text_option_value(name, inline, &mut args)?;
                    publication.set_option(name, value)?;
                }
            }
            "--topic" | "--scope" | "--publisher" | "--logical-key" | "--limit"
                if query.is_some() =>
            {
                if !command_options.insert(name.to_owned()) {
                    return Err(format!("{name} must not be repeated"));
                }
                let value = text_option_value(name, inline, &mut args)?;
                query
                    .as_mut()
                    .expect("query command")
                    .set_option(name, value)?;
            }
            "--scope" | "--operation-key" if subscription.is_some() => {
                if !command_options.insert(name.to_owned()) {
                    return Err(format!("{name} must not be repeated"));
                }
                let value = text_option_value(name, inline, &mut args)?;
                subscription
                    .as_mut()
                    .expect("subscribe command")
                    .set_option(name, value)?;
            }
            _ => return Err("unknown argument or command; see --help".into()),
        }
    }
    if !host.is_loopback() {
        return Err(
            "host must be a loopback IPv4 or IPv6 address; plaintext RPC is local-only".into(),
        );
    }
    if let Some(publication) = &publication {
        publication.validate()?;
    }
    if let Some(subscription) = &subscription {
        subscription.validate()?;
    }
    let options = Options {
        host,
        port,
        timeout,
        json,
        token: token.ok_or("specify --token or --token-file; see --help")?,
    };
    Ok(if let Some(publication) = publication {
        Command::Publish(options, Box::new(publication))
    } else if let Some(query) = query {
        Command::Query(options, query)
    } else if let Some(subscription) = subscription {
        Command::Subscribe(options, subscription)
    } else if subscriptions {
        Command::Subscriptions(options)
    } else {
        Command::Status(options)
    })
}

fn option_value(
    name: &str,
    inline: Option<&str>,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<OsString, String> {
    match inline {
        Some(value) if name.starts_with("--") => Ok(OsString::from(value)),
        Some(_) => Err(format!("use a separate value after {name}")),
        None => args
            .next()
            .ok_or_else(|| format!("{name} requires a value")),
    }
}

fn text_option_value(
    name: &str,
    inline: Option<&str>,
    args: &mut impl Iterator<Item = OsString>,
) -> Result<String, String> {
    option_value(name, inline, args)?
        .into_string()
        .map_err(|_| format!("{name} value must be UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(args: &[&str]) -> Result<Command, String> {
        raw_arguments(&[&["--token-file", "/tmp/asterctl-fixture-token"][..], args].concat())
    }

    fn raw_arguments(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn rejects_non_loopback_hosts_for_every_command() {
        for command in ["status", "publish", "query", "subscribe"] {
            for host in [
                "0.0.0.0",
                "192.0.2.1",
                "::",
                "2001:db8::1",
                "::ffff:127.0.0.1",
            ] {
                let error = arguments(&[command, "--host", host]).unwrap_err();
                assert!(error.contains("loopback"), "{command} {host}: {error}");
            }
        }
        for host in ["127.0.0.1", "127.0.0.2", "::1"] {
            assert!(arguments(&["status", "--host", host]).is_ok());
        }
    }

    #[test]
    fn status_defaults_to_local_agent() {
        for args in [&["status"][..], &[]] {
            assert_eq!(
                arguments(args),
                Ok(Command::Status(Options {
                    host: "127.0.0.1".parse().unwrap(),
                    port: 8181,
                    timeout: Duration::from_secs(10),
                    json: false,
                    token: TokenSource::File("/tmp/asterctl-fixture-token".into()),
                }))
            );
        }
    }

    #[test]
    fn accepts_short_and_long_flags_around_status() {
        for args in [
            vec!["-h", "::1", "-p", "8189", "status", "-j"],
            vec!["status", "--host", "::1", "--port", "8189", "--json"],
            vec!["--host=::1", "status", "--port=8189", "--json"],
            vec!["--host=::1", "--port=8189", "--json"],
        ] {
            assert_eq!(
                arguments(&args),
                Ok(Command::Status(Options {
                    host: "::1".parse().unwrap(),
                    port: 8189,
                    timeout: Duration::from_secs(10),
                    json: true,
                    token: TokenSource::File("/tmp/asterctl-fixture-token".into()),
                }))
            );
        }
    }

    #[test]
    fn help_is_long_only() {
        assert_eq!(arguments(&["--help"]), Ok(Command::Help));
        assert_eq!(arguments(&["status", "--help"]), Ok(Command::Help));
        assert!(arguments(&["-h"]).is_err());
    }

    #[test]
    fn accepts_each_approved_token_source() {
        for args in [
            vec!["status", "-t", "asterctl-test-token-00000000000000"],
            vec!["--token", "asterctl-test-token-00000000000000", "status"],
            vec!["status", "--token=asterctl-test-token-00000000000000"],
            vec!["--token-file", "/tmp/asterctl-fixture-token", "status"],
            vec!["status", "--token-file=/tmp/asterctl-fixture-token"],
        ] {
            assert!(raw_arguments(&args).is_ok(), "token source rejected");
        }
    }

    #[test]
    fn rejects_ambiguous_and_invalid_token_sources_without_echoing_values() {
        for args in [
            vec!["status", "--token", "invalid-secret"],
            vec!["status", "--token"],
            vec!["status", "--token-file"],
            vec!["status", "--token-file="],
            vec!["status", "--token-file", "a", "--token-file", "b"],
            vec![
                "status",
                "-t",
                "asterctl-test-token-00000000000000",
                "--token-file",
                "a",
            ],
        ] {
            let error = raw_arguments(&args).unwrap_err();
            assert!(!error.contains("invalid-secret"));
            assert!(!error.contains("asterctl-test-token-00000000000000"));
        }
        assert!(raw_arguments(&["status"]).is_err());
        assert!(raw_arguments(&[]).is_err());
        assert!(raw_arguments(&["--json"]).is_err());
        assert_eq!(raw_arguments(&["--help"]), Ok(Command::Help));
    }

    #[test]
    fn rejects_invalid_commands_addresses_ports_and_options() {
        for args in [
            vec!["publish"],
            vec!["status", "status"],
            vec!["status", "--unknown"],
            vec!["status", "--host"],
            vec!["status", "--host", "127.0.0.1:8181"],
            vec!["status", "--host", "http://127.0.0.1"],
            vec!["status", "--host", "localhost"],
            vec!["status", "--port"],
            vec!["status", "--port", "0"],
            vec!["status", "--port", "65536"],
            vec!["status", "--port", "-1"],
            vec!["status", "--port", "+8181"],
            vec!["status", "--port", "port"],
            vec!["status", "--json=true"],
        ] {
            assert!(arguments(&args).is_err(), "accepted {args:?}");
        }
    }

    #[test]
    fn publish_validates_required_fields_and_byte_limits() {
        for args in [
            vec!["publish", "--topic=x"],
            vec!["publish", "--scope=x"],
            vec!["--topic=x", "publish", "--scope=x"],
            vec!["status", "publish"],
            vec!["publish", "--topic=x", "--scope=x", "--tombstone=false"],
        ] {
            assert!(arguments(&args).is_err());
        }
        for (option, valid, invalid) in [
            ("--topic", "a".repeat(128), "a".repeat(129)),
            ("--scope", "a".repeat(128), "a".repeat(129)),
            ("--operation-key", "ї".repeat(128), "ї".repeat(129)),
            ("--logical-key", "ї".repeat(2048), "ї".repeat(2049)),
        ] {
            for (value, accepted) in [(valid, true), (invalid, false)] {
                let mut args = vec!["publish"];
                if option != "--topic" {
                    args.push("--topic=x");
                }
                if option != "--scope" {
                    args.push("--scope=x");
                }
                if option != "--operation-key" {
                    args.push("--operation-key=test");
                }
                args.extend([option, &value]);
                assert_eq!(arguments(&args).is_ok(), accepted, "{option}");
            }
        }
        for scope in ["/a", "a/", "a//b", ".", "..", "a/./b", "a/../b", "a b", "ї"] {
            assert!(arguments(&["publish", "--topic=x", "--scope", scope]).is_err());
        }
        for topic in ["", "a/b", "a b", "ї"] {
            assert!(arguments(&["publish", "--topic", topic, "--scope=x"]).is_err());
        }
    }

    #[test]
    fn publish_accepts_all_priorities_and_the_full_ttl_range() {
        for (priority, expected) in [
            ("routine", crate::api::Priority::PRIORITY_ROUTINE),
            ("priority", crate::api::Priority::PRIORITY_PRIORITY),
            ("immediate", crate::api::Priority::PRIORITY_IMMEDIATE),
            ("flash", crate::api::Priority::PRIORITY_FLASH),
        ] {
            let Command::Publish(options, publication) = arguments(&[
                "publish",
                "--topic=x",
                "--scope=mission-1/team/alpha_2",
                "--operation-key=test",
                "--priority",
                priority,
                "--ttl-ms=18446744073709551615",
                "--json",
                "a=b",
            ])
            .unwrap() else {
                panic!("publish command")
            };
            assert!(options.json);
            assert_eq!(publication.request.priority, expected);
            assert_eq!(publication.request.ttl_ms, Some(u64::MAX));
            assert_eq!(
                publication
                    .into_request(std::io::empty())
                    .unwrap()
                    .0
                    .payload,
                b"a=b"
            );
        }
    }
}
