// Copyright 2026 Defense Unicorns, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated, bounded hierarchy MVP and generated scale-baseline process.
//!
//! This binary is intentionally not a general operator surface. `init` creates
//! one shared set of demo-only unprotected reference artifacts across five
//! mounted state roots. `run` starts exactly one fixed role, optionally enables
//! rosterless nearby discovery, and lets the selected node runtime carry the
//! opaque bridge frames. The publisher role creates three fixed Events and
//! emits hashes, never payload plaintext.

use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr as _,
    time::Duration,
};

use aster_mesh::{
    BridgeAuthorizationLink, Priority, ProvisioningAccess, ReferenceEnvelopeSealer,
    ReferenceProvisioner, Scope, SelectedBridgeAuthorizationPolicy, SelectedBridgeNarrowingPolicy,
    SelectedEventBridgeAdapter, Topic,
};
use aster_node::application::{EventId, EventQuery, SelectedEventHandle};
use aster_node::bridge_runtime::{SelectedEventBridgeConfig, SelectedEventBridgeEdge};
use aster_node::mission::UnprotectedReferenceMission;
use aster_node::publication_journal as numbered;
use aster_node::{
    EventEmissionPolicy, NodeApplication, NodeConfig, SelectedForwardingConfig, StoreLimits,
    format_node_id, format_receipt_field, start_node_with_forwarding,
};
use sha2::{Digest as _, Sha256};

const ROLES: [&str; 5] = [
    "publisher",
    "bridge-alpha",
    "bridge-bravo",
    "consumer",
    "outsider",
];
const MISSION_FILE: &str = "mission.unprotected-reference.bundle";
const FIRST_AUTHORIZATION_FILE: &str = "bridge-authorization-1.bin";
const SECOND_AUTHORIZATION_FILE: &str = "bridge-authorization-2.bin";
const PUBLICATION_JOURNAL_FILE: &str = "publication.redb";
const PUBLICATION_CLIENT: &[u8] = b"native.hierarchy-source.v1";
const SCALE_PUBLICATION_CLIENT: &[u8] = b"native.hierarchy-scale-source.v1";
const COMPLETE_FILE: &str = ".hierarchy-provisioned-v1";
const SCALE_COMPLETE_FILE: &str = ".hierarchy-scale-provisioned-v1";
const SCALE_AUTHORIZATION_COUNT_FILE: &str = ".bridge-authorization-count-v1";
const ALPHA_SCOPE: &str = "demo/alpha";
const PARENT_SCOPE: &str = "demo/parent";
const BRAVO_SCOPE: &str = "demo/bravo";
const SCALE_ROOT_SCOPE: &str = "demo/root";
const ALLOWED_TOPIC: &str = "mesh.allowed";
const DENIED_TOPIC: &str = "mesh.denied";
const ALLOWED_PAYLOAD: &[u8] = b"HIERARCHY_ALLOWED_PAYLOAD_SENTINEL_4f923b";
const DENIED_TOPIC_PAYLOAD: &[u8] = b"HIERARCHY_DENIED_TOPIC_SENTINEL_81f2a0";
const DENIED_PRIORITY_PAYLOAD: &[u8] = b"HIERARCHY_DENIED_PRIORITY_SENTINEL_6d35cc";
const MAX_AUTHORIZATION_FILE_BYTES: u64 = 65_536;
const MAX_DISCOVERY_IPV4_INTERFACES: usize = 8;
const SCALE_LEAF_COUNT: u8 = 8;
const SCALE_REGIONAL_COUNT: u8 = 2;
const SCALE_MAX_PUBLISHERS_PER_LEAF: u8 = 8;
const SCALE_MAX_PUBLISHERS: u8 = SCALE_LEAF_COUNT * SCALE_MAX_PUBLISHERS_PER_LEAF;
const SCALE_AUTHORIZATION_COUNT: usize = SCALE_LEAF_COUNT as usize + SCALE_REGIONAL_COUNT as usize;
const SCALE_AUTHORIZATION_COUNT_BYTES: &[u8] = b"10\n";
const MAX_SCALE_MARKER_BYTES: u64 = 128;

type DemoResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Publisher,
    BridgeAlpha,
    BridgeBravo,
    Consumer,
    Outsider,
    ScalePublisher(u8),
    ScaleLeaf(u8),
    ScaleRegional(u8),
    ScaleRootConsumer,
}

impl Role {
    fn parse(value: &str) -> DemoResult<Self> {
        match value {
            "publisher" => Ok(Self::Publisher),
            "bridge-alpha" => Ok(Self::BridgeAlpha),
            "bridge-bravo" => Ok(Self::BridgeBravo),
            "consumer" => Ok(Self::Consumer),
            "outsider" => Ok(Self::Outsider),
            "root-consumer" => Ok(Self::ScaleRootConsumer),
            _ => {
                if let Some(index) = parse_numbered_role(value, 'p', 3, SCALE_MAX_PUBLISHERS - 1) {
                    Ok(Self::ScalePublisher(index))
                } else if let Some(index) = parse_numbered_role(value, 'l', 2, SCALE_LEAF_COUNT - 1)
                {
                    Ok(Self::ScaleLeaf(index))
                } else if let Some(index) =
                    parse_numbered_role(value, 'r', 2, SCALE_REGIONAL_COUNT - 1)
                {
                    Ok(Self::ScaleRegional(index))
                } else {
                    Err("unknown hierarchy role".into())
                }
            }
        }
    }

    fn name(self) -> String {
        match self {
            Self::Publisher => "publisher".into(),
            Self::BridgeAlpha => "bridge-alpha".into(),
            Self::BridgeBravo => "bridge-bravo".into(),
            Self::Consumer => "consumer".into(),
            Self::Outsider => "outsider".into(),
            Self::ScalePublisher(index) => format!("p{index:03}"),
            Self::ScaleLeaf(index) => format!("l{index:02}"),
            Self::ScaleRegional(index) => format!("r{index:02}"),
            Self::ScaleRootConsumer => "root-consumer".into(),
        }
    }

    const fn is_scale_only(self) -> bool {
        matches!(
            self,
            Self::ScalePublisher(_)
                | Self::ScaleLeaf(_)
                | Self::ScaleRegional(_)
                | Self::ScaleRootConsumer
        )
    }
}

fn parse_numbered_role(value: &str, prefix: char, digits: usize, maximum: u8) -> Option<u8> {
    let suffix = value.strip_prefix(prefix)?;
    if suffix.len() != digits || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let parsed = suffix.parse::<u8>().ok()?;
    (parsed <= maximum).then_some(parsed)
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Init {
        root: PathBuf,
    },
    InitScale {
        root: PathBuf,
        publishers_per_leaf: u8,
    },
    Run {
        role: Role,
        state: PathBuf,
        bind: SocketAddr,
        sync: Duration,
        nearby_window: Option<Duration>,
        nearby_ipv4_interfaces: Vec<Ipv4Addr>,
    },
}

#[derive(Clone, Copy)]
struct Fixture {
    case: &'static str,
    topic: &'static str,
    priority: Priority,
    priority_name: &'static str,
    payload: &'static [u8],
}

const FIXTURES: [Fixture; 3] = [
    Fixture {
        case: "allowed",
        topic: ALLOWED_TOPIC,
        priority: Priority::Immediate,
        priority_name: "immediate",
        payload: ALLOWED_PAYLOAD,
    },
    Fixture {
        case: "denied-topic",
        topic: DENIED_TOPIC,
        priority: Priority::Immediate,
        priority_name: "immediate",
        payload: DENIED_TOPIC_PAYLOAD,
    },
    Fixture {
        case: "denied-priority",
        topic: ALLOWED_TOPIC,
        priority: Priority::Routine,
        priority_name: "routine",
        payload: DENIED_PRIORITY_PAYLOAD,
    },
];

#[tokio::main]
async fn main() -> ExitCode {
    match parse_command(std::env::args().skip(1).collect()).and_then(|command| {
        match &command {
            Command::Init { root } => provision(root),
            Command::InitScale {
                root,
                publishers_per_leaf,
            } => provision_scale(root, *publishers_per_leaf),
            Command::Run { .. } => Ok(()),
        }
        .map(|()| command)
    }) {
        Ok(Command::Init { .. } | Command::InitScale { .. }) => ExitCode::SUCCESS,
        Ok(command @ Command::Run { .. }) => match run_role(command).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!(
                    "HIERARCHY_DEMO status=error error={}",
                    format_receipt_field(&error.to_string())
                );
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!(
                "HIERARCHY_DEMO status=error error={}",
                format_receipt_field(&error.to_string())
            );
            ExitCode::from(2)
        }
    }
}

fn parse_command(values: Vec<String>) -> DemoResult<Command> {
    let mut values = values.into_iter();
    match values.next().as_deref() {
        Some("init") => {
            let root = required_option(&mut values, "--root")?;
            reject_remaining(values)?;
            Ok(Command::Init {
                root: PathBuf::from(root),
            })
        }
        Some("init-scale") => {
            let root = required_option(&mut values, "--root")?;
            let publishers_per_leaf = bounded_u8(
                &required_option(&mut values, "--publishers-per-leaf")?,
                "publishers-per-leaf",
                1,
                SCALE_MAX_PUBLISHERS_PER_LEAF,
            )?;
            reject_remaining(values)?;
            Ok(Command::InitScale {
                root: PathBuf::from(root),
                publishers_per_leaf,
            })
        }
        Some("run") => {
            let role = Role::parse(&required_option(&mut values, "--role")?)?;
            let state = PathBuf::from(required_option(&mut values, "--state")?);
            let bind = SocketAddr::from_str(&required_option(&mut values, "--bind")?)?;
            let sync_ms = positive_u64(&required_option(&mut values, "--sync-ms")?, "sync-ms")?;
            let remaining = values.collect::<Vec<_>>();
            let (nearby_window, nearby_ipv4_interfaces) = match remaining.as_slice() {
                [] => (None, Vec::new()),
                [discover, window_flag, seconds, interfaces_flag, interfaces]
                    if discover == "--discover-lan"
                        && window_flag == "--nearby-window"
                        && interfaces_flag == "--discovery-ipv4-interfaces" =>
                {
                    (
                        Some(Duration::from_secs(positive_u64(
                            seconds,
                            "nearby-window",
                        )?)),
                        discovery_ipv4_interfaces(interfaces)?,
                    )
                }
                _ => return Err("run accepts only --discover-lan --nearby-window SECONDS --discovery-ipv4-interfaces ADDR[,ADDR] after required options".into()),
            };
            Ok(Command::Run {
                role,
                state,
                bind,
                sync: Duration::from_millis(sync_ms),
                nearby_window,
                nearby_ipv4_interfaces,
            })
        }
        _ => Err("expected init, init-scale, or run command".into()),
    }
}

fn required_option(
    values: &mut impl Iterator<Item = String>,
    expected: &'static str,
) -> DemoResult<String> {
    if values.next().as_deref() != Some(expected) {
        return Err(format!("expected {expected}").into());
    }
    values
        .next()
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
        .ok_or_else(|| format!("{expected} requires a value").into())
}

fn reject_remaining(mut values: impl Iterator<Item = String>) -> DemoResult<()> {
    if values.next().is_some() {
        Err("unexpected trailing arguments".into())
    } else {
        Ok(())
    }
}

fn positive_u64(value: &str, label: &str) -> DemoResult<u64> {
    let value = value.parse::<u64>()?;
    if value == 0 {
        return Err(format!("{label} must be positive").into());
    }
    Ok(value)
}

fn bounded_u8(value: &str, label: &str, minimum: u8, maximum: u8) -> DemoResult<u8> {
    let parsed = value.parse::<u8>()?;
    if value != parsed.to_string() || !(minimum..=maximum).contains(&parsed) {
        return Err(format!("{label} must be within {minimum}..={maximum}").into());
    }
    Ok(parsed)
}

fn discovery_ipv4_interfaces(value: &str) -> DemoResult<Vec<Ipv4Addr>> {
    let mut interfaces = value
        .split(',')
        .map(|candidate| -> DemoResult<Ipv4Addr> {
            if candidate.is_empty() || candidate.trim() != candidate {
                return Err("discovery IPv4 interfaces must be comma-separated addresses".into());
            }
            Ipv4Addr::from_str(candidate).map_err(Into::into)
        })
        .collect::<DemoResult<Vec<_>>>()?;
    if interfaces.is_empty() || interfaces.len() > MAX_DISCOVERY_IPV4_INTERFACES {
        return Err(format!(
            "discovery IPv4 interface count must be within 1..={MAX_DISCOVERY_IPV4_INTERFACES}"
        )
        .into());
    }
    interfaces.sort_unstable();
    let original_len = interfaces.len();
    interfaces.dedup();
    if interfaces.len() != original_len {
        return Err("discovery IPv4 interfaces must be unique".into());
    }
    Ok(interfaces)
}

fn scope(value: &str) -> DemoResult<Scope> {
    Scope::new(value).map_err(Into::into)
}

fn topic(value: &str) -> DemoResult<Topic> {
    Topic::new(value).map_err(Into::into)
}

fn relay(value: &str, epoch: u64) -> DemoResult<ProvisioningAccess> {
    ProvisioningAccess::relay(scope(value)?, vec![epoch]).map_err(Into::into)
}

fn member(value: &str, epoch: u64, topics: &[&str]) -> DemoResult<ProvisioningAccess> {
    ProvisioningAccess::member(
        scope(value)?,
        vec![epoch],
        topics
            .iter()
            .map(|value| topic(value))
            .collect::<DemoResult<Vec<_>>>()?,
    )
    .map_err(Into::into)
}

fn content_only(value: &str, epoch: u64, topics: &[&str]) -> DemoResult<ProvisioningAccess> {
    ProvisioningAccess::content_only(
        scope(value)?,
        vec![epoch],
        topics
            .iter()
            .map(|value| topic(value))
            .collect::<DemoResult<Vec<_>>>()?,
    )
    .map_err(Into::into)
}

fn provision(root: &Path) -> DemoResult<()> {
    let role_roots = ROLES
        .iter()
        .map(|&role| (role, root.join(role)))
        .collect::<Vec<_>>();
    for (_, path) in &role_roots {
        fs::create_dir_all(path)?;
    }
    if role_roots
        .iter()
        .all(|(_, path)| path.join(COMPLETE_FILE).is_file())
    {
        validate_existing_provisioning(&role_roots)?;
        println!(
            "HIERARCHY_INIT status=pass disposition=existing nodes=5 authorities=2 edges=2 provisioning=unprotected-reference"
        );
        return Ok(());
    }
    if role_roots
        .iter()
        .any(|(_, path)| directory_has_entries(path))
    {
        return Err("hierarchy provisioning roots are partially initialized".into());
    }

    let alpha = relay(ALPHA_SCOPE, 1)?;
    let parent = relay(PARENT_SCOPE, 2)?;
    let bravo = relay(BRAVO_SCOPE, 3)?;
    let topics = [ALLOWED_TOPIC, DENIED_TOPIC];
    let mut provisioner = ReferenceProvisioner::from_seed([0x91; 32])?;

    let authority_bundle =
        provisioner.issue_control_authority(1, &[alpha.clone(), parent.clone(), bravo.clone()])?;
    let mut authority = ReferenceEnvelopeSealer::open(authority_bundle)?;

    let publisher_bundle = provisioner.issue_node(2, &[member(ALPHA_SCOPE, 1, &topics)?])?;
    let publisher_bytes = publisher_bundle.to_bytes()?;

    let first_bridge_bundle = provisioner.issue_node(3, &[alpha.clone(), parent.clone()])?;
    let first_bridge_bytes = first_bridge_bundle.to_bytes()?;
    let first_bridge = ReferenceEnvelopeSealer::open(first_bridge_bundle)?;

    let second_bridge_bundle =
        provisioner.issue_node(4, &[alpha.clone(), parent.clone(), bravo.clone()])?;
    let second_bridge_bytes = second_bridge_bundle.to_bytes()?;
    let second_bridge = ReferenceEnvelopeSealer::open(second_bridge_bundle)?;

    let consumer_bundle = provisioner.issue_node(
        5,
        &[
            member(BRAVO_SCOPE, 3, &topics)?,
            content_only(ALPHA_SCOPE, 1, &topics)?,
        ],
    )?;
    let consumer_bytes = consumer_bundle.to_bytes()?;

    let enrollment_one = SelectedEventBridgeAdapter::create_enrollment(
        &first_bridge,
        &scope(ALPHA_SCOPE)?,
        1,
        &scope(PARENT_SCOPE)?,
        2,
    )?;
    let verified_one = SelectedEventBridgeAdapter::verify_enrollment(&authority, &enrollment_one)?;
    let policy = SelectedBridgeAuthorizationPolicy::new(
        vec![topic(ALLOWED_TOPIC)?],
        vec![Priority::Immediate],
        2,
    )?;
    let authorization_one = SelectedEventBridgeAdapter::issue_authorization(
        &mut authority,
        &verified_one,
        BridgeAuthorizationLink::new(1, None, 1)?,
        &policy,
    )?;
    let enrollment_two = SelectedEventBridgeAdapter::create_enrollment(
        &second_bridge,
        &scope(PARENT_SCOPE)?,
        2,
        &scope(BRAVO_SCOPE)?,
        3,
    )?;
    let verified_two = SelectedEventBridgeAdapter::verify_enrollment(&authority, &enrollment_two)?;
    let authorization_two = SelectedEventBridgeAdapter::issue_authorization(
        &mut authority,
        &verified_two,
        BridgeAuthorizationLink::new(2, Some(authorization_one.envelope_id()), 1)?,
        &policy,
    )?;

    let mut outsider_provisioner = ReferenceProvisioner::from_seed([0xd2; 32])?;
    let outsider_bundle = outsider_provisioner.issue_node(1, &[relay(PARENT_SCOPE, 2)?])?;
    let outsider_bytes = outsider_bundle.to_bytes()?;

    write_owner_only(&root.join("publisher").join(MISSION_FILE), &publisher_bytes)?;
    write_owner_only(
        &root.join("bridge-alpha").join(MISSION_FILE),
        &first_bridge_bytes,
    )?;
    write_owner_only(
        &root.join("bridge-bravo").join(MISSION_FILE),
        &second_bridge_bytes,
    )?;
    write_owner_only(&root.join("consumer").join(MISSION_FILE), &consumer_bytes)?;
    write_owner_only(&root.join("outsider").join(MISSION_FILE), &outsider_bytes)?;
    for role in ["bridge-alpha", "bridge-bravo", "consumer"] {
        write_owner_only(
            &root.join(role).join(FIRST_AUTHORIZATION_FILE),
            authorization_one.exact_bytes(),
        )?;
        write_owner_only(
            &root.join(role).join(SECOND_AUTHORIZATION_FILE),
            authorization_two.exact_bytes(),
        )?;
    }
    numbered::Journal::initialize(
        &root.join("publisher").join(PUBLICATION_JOURNAL_FILE),
        PUBLICATION_CLIENT,
    )?;
    for (_, path) in &role_roots {
        write_owner_only(&path.join(COMPLETE_FILE), b"aster-hierarchy-demo/v1\n")?;
        File::open(path)?.sync_all()?;
    }
    println!(
        "HIERARCHY_INIT status=pass disposition=created nodes=5 authorities=2 edges=2 provisioning=unprotected-reference"
    );
    Ok(())
}

fn scale_leaf_scope(index: u8) -> String {
    format!("demo/leaf{index:02}")
}

fn scale_regional_scope(index: u8) -> String {
    format!("demo/region{index:02}")
}

const fn scale_region_for_leaf(leaf: u8) -> u8 {
    leaf / (SCALE_LEAF_COUNT / SCALE_REGIONAL_COUNT)
}

const fn scale_leaf_epoch(_index: u8) -> u64 {
    // Fresh stores publish at epoch 1 until an authenticated scope-epoch
    // control is applied. Scope names already separate the eight leaves.
    1
}

const fn scale_regional_epoch(index: u8) -> u64 {
    SCALE_LEAF_COUNT as u64 + index as u64 + 1
}

const fn scale_root_epoch() -> u64 {
    SCALE_LEAF_COUNT as u64 + SCALE_REGIONAL_COUNT as u64 + 1
}

fn scale_publisher_count(publishers_per_leaf: u8) -> usize {
    usize::from(SCALE_LEAF_COUNT) * usize::from(publishers_per_leaf)
}

fn scale_role_names(publishers_per_leaf: u8) -> Vec<String> {
    let mut roles = Vec::with_capacity(scale_publisher_count(publishers_per_leaf) + 12);
    for index in 0..scale_publisher_count(publishers_per_leaf) {
        roles.push(format!("p{index:03}"));
    }
    for index in 0..SCALE_LEAF_COUNT {
        roles.push(format!("l{index:02}"));
    }
    for index in 0..SCALE_REGIONAL_COUNT {
        roles.push(format!("r{index:02}"));
    }
    roles.push("root-consumer".into());
    roles.push("outsider".into());
    roles
}

fn scale_authorization_file(index: usize) -> String {
    format!("bridge-authorization-{index:02}.bin")
}

fn scale_complete_bytes(role: &str, publishers_per_leaf: u8) -> Vec<u8> {
    format!("aster-hierarchy-scale/v1\nrole={role}\npublishers-per-leaf={publishers_per_leaf}\n")
        .into_bytes()
}

fn scale_role_loads_authorizations(role: &str) -> bool {
    role == "root-consumer" || role.starts_with('l') || role.starts_with('r')
}

fn provision_scale(root: &Path, publishers_per_leaf: u8) -> DemoResult<()> {
    if !(1..=SCALE_MAX_PUBLISHERS_PER_LEAF).contains(&publishers_per_leaf) {
        return Err("publishers-per-leaf is outside its bound".into());
    }
    let roles = scale_role_names(publishers_per_leaf);
    let role_roots = roles
        .iter()
        .map(|role| (role.as_str(), root.join(role)))
        .collect::<Vec<_>>();
    for (_, path) in &role_roots {
        fs::create_dir_all(path)?;
    }
    if role_roots
        .iter()
        .all(|(_, path)| path.join(SCALE_COMPLETE_FILE).is_file())
    {
        validate_existing_scale_provisioning(&role_roots, publishers_per_leaf)?;
        println!(
            "HIERARCHY_SCALE_INIT status=pass disposition=existing publishers={} nodes={} authorities=2 edges=10 leaf_scopes=8 regional_scopes=2 provisioning=unprotected-reference",
            scale_publisher_count(publishers_per_leaf),
            roles.len(),
        );
        return Ok(());
    }
    if role_roots
        .iter()
        .any(|(_, path)| directory_has_entries(path))
    {
        return Err("hierarchy scale provisioning roots are partially initialized".into());
    }

    let topics = [ALLOWED_TOPIC, DENIED_TOPIC];
    let leaf_accesses = (0..SCALE_LEAF_COUNT)
        .map(|index| relay(&scale_leaf_scope(index), scale_leaf_epoch(index)))
        .collect::<DemoResult<Vec<_>>>()?;
    let regional_accesses = (0..SCALE_REGIONAL_COUNT)
        .map(|index| relay(&scale_regional_scope(index), scale_regional_epoch(index)))
        .collect::<DemoResult<Vec<_>>>()?;
    let root_access = relay(SCALE_ROOT_SCOPE, scale_root_epoch())?;
    let mut authority_accesses = leaf_accesses.clone();
    authority_accesses.extend(regional_accesses.iter().cloned());
    authority_accesses.push(root_access.clone());

    let mut provisioner = ReferenceProvisioner::from_seed([0xa6; 32])?;
    let authority_bundle = provisioner.issue_control_authority(1, &authority_accesses)?;
    let mut authority = ReferenceEnvelopeSealer::open(authority_bundle)?;
    let mut next_serial = 2u64;

    let mut publisher_missions = Vec::with_capacity(scale_publisher_count(publishers_per_leaf));
    for publisher_index in 0..scale_publisher_count(publishers_per_leaf) {
        let leaf_index = u8::try_from(publisher_index)? / publishers_per_leaf;
        let bundle = provisioner.issue_node(
            next_serial,
            &[member(
                &scale_leaf_scope(leaf_index),
                scale_leaf_epoch(leaf_index),
                &topics,
            )?],
        )?;
        publisher_missions.push((format!("p{publisher_index:03}"), bundle.to_bytes()?));
        next_serial = next_serial
            .checked_add(1)
            .ok_or("scale node serial exhausted")?;
    }

    let mut leaf_bridges = Vec::with_capacity(usize::from(SCALE_LEAF_COUNT));
    for leaf_index in 0..SCALE_LEAF_COUNT {
        let regional_index = scale_region_for_leaf(leaf_index);
        let bundle = provisioner.issue_node(
            next_serial,
            &[
                leaf_accesses[usize::from(leaf_index)].clone(),
                regional_accesses[usize::from(regional_index)].clone(),
            ],
        )?;
        let bytes = bundle.to_bytes()?;
        let sealer = ReferenceEnvelopeSealer::open(bundle)?;
        leaf_bridges.push((format!("l{leaf_index:02}"), bytes, sealer));
        next_serial = next_serial
            .checked_add(1)
            .ok_or("scale node serial exhausted")?;
    }

    let mut regional_bridges = Vec::with_capacity(usize::from(SCALE_REGIONAL_COUNT));
    for regional_index in 0..SCALE_REGIONAL_COUNT {
        let first_leaf = regional_index * (SCALE_LEAF_COUNT / SCALE_REGIONAL_COUNT);
        let mut accesses = (first_leaf..first_leaf + (SCALE_LEAF_COUNT / SCALE_REGIONAL_COUNT))
            .map(|leaf_index| leaf_accesses[usize::from(leaf_index)].clone())
            .collect::<Vec<_>>();
        accesses.push(regional_accesses[usize::from(regional_index)].clone());
        accesses.push(root_access.clone());
        let bundle = provisioner.issue_node(next_serial, &accesses)?;
        let bytes = bundle.to_bytes()?;
        let sealer = ReferenceEnvelopeSealer::open(bundle)?;
        regional_bridges.push((format!("r{regional_index:02}"), bytes, sealer));
        next_serial = next_serial
            .checked_add(1)
            .ok_or("scale node serial exhausted")?;
    }

    let mut root_accesses = vec![member(SCALE_ROOT_SCOPE, scale_root_epoch(), &topics)?];
    for leaf_index in 0..SCALE_LEAF_COUNT {
        root_accesses.push(content_only(
            &scale_leaf_scope(leaf_index),
            scale_leaf_epoch(leaf_index),
            &topics,
        )?);
    }
    let root_bundle = provisioner.issue_node(next_serial, &root_accesses)?;
    let root_bytes = root_bundle.to_bytes()?;

    let mut outsider_provisioner = ReferenceProvisioner::from_seed([0xe7; 32])?;
    let outsider_bundle =
        outsider_provisioner.issue_node(1, &[relay(SCALE_ROOT_SCOPE, scale_root_epoch())?])?;
    let outsider_bytes = outsider_bundle.to_bytes()?;

    let policy = SelectedBridgeAuthorizationPolicy::new(
        vec![topic(ALLOWED_TOPIC)?],
        vec![Priority::Immediate],
        2,
    )?;
    let mut authorization_bytes = Vec::with_capacity(SCALE_AUTHORIZATION_COUNT);
    let mut previous = None;
    for (leaf_index, (_, _, bridge)) in leaf_bridges.iter().enumerate() {
        let leaf_index = u8::try_from(leaf_index)?;
        let regional_index = scale_region_for_leaf(leaf_index);
        let enrollment = SelectedEventBridgeAdapter::create_enrollment(
            bridge,
            &scope(&scale_leaf_scope(leaf_index))?,
            scale_leaf_epoch(leaf_index),
            &scope(&scale_regional_scope(regional_index))?,
            scale_regional_epoch(regional_index),
        )?;
        let verified = SelectedEventBridgeAdapter::verify_enrollment(&authority, &enrollment)?;
        let sequence = u64::from(leaf_index) + 1;
        let authorization = SelectedEventBridgeAdapter::issue_authorization(
            &mut authority,
            &verified,
            BridgeAuthorizationLink::new(sequence, previous, 1)?,
            &policy,
        )?;
        previous = Some(authorization.envelope_id());
        authorization_bytes.push(authorization.exact_bytes().to_vec());
    }
    for (regional_index, (_, _, bridge)) in regional_bridges.iter().enumerate() {
        let regional_index = u8::try_from(regional_index)?;
        let enrollment = SelectedEventBridgeAdapter::create_enrollment(
            bridge,
            &scope(&scale_regional_scope(regional_index))?,
            scale_regional_epoch(regional_index),
            &scope(SCALE_ROOT_SCOPE)?,
            scale_root_epoch(),
        )?;
        let verified = SelectedEventBridgeAdapter::verify_enrollment(&authority, &enrollment)?;
        let sequence = u64::from(SCALE_LEAF_COUNT) + u64::from(regional_index) + 1;
        let authorization = SelectedEventBridgeAdapter::issue_authorization(
            &mut authority,
            &verified,
            BridgeAuthorizationLink::new(sequence, previous, 1)?,
            &policy,
        )?;
        previous = Some(authorization.envelope_id());
        authorization_bytes.push(authorization.exact_bytes().to_vec());
    }
    if authorization_bytes.len() != SCALE_AUTHORIZATION_COUNT {
        return Err("hierarchy scale authorization count mismatch".into());
    }

    for (role, bytes) in &publisher_missions {
        write_owner_only(&root.join(role).join(MISSION_FILE), bytes)?;
    }
    for (role, bytes, _) in &leaf_bridges {
        write_owner_only(&root.join(role).join(MISSION_FILE), bytes)?;
    }
    for (role, bytes, _) in &regional_bridges {
        write_owner_only(&root.join(role).join(MISSION_FILE), bytes)?;
    }
    write_owner_only(&root.join("root-consumer").join(MISSION_FILE), &root_bytes)?;
    write_owner_only(&root.join("outsider").join(MISSION_FILE), &outsider_bytes)?;

    for role in roles
        .iter()
        .filter(|role| scale_role_loads_authorizations(role))
    {
        let state = root.join(role);
        write_owner_only(
            &state.join(SCALE_AUTHORIZATION_COUNT_FILE),
            SCALE_AUTHORIZATION_COUNT_BYTES,
        )?;
        for (index, exact) in authorization_bytes.iter().enumerate() {
            write_owner_only(&state.join(scale_authorization_file(index)), exact)?;
        }
    }
    for (role, path) in &role_roots {
        if matches!(Role::parse(role)?, Role::ScalePublisher(_)) {
            numbered::Journal::initialize(
                &path.join(PUBLICATION_JOURNAL_FILE),
                SCALE_PUBLICATION_CLIENT,
            )?;
        }
        write_owner_only(
            &path.join(SCALE_COMPLETE_FILE),
            &scale_complete_bytes(role, publishers_per_leaf),
        )?;
        File::open(path)?.sync_all()?;
    }
    println!(
        "HIERARCHY_SCALE_INIT status=pass disposition=created publishers={} nodes={} authorities=2 edges=10 leaf_scopes=8 regional_scopes=2 provisioning=unprotected-reference",
        scale_publisher_count(publishers_per_leaf),
        roles.len(),
    );
    Ok(())
}

fn directory_has_entries(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
}

fn load_bounded_regular_file(path: &Path, maximum: u64, label: &str) -> DemoResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(format!("{label} is missing or outside its bound").into());
    }
    fs::read(path).map_err(Into::into)
}

fn validate_existing_scale_provisioning(
    role_roots: &[(&str, PathBuf)],
    publishers_per_leaf: u8,
) -> DemoResult<()> {
    for (role, path) in role_roots {
        if matches!(Role::parse(role)?, Role::ScalePublisher(_)) {
            drop(numbered::Journal::open(
                &path.join(PUBLICATION_JOURNAL_FILE),
                SCALE_PUBLICATION_CLIENT,
            )?);
        }
        if !path.join(MISSION_FILE).is_file() {
            return Err(format!("{role} scale provisioning is incomplete").into());
        }
        let marker = load_bounded_regular_file(
            &path.join(SCALE_COMPLETE_FILE),
            MAX_SCALE_MARKER_BYTES,
            "hierarchy scale marker",
        )?;
        if marker != scale_complete_bytes(role, publishers_per_leaf) {
            return Err(format!("{role} scale marker is not canonical").into());
        }
        if scale_role_loads_authorizations(role) {
            let count = load_bounded_regular_file(
                &path.join(SCALE_AUTHORIZATION_COUNT_FILE),
                SCALE_AUTHORIZATION_COUNT_BYTES.len() as u64,
                "hierarchy scale authorization count",
            )?;
            if count != SCALE_AUTHORIZATION_COUNT_BYTES {
                return Err(format!("{role} scale authorization count is not canonical").into());
            }
            for index in 0..SCALE_AUTHORIZATION_COUNT {
                load_authorization(&path.join(scale_authorization_file(index)))?;
            }
        }
    }
    Ok(())
}

fn validate_existing_provisioning(role_roots: &[(&str, PathBuf)]) -> DemoResult<()> {
    for (role, path) in role_roots {
        if *role == "publisher" {
            drop(numbered::Journal::open(
                &path.join(PUBLICATION_JOURNAL_FILE),
                PUBLICATION_CLIENT,
            )?);
        }
        if !path.join(MISSION_FILE).is_file() {
            return Err(format!("{role} provisioning is incomplete").into());
        }
        if matches!(*role, "bridge-alpha" | "bridge-bravo" | "consumer")
            && (!path.join(FIRST_AUTHORIZATION_FILE).is_file()
                || !path.join(SECOND_AUTHORIZATION_FILE).is_file())
        {
            return Err(format!("{role} bridge authorization chain is incomplete").into());
        }
    }
    Ok(())
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> DemoResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn load_authorization(path: &Path) -> DemoResult<Vec<u8>> {
    load_bounded_regular_file(
        path,
        MAX_AUTHORIZATION_FILE_BYTES,
        "bridge authorization file",
    )
}

fn bridge_config(role: Role, state: &Path) -> DemoResult<Option<SelectedEventBridgeConfig>> {
    if matches!(role, Role::Publisher | Role::Outsider) {
        return Ok(None);
    }
    if role.is_scale_only() {
        return Err("scale role cannot load MVP bridge configuration".into());
    }
    let first = load_authorization(&state.join(FIRST_AUTHORIZATION_FILE))?;
    let second = load_authorization(&state.join(SECOND_AUTHORIZATION_FILE))?;
    let first_id: [u8; 32] = Sha256::digest(&first).into();
    let second_id: [u8; 32] = Sha256::digest(&second).into();
    let narrowing =
        SelectedBridgeNarrowingPolicy::new(vec![topic(ALLOWED_TOPIC)?], vec![Priority::Immediate])?;
    let edges = match role {
        Role::BridgeAlpha => vec![SelectedEventBridgeEdge::new(first_id, narrowing)],
        Role::BridgeBravo => vec![SelectedEventBridgeEdge::new(second_id, narrowing)],
        Role::Consumer => Vec::new(),
        Role::Publisher | Role::Outsider => unreachable!("non-bridge roles returned above"),
        Role::ScalePublisher(_)
        | Role::ScaleLeaf(_)
        | Role::ScaleRegional(_)
        | Role::ScaleRootConsumer => unreachable!("scale roles returned above"),
    };
    SelectedEventBridgeConfig::new(vec![first, second], edges, role == Role::Consumer)
        .map(Some)
        .map_err(Into::into)
}

fn load_scale_state(role: Role, state: &Path) -> DemoResult<Option<u8>> {
    let marker_path = state.join(SCALE_COMPLETE_FILE);
    if !marker_path.exists() {
        return Ok(None);
    }
    if !role.is_scale_only() && role != Role::Outsider {
        return Err("MVP role cannot load hierarchy scale state".into());
    }
    let marker = load_bounded_regular_file(
        &marker_path,
        MAX_SCALE_MARKER_BYTES,
        "hierarchy scale marker",
    )?;
    let role_name = role.name();
    for publishers_per_leaf in 1..=SCALE_MAX_PUBLISHERS_PER_LEAF {
        if marker == scale_complete_bytes(&role_name, publishers_per_leaf) {
            if let Role::ScalePublisher(index) = role
                && usize::from(index) >= scale_publisher_count(publishers_per_leaf)
            {
                return Err("scale publisher role is outside the provisioned bound".into());
            }
            return Ok(Some(publishers_per_leaf));
        }
    }
    Err("hierarchy scale marker is not canonical for this role".into())
}

fn load_scale_authorizations(state: &Path) -> DemoResult<Vec<Vec<u8>>> {
    let count = load_bounded_regular_file(
        &state.join(SCALE_AUTHORIZATION_COUNT_FILE),
        SCALE_AUTHORIZATION_COUNT_BYTES.len() as u64,
        "hierarchy scale authorization count",
    )?;
    if count != SCALE_AUTHORIZATION_COUNT_BYTES {
        return Err("hierarchy scale authorization count is not canonical".into());
    }
    (0..SCALE_AUTHORIZATION_COUNT)
        .map(|index| load_authorization(&state.join(scale_authorization_file(index))))
        .collect()
}

fn scale_bridge_config(role: Role, state: &Path) -> DemoResult<Option<SelectedEventBridgeConfig>> {
    if matches!(role, Role::ScalePublisher(_) | Role::Outsider) {
        return Ok(None);
    }
    let selected_index = match role {
        Role::ScaleLeaf(index) => Some(usize::from(index)),
        Role::ScaleRegional(index) => Some(usize::from(SCALE_LEAF_COUNT) + usize::from(index)),
        Role::ScaleRootConsumer => None,
        Role::Publisher | Role::BridgeAlpha | Role::BridgeBravo | Role::Consumer => {
            return Err("MVP role cannot load hierarchy scale bridge configuration".into());
        }
        Role::Outsider | Role::ScalePublisher(_) => unreachable!("returned above"),
    };
    let authorizations = load_scale_authorizations(state)?;
    let narrowing =
        SelectedBridgeNarrowingPolicy::new(vec![topic(ALLOWED_TOPIC)?], vec![Priority::Immediate])?;
    let edges = selected_index
        .map(|index| {
            let authorization_id: [u8; 32] = Sha256::digest(&authorizations[index]).into();
            vec![SelectedEventBridgeEdge::new(authorization_id, narrowing)]
        })
        .unwrap_or_default();
    SelectedEventBridgeConfig::new(authorizations, edges, role == Role::ScaleRootConsumer)
        .map(Some)
        .map_err(Into::into)
}

async fn run_role(command: Command) -> DemoResult<()> {
    let Command::Run {
        role,
        state,
        bind,
        sync,
        nearby_window,
        nearby_ipv4_interfaces,
    } = command
    else {
        return Err("run_role received an initializer command".into());
    };
    let scale_state = load_scale_state(role, &state)?;
    if scale_state.is_some() && state.join(COMPLETE_FILE).exists() {
        return Err("hierarchy state has conflicting provisioning markers".into());
    }
    if scale_state.is_none() && (role.is_scale_only() || !state.join(COMPLETE_FILE).is_file()) {
        return Err("hierarchy state is not initialized for this role".into());
    }
    let mut publication_journal = match role {
        Role::Publisher => Some(numbered::Journal::open(
            &state.join(PUBLICATION_JOURNAL_FILE),
            PUBLICATION_CLIENT,
        )?),
        Role::ScalePublisher(_) => Some(numbered::Journal::open(
            &state.join(PUBLICATION_JOURNAL_FILE),
            SCALE_PUBLICATION_CLIENT,
        )?),
        _ => None,
    };
    let mission = UnprotectedReferenceMission::load(state.join(MISSION_FILE))?;
    let mission_id = mission.identity();
    let mission_authority = mission.mission_authority_id();
    let mut config = NodeConfig::new(&state, bind, mission);
    config.sync_interval = sync;
    config.application = NodeApplication::Relay;
    let mut forwarding =
        SelectedForwardingConfig::new(EventEmissionPolicy::Normal, StoreLimits::default());
    let bridge = if scale_state.is_some() {
        scale_bridge_config(role, &state)?
    } else {
        bridge_config(role, &state)?
    };
    if let Some(bridge) = bridge {
        forwarding = forwarding.with_event_bridge(bridge);
    }
    #[cfg(feature = "nearby-discovery")]
    if let Some(window) = nearby_window {
        forwarding = forwarding
            .with_automatic_nearby_discovery_on_ipv4_interfaces(window, nearby_ipv4_interfaces)?;
    }
    #[cfg(not(feature = "nearby-discovery"))]
    if nearby_window.is_some() {
        let _ = nearby_ipv4_interfaces;
        return Err("nearby discovery support is not compiled".into());
    }

    let running = start_node_with_forwarding(config, forwarding).await?;
    println!(
        "HIERARCHY_READY status=started role={} mission_id={} mission_authority={} nearby_discovery={}",
        role.name(),
        format_node_id(mission_id),
        format_node_id(mission_authority),
        if nearby_window.is_some() {
            "active-evaluation"
        } else {
            "disabled"
        },
    );
    if let Some(journal) = &mut publication_journal {
        journal
            .recover(&mut numbered::Backend::Live(&running.selected_events()))
            .await?;
    }
    if role == Role::Publisher {
        publish_fixtures(
            &running.selected_events(),
            publication_journal
                .as_mut()
                .ok_or("publisher journal missing")?,
        )
        .await?;
    } else if let Role::ScalePublisher(index) = role {
        publish_scale_fixtures(
            &running.selected_events(),
            publication_journal
                .as_mut()
                .ok_or("scale publisher journal missing")?,
            index,
            scale_state.ok_or("scale publisher did not load scale state")?,
        )
        .await?;
    }
    running.wait().await?;
    Ok(())
}

async fn publish_planned(
    events: &SelectedEventHandle,
    journal: &mut numbered::Journal,
    index: usize,
    intent: numbered::Intent,
) -> DemoResult<EventId> {
    let sequence = index as u64 + 1;
    if sequence <= journal.completed_through() {
        let mut query = EventQuery {
            publisher: Some(events.identity()),
            topic: Some(Topic::new(intent.topic.clone())?),
            scope: Some(Scope::new(intent.scope.clone())?),
            logical_key: Some(intent.logical_key.clone()),
            limit: 128,
            ..EventQuery::default()
        };
        let mut found = None;
        loop {
            let page = events.query(query.clone()).await?;
            for event in page.items {
                if found.replace(event).is_some() {
                    return Err("completed hierarchy publication is ambiguous".into());
                }
            }
            if !page.has_more {
                break;
            }
            if page.scanned_through <= query.after_acceptance_marker {
                return Err("hierarchy query did not advance".into());
            }
            query.after_acceptance_marker = page.scanned_through;
        }
        let event = found.ok_or("completed hierarchy publication is missing")?;
        if event.payload != intent.payload
            || event.priority as u8 != intent.priority
            || event.tombstone != intent.tombstone
            || event.ttl_ms != intent.ttl_ms
        {
            return Err("completed hierarchy publication differs from its fixed plan".into());
        }
        return Ok(event.id);
    }
    if journal.completed_through() + 1 != sequence {
        return Err("hierarchy publication plan has a gap".into());
    }
    let result = journal
        .publish(&mut numbered::Backend::Live(events), intent)
        .await?;
    Ok(EventId::from_bytes(
        *result.result.receipt.semantic_id.as_bytes(),
    ))
}
async fn finish_planned(
    events: &SelectedEventHandle,
    journal: &mut numbered::Journal,
) -> DemoResult<()> {
    if journal.pending().is_some() {
        journal
            .acknowledge(&mut numbered::Backend::Live(events))
            .await?;
    }
    Ok(())
}
async fn publish_fixtures(
    events: &SelectedEventHandle,
    journal: &mut numbered::Journal,
) -> DemoResult<()> {
    if journal.completed_through() > FIXTURES.len() as u64 {
        return Err("hierarchy publication plan frontier exceeds its bound".into());
    }
    for (index, fixture) in FIXTURES.iter().enumerate() {
        let id = publish_planned(
            events,
            journal,
            index,
            numbered::Intent {
                predecessor: None,
                topic: topic(fixture.topic)?.as_str().into(),
                scope: scope(ALPHA_SCOPE)?.as_str().into(),
                priority: fixture.priority as u8,
                logical_key: format!("hierarchy/{}", fixture.case).into_bytes(),
                payload: fixture.payload.to_vec(),
                tombstone: false,
                ttl_ms: None,
            },
        )
        .await?;
        finish_planned(events, journal).await?;
        println!(
            "BRIDGE_SOURCE status=published case={} source_id={} topic={} priority={} payload_sha256={}",
            fixture.case,
            id,
            fixture.topic,
            fixture.priority_name,
            format_node_id(Sha256::digest(fixture.payload).into())
        );
        std::io::stdout().flush()?;
    }
    Ok(())
}
async fn publish_scale_fixtures(
    events: &SelectedEventHandle,
    journal: &mut numbered::Journal,
    publisher_index: u8,
    publishers_per_leaf: u8,
) -> DemoResult<()> {
    if publishers_per_leaf == 0 || publishers_per_leaf > SCALE_MAX_PUBLISHERS_PER_LEAF {
        return Err("scale publisher count is outside its bound".into());
    }
    let leaf_index = publisher_index / publishers_per_leaf;
    if leaf_index >= SCALE_LEAF_COUNT {
        return Err("scale publisher role is outside its leaf bound".into());
    }
    let role = format!("p{publisher_index:03}");
    if journal.completed_through() > 2 {
        return Err("hierarchy scale publication plan frontier exceeds its bound".into());
    }
    for (index, (case, topic_name)) in [("allowed", ALLOWED_TOPIC), ("denied", DENIED_TOPIC)]
        .into_iter()
        .enumerate()
    {
        let payload = format!("HIERARCHY_SCALE_PAYLOAD_SENTINEL_{role}_{case}").into_bytes();
        let id = publish_planned(
            events,
            journal,
            index,
            numbered::Intent {
                predecessor: None,
                topic: topic(topic_name)?.as_str().into(),
                scope: scope(&scale_leaf_scope(leaf_index))?.as_str().into(),
                priority: Priority::Immediate as u8,
                logical_key: format!("hierarchy-scale/{role}/{case}").into_bytes(),
                payload: payload.clone(),
                tombstone: false,
                ttl_ms: None,
            },
        )
        .await?;
        finish_planned(events, journal).await?;
        println!(
            "HIERARCHY_SCALE_SOURCE status=published role={} case={} source_id={} topic={} priority=immediate payload_sha256={}",
            role,
            case,
            id,
            topic_name,
            format_node_id(Sha256::digest(&payload).into())
        );
        std::io::stdout().flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn completed_source_plan_reopens_without_new_events_or_legacy_rows() {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("aster-numbered-hierarchy-test-{suffix}"));
        fs::create_dir(&root).unwrap();
        provision(&root).unwrap();
        let state = root.join("publisher");
        let path = state.join(PUBLICATION_JOURNAL_FILE);
        let mut first_ids = None;
        for _ in 0..2 {
            let mission = UnprotectedReferenceMission::load(state.join(MISSION_FILE)).unwrap();
            let running = aster_node::start_node(NodeConfig::new(
                &state,
                "127.0.0.1:0".parse().unwrap(),
                mission,
            ))
            .await
            .unwrap();
            let events = running.selected_events();
            let mut journal = numbered::Journal::open(&path, PUBLICATION_CLIENT).unwrap();
            journal
                .recover(&mut numbered::Backend::Live(&events))
                .await
                .unwrap();
            publish_fixtures(&events, &mut journal).await.unwrap();
            let page = events
                .query(EventQuery {
                    publisher: Some(events.identity()),
                    ..EventQuery::default()
                })
                .await
                .unwrap();
            assert_eq!(page.items.len(), FIXTURES.len());
            let ids: Vec<_> = page.items.into_iter().map(|event| event.id).collect();
            if let Some(previous) = &first_ids {
                assert_eq!(previous, &ids);
            } else {
                first_ids = Some(ids);
            }
            let status = events.status().await.unwrap();
            assert_eq!(status.event_operation_capacity.numbered_stats.clients, 1);
            assert_eq!(
                status
                    .event_operation_capacity
                    .numbered_stats
                    .outstanding_results,
                0
            );
            assert_eq!(status.event_operation_capacity.stats.records_total, 0);
            drop(journal);
            drop(events);
            running.shutdown().await.unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parser_keeps_init_and_run_modes_bounded() {
        assert_eq!(
            parse_command(vec!["init".into(), "--root".into(), "/tmp/x".into()]).expect("init"),
            Command::Init {
                root: PathBuf::from("/tmp/x")
            }
        );
        let run = parse_command(vec![
            "run".into(),
            "--role".into(),
            "consumer".into(),
            "--state".into(),
            "/tmp/x".into(),
            "--bind".into(),
            "0.0.0.0:4433".into(),
            "--sync-ms".into(),
            "500".into(),
            "--discover-lan".into(),
            "--nearby-window".into(),
            "3".into(),
            "--discovery-ipv4-interfaces".into(),
            "172.30.252.11,172.30.251.11".into(),
        ])
        .expect("run");
        assert!(matches!(
            run,
            Command::Run {
                role: Role::Consumer,
                nearby_window: Some(_),
                ref nearby_ipv4_interfaces,
                ..
            } if nearby_ipv4_interfaces == &[
                Ipv4Addr::new(172, 30, 251, 11),
                Ipv4Addr::new(172, 30, 252, 11),
            ]
        ));
        assert!(
            parse_command(vec![
                "run".into(),
                "--role".into(),
                "consumer".into(),
                "--state".into(),
                "/tmp/x".into(),
                "--bind".into(),
                "0.0.0.0:4433".into(),
                "--sync-ms".into(),
                "500".into(),
                "--discover-lan".into(),
                "--nearby-window".into(),
                "3".into(),
            ])
            .is_err()
        );
        assert!(parse_command(vec!["run".into(), "--role".into()]).is_err());
    }

    #[test]
    fn scale_parser_accepts_only_canonical_bounded_generation() {
        assert_eq!(
            parse_command(vec![
                "init-scale".into(),
                "--root".into(),
                "/tmp/scale".into(),
                "--publishers-per-leaf".into(),
                "8".into(),
            ])
            .expect("scale init"),
            Command::InitScale {
                root: PathBuf::from("/tmp/scale"),
                publishers_per_leaf: 8,
            }
        );
        for invalid in ["0", "9", "01", "-1", "eight"] {
            assert!(
                parse_command(vec![
                    "init-scale".into(),
                    "--root".into(),
                    "/tmp/scale".into(),
                    "--publishers-per-leaf".into(),
                    invalid.into(),
                ])
                .is_err(),
                "accepted invalid publishers-per-leaf {invalid}",
            );
        }

        for (name, expected) in [
            ("p000", Role::ScalePublisher(0)),
            ("p063", Role::ScalePublisher(63)),
            ("l00", Role::ScaleLeaf(0)),
            ("l07", Role::ScaleLeaf(7)),
            ("r00", Role::ScaleRegional(0)),
            ("r01", Role::ScaleRegional(1)),
            ("root-consumer", Role::ScaleRootConsumer),
            ("outsider", Role::Outsider),
        ] {
            assert_eq!(Role::parse(name).expect("canonical role"), expected);
            assert_eq!(expected.name(), name);
        }
        for invalid in [
            "p00",
            "p0000",
            "p064",
            "p-01",
            "p0a0",
            "P000",
            "l0",
            "l08",
            "l000",
            "r0",
            "r02",
            "r000",
            "root_consumer",
        ] {
            assert!(
                Role::parse(invalid).is_err(),
                "accepted invalid role {invalid}"
            );
        }
    }

    #[test]
    fn scale_roles_are_leaf_major_and_exactly_bounded() {
        let minimum = scale_role_names(1);
        assert_eq!(minimum.len(), 20);
        assert_eq!(
            &minimum[..8],
            [
                "p000", "p001", "p002", "p003", "p004", "p005", "p006", "p007"
            ]
        );
        assert_eq!(minimum.last().map(String::as_str), Some("outsider"));

        let maximum = scale_role_names(8);
        assert_eq!(maximum.len(), 76);
        assert_eq!(maximum[63], "p063");
        assert_eq!(maximum[64], "l00");
        assert_eq!(scale_region_for_leaf(0), 0);
        assert_eq!(scale_region_for_leaf(3), 0);
        assert_eq!(scale_region_for_leaf(4), 1);
        assert_eq!(scale_region_for_leaf(7), 1);
        assert!((0..SCALE_LEAF_COUNT).all(|index| scale_leaf_epoch(index) == 1));
        assert_eq!(scale_regional_epoch(0), 9);
        assert_eq!(scale_regional_epoch(1), 10);
        assert_eq!(scale_root_epoch(), 11);
    }
}
