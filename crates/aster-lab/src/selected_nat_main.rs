//! Stopped-state selected Event fixture for the retained Iroh NAT laboratory.
//!
//! This binary deliberately prepares credentials and exercises application
//! semantics while the production node is stopped. The production `aster`
//! binary is the only process that drives live network contacts.

#![forbid(unsafe_code)]

use aster_mesh::{
    ProvisioningAccess, ProvisioningBundle, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope,
    Topic,
};
use aster_node::{
    NodeIdentity,
    application::{
        EventAcknowledgement, EventId, EventPollRequest, EventPublishRequest, EventQuery,
        EventSubscriptionId, EventSubscriptionRequest, Priority, SelectedEventNode,
    },
    format_node_id, format_path_field, parse_node_id,
};
use iroh::EndpointId;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    ffi::OsString,
    fs::{self, File},
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::ExitCode,
};
use zeroize::{Zeroize, Zeroizing};

const MANIFEST_HEADER: &str = "ASTER_SELECTED_NAT_MANIFEST";
const MANIFEST_VERSION: u16 = 2;
const MAX_MANIFEST_BYTES: u64 = 16_384;
const MAX_BUNDLE_BYTES: usize = 1_048_576;
const MAX_DNS_NAME_BYTES: usize = 253;
const MAX_CERTIFICATE_BYTES: usize = 1_048_576;
const MAX_PRIVATE_KEY_BYTES: usize = 16_384;
const CANARY_BYTES: usize = 32;
const NODE_NAMES: [&str; 2] = ["a", "b"];
const CANARY_LOGICAL_KEY: &[u8] = b"selected-nat/v1/canary-sha256";
#[cfg(not(any(target_os = "linux", target_os = "android")))]
const UNSUPPORTED_PLATFORM: &str =
    "selected NAT commands require Linux/Android /proc/self/fd descriptor paths";

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aster-selected-nat: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        print_help();
        return Ok(());
    };
    let command = command
        .into_string()
        .map_err(|_| invalid("command must be valid UTF-8"))?;
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    require_selected_nat_runtime()?;
    let options = Options::parse(arguments.collect())?;
    match command.as_str() {
        "prepare" => prepare(&options),
        "publish" => publish(&options),
        "verify" => verify(&options),
        "relay-material" => relay_material(&options),
        "relay-material-destroy" => relay_material_destroy(&options),
        "canary-destroy" => canary_destroy(&options),
        _ => Err(invalid(format!("unknown command {command}"))),
    }
}

fn print_help() {
    println!(
        "Selected-Iroh NAT acceptance helper\n\n\
         Usage:\n\
           aster-selected-nat prepare --root PATH --scope SCOPE --topic TOPIC\n\
           aster-selected-nat publish --root PATH --node a --canary-sha256 HEX64\n\
           aster-selected-nat verify --root PATH --node b \\\n\
             --publisher HEX64 --canary-sha256 HEX64\n\
           aster-selected-nat relay-material --root PATH \\\n\
             --dns-name relay.aster.test --ip-address 10.250.0.20\n\
           aster-selected-nat relay-material-destroy --root PATH\n\n\
           aster-selected-nat canary-destroy --root PATH\n\n\
         Commands require Linux/Android /proc/self/fd semantics. Prepare and\n\
         relay-material accept only an absent or empty root and never overwrite an\n\
         artifact. A failure after root creation can leave an owner-only partial root;\n\
         the helper does not automatically retry or recursively delete it. Inspect and\n\
         explicitly clean that exact root externally before retrying. Mission bundles,\n\
         carrier keys, and relay private keys\n\
         are owner-only. Retained output contains identifiers and public digests, never\n\
         credential or private-key bytes. The invoking effective UID must have exclusive\n\
         custody of each root for the complete command: descriptor binding prevents path\n\
         substitution, but cannot protect state bytes from a concurrent same-UID writer."
    );
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn require_selected_nat_runtime() -> Result<()> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn require_selected_nat_runtime() -> Result<()> {
    Err(invalid(UNSUPPORTED_PLATFORM))
}

#[derive(Debug)]
struct Options(BTreeMap<String, String>);

impl Options {
    fn parse(arguments: Vec<OsString>) -> Result<Self> {
        let mut values = BTreeMap::new();
        let mut arguments = arguments.into_iter();
        while let Some(name) = arguments.next() {
            let name = name
                .into_string()
                .map_err(|_| invalid("option name must be valid UTF-8"))?;
            if !name.starts_with("--") || name.len() == 2 {
                return Err(invalid(format!("expected --option, found {name}")));
            }
            let value = arguments
                .next()
                .ok_or_else(|| invalid(format!("{name} requires a value")))?
                .into_string()
                .map_err(|_| invalid(format!("{name} value must be valid UTF-8")))?;
            let key = name.trim_start_matches("--").to_owned();
            if values.insert(key.clone(), value).is_some() {
                return Err(invalid(format!("duplicate option --{key}")));
            }
        }
        Ok(Self(values))
    }

    fn required(&self, name: &str) -> Result<&str> {
        self.0
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| invalid(format!("--{name} is required")))
    }

    fn required_path(&self, name: &str) -> Result<PathBuf> {
        self.required(name).map(PathBuf::from)
    }

    fn reject_except(&self, names: &[&str]) -> Result<()> {
        if let Some(name) = self.0.keys().find(|name| !names.contains(&name.as_str())) {
            return Err(invalid(format!("unexpected option --{name}")));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestNode {
    name: String,
    mission_id: [u8; 32],
    carrier_id: EndpointId,
    subscription_id: EventSubscriptionId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Manifest {
    scope: Scope,
    topic: Topic,
    mission_authority: [u8; 32],
    canary_sha256: [u8; 32],
    nodes: Vec<ManifestNode>,
}

impl Manifest {
    fn node(&self, name: &str) -> Result<&ManifestNode> {
        self.nodes
            .iter()
            .find(|node| node.name == name)
            .ok_or_else(|| invalid(format!("manifest has no node {name}")))
    }

    fn to_text(&self) -> String {
        let mut text = format!(
            "{MANIFEST_HEADER}\tversion={MANIFEST_VERSION}\tscope={}\ttopic={}\tmission_authority={}\tcanary_sha256={}\tnodes={}\n",
            self.scope.as_str(),
            self.topic.as_str(),
            format_node_id(self.mission_authority),
            hex(&self.canary_sha256),
            self.nodes.len()
        );
        text.push_str("name\tmission_id\tcarrier_id\tsubscription_id\n");
        for node in &self.nodes {
            text.push_str(&format!(
                "{}\t{}\t{}\t{}\n",
                node.name,
                format_node_id(node.mission_id),
                node.carrier_id,
                node.subscription_id
            ));
        }
        text
    }

    fn parse(text: &str) -> Result<Self> {
        let mut lines = text.lines();
        let header = lines.next().ok_or_else(|| invalid("empty manifest"))?;
        let mut fields = header.split('\t');
        if fields.next() != Some(MANIFEST_HEADER) {
            return Err(invalid("invalid selected NAT manifest header"));
        }
        let mut values = BTreeMap::new();
        for field in fields {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| invalid("malformed manifest header field"))?;
            if values.insert(name, value).is_some() {
                return Err(invalid("duplicate manifest header field"));
            }
        }
        if values.remove("version") != Some("2") || values.remove("nodes") != Some("2") {
            return Err(invalid("unsupported selected NAT manifest shape"));
        }
        let scope = Scope::new(
            values
                .remove("scope")
                .ok_or_else(|| invalid("manifest scope is missing"))?
                .to_owned(),
        )?;
        let topic = Topic::new(
            values
                .remove("topic")
                .ok_or_else(|| invalid("manifest topic is missing"))?
                .to_owned(),
        )?;
        let mission_authority_text = values
            .remove("mission_authority")
            .ok_or_else(|| invalid("manifest mission authority is missing"))?;
        let mission_authority = parse_node_id(mission_authority_text)?;
        if format_node_id(mission_authority) != mission_authority_text {
            return Err(invalid(
                "manifest mission authority is not canonical lowercase hex",
            ));
        }
        let canary_sha256 = parse_hex_32(
            values
                .remove("canary_sha256")
                .ok_or_else(|| invalid("manifest canary SHA-256 is missing"))?,
            "manifest canary SHA-256",
        )?;
        if !values.is_empty()
            || lines.next() != Some("name\tmission_id\tcarrier_id\tsubscription_id")
        {
            return Err(invalid("non-canonical selected NAT manifest header"));
        }

        let mut nodes = Vec::with_capacity(2);
        for expected in NODE_NAMES {
            let row = lines
                .next()
                .ok_or_else(|| invalid("selected NAT manifest is truncated"))?;
            let mut fields = row.split('\t');
            let name = fields
                .next()
                .ok_or_else(|| invalid("manifest node name is missing"))?;
            let mission_id = parse_node_id(
                fields
                    .next()
                    .ok_or_else(|| invalid("manifest mission ID is missing"))?,
            )?;
            let carrier_text = fields
                .next()
                .ok_or_else(|| invalid("manifest carrier ID is missing"))?;
            let carrier_id: EndpointId = carrier_text.parse()?;
            if carrier_id.to_string() != carrier_text {
                return Err(invalid(
                    "manifest carrier ID is not canonical lowercase hex",
                ));
            }
            let subscription_id = EventSubscriptionId::from_bytes(parse_hex_32(
                fields
                    .next()
                    .ok_or_else(|| invalid("manifest subscription ID is missing"))?,
                "subscription",
            )?);
            if fields.next().is_some() || name != expected {
                return Err(invalid("non-canonical selected NAT manifest row"));
            }
            nodes.push(ManifestNode {
                name: name.to_owned(),
                mission_id,
                carrier_id,
                subscription_id,
            });
        }
        if lines.any(|line| !line.is_empty()) {
            return Err(invalid("selected NAT manifest has trailing rows"));
        }
        require_independent_identities(&nodes, mission_authority)?;
        Ok(Self {
            scope,
            topic,
            mission_authority,
            canary_sha256,
            nodes,
        })
    }
}

#[cfg(unix)]
fn prepare(options: &Options) -> Result<()> {
    options.reject_except(&["root", "scope", "topic"])?;
    let root = options.required_path("root")?;
    let scope = Scope::new(options.required("scope")?.to_owned())?;
    let topic = Topic::new(options.required("topic")?.to_owned())?;
    let root_directory = prepare_fresh_root(&root)?;
    let private_directory =
        create_owned_directory_at(&root_directory, "private", "selected NAT private directory")?;
    drop(private_directory);
    let tree = SecurePrivateTree::from_retained_root(&root, root_directory)?;
    let mut canary = Zeroizing::new([0u8; CANARY_BYTES]);
    getrandom::fill(&mut *canary)?;
    let canary_sha256: [u8; 32] = Sha256::digest(*canary).into();
    write_new_at(&tree.private, "canary.bin", &*canary, 0o600)?;
    canary.zeroize();

    let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed)?;
    let mut provisioner = ReferenceProvisioner::from_seed(*seed)?;
    seed.zeroize();
    let mut nodes = Vec::with_capacity(2);
    let mut mission_authority = None;

    for (index, name) in NODE_NAMES.into_iter().enumerate() {
        let bundle = provisioner.issue_node(
            u64::try_from(index)?.saturating_add(1),
            std::slice::from_ref(&access),
        )?;
        let mut bundle_bytes = Zeroizing::new(bundle.to_bytes()?);
        if bundle_bytes.len() > MAX_BUNDLE_BYTES {
            return Err(invalid(
                "generated mission bundle exceeds the laboratory bound",
            ));
        }
        let decoded = ProvisioningBundle::from_bytes(&bundle_bytes)?;
        let mission_id = ReferenceEnvelopeSealer::open(decoded)?.identity();
        let mission_filename = mission_filename(name);
        write_new_at(&tree.private, &mission_filename, &bundle_bytes, 0o600)?;
        let retained_bundle = RetainedRegularFile::open(
            &tree.private,
            &mission_filename,
            u64::try_from(MAX_BUNDLE_BYTES)?,
            0o600,
        )?;
        bundle_bytes.zeroize();

        let state_filename = state_filename(name);
        let state_directory =
            create_owned_directory_at(&tree.root, &state_filename, "selected NAT node state")?;
        let state = descriptor_path(&state_directory)?;
        let mission_path = descriptor_child_path(&tree.private, &mission_filename)?;
        let identity = NodeIdentity::load_or_create(&state)?;
        let carrier_id = identity.id();
        drop(identity);
        state_directory.sync_all()?;

        let mut selected = SelectedEventNode::open_unprotected_reference(&state, &mission_path)?;
        retained_bundle.require_unchanged()?;
        retained_bundle.require_pathname(&tree.private, &mission_filename)?;
        if selected.identity() != mission_id {
            return Err(invalid(
                "selected mission identity changed while opening state",
            ));
        }
        match mission_authority {
            Some(authority) if authority != selected.mission_authority() => {
                return Err(invalid(
                    "selected nodes do not share one exact mission authority",
                ));
            }
            Some(_) => {}
            None => mission_authority = Some(selected.mission_authority()),
        }
        let subscription = selected.subscribe(subscription_request(name, &scope, &topic))?;
        if !subscription.inserted {
            return Err(invalid(
                "fresh subscription was unexpectedly already present",
            ));
        }
        let pre_inventory = selected.query(exact_query(mission_id, &scope, &topic))?;
        if pre_inventory.has_more || !pre_inventory.items.is_empty() {
            return Err(invalid(
                "fresh selected NAT state contained an Event before publication",
            ));
        }
        drop(selected);
        retained_bundle.require_unchanged()?;
        retained_bundle.require_pathname(&tree.private, &mission_filename)?;
        state_directory.sync_all()?;
        tree.require_stable()?;
        nodes.push(ManifestNode {
            name: name.to_owned(),
            mission_id,
            carrier_id,
            subscription_id: subscription.id,
        });
    }

    let mission_authority =
        mission_authority.ok_or_else(|| invalid("selected NAT mission authority is missing"))?;
    require_independent_identities(&nodes, mission_authority)?;
    let manifest = Manifest {
        scope,
        topic,
        mission_authority,
        canary_sha256,
        nodes,
    };
    let manifest_path = root.join("manifest.tsv");
    write_new_at(
        &tree.root,
        "manifest.tsv",
        manifest.to_text().as_bytes(),
        0o644,
    )?;
    tree.require_stable()?;

    println!(
        "SELECTED_NAT_PREPARE status=pass version=2 nodes=2 scope={} topic={} manifest={} mission_authority={} mission_authority_shared=true mission_authority_disjoint=true mission_ids_distinct=true carrier_ids_distinct=true mission_carrier_disjoint=true subscriptions=2 pre_inventory_events=0 canary_sha256={} canary_bytes=32 canary=redacted",
        manifest.scope.as_str(),
        manifest.topic.as_str(),
        format_path_field(&manifest_path),
        format_node_id(manifest.mission_authority),
        hex(&manifest.canary_sha256),
    );
    for node in &manifest.nodes {
        println!(
            "SELECTED_NAT_NODE name={} mission_id={} carrier_id={}",
            node.name,
            format_node_id(node.mission_id),
            node.carrier_id,
        );
    }
    Ok(())
}

#[cfg(unix)]
fn publish(options: &Options) -> Result<()> {
    options.reject_except(&["root", "node", "canary-sha256"])?;
    let root = options.required_path("root")?;
    let tree = SecurePrivateTree::open(&root)?;
    let name = exact_node_name(options.required("node")?)?;
    let expected_canary_sha256 =
        parse_hex_32(options.required("canary-sha256")?, "canary SHA-256")?;
    let manifest = load_manifest(&tree)?;
    if expected_canary_sha256 != manifest.canary_sha256 {
        return Err(invalid("requested canary SHA-256 does not match manifest"));
    }
    let canary = load_private_canary(&tree, &manifest)?;
    let canary_text = hex(&manifest.canary_sha256);
    let expected = manifest.node(name)?;
    let request = publication_request(
        name,
        &manifest.scope,
        &manifest.topic,
        &canary,
        manifest.canary_sha256,
    );
    let state_directory =
        open_owned_directory_at(&tree.root, &state_filename(name), "selected NAT node state")?;
    let state = descriptor_path(&state_directory)?;
    let mission_name = mission_filename(name);
    let retained_bundle = RetainedRegularFile::open(
        &tree.private,
        &mission_name,
        u64::try_from(MAX_BUNDLE_BYTES)?,
        0o600,
    )?;
    let mission = descriptor_child_path(&tree.private, &mission_name)?;
    let mut selected = SelectedEventNode::open_unprotected_reference(&state, &mission)?;
    retained_bundle.require_unchanged()?;
    retained_bundle.require_pathname(&tree.private, &mission_name)?;
    if selected.identity() != expected.mission_id {
        return Err(invalid(
            "publisher mission identity does not match manifest",
        ));
    }
    if selected.mission_authority() != manifest.mission_authority {
        return Err(invalid(
            "publisher mission authority does not match manifest",
        ));
    }
    let publication = selected.publish(request.clone())?;
    if !publication.inserted || publication.publisher != expected.mission_id {
        return Err(invalid(
            "fresh selected NAT publication was not inserted exactly once",
        ));
    }
    let replay = selected.publish(request)?;
    if replay.inserted || replay.id != publication.id || replay.publisher_counter != 1 {
        return Err(invalid(
            "selected NAT publication replay was not an exact no-op",
        ));
    }
    let page = selected.query(exact_query(
        expected.mission_id,
        &manifest.scope,
        &manifest.topic,
    ))?;
    if page.has_more {
        return Err(invalid(
            "exact publisher inventory unexpectedly has more rows",
        ));
    }
    require_exact_event(
        &page.items,
        expected.mission_id,
        &manifest,
        &canary,
        publication.id,
    )?;
    drop(selected);
    retained_bundle.require_unchanged()?;
    retained_bundle.require_pathname(&tree.private, &mission_name)?;
    state_directory.sync_all()?;
    tree.require_stable()?;
    let payload_sha256 = Sha256::digest(&*canary);
    println!(
        "SELECTED_NAT_PUBLISH status=pass version=1 node={} event_id={} publisher={} sequence={} inserted=true replay_publish=noop pre_inventory_events=0 post_inventory_events=1 canary_sha256={} payload_sha256={} payload_bytes=32 sealed_sha256=not-exposed-by-production-api exact_query=true",
        name,
        publication.id,
        format_node_id(publication.publisher),
        publication.event_sequence,
        canary_text,
        hex(payload_sha256.as_slice()),
    );
    Ok(())
}

#[cfg(unix)]
fn verify(options: &Options) -> Result<()> {
    options.reject_except(&["root", "node", "publisher", "canary-sha256"])?;
    let root = options.required_path("root")?;
    let tree = SecurePrivateTree::open(&root)?;
    let name = exact_node_name(options.required("node")?)?;
    let publisher = parse_node_id(options.required("publisher")?)?;
    let expected_canary_sha256 =
        parse_hex_32(options.required("canary-sha256")?, "canary SHA-256")?;
    let manifest = load_manifest(&tree)?;
    if expected_canary_sha256 != manifest.canary_sha256 {
        return Err(invalid("requested canary SHA-256 does not match manifest"));
    }
    let canary = load_private_canary(&tree, &manifest)?;
    let expected = manifest.node(name)?;
    if publisher == expected.mission_id {
        return Err(invalid(
            "verification publisher must be the other mission node",
        ));
    }
    if !manifest
        .nodes
        .iter()
        .any(|node| node.mission_id == publisher)
    {
        return Err(invalid("verification publisher is absent from manifest"));
    }
    let state_directory =
        open_owned_directory_at(&tree.root, &state_filename(name), "selected NAT node state")?;
    let state = descriptor_path(&state_directory)?;
    let mission_name = mission_filename(name);
    let retained_bundle = RetainedRegularFile::open(
        &tree.private,
        &mission_name,
        u64::try_from(MAX_BUNDLE_BYTES)?,
        0o600,
    )?;
    let mission = descriptor_child_path(&tree.private, &mission_name)?;
    let mut selected = SelectedEventNode::open_unprotected_reference(&state, &mission)?;
    retained_bundle.require_unchanged()?;
    retained_bundle.require_pathname(&tree.private, &mission_name)?;
    if selected.identity() != expected.mission_id {
        return Err(invalid("receiver mission identity does not match manifest"));
    }
    if selected.mission_authority() != manifest.mission_authority {
        return Err(invalid(
            "receiver mission authority does not match manifest",
        ));
    }
    let replay_subscription =
        selected.subscribe(subscription_request(name, &manifest.scope, &manifest.topic))?;
    if replay_subscription.inserted || replay_subscription.id != expected.subscription_id {
        return Err(invalid(
            "durable subscription replay was not an exact no-op",
        ));
    }

    let page = selected.poll(EventPollRequest {
        subscription: expected.subscription_id,
        delivery_limit: 16,
        scan_limit: 16,
    })?;
    if page.has_more || page.deliveries.len() != 1 {
        return Err(invalid(
            "receiver did not produce exactly one bounded canary delivery",
        ));
    }
    let delivery = &page.deliveries[0];
    require_exact_event(
        std::slice::from_ref(&delivery.event),
        publisher,
        &manifest,
        &canary,
        delivery.event.id,
    )?;
    let event_id = delivery.event.id;
    let attempt = delivery.attempt;
    if attempt != 1 {
        return Err(invalid("fresh canary delivery attempt was not one"));
    }
    if selected.acknowledge(expected.subscription_id, event_id)?
        != EventAcknowledgement::Acknowledged
    {
        return Err(invalid("first canary acknowledgement was not committed"));
    }
    let empty = selected.poll(EventPollRequest {
        subscription: expected.subscription_id,
        delivery_limit: 16,
        scan_limit: 16,
    })?;
    if empty.has_more || !empty.deliveries.is_empty() {
        return Err(invalid(
            "canary subscription was not empty after acknowledgement",
        ));
    }
    if selected.acknowledge(expected.subscription_id, event_id)?
        != EventAcknowledgement::AlreadyAcknowledged
    {
        return Err(invalid("repeated canary acknowledgement was not a no-op"));
    }
    let query = selected.query(exact_query(publisher, &manifest.scope, &manifest.topic))?;
    if query.has_more {
        return Err(invalid(
            "exact receiver inventory unexpectedly has more rows",
        ));
    }
    require_exact_event(&query.items, publisher, &manifest, &canary, event_id)?;
    drop(selected);
    retained_bundle.require_unchanged()?;
    retained_bundle.require_pathname(&tree.private, &mission_name)?;
    state_directory.sync_all()?;
    tree.require_stable()?;
    let payload_sha256 = Sha256::digest(&*canary);
    println!(
        "SELECTED_NAT_VERIFY status=pass version=1 node={} event_id={} publisher={} pre_inventory_events=0 post_inventory_events=1 canary_sha256={} payload_sha256={} payload_bytes=32 sealed_sha256=not-exposed-by-production-api deliveries=1 attempt={} acknowledged=true empty_after_ack=true replay_ack=noop replay_subscription=noop exact_query=true",
        name,
        event_id,
        format_node_id(publisher),
        hex(&manifest.canary_sha256),
        hex(payload_sha256.as_slice()),
        attempt,
    );
    Ok(())
}

#[cfg(unix)]
fn relay_material(options: &Options) -> Result<()> {
    options.reject_except(&["root", "dns-name", "ip-address"])?;
    let root = options.required_path("root")?;
    let dns_name = options.required("dns-name")?;
    validate_dns_name(dns_name)?;
    let ip_address: IpAddr = options.required("ip-address")?.parse()?;
    if ip_address.is_loopback() || ip_address.is_unspecified() || ip_address.is_multicast() {
        return Err(invalid(
            "relay certificate IP must be a concrete non-loopback unicast address",
        ));
    }
    let root_directory = prepare_fresh_root(&root)?;
    let private_directory =
        create_owned_directory_at(&root_directory, "private", "selected NAT private directory")?;
    drop(private_directory);
    let tree = SecurePrivateTree::from_retained_root(&root, root_directory)?;

    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Aster selected NAT laboratory CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;

    // `CertificateParams::new` parses IP strings into an IP SAN. Supplying both
    // values produces the exact DNS + IP SAN set used by the isolated topology.
    let mut server_params =
        CertificateParams::new(vec![dns_name.to_owned(), ip_address.to_string()])?;
    server_params
        .distinguished_name
        .push(DnType::CommonName, dns_name);
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.use_authority_key_identifier_extension = true;
    let server_key = KeyPair::generate()?;
    let server_certificate = server_params.signed_by(&server_key, &ca)?;
    let ca_der = ca.der().as_ref();
    let certificate_der = server_certificate.der().as_ref();
    let mut private_key = Zeroizing::new(server_key.serialize_der());
    if ca_der.len() > MAX_CERTIFICATE_BYTES
        || certificate_der.len() > MAX_CERTIFICATE_BYTES
        || private_key.len() > MAX_PRIVATE_KEY_BYTES
    {
        return Err(invalid(
            "generated relay material exceeds its laboratory bound",
        ));
    }
    write_new_at(&tree.root, "ca.der", ca_der, 0o644)?;
    write_new_at(&tree.root, "server.cert.der", certificate_der, 0o644)?;
    write_new_at(&tree.private, "server.key.pkcs8.der", &private_key, 0o600)?;
    private_key.zeroize();
    tree.require_stable()?;
    println!(
        "SELECTED_NAT_RELAY_MATERIAL status=pass version=1 dns_name={} ip_address={} san=dns+ip ca_sha256={} certificate_sha256={} certificate_format=der private_key_format=pkcs8-der private_key=redacted key_mode=0600",
        dns_name,
        ip_address,
        hex(Sha256::digest(ca_der).as_slice()),
        hex(Sha256::digest(certificate_der).as_slice()),
    );
    Ok(())
}

#[cfg(unix)]
fn relay_material_destroy(options: &Options) -> Result<()> {
    options.reject_except(&["root"])?;
    let root = options.required_path("root")?;
    let destroyed =
        destroy_private_artifact(&root, "server.key.pkcs8.der", 1, MAX_PRIVATE_KEY_BYTES)?;
    println!(
        "SELECTED_NAT_RELAY_MATERIAL_DESTROY status=pass version=1 artifact_destroyed=true global_secret_destruction=false target=private/server.key.pkcs8.der previous_bytes={} previous_mode={:04o} owner_uid={} overwrite=zero sync=file+directory unlinked=true assurance=bounded-software physical_sanitization=not-claimed",
        destroyed.bytes, destroyed.mode, destroyed.owner,
    );
    Ok(())
}

#[cfg(unix)]
fn canary_destroy(options: &Options) -> Result<()> {
    options.reject_except(&["root"])?;
    let root = options.required_path("root")?;
    let destroyed = destroy_private_artifact(&root, "canary.bin", CANARY_BYTES, CANARY_BYTES)?;
    println!(
        "SELECTED_NAT_CANARY_DESTROY status=pass version=1 artifact_destroyed=true global_secret_destruction=false target=private/canary.bin previous_bytes={} previous_mode={:04o} owner_uid={} overwrite=zero sync=file+directory unlinked=true assurance=bounded-software physical_sanitization=not-claimed",
        destroyed.bytes, destroyed.mode, destroyed.owner,
    );
    Ok(())
}

#[cfg(not(unix))]
macro_rules! unsupported_selected_nat_commands {
    ($($name:ident),+ $(,)?) => {
        $(
            fn $name(_options: &Options) -> Result<()> {
                require_selected_nat_runtime()
            }
        )+
    };
}

#[cfg(not(unix))]
unsupported_selected_nat_commands!(
    prepare,
    publish,
    verify,
    relay_material,
    relay_material_destroy,
    canary_destroy,
);

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
struct SecurePrivateTree {
    root_path: PathBuf,
    root: File,
    private: File,
    ancestry: Vec<DirectoryIdentity>,
    root_identity: DirectoryIdentity,
    private_identity: DirectoryIdentity,
}

#[cfg(unix)]
impl SecurePrivateTree {
    fn open(root_path: &Path) -> Result<Self> {
        let (root, ancestry) = open_absolute_directory_chain(root_path)?;
        Self::from_open_root(root_path, root, ancestry)
    }

    fn from_retained_root(root_path: &Path, root: File) -> Result<Self> {
        require_owned_directory(&root, "selected NAT root")?;
        let root_identity = directory_identity(&root, "selected NAT root")?;
        let (reopened, ancestry) = open_absolute_directory_chain(root_path)?;
        require_owned_directory(&reopened, "selected NAT root")?;
        if directory_identity(&reopened, "selected NAT root")? != root_identity {
            return Err(invalid(
                "selected NAT root pathname changed before private setup",
            ));
        }
        Self::from_open_root(root_path, root, ancestry)
    }

    fn from_open_root(
        root_path: &Path,
        root: File,
        ancestry: Vec<DirectoryIdentity>,
    ) -> Result<Self> {
        require_owned_directory(&root, "selected NAT root")?;
        let root_identity = directory_identity(&root, "selected NAT root")?;
        let private_descriptor = rustix::fs::openat(
            &root,
            "private",
            directory_open_flags(),
            rustix::fs::Mode::empty(),
        )?;
        let private = File::from(private_descriptor);
        require_owned_directory(&private, "selected NAT private directory")?;
        let private_identity = directory_identity(&private, "selected NAT private directory")?;
        let tree = Self {
            root_path: root_path.to_path_buf(),
            root,
            private,
            ancestry,
            root_identity,
            private_identity,
        };
        tree.require_stable()?;
        Ok(tree)
    }

    fn require_stable(&self) -> Result<()> {
        require_owned_directory(&self.root, "selected NAT root")?;
        require_owned_directory(&self.private, "selected NAT private directory")?;
        if directory_identity(&self.root, "selected NAT root")? != self.root_identity
            || directory_identity(&self.private, "selected NAT private directory")?
                != self.private_identity
        {
            return Err(invalid(
                "selected NAT root/private directory identity changed",
            ));
        }

        let (reopened_root, ancestry) = open_absolute_directory_chain(&self.root_path)?;
        require_owned_directory(&reopened_root, "selected NAT root")?;
        if ancestry != self.ancestry
            || directory_identity(&reopened_root, "selected NAT root")? != self.root_identity
        {
            return Err(invalid(
                "selected NAT root ancestry changed during the operation",
            ));
        }
        let reopened_private_descriptor = rustix::fs::openat(
            &reopened_root,
            "private",
            directory_open_flags(),
            rustix::fs::Mode::empty(),
        )?;
        let reopened_private = File::from(reopened_private_descriptor);
        require_owned_directory(&reopened_private, "selected NAT private directory")?;
        if directory_identity(&reopened_private, "selected NAT private directory")?
            != self.private_identity
        {
            return Err(invalid(
                "selected NAT private directory identity changed during the operation",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn directory_open_flags() -> rustix::fs::OFlags {
    rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NONBLOCK
}

#[cfg(unix)]
fn open_absolute_directory_chain(path: &Path) -> Result<(File, Vec<DirectoryIdentity>)> {
    use std::path::Component;

    if !path.is_absolute() {
        return Err(invalid("selected NAT root path must be absolute"));
    }
    let mut components = path.components();
    if components.next() != Some(Component::RootDir) {
        return Err(invalid("selected NAT root path has no absolute root"));
    }
    let root_descriptor = rustix::fs::open("/", directory_open_flags(), rustix::fs::Mode::empty())?;
    let mut directory = File::from(root_descriptor);
    let mut identities = vec![directory_identity(&directory, "filesystem root")?];
    for component in components {
        let Component::Normal(name) = component else {
            return Err(invalid(
                "selected NAT root path contains a non-canonical component",
            ));
        };
        let descriptor = rustix::fs::openat(
            &directory,
            name,
            directory_open_flags(),
            rustix::fs::Mode::empty(),
        )?;
        directory = File::from(descriptor);
        identities.push(directory_identity(
            &directory,
            "selected NAT root ancestry",
        )?);
    }
    Ok((directory, identities))
}

#[cfg(unix)]
fn directory_identity(file: &File, label: &str) -> Result<DirectoryIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    if !metadata.is_dir() {
        return Err(invalid(format!("{label} is not a directory")));
    }
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn require_owned_directory(file: &File, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(invalid(format!(
            "{label} must be owned by the effective user with exact mode 0700"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn directory_is_empty(directory: &File) -> Result<bool> {
    let entries = rustix::fs::Dir::read_from(directory)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(unix)]
fn require_exact_entry_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(invalid("descriptor-relative entry name is not exact"));
    }
    Ok(())
}

#[cfg(unix)]
fn create_owned_directory_at(parent: &File, name: &str, label: &str) -> Result<File> {
    require_exact_entry_name(name)?;
    require_owned_directory(parent, "private directory parent")?;
    rustix::fs::mkdirat(
        parent,
        name,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
    )?;
    parent.sync_all()?;
    let descriptor = rustix::fs::openat(
        parent,
        name,
        directory_open_flags(),
        rustix::fs::Mode::empty(),
    )?;
    let directory = File::from(descriptor);
    require_owned_directory(&directory, label)?;
    Ok(directory)
}

#[cfg(unix)]
fn open_owned_directory_at(parent: &File, name: &str, label: &str) -> Result<File> {
    require_exact_entry_name(name)?;
    require_owned_directory(parent, "private directory parent")?;
    let descriptor = rustix::fs::openat(
        parent,
        name,
        directory_open_flags(),
        rustix::fs::Mode::empty(),
    )?;
    let directory = File::from(descriptor);
    require_owned_directory(&directory, label)?;
    Ok(directory)
}

#[cfg(unix)]
fn descriptor_path(directory: &File) -> Result<PathBuf> {
    use std::os::fd::AsRawFd as _;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        Ok(proc_descriptor_path(directory.as_raw_fd()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = directory.as_raw_fd();
        Err(invalid(UNSUPPORTED_PLATFORM))
    }
}

#[cfg(unix)]
fn descriptor_child_path(directory: &File, name: &str) -> Result<PathBuf> {
    use std::os::fd::AsRawFd as _;

    require_exact_entry_name(name)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        proc_descriptor_child_path(directory.as_raw_fd(), name)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = directory.as_raw_fd();
        Err(invalid(UNSUPPORTED_PLATFORM))
    }
}

#[cfg(all(unix, any(test, target_os = "linux", target_os = "android")))]
fn proc_descriptor_path(raw_fd: std::os::fd::RawFd) -> PathBuf {
    Path::new("/proc/self/fd").join(raw_fd.to_string())
}

#[cfg(all(unix, any(test, target_os = "linux", target_os = "android")))]
fn proc_descriptor_child_path(raw_fd: std::os::fd::RawFd, name: &str) -> Result<PathBuf> {
    require_exact_entry_name(name)?;
    Ok(proc_descriptor_path(raw_fd).join(name))
}

#[cfg(unix)]
fn mode_bits(mode: u32) -> Result<rustix::fs::Mode> {
    match mode {
        0o600 => Ok(rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR),
        0o644 => Ok(rustix::fs::Mode::RUSR
            | rustix::fs::Mode::WUSR
            | rustix::fs::Mode::RGRP
            | rustix::fs::Mode::ROTH),
        _ => Err(invalid("descriptor write mode is not permitted")),
    }
}

#[cfg(unix)]
fn write_new_at(directory: &File, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    require_exact_entry_name(name)?;
    let descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::WRONLY
            | rustix::fs::OFlags::CREATE
            | rustix::fs::OFlags::EXCL
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        mode_bits(mode)?,
    )?;
    let mut file = File::from(descriptor);
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    let before = file.metadata()?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !before.is_file()
        || before.uid() != effective_uid
        || before.mode() & 0o7777 != mode
        || before.nlink() != 1
        || before.len() != 0
    {
        return Err(invalid(
            "new descriptor-bound artifact did not retain its exact owner/mode/link/length",
        ));
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    let written = file.metadata()?;
    if before.dev() != written.dev()
        || before.ino() != written.ino()
        || written.uid() != effective_uid
        || written.mode() & 0o7777 != mode
        || written.nlink() != 1
        || written.len() != u64::try_from(bytes.len())?
    {
        return Err(invalid("descriptor-bound artifact changed while writing"));
    }
    let reopened_descriptor = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let reopened = File::from(reopened_descriptor);
    let pathname = reopened.metadata()?;
    if written.dev() != pathname.dev()
        || written.ino() != pathname.ino()
        || written.len() != pathname.len()
        || pathname.uid() != effective_uid
        || pathname.mode() & 0o7777 != mode
        || pathname.nlink() != 1
    {
        return Err(invalid(
            "descriptor-bound artifact pathname changed after writing",
        ));
    }
    directory.sync_all()?;
    Ok(())
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegularFileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    owner: u32,
    mode: u32,
    links: u64,
}

#[cfg(unix)]
struct RetainedRegularFile {
    file: File,
    identity: RegularFileIdentity,
    bytes: Zeroizing<Vec<u8>>,
}

#[cfg(unix)]
impl RetainedRegularFile {
    fn open(directory: &File, name: &str, maximum: u64, expected_mode: u32) -> Result<Self> {
        require_exact_entry_name(name)?;
        let descriptor = rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )?;
        let file = File::from(descriptor);
        let identity = regular_file_identity(&file)?;
        if identity.length > maximum
            || identity.owner != rustix::process::geteuid().as_raw()
            || identity.mode != expected_mode
            || identity.links != 1
        {
            return Err(invalid(
                "descriptor-bound input does not match its exact owner/mode/link/size contract",
            ));
        }
        let bytes = read_exact_retained_bytes(&file, identity.length)?;
        let retained = Self {
            file,
            identity,
            bytes,
        };
        retained.require_unchanged()?;
        retained.require_pathname(directory, name)?;
        Ok(retained)
    }

    fn require_unchanged(&self) -> Result<()> {
        if regular_file_identity(&self.file)? != self.identity
            || read_exact_retained_bytes(&self.file, self.identity.length)?.as_slice()
                != self.bytes.as_slice()
        {
            return Err(invalid(
                "retained descriptor-bound input changed after validation",
            ));
        }
        Ok(())
    }

    fn require_pathname(&self, directory: &File, name: &str) -> Result<()> {
        require_exact_entry_name(name)?;
        let descriptor = rustix::fs::openat(
            directory,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NONBLOCK,
            rustix::fs::Mode::empty(),
        )?;
        let pathname = File::from(descriptor);
        if regular_file_identity(&pathname)? != self.identity {
            return Err(invalid(
                "retained descriptor-bound input pathname changed after validation",
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn regular_file_identity(file: &File) -> Result<RegularFileIdentity> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("descriptor-bound input is not a regular file"));
    }
    Ok(RegularFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        owner: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        links: metadata.nlink(),
    })
}

#[cfg(unix)]
fn read_exact_retained_bytes(file: &File, length: u64) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::FileExt as _;

    let length = usize::try_from(length)?;
    let mut bytes = Zeroizing::new(vec![0u8; length]);
    let mut offset = 0usize;
    while offset < length {
        let read = file.read_at(&mut bytes[offset..], u64::try_from(offset)?)?;
        if read == 0 {
            return Err(invalid(
                "descriptor-bound input ended before its retained length",
            ));
        }
        offset = offset.saturating_add(read);
    }
    let mut extra = [0u8; 1];
    if file.read_at(&mut extra, u64::try_from(length)?)? != 0 {
        return Err(invalid(
            "descriptor-bound input grew beyond its retained length",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn read_regular_bounded_at(
    directory: &File,
    name: &str,
    maximum: u64,
    expected_mode: u32,
) -> Result<Vec<u8>> {
    let retained = RetainedRegularFile::open(directory, name, maximum, expected_mode)?;
    Ok(retained.bytes.to_vec())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DestroyedArtifact {
    bytes: usize,
    mode: u32,
    owner: u32,
}

fn destroy_private_artifact(
    root: &Path,
    filename: &str,
    minimum: usize,
    maximum: usize,
) -> Result<DestroyedArtifact> {
    if filename.contains('/') || filename.contains('\\') || filename == "." || filename == ".." {
        return Err(invalid("private destruction filename is not exact"));
    }
    #[cfg(unix)]
    {
        destroy_private_artifact_unix(root, filename, minimum, maximum)
    }
    #[cfg(not(unix))]
    {
        let _ = (root, minimum, maximum);
        Err(invalid(
            "private artifact destruction requires Unix descriptor binding",
        ))
    }
}

#[cfg(unix)]
fn destroy_private_artifact_unix(
    root: &Path,
    filename: &str,
    minimum: usize,
    maximum: usize,
) -> Result<DestroyedArtifact> {
    use std::os::unix::fs::MetadataExt as _;

    let tree = SecurePrivateTree::open(root)?;
    tree.require_stable()?;
    let descriptor = rustix::fs::openat(
        &tree.private,
        filename,
        rustix::fs::OFlags::RDWR
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let mut file = File::from(descriptor);
    let before = file.metadata()?;
    let minimum = u64::try_from(minimum)?;
    let maximum = u64::try_from(maximum)?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if !before.is_file()
        || before.len() < minimum
        || before.len() > maximum
        || before.uid() != effective_uid
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
    {
        return Err(invalid(
            "private destruction target must be a uniquely linked, effective-user-owned, exact-mode-0600 bounded regular artifact",
        ));
    }

    let length = usize::try_from(before.len())?;
    let zeros = Zeroizing::new(vec![0u8; length]);
    file.write_all(&zeros)?;
    file.sync_all()?;
    tree.require_stable()?;

    let pathname_descriptor = rustix::fs::openat(
        &tree.private,
        filename,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    )?;
    let pathname_file = File::from(pathname_descriptor);
    let after = pathname_file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || after.uid() != effective_uid
        || after.mode() & 0o7777 != 0o600
        || after.nlink() != 1
    {
        return Err(invalid("private artifact pathname changed before unlink"));
    }
    drop(pathname_file);

    rustix::fs::unlinkat(&tree.private, filename, rustix::fs::AtFlags::empty())?;
    tree.private.sync_all()?;
    tree.require_stable()?;
    match rustix::fs::openat(
        &tree.private,
        filename,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NONBLOCK,
        rustix::fs::Mode::empty(),
    ) {
        Err(error) if error == rustix::io::Errno::NOENT => {}
        Ok(_) => {
            return Err(invalid(
                "private artifact pathname remains after destruction",
            ));
        }
        Err(error) => return Err(error.into()),
    }
    drop(file);
    Ok(DestroyedArtifact {
        bytes: length,
        mode: before.mode() & 0o7777,
        owner: before.uid(),
    })
}

fn subscription_request(name: &str, scope: &Scope, topic: &Topic) -> EventSubscriptionRequest {
    EventSubscriptionRequest {
        operation_key: format!("selected-nat/v1/node-{name}/consume").into_bytes(),
        topic: topic.clone(),
        scope: scope.clone(),
        include_descendant_scopes: false,
    }
}

fn publication_request(
    name: &str,
    scope: &Scope,
    topic: &Topic,
    canary: &[u8],
    canary_sha256: [u8; 32],
) -> EventPublishRequest {
    EventPublishRequest {
        operation_key: format!(
            "selected-nat/v1/node-{name}/publish/{}",
            hex(&canary_sha256)
        )
        .into_bytes(),
        predecessor: None,
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Priority,
        logical_key: CANARY_LOGICAL_KEY.to_vec(),
        payload: canary.to_vec(),
        tombstone: false,
    }
}

fn exact_query(publisher: [u8; 32], scope: &Scope, topic: &Topic) -> EventQuery {
    EventQuery {
        publisher: Some(publisher),
        topic: Some(topic.clone()),
        scope: Some(scope.clone()),
        include_descendant_scopes: false,
        logical_key: Some(CANARY_LOGICAL_KEY.to_vec()),
        after_acceptance_marker: 0,
        before_acceptance_marker: None,
        limit: 16,
    }
}

fn require_exact_event(
    events: &[aster_node::application::EventItem],
    publisher: [u8; 32],
    manifest: &Manifest,
    canary: &[u8],
    expected_id: EventId,
) -> Result<()> {
    if events.len() != 1 {
        return Err(invalid("exact canary query did not return one Event"));
    }
    let event = &events[0];
    if event.id != expected_id
        || event.publisher != publisher
        || event.publisher_counter != 1
        || event.event_sequence != 1
        || event.topic != manifest.topic
        || event.scope != manifest.scope
        || event.priority != Priority::Priority
        || event.ttl_ms.is_some()
        || event.logical_key != CANARY_LOGICAL_KEY
        || event.payload.as_slice() != canary
        || event.tombstone
    {
        return Err(invalid(
            "selected canary Event semantic fields do not match exactly",
        ));
    }
    Ok(())
}

fn require_independent_identities(
    nodes: &[ManifestNode],
    mission_authority: [u8; 32],
) -> Result<()> {
    if nodes.len() != 2 || nodes[0].mission_id == nodes[1].mission_id {
        return Err(invalid("mission identities are not independent"));
    }
    if nodes[0].carrier_id == nodes[1].carrier_id {
        return Err(invalid("carrier identities are not independent"));
    }
    let all = nodes
        .iter()
        .flat_map(|node| [format_node_id(node.mission_id), node.carrier_id.to_string()])
        .collect::<BTreeSet<_>>();
    if all.len() != 4 {
        return Err(invalid("mission and carrier identity domains overlap"));
    }
    let mission_authority = format_node_id(mission_authority);
    if all.contains(&mission_authority) {
        return Err(invalid(
            "mission authority overlaps a node mission or carrier identity",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn load_private_canary(
    tree: &SecurePrivateTree,
    manifest: &Manifest,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = Zeroizing::new(read_regular_bounded_at(
        &tree.private,
        "canary.bin",
        u64::try_from(CANARY_BYTES)?,
        0o600,
    )?);
    if bytes.len() != CANARY_BYTES {
        return Err(invalid(
            "private canary does not have its exact expected length",
        ));
    }
    let actual: [u8; 32] = Sha256::digest(&*bytes).into();
    if actual != manifest.canary_sha256 {
        return Err(invalid(
            "private canary content does not match the public manifest digest",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn load_manifest(tree: &SecurePrivateTree) -> Result<Manifest> {
    let bytes = read_regular_bounded_at(&tree.root, "manifest.tsv", MAX_MANIFEST_BYTES, 0o644)?;
    Manifest::parse(std::str::from_utf8(&bytes)?)
}

fn mission_filename(name: &str) -> String {
    format!("node-{name}.bundle")
}

fn state_filename(name: &str) -> String {
    format!("node-{name}")
}

#[cfg(all(test, unix))]
fn mission_path(root: &Path, name: &str) -> PathBuf {
    root.join("private").join(mission_filename(name))
}

#[cfg(all(test, unix))]
fn state_path(root: &Path, name: &str) -> PathBuf {
    root.join(state_filename(name))
}

fn exact_node_name(value: &str) -> Result<&str> {
    if NODE_NAMES.contains(&value) {
        Ok(value)
    } else {
        Err(invalid("--node must be a or b"))
    }
}

fn validate_dns_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_DNS_NAME_BYTES
        || value.parse::<IpAddr>().is_ok()
        || value.starts_with('.')
        || value.ends_with('.')
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid(
            "relay DNS name is not a bounded canonical hostname",
        ));
    }
    Ok(())
}

fn prepare_fresh_root(path: &Path) -> Result<File> {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;

        if !path.is_absolute() {
            return Err(invalid("fresh root path must be absolute"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| invalid("fresh root path has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("fresh root path has no final component"))?;
        if name == OsStr::new(".") || name == OsStr::new("..") {
            return Err(invalid("fresh root path is not canonical"));
        }
        let (parent_directory, _) = open_absolute_directory_chain(parent)?;
        let (root, created) = match rustix::fs::openat(
            &parent_directory,
            name,
            directory_open_flags(),
            rustix::fs::Mode::empty(),
        ) {
            Ok(descriptor) => (File::from(descriptor), false),
            Err(error) if error == rustix::io::Errno::NOENT => {
                rustix::fs::mkdirat(
                    &parent_directory,
                    name,
                    rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
                )?;
                parent_directory.sync_all()?;
                let descriptor = rustix::fs::openat(
                    &parent_directory,
                    name,
                    directory_open_flags(),
                    rustix::fs::Mode::empty(),
                )?;
                (File::from(descriptor), true)
            }
            Err(error) => return Err(error.into()),
        };
        require_owned_directory(&root, "fresh selected NAT root")?;
        let identity = directory_identity(&root, "fresh selected NAT root")?;
        if !created && !directory_is_empty(&root)? {
            return Err(invalid(
                "fresh root is not empty; inspect and explicitly clean that exact owner-only root externally before retrying",
            ));
        }
        let (reopened, _) = open_absolute_directory_chain(path)?;
        require_owned_directory(&reopened, "fresh selected NAT root")?;
        if directory_identity(&reopened, "fresh selected NAT root")? != identity {
            return Err(invalid("fresh selected NAT root changed during validation"));
        }
        Ok(root)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(invalid("fresh selected NAT root validation requires Unix"))
    }
}

#[cfg(test)]
fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        if !path.is_absolute() {
            return Err(invalid("private directory path must be absolute"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| invalid("private directory path has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| invalid("private directory path has no final component"))?;
        let (parent_directory, _) = open_absolute_directory_chain(parent)?;
        require_owned_directory(&parent_directory, "private directory parent")?;
        rustix::fs::mkdirat(
            &parent_directory,
            name,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR | rustix::fs::Mode::XUSR,
        )?;
        parent_directory.sync_all()?;
        let descriptor = rustix::fs::openat(
            &parent_directory,
            name,
            directory_open_flags(),
            rustix::fs::Mode::empty(),
        )?;
        let directory = File::from(descriptor);
        require_owned_directory(&directory, "new private directory")?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(invalid("private directory creation requires Unix"))
    }
}

#[cfg(test)]
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

fn parse_hex_32(value: &str, label: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(format!(
            "{label} must contain exactly 64 hexadecimal characters"
        )));
    }
    let mut output = [0u8; 32];
    for (pair, byte) in value.as_bytes().chunks_exact(2).zip(&mut output) {
        *byte = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    if hex(&output) != value {
        return Err(invalid(format!("{label} must use canonical lowercase hex")));
    }
    Ok(output)
}

const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => 0,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message.into()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let temporary_base = env::temp_dir()
                .canonicalize()
                .expect("canonical temporary base");
            let path = temporary_base.join(format!(
                "aster-selected-nat-{label}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create test root");
            set_mode(&path, 0o700).expect("secure test root mode");
            Self(path)
        }

        fn private(&self) -> PathBuf {
            self.0.join("private")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn canary_hex_and_dns_inputs_are_canonical() {
        let lower = "ab".repeat(32);
        assert_eq!(parse_hex_32(&lower, "test").expect("hex"), [0xab; 32]);
        assert!(parse_hex_32(&"AB".repeat(32), "test").is_err());
        assert!(parse_hex_32("ab", "test").is_err());
        validate_dns_name("relay.aster.test").expect("DNS");
        assert!(validate_dns_name("127.0.0.1").is_err());
        assert!(validate_dns_name("-relay.aster.test").is_err());
    }

    #[test]
    fn manifest_v2_binds_one_disjoint_mission_authority() {
        let manifest = Manifest {
            scope: Scope::new("lab/manifest-authority".to_owned()).expect("scope"),
            topic: Topic::new("lab.manifest.authority".to_owned()).expect("topic"),
            mission_authority: [0xab; 32],
            canary_sha256: [0x66; 32],
            nodes: vec![
                ManifestNode {
                    name: "a".to_owned(),
                    mission_id: [0x11; 32],
                    carrier_id: iroh::SecretKey::from_bytes(&[0x33; 32]).public(),
                    subscription_id: EventSubscriptionId::from_bytes([0x77; 32]),
                },
                ManifestNode {
                    name: "b".to_owned(),
                    mission_id: [0x22; 32],
                    carrier_id: iroh::SecretKey::from_bytes(&[0x44; 32]).public(),
                    subscription_id: EventSubscriptionId::from_bytes([0x88; 32]),
                },
            ],
        };
        let encoded = manifest.to_text();
        assert!(encoded.starts_with("ASTER_SELECTED_NAT_MANIFEST\tversion=2\t"));
        assert_eq!(Manifest::parse(&encoded).expect("manifest v2"), manifest);

        let collision = encoded.replacen(
            &format!("mission_authority={}", format_node_id([0xab; 32])),
            &format!("mission_authority={}", format_node_id([0x11; 32])),
            1,
        );
        assert!(Manifest::parse(&collision).is_err());

        let missing = encoded.replacen(
            &format!("\tmission_authority={}", format_node_id([0xab; 32])),
            "",
            1,
        );
        assert!(Manifest::parse(&missing).is_err());

        let uppercase = encoded.replacen(
            &format_node_id([0xab; 32]),
            &format_node_id([0xab; 32]).to_ascii_uppercase(),
            1,
        );
        assert!(Manifest::parse(&uppercase).is_err());

        let duplicate = encoded.replacen(
            "\tcanary_sha256=",
            &format!(
                "\tmission_authority={}\tcanary_sha256=",
                format_node_id([0x99; 32])
            ),
            1,
        );
        assert!(Manifest::parse(&duplicate).is_err());
        assert!(Manifest::parse(&encoded.replacen("version=2", "version=1", 1)).is_err());
    }

    #[test]
    fn options_reject_duplicates_and_bare_arguments() {
        assert!(
            Options::parse(vec![
                "--root".into(),
                "one".into(),
                "--root".into(),
                "two".into()
            ])
            .is_err()
        );
        assert!(Options::parse(vec!["root".into(), "one".into()]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn root_and_private_validation_requires_absolute_symlink_free_exact_mode_paths() {
        use std::os::unix::fs::symlink;

        assert!(prepare_fresh_root(Path::new("relative-selected-nat-root")).is_err());

        let broad_root = TestRoot::new("broad-root");
        create_private_directory(&broad_root.private()).expect("private directory");
        set_mode(&broad_root.0, 0o755).expect("broaden root mode");
        assert!(SecurePrivateTree::open(&broad_root.0).is_err());

        let broad_private = TestRoot::new("broad-private");
        create_private_directory(&broad_private.private()).expect("private directory");
        set_mode(&broad_private.private(), 0o755).expect("broaden private mode");
        assert!(SecurePrivateTree::open(&broad_private.0).is_err());

        let symlinked = TestRoot::new("symlinked-ancestry");
        let actual_root = symlinked.0.join("actual");
        create_private_directory(&actual_root).expect("actual root");
        create_private_directory(&actual_root.join("private")).expect("actual private");
        let linked_root = symlinked.0.join("linked");
        symlink(&actual_root, &linked_root).expect("root ancestry symlink");
        assert!(SecurePrivateTree::open(&linked_root).is_err());

        let partial = TestRoot::new("partial-root");
        let partial_artifact = partial.0.join("partial-artifact");
        fs::write(&partial_artifact, b"retained").expect("partial artifact");
        let error = prepare_fresh_root(&partial.0).expect_err("partial root must fail closed");
        assert!(error.to_string().contains("explicitly clean"));
        assert_eq!(
            fs::read(partial_artifact).expect("partial artifact retained"),
            b"retained"
        );
    }

    #[cfg(unix)]
    #[test]
    fn retained_mission_descriptor_rejects_path_replacement_mode_and_link_mutation() {
        let root = TestRoot::new("retained-mission");
        create_private_directory(&root.private()).expect("private directory");
        let tree = SecurePrivateTree::open(&root.0).expect("secure tree");
        let mission_name = "node-a.bundle";
        write_new_at(&tree.private, mission_name, &[0xa5; 64], 0o600).expect("mission fixture");
        let retained =
            RetainedRegularFile::open(&tree.private, mission_name, 64, 0o600).expect("retain");
        let original = root.private().join("original.bundle");
        fs::rename(root.private().join(mission_name), &original).expect("move retained leaf");
        write_new_at(&tree.private, mission_name, &[0x5a; 64], 0o600).expect("replacement leaf");
        assert_eq!(
            read_exact_retained_bytes(&retained.file, 64)
                .expect("read retained descriptor")
                .as_slice(),
            &[0xa5; 64]
        );
        retained
            .require_unchanged()
            .expect("retained inode unchanged");
        assert!(
            retained
                .require_pathname(&tree.private, mission_name)
                .is_err()
        );

        set_mode(&original, 0o640).expect("mutate retained mode");
        assert!(retained.require_unchanged().is_err());
        set_mode(&original, 0o600).expect("restore retained mode");
        let alias = root.private().join("mission-alias.bundle");
        fs::hard_link(&original, &alias).expect("mutate retained link count");
        assert!(retained.require_unchanged().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn linux_mission_descriptor_layout_is_private_directory_fd_plus_exact_child() {
        let mission = proc_descriptor_child_path(17, "node-a.bundle").expect("mission path");
        assert_eq!(mission, Path::new("/proc/self/fd/17/node-a.bundle"));
        assert!(proc_descriptor_child_path(17, "../node-a.bundle").is_err());
        assert!(proc_descriptor_child_path(17, "nested/node-a.bundle").is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn mission_path_is_private_directory_descriptor_plus_exact_child_name() {
        use std::os::fd::AsRawFd as _;

        let root = TestRoot::new("mission-descriptor-child");
        create_private_directory(&root.private()).expect("private directory");
        let tree = SecurePrivateTree::open(&root.0).expect("secure tree");
        let mission_name = "node-a.bundle";
        write_new_at(&tree.private, mission_name, &[0xa5; 64], 0o600).expect("mission fixture");
        let retained =
            RetainedRegularFile::open(&tree.private, mission_name, 64, 0o600).expect("retain");
        let mission = descriptor_child_path(&tree.private, mission_name).expect("mission path");

        assert_eq!(
            mission,
            PathBuf::from(format!(
                "/proc/self/fd/{}/{}",
                tree.private.as_raw_fd(),
                mission_name
            ))
        );
        assert_ne!(
            mission,
            descriptor_path(&retained.file).expect("leaf descriptor path")
        );
        assert_eq!(
            fs::read(&mission).expect("read descriptor child"),
            [0xa5; 64]
        );
        retained
            .require_pathname(&tree.private, mission_name)
            .expect("mission child remains bound");
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[test]
    fn selected_nat_runtime_fails_with_stable_unsupported_platform_error() {
        assert_eq!(
            require_selected_nat_runtime()
                .expect_err("platform must be unsupported")
                .to_string(),
            UNSUPPORTED_PLATFORM
        );
    }

    #[cfg(unix)]
    #[test]
    fn descriptor_bound_creation_cannot_be_redirected_by_root_path_replacement() {
        let container = TestRoot::new("descriptor-root-replacement");
        let root_path = container.0.join("selected");
        let retained_root = prepare_fresh_root(&root_path).expect("fresh root");
        let private =
            create_owned_directory_at(&retained_root, "private", "selected NAT private directory")
                .expect("retained private");
        drop(private);
        let tree = SecurePrivateTree::from_retained_root(&root_path, retained_root)
            .expect("retained secure tree");

        let moved_root = container.0.join("moved-selected");
        fs::rename(&root_path, &moved_root).expect("move retained root");
        let replacement_root = prepare_fresh_root(&root_path).expect("replacement root");
        let replacement_private = create_owned_directory_at(
            &replacement_root,
            "private",
            "replacement private directory",
        )
        .expect("replacement private");
        drop(replacement_private);
        write_new_at(&tree.private, "canary.bin", &[0xa5; CANARY_BYTES], 0o600)
            .expect("descriptor-bound canary");
        assert!(tree.require_stable().is_err());
        assert_eq!(
            fs::read(moved_root.join("private/canary.bin")).expect("retained-root canary"),
            [0xa5; CANARY_BYTES]
        );
        assert!(!root_path.join("private/canary.bin").exists());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_private_artifact_destruction_overwrites_syncs_and_unlinks() {
        let root = TestRoot::new("destroy");
        create_private_directory(&root.private()).expect("private directory");
        let tree = SecurePrivateTree::open(&root.0).expect("secure tree");
        let target = root.private().join("canary.bin");
        write_new_at(&tree.private, "canary.bin", &[0xa5; CANARY_BYTES], 0o600)
            .expect("private artifact");
        drop(tree);
        let destroyed = destroy_private_artifact(&root.0, "canary.bin", CANARY_BYTES, CANARY_BYTES)
            .expect("destroy");
        assert_eq!(destroyed.bytes, CANARY_BYTES);
        assert_eq!(destroyed.mode, 0o600);
        assert!(!target.exists());
    }

    #[cfg(unix)]
    #[test]
    fn private_artifact_destruction_rejects_wrong_size_and_permissions() {
        let short = TestRoot::new("destroy-short");
        create_private_directory(&short.private()).expect("private directory");
        let short_tree = SecurePrivateTree::open(&short.0).expect("secure tree");
        let short_target = short.private().join("canary.bin");
        write_new_at(
            &short_tree.private,
            "canary.bin",
            &[0xa5; CANARY_BYTES - 1],
            0o600,
        )
        .expect("short artifact");
        drop(short_tree);
        assert!(
            destroy_private_artifact(&short.0, "canary.bin", CANARY_BYTES, CANARY_BYTES).is_err()
        );
        assert!(short_target.exists());

        #[cfg(unix)]
        {
            let broad = TestRoot::new("destroy-mode");
            create_private_directory(&broad.private()).expect("private directory");
            let broad_tree = SecurePrivateTree::open(&broad.0).expect("secure tree");
            let broad_target = broad.private().join("canary.bin");
            write_new_at(
                &broad_tree.private,
                "canary.bin",
                &[0xa5; CANARY_BYTES],
                0o644,
            )
            .expect("broad artifact");
            drop(broad_tree);
            assert!(
                destroy_private_artifact(&broad.0, "canary.bin", CANARY_BYTES, CANARY_BYTES)
                    .is_err()
            );
            assert!(broad_target.exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn private_artifact_destruction_rejects_symlink_without_touching_target() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new("destroy-symlink");
        create_private_directory(&root.private()).expect("private directory");
        let tree = SecurePrivateTree::open(&root.0).expect("secure tree");
        let outside = root.0.join("outside.bin");
        write_new_at(&tree.root, "outside.bin", &[0xa5; CANARY_BYTES], 0o600)
            .expect("outside artifact");
        symlink(&outside, root.private().join("canary.bin")).expect("symlink");
        drop(tree);
        assert!(
            destroy_private_artifact(&root.0, "canary.bin", CANARY_BYTES, CANARY_BYTES).is_err()
        );
        assert_eq!(
            fs::read(outside).expect("outside retained"),
            [0xa5; CANARY_BYTES]
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_artifact_destruction_rejects_hard_link_without_overwrite() {
        let root = TestRoot::new("destroy-hard-link");
        create_private_directory(&root.private()).expect("private directory");
        let tree = SecurePrivateTree::open(&root.0).expect("secure tree");
        let target = root.private().join("canary.bin");
        let alias = root.0.join("canary-alias.bin");
        write_new_at(&tree.private, "canary.bin", &[0xa5; CANARY_BYTES], 0o600)
            .expect("private artifact");
        drop(tree);
        fs::hard_link(&target, &alias).expect("hard link");
        assert!(
            destroy_private_artifact(&root.0, "canary.bin", CANARY_BYTES, CANARY_BYTES).is_err()
        );
        assert_eq!(
            fs::read(&target).expect("target retained"),
            [0xa5; CANARY_BYTES]
        );
        assert_eq!(
            fs::read(alias).expect("alias retained"),
            [0xa5; CANARY_BYTES]
        );
    }

    #[cfg(unix)]
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "android")),
        ignore = "requires Linux/Android /proc/self/fd descriptor semantics"
    )]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopped_prepare_publish_and_verify_complete_exact_event_semantics() {
        use aster_node::{
            MissionExpectedPeer, NodeApplication, NodeConfig, RunningNode,
            mission::UnprotectedReferenceMission, start_node,
        };
        use std::{net::UdpSocket, time::Duration};
        use tokio::time::{sleep, timeout};

        fn options(values: &[(&str, String)]) -> Options {
            Options(
                values
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), value.clone()))
                    .collect(),
            )
        }

        fn reserved_loopback_pair() -> (UdpSocket, UdpSocket) {
            let publisher = UdpSocket::bind(("127.0.0.1", 0)).expect("reserve publisher address");
            let receiver = UdpSocket::bind(("127.0.0.1", 0)).expect("reserve receiver address");
            assert_ne!(
                publisher.local_addr().expect("publisher address"),
                receiver.local_addr().expect("receiver address")
            );
            (publisher, receiver)
        }

        async fn start_reserved_pair(
            root: &Path,
            publisher: &ManifestNode,
            receiver: &ManifestNode,
            publisher_mission: &UnprotectedReferenceMission,
            receiver_mission: &UnprotectedReferenceMission,
        ) -> (RunningNode, RunningNode) {
            const START_ATTEMPTS: usize = 8;
            let mut errors = Vec::with_capacity(START_ATTEMPTS);
            for attempt in 1..=START_ATTEMPTS {
                let (publisher_reservation, receiver_reservation) = reserved_loopback_pair();
                let publisher_address = publisher_reservation
                    .local_addr()
                    .expect("reserved publisher address");
                let receiver_address = receiver_reservation
                    .local_addr()
                    .expect("reserved receiver address");
                let publisher_peer: MissionExpectedPeer = format!(
                    "{}@{}={}",
                    receiver.carrier_id,
                    receiver_address,
                    format_node_id(receiver.mission_id)
                )
                .parse()
                .expect("publisher peer");
                let receiver_peer: MissionExpectedPeer = format!(
                    "{}@{}={}",
                    publisher.carrier_id,
                    publisher_address,
                    format_node_id(publisher.mission_id)
                )
                .parse()
                .expect("receiver peer");
                let publisher_config = NodeConfig {
                    state: state_path(root, "a"),
                    bind: publisher_address,
                    mission: publisher_mission.clone(),
                    peers: vec![publisher_peer],
                    mutable_interests: Default::default(),
                    sync_interval: Duration::from_millis(20),
                    run_for: None,
                    application: NodeApplication::Relay,
                };
                let receiver_config = NodeConfig {
                    state: state_path(root, "b"),
                    bind: receiver_address,
                    mission: receiver_mission.clone(),
                    peers: vec![receiver_peer],
                    mutable_interests: Default::default(),
                    sync_interval: Duration::from_millis(20),
                    run_for: None,
                    application: NodeApplication::Relay,
                };

                drop((publisher_reservation, receiver_reservation));
                let (publisher_result, receiver_result) =
                    tokio::join!(start_node(publisher_config), start_node(receiver_config));
                match (publisher_result, receiver_result) {
                    (Ok(publisher_running), Ok(receiver_running)) => {
                        return (publisher_running, receiver_running);
                    }
                    (Ok(publisher_running), Err(error)) => {
                        errors.push(format!("attempt {attempt} receiver start: {error}"));
                        let _ = publisher_running.shutdown().await;
                    }
                    (Err(error), Ok(receiver_running)) => {
                        errors.push(format!("attempt {attempt} publisher start: {error}"));
                        let _ = receiver_running.shutdown().await;
                    }
                    (Err(publisher_error), Err(receiver_error)) => {
                        errors.push(format!(
                            "attempt {attempt} publisher start: {publisher_error}; receiver start: {receiver_error}"
                        ));
                    }
                }
                sleep(Duration::from_millis(20)).await;
            }
            panic!(
                "reserved selected-node startup exhausted retries: {}",
                errors.join(" | ")
            );
        }

        let root = TestRoot::new("stopped-event-lifecycle");
        prepare(&options(&[
            ("root", root.0.display().to_string()),
            ("scope", "lab/stopped-selected-nat".to_owned()),
            ("topic", "lab.stopped.selected-nat".to_owned()),
        ]))
        .expect("stopped prepare");
        let prepared_tree = SecurePrivateTree::open(&root.0).expect("prepared secure tree");
        let manifest = load_manifest(&prepared_tree).expect("prepared manifest");
        drop(prepared_tree);
        let publisher = manifest.node("a").expect("publisher").clone();
        let receiver = manifest.node("b").expect("receiver").clone();
        let canary_sha256 = hex(&manifest.canary_sha256);
        publish(&options(&[
            ("root", root.0.display().to_string()),
            ("node", "a".to_owned()),
            ("canary-sha256", canary_sha256.clone()),
        ]))
        .expect("stopped publish");

        let publisher_mission = UnprotectedReferenceMission::load(mission_path(&root.0, "a"))
            .expect("publisher mission");
        let receiver_mission = UnprotectedReferenceMission::load(mission_path(&root.0, "b"))
            .expect("receiver mission");
        let (publisher_running, receiver_running) = start_reserved_pair(
            &root.0,
            &publisher,
            &receiver,
            &publisher_mission,
            &receiver_mission,
        )
        .await;
        let publisher_events = publisher_running.selected_events();
        let receiver_events = receiver_running.selected_events();
        timeout(Duration::from_secs(20), async {
            loop {
                let page = receiver_events
                    .query(exact_query(
                        publisher.mission_id,
                        &manifest.scope,
                        &manifest.topic,
                    ))
                    .await
                    .expect("live receiver query");
                if !page.has_more && page.items.len() == 1 {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("exact Event crosses local authenticated contact");
        timeout(Duration::from_secs(20), async {
            loop {
                let (publisher_status, receiver_status) =
                    tokio::join!(publisher_events.status(), receiver_events.status());
                if publisher_status
                    .expect("publisher live status")
                    .authenticated_contacts
                    > 0
                    && receiver_status
                        .expect("receiver live status")
                        .authenticated_contacts
                        > 0
                {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("both nodes record completed authenticated contacts before shutdown");
        let (publisher_receipt, receiver_receipt) =
            tokio::join!(publisher_running.shutdown(), receiver_running.shutdown());
        assert!(publisher_receipt.expect("publisher stops").contacts > 0);
        assert!(receiver_receipt.expect("receiver stops").contacts > 0);
        drop(publisher_mission);
        drop(receiver_mission);

        verify(&options(&[
            ("root", root.0.display().to_string()),
            ("node", "b".to_owned()),
            ("publisher", format_node_id(publisher.mission_id)),
            ("canary-sha256", canary_sha256),
        ]))
        .expect("stopped verify");
    }
}
