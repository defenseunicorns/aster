//! Profile-independent authenticated Iroh carrier for Aster.
//!
//! This crate owns endpoint lifecycle and bounded opaque byte exchanges only.
//! It deliberately knows nothing about Aster items, reconciliation, mission
//! membership, or application policy.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeSet, VecDeque},
    error::Error,
    fmt,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(feature = "nearby-discovery")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "nearby-discovery")]
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
};

use futures::StreamExt;
#[cfg(feature = "nearby-discovery")]
use iroh::address_lookup::{
    AddrFilter, AddressLookup, AddressLookupServices, EndpointData, EndpointInfo,
    Error as AddressLookupError, Item as AddressLookupItem, MemoryLookup,
};
use iroh::{
    Endpoint as IrohEndpoint, EndpointAddr, RelayConfig as IrohRelayConfig, RelayMode,
    TransportAddr,
    endpoint::{
        ConnectionError, NetReportConfig, PathEvent, PortmapperConfig, QuicTransportConfig,
        ReadToEndError, RecvStream, SendStream, VarInt, presets,
    },
    tls::CaTlsConfig,
};
#[cfg(feature = "nearby-discovery")]
use iroh_mdns_address_lookup::{DiscoveryEvent as MdnsDiscoveryEvent, MdnsAddressLookup};
#[cfg(feature = "nearby-discovery")]
use swarm_discovery::{
    Discoverer as SwarmDiscoverer, DropGuard as SwarmDiscoveryGuard, IpClass as SwarmIpClass,
    Peer as SwarmPeer,
};
use tokio::task::{AbortHandle, Id as TaskId, JoinError, JoinSet};
use tokio::time::{Instant, timeout, timeout_at};

pub use iroh::{EndpointId, RelayUrl, SecretKey};

/// ALPN used by the bounded opaque carrier protocol.
///
/// This version identifies carrier framing only; it does not define an Aster
/// item encoding or reconciliation profile.
pub const ALPN: &[u8] = b"aster-carrier/1";

const MAX_PENDING_INBOUND_HANDSHAKES: usize = 16;

/// Private DNS-SD service label used by the explicit nearby evaluation mode.
///
/// The service publishes Iroh endpoint identities and direct transport
/// addresses only. Aster mission identities, topics, scopes, membership, and
/// application metadata are never placed in discovery records.
#[cfg(feature = "nearby-discovery")]
pub const NEARBY_SERVICE_NAME: &str = "aster-nearby-v1";

/// Shortest accepted lifetime for one nearby-discovery session.
#[cfg(feature = "nearby-discovery")]
pub const MIN_NEARBY_DISCOVERY_WINDOW: Duration = Duration::from_secs(1);

/// Longest accepted lifetime for one nearby-discovery session.
#[cfg(feature = "nearby-discovery")]
pub const MAX_NEARBY_DISCOVERY_WINDOW: Duration = Duration::from_secs(30);

#[cfg(feature = "nearby-discovery")]
const NEARBY_DISCOVERY_EVENT_BUFFER: usize = 20;

/// Maximum explicit IPv4 interfaces used by one nearby-discovery session.
#[cfg(feature = "nearby-discovery")]
pub const MAX_NEARBY_DISCOVERY_IPV4_INTERFACES: usize = 8;

#[cfg(feature = "nearby-discovery")]
const MAX_MULTI_INTERFACE_NEARBY_PEERS: usize = 32;

#[cfg(feature = "nearby-discovery")]
const MAX_MULTI_INTERFACE_NEARBY_ADDRS_PER_PEER: usize = 32;

#[cfg(feature = "nearby-discovery")]
const MAX_MULTI_INTERFACE_LOCAL_ADDRS: usize = 32;

#[cfg(feature = "nearby-discovery")]
const NEARBY_ENDPOINT_ID_LABEL_BYTES: usize = 52;

#[cfg(feature = "nearby-discovery")]
const NEARBY_ENDPOINT_ID_BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

#[cfg(feature = "nearby-discovery")]
const MULTI_INTERFACE_NEARBY_PROVENANCE: &str = "aster-nearby-multi-interface-v1";

#[cfg(feature = "nearby-discovery")]
fn encode_nearby_endpoint_id_label(endpoint_id: EndpointId) -> String {
    let mut encoded = String::with_capacity(NEARBY_ENDPOINT_ID_LABEL_BYTES);
    let mut accumulator = 0u16;
    let mut bits = 0u8;
    for byte in endpoint_id.as_bytes() {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::from((accumulator >> bits) & 0x1f);
            encoded.push(char::from(NEARBY_ENDPOINT_ID_BASE32_ALPHABET[index]));
        }
        accumulator &= if bits == 0 { 0 } else { (1 << bits) - 1 };
    }
    if bits != 0 {
        let index = usize::from((accumulator << (5 - bits)) & 0x1f);
        encoded.push(char::from(NEARBY_ENDPOINT_ID_BASE32_ALPHABET[index]));
    }
    debug_assert_eq!(encoded.len(), NEARBY_ENDPOINT_ID_LABEL_BYTES);
    encoded
}

#[cfg(feature = "nearby-discovery")]
fn decode_nearby_endpoint_id_label(label: &str) -> Option<EndpointId> {
    if label.len() != NEARBY_ENDPOINT_ID_LABEL_BYTES
        || !label
            .bytes()
            .all(|byte| NEARBY_ENDPOINT_ID_BASE32_ALPHABET.contains(&byte))
    {
        return None;
    }
    EndpointId::from_str(label).ok()
}

#[cfg(feature = "nearby-discovery")]
fn normalize_nearby_ipv4_interfaces(
    mut interfaces: Vec<Ipv4Addr>,
) -> Result<Vec<Ipv4Addr>, CarrierError> {
    interfaces.sort_unstable();
    interfaces.dedup();
    if interfaces.len() > MAX_NEARBY_DISCOVERY_IPV4_INTERFACES {
        return Err(CarrierError::Configuration(format!(
            "nearby discovery IPv4 interface count must be within 0..={MAX_NEARBY_DISCOVERY_IPV4_INTERFACES}"
        )));
    }
    if interfaces.iter().any(|interface| {
        interface.is_unspecified() || interface.is_multicast() || *interface == Ipv4Addr::BROADCAST
    }) {
        return Err(CarrierError::Configuration(
            "nearby discovery IPv4 interfaces must be concrete local unicast addresses".into(),
        ));
    }
    Ok(interfaces)
}

/// ALPN for the Iroh-QUIC-protected carrier profile.
///
/// This is deliberately distinct from [`ALPN`]. An endpoint advertises and
/// dials exactly one carrier security profile, so a profile mismatch fails the
/// QUIC handshake instead of retrying a different profile.
pub const IROH_QUIC_ALPN: &[u8] = b"aster-carrier-iroh-quic/1";

const CHANNEL_BINDING_EXPORTER_LABEL: &[u8] = b"EXPORTER-Aster-Iroh-Channel-Binding-v1";
const CHANNEL_BINDING_CONTEXT_DOMAIN: &[u8] = b"aster-iroh/channel-binding/context/v1";

/// Length of the channel-binding value derived from one QUIC TLS session.
pub const CHANNEL_BINDING_BYTES: usize = 32;

/// Keepalive interval for an open `IrohQuicV1` connection and its default path.
///
/// An idle connection is therefore not traffic-free. Bounded contacts should
/// close their owned connection when work completes instead of retaining it
/// indefinitely. The default legacy carrier profile intentionally leaves QUIC
/// keepalives unset to preserve its existing idle-transport behavior.
pub const CONNECTION_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum caller-owned context accepted for one channel-binding derivation.
pub const MAX_CHANNEL_BINDING_CONTEXT_BYTES: usize = 4 * 1024;

/// Exact carrier protection selected before an Iroh handshake begins.
///
/// This selection is carrier-only. Higher layers remain responsible for
/// authenticating the Aster mission profile and enforcing its policy minimum.
/// The default preserves the original `aster-carrier/1` wire behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CarrierSecurityProfile {
    /// Existing carrier framing used with the Aster hybrid mission record layer.
    #[default]
    HybridAsterRecordV1,
    /// Iroh QUIC protects ephemeral carrier frames for a channel-bound mission exchange.
    IrohQuicV1,
}

impl CarrierSecurityProfile {
    /// Returns the exact ALPN advertised and dialed for this carrier profile.
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::HybridAsterRecordV1 => ALPN,
            Self::IrohQuicV1 => IROH_QUIC_ALPN,
        }
    }
}

const fn connection_keepalive_interval(
    security_profile: CarrierSecurityProfile,
) -> Option<Duration> {
    match security_profile {
        CarrierSecurityProfile::HybridAsterRecordV1 => None,
        CarrierSecurityProfile::IrohQuicV1 => Some(CONNECTION_KEEPALIVE_INTERVAL),
    }
}

/// Caller-owned, bounded context for deriving an exact QUIC channel binding.
///
/// The Aster mission layer should supply one canonical encoding that includes
/// its complete security-profile identifier, authenticated policy generation,
/// both carrier endpoint identities, and both mission identities. The carrier
/// treats those bytes as opaque and additionally binds its selected ALPN.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ChannelBindingContext<'a>(&'a [u8]);

impl<'a> ChannelBindingContext<'a> {
    /// Validates a nonempty canonical application context.
    pub fn new(bytes: &'a [u8]) -> Result<Self, CarrierError> {
        if bytes.is_empty() || bytes.len() > MAX_CHANNEL_BINDING_CONTEXT_BYTES {
            return Err(CarrierError::Configuration(format!(
                "channel-binding context must be within 1..={MAX_CHANNEL_BINDING_CONTEXT_BYTES} bytes"
            )));
        }
        Ok(Self(bytes))
    }

    fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Debug for ChannelBindingContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChannelBindingContext")
            .field("bytes", &self.0.len())
            .finish()
    }
}

/// Opaque binding to one exact Iroh QUIC TLS session and application context.
#[derive(Clone, Eq, PartialEq)]
pub struct ChannelBinding([u8; CHANNEL_BINDING_BYTES]);

impl ChannelBinding {
    /// Borrows the fixed-length binding for a higher-layer authenticated transcript.
    pub fn as_bytes(&self) -> &[u8; CHANNEL_BINDING_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ChannelBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChannelBinding([REDACTED])")
    }
}

const RESPONSE_CONSUMED_MARKER: &[u8] = b"\0";
const UNI_TURN_MAGIC: &[u8; 5] = b"ASTU\x01";

/// Default upper bound for one opaque request or response.
pub const DEFAULT_MAX_EXCHANGE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of direct socket addresses in one controlled peer route.
pub const MAX_DIRECT_ADDRESSES: usize = 8;

/// Maximum serialized length of one pinned relay URL.
pub const MAX_RELAY_URL_BYTES: usize = 2 * 1024;

/// Maximum serialized length of one controlled peer route.
///
/// The allowance above [`MAX_RELAY_URL_BYTES`] covers one endpoint ID,
/// separators, and [`MAX_DIRECT_ADDRESSES`] maximally formatted socket
/// addresses with conservative headroom.
pub const MAX_PEER_ROUTE_TEXT_BYTES: usize = MAX_RELAY_URL_BYTES + 1_024;

/// Maximum number of explicit CA roots accepted for one pinned relay.
pub const MAX_RELAY_CA_ROOTS: usize = 8;

/// Maximum DER length of one explicit relay CA root.
pub const MAX_RELAY_CA_ROOT_BYTES: usize = 64 * 1024;

/// Maximum combined DER length of all explicit relay CA roots.
pub const MAX_RELAY_CA_ROOT_TOTAL_BYTES: usize = 256 * 1024;

/// Maximum selected-path transition count retained by an observation witness.
pub const MAX_PATH_TRANSITIONS: u16 = 1_024;

/// A controlled peer locator with bounded initial direct candidates and one pinned relay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRoute {
    id: EndpointId,
    direct_addresses: Vec<SocketAddr>,
    relay_url: RelayUrl,
}

impl PeerRoute {
    /// Constructs an authenticated route with an exact identity and relay.
    ///
    /// The direct list bounds operator-supplied initial locators. After peer
    /// authentication, Iroh NAT negotiation may derive additional direct paths.
    /// Use [`Endpoint::bind_relay_only`] to preclude all IP paths.
    pub fn new(
        id: EndpointId,
        direct_addresses: impl IntoIterator<Item = SocketAddr>,
        relay_url: RelayUrl,
    ) -> Result<Self, CarrierError> {
        validate_relay_url(&relay_url)?;
        let mut unique = BTreeSet::new();
        for address in direct_addresses {
            if unique.len() == MAX_DIRECT_ADDRESSES {
                return Err(CarrierError::Configuration(format!(
                    "peer route has more than {MAX_DIRECT_ADDRESSES} direct addresses"
                )));
            }
            if !unique.insert(address) {
                return Err(CarrierError::Configuration(format!(
                    "peer route contains duplicate direct address {address}"
                )));
            }
        }
        Ok(Self {
            id,
            direct_addresses: unique.into_iter().collect(),
            relay_url,
        })
    }

    /// Returns the exact authenticated endpoint identity.
    pub fn id(&self) -> EndpointId {
        self.id
    }

    /// Returns the sorted operator-supplied initial direct candidates.
    pub fn direct_addresses(&self) -> &[SocketAddr] {
        &self.direct_addresses
    }

    /// Returns the single pinned relay URL.
    pub fn relay_url(&self) -> &RelayUrl {
        &self.relay_url
    }
}

impl fmt::Display for PeerRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@", self.id)?;
        for (index, address) in self.direct_addresses.iter().enumerate() {
            if index != 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{address}")?;
        }
        write!(formatter, "#{}", self.relay_url)
    }
}

impl FromStr for PeerRoute {
    type Err = CarrierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_PEER_ROUTE_TEXT_BYTES {
            return Err(CarrierError::Configuration(format!(
                "peer route exceeds {MAX_PEER_ROUTE_TEXT_BYTES} bytes"
            )));
        }
        let (peer, relay_url) = value.split_once('#').ok_or_else(|| {
            CarrierError::Configuration(
                "route must be ENDPOINT_ID@IP:PORT[,IP:PORT]#HTTPS_RELAY_URL".into(),
            )
        })?;
        if relay_url.contains('#') {
            return Err(CarrierError::Configuration(
                "route must contain exactly one relay separator".into(),
            ));
        }
        if relay_url.len() > MAX_RELAY_URL_BYTES {
            return Err(CarrierError::Configuration(format!(
                "relay URL exceeds {MAX_RELAY_URL_BYTES} bytes"
            )));
        }
        let (id, direct_addresses) = peer.split_once('@').ok_or_else(|| {
            CarrierError::Configuration(
                "route must be ENDPOINT_ID@IP:PORT[,IP:PORT]#HTTPS_RELAY_URL".into(),
            )
        })?;
        let id = id
            .parse()
            .map_err(|error| CarrierError::Configuration(format!("invalid peer id: {error}")))?;
        let relay_url = relay_url
            .parse()
            .map_err(|error| CarrierError::Configuration(format!("invalid relay URL: {error}")))?;
        let mut addresses = Vec::new();
        if !direct_addresses.is_empty() {
            for address in direct_addresses.split(',') {
                if addresses.len() == MAX_DIRECT_ADDRESSES {
                    return Err(CarrierError::Configuration(format!(
                        "peer route has more than {MAX_DIRECT_ADDRESSES} direct addresses"
                    )));
                }
                addresses.push(address.parse().map_err(|error| {
                    CarrierError::Configuration(format!("invalid peer address: {error}"))
                })?);
            }
        }
        Self::new(id, addresses, relay_url)
    }
}

/// TLS trust and URL pin for the one operator-selected relay.
///
/// An empty explicit-root list means the embedded WebPKI roots are used.
/// Nonempty roots replace that set, making a private relay trust boundary exact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedRelay {
    url: RelayUrl,
    ca_roots_der: Arc<[Vec<u8>]>,
}

impl PinnedRelay {
    /// Pins an HTTPS relay using the embedded WebPKI trust roots.
    pub fn new(url: RelayUrl) -> Result<Self, CarrierError> {
        validate_relay_url(&url)?;
        Ok(Self {
            url,
            ca_roots_der: Arc::from([]),
        })
    }

    /// Pins an HTTPS relay using only the supplied DER-encoded CA roots.
    pub fn with_ca_roots(
        url: RelayUrl,
        roots: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<Self, CarrierError> {
        validate_relay_url(&url)?;
        let mut ca_roots_der = Vec::new();
        let mut validated_roots = rustls::RootCertStore::empty();
        let mut total = 0usize;
        for root in roots {
            if ca_roots_der.len() == MAX_RELAY_CA_ROOTS {
                return Err(CarrierError::Configuration(format!(
                    "relay trust has more than {MAX_RELAY_CA_ROOTS} CA roots"
                )));
            }
            if root.is_empty() || root.len() > MAX_RELAY_CA_ROOT_BYTES {
                return Err(CarrierError::Configuration(format!(
                    "relay CA root must be within 1..={MAX_RELAY_CA_ROOT_BYTES} DER bytes"
                )));
            }
            total = total.checked_add(root.len()).ok_or_else(|| {
                CarrierError::Configuration("relay CA root byte total overflowed".into())
            })?;
            if total > MAX_RELAY_CA_ROOT_TOTAL_BYTES {
                return Err(CarrierError::Configuration(format!(
                    "relay CA roots exceed {MAX_RELAY_CA_ROOT_TOTAL_BYTES} total DER bytes"
                )));
            }
            validated_roots
                .add(rustls::pki_types::CertificateDer::from(root.clone()))
                .map_err(|error| {
                    CarrierError::Configuration(format!(
                        "invalid relay CA root DER certificate: {error}"
                    ))
                })?;
            ca_roots_der.push(root);
        }
        if ca_roots_der.is_empty() {
            return Err(CarrierError::Configuration(
                "explicit relay CA trust requires at least one root".into(),
            ));
        }
        Ok(Self {
            url,
            ca_roots_der: ca_roots_der.into(),
        })
    }

    /// Returns the pinned relay URL.
    pub fn url(&self) -> &RelayUrl {
        &self.url
    }

    /// Returns explicit DER CA roots, or an empty slice for embedded WebPKI trust.
    pub fn ca_roots_der(&self) -> &[Vec<u8>] {
        &self.ca_roots_der
    }
}

fn validate_relay_url(url: &RelayUrl) -> Result<(), CarrierError> {
    if url.as_str().len() > MAX_RELAY_URL_BYTES {
        return Err(CarrierError::Configuration(format!(
            "relay URL exceeds {MAX_RELAY_URL_BYTES} bytes"
        )));
    }
    if url.scheme() != "https" {
        return Err(CarrierError::Configuration(
            "relay URL must use HTTPS".into(),
        ));
    }
    if url.host().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(CarrierError::Configuration(
            "relay URL must have a host and no user information".into(),
        ));
    }
    if url.path() != "/" {
        return Err(CarrierError::Configuration(
            "relay URL must identify the root origin".into(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(CarrierError::Configuration(
            "relay URL queries and fragments are not allowed".into(),
        ));
    }
    Ok(())
}

/// Direct peer identity and address supplied by an operator or coordinator.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExpectedPeer {
    /// Iroh endpoint identity expected during the TLS handshake.
    pub id: EndpointId,
    /// Explicit direct socket address; the carrier performs no hosted lookup.
    pub address: SocketAddr,
}

impl fmt::Display for ExpectedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}@{}", self.id, self.address)
    }
}

impl FromStr for ExpectedPeer {
    type Err = CarrierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (id, address) = value.split_once('@').ok_or_else(|| {
            CarrierError::Configuration("peer must be ENDPOINT_ID@IP:PORT".into())
        })?;
        Ok(Self {
            id: id.parse().map_err(|error| {
                CarrierError::Configuration(format!("invalid peer id: {error}"))
            })?,
            address: address.parse().map_err(|error| {
                CarrierError::Configuration(format!("invalid peer address: {error}"))
            })?,
        })
    }
}

/// Bounded endpoint configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointConfig {
    /// Socket on which the endpoint listens.
    pub bind: SocketAddr,
    /// Bound for establishing or accepting an authenticated connection.
    pub connect_timeout: Duration,
    /// Bound for one opaque request/response exchange.
    pub exchange_timeout: Duration,
    /// Maximum request or response bytes.
    pub max_exchange_bytes: usize,
}

impl EndpointConfig {
    /// Creates a loopback-friendly direct configuration with conservative bounds.
    pub fn direct(bind: SocketAddr) -> Self {
        Self {
            bind,
            connect_timeout: Duration::from_secs(10),
            exchange_timeout: Duration::from_secs(10),
            max_exchange_bytes: DEFAULT_MAX_EXCHANGE_BYTES,
        }
    }
}

/// Carrier failure at a bounded, operator-visible stage.
#[derive(Debug)]
pub enum CarrierError {
    /// Invalid local or peer configuration.
    Configuration(String),
    /// An Iroh or QUIC operation failed.
    Transport(String),
    /// A bounded operation made no progress before its deadline.
    Timeout(&'static str),
    /// An authenticated endpoint was not in the configured peer set.
    UnauthorizedPeer(EndpointId),
    /// An opaque frame exceeded its configured bound. `actual` is the exact
    /// local size or the smallest size proven by a bounded remote read.
    FrameTooLarge { actual: usize, maximum: usize },
    /// One length-delimited turn exceeded the caller-owned aggregate byte bound.
    TurnTooLarge { actual: usize, maximum: usize },
}

impl fmt::Display for CarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(formatter, "carrier configuration: {message}"),
            Self::Transport(message) => write!(formatter, "carrier transport: {message}"),
            Self::Timeout(stage) => write!(formatter, "carrier timed out during {stage}"),
            Self::UnauthorizedPeer(peer) => write!(formatter, "unauthorized carrier peer {peer}"),
            Self::FrameTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "carrier frame is at least {actual} bytes; maximum is {maximum}"
                )
            }
            Self::TurnTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "carrier turn is at least {actual} bytes; maximum is {maximum}"
                )
            }
        }
    }
}

impl Error for CarrierError {}

/// A bound Iroh endpoint with hosted discovery and public relays disabled.
#[derive(Clone)]
pub struct Endpoint {
    inner: IrohEndpoint,
    config: EndpointConfig,
    relay_url: Option<RelayUrl>,
    security_profile: CarrierSecurityProfile,
    #[cfg(feature = "nearby-discovery")]
    nearby_discovery_occupied: Arc<AtomicBool>,
}

#[derive(Clone)]
enum InboundAuthorization {
    Rostered(Arc<BTreeSet<EndpointId>>),
    Candidate,
}

/// Stateful inbound carrier acceptance with bounded concurrent handshakes.
///
/// The acceptor keeps dequeuing QUIC attempts while earlier handshakes are in
/// progress. Address validation happens before a handshake consumes one of the
/// bounded slots, and the oldest pending handshake is retired when all slots
/// are occupied so a stalled peer cannot monopolize admission indefinitely.
pub struct InboundAcceptor {
    endpoint: Endpoint,
    authorization: InboundAuthorization,
    handshakes: JoinSet<Result<Connection, CarrierError>>,
    handshake_order: VecDeque<AbortHandle>,
    #[cfg(test)]
    test_handshake_gates: VecDeque<TestHandshakeGate>,
}

#[cfg(test)]
struct TestHandshakeGate {
    entered: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
}

impl InboundAcceptor {
    fn new(endpoint: Endpoint, authorization: InboundAuthorization) -> Self {
        Self {
            endpoint,
            authorization,
            handshakes: JoinSet::new(),
            handshake_order: VecDeque::new(),
            #[cfg(test)]
            test_handshake_gates: VecDeque::new(),
        }
    }

    /// Returns the next carrier-authenticated connection without allowing an
    /// earlier incomplete handshake to block acceptance of later attempts.
    pub async fn accept(&mut self) -> Result<Connection, CarrierError> {
        loop {
            let endpoint = self.endpoint.clone();
            let accept_timeout = endpoint.config.connect_timeout;
            tokio::select! {
                completed = self.handshakes.join_next_with_id(), if !self.handshakes.is_empty() => {
                    if let Some(result) = self.handle_completion(
                        completed.expect("nonempty inbound handshake set has a completion"),
                    ) {
                        return result;
                    }
                }
                incoming = timeout(accept_timeout, endpoint.inner.accept()) => {
                    let incoming = incoming
                        .map_err(|_| CarrierError::Timeout("accept"))?
                        .ok_or_else(|| CarrierError::Transport("endpoint stopped accepting".into()))?;
                    let incoming = if incoming.remote_addr_validated() {
                        incoming
                    } else {
                        match incoming.retry() {
                            Ok(()) => continue,
                            Err(error) => error.into_incoming(),
                        }
                    };

                    let displaced = if self.handshakes.len() >= MAX_PENDING_INBOUND_HANDSHAKES {
                        self.handshake_order
                            .pop_front()
                            .expect("a full handshake set has an oldest task")
                            .abort();
                        let completed = self
                            .handshakes
                            .join_next_with_id()
                            .await
                            .expect("a full handshake set has a completion after retirement");
                        self.handle_completion(completed)
                    } else {
                        None
                    };
                    self.spawn_handshake(incoming);
                    if let Some(result) = displaced {
                        return result;
                    }
                }
            }
        }
    }

    fn spawn_handshake(&mut self, incoming: iroh::endpoint::Incoming) {
        let endpoint = self.endpoint.clone();
        let authorization = self.authorization.clone();
        #[cfg(test)]
        let gate = self.test_handshake_gates.pop_front();
        let handle = self.handshakes.spawn(async move {
            #[cfg(test)]
            if let Some(gate) = gate {
                let _ = gate.entered.send(());
                let _ = gate.release.await;
            }
            endpoint.finish_incoming(incoming, &authorization).await
        });
        self.handshake_order.push_back(handle);
    }

    fn handle_completion(
        &mut self,
        completed: Result<(TaskId, Result<Connection, CarrierError>), JoinError>,
    ) -> Option<Result<Connection, CarrierError>> {
        let completed_id = match &completed {
            Ok((id, _)) => *id,
            Err(error) => error.id(),
        };
        self.handshake_order
            .retain(|handle| handle.id() != completed_id);
        match completed {
            Ok((_, result)) => Some(result),
            Err(error) if error.is_cancelled() => None,
            Err(_) => Some(Err(CarrierError::Transport(
                "inbound handshake task stopped unexpectedly".into(),
            ))),
        }
    }
}

/// Shared synchronous stop authority for one nearby-discovery session.
///
/// A handle is bound to exactly one session generation. Stopping or dropping
/// an older session cannot clear a newer session on the same endpoint.
#[cfg(feature = "nearby-discovery")]
#[derive(Clone)]
pub struct NearbyDiscoveryStopHandle {
    state: Arc<NearbyDiscoveryState>,
}

#[cfg(feature = "nearby-discovery")]
impl NearbyDiscoveryStopHandle {
    /// Stops advertising and resolving this session's nearby address hints.
    ///
    /// The complete lookup registry and provider ownership are cleared before
    /// this method returns. Repeated calls are harmless.
    pub fn stop(&self) {
        self.state.stop(true);
    }

    /// Returns whether this exact session still owns its lookup provider.
    ///
    /// This is lifecycle observation only, not discovery, connectivity, or
    /// authorization evidence.
    pub fn is_active(&self) -> bool {
        self.state.active.load(Ordering::Acquire)
    }
}

/// Exclusive lifetime guard for the optional local-network address lookup.
///
/// Dropping or stopping the guard clears the endpoint's complete lookup
/// registry before dropping the provider. Selected endpoints begin with an
/// empty registry, and callers cannot stack this mode with another lookup
/// service through this crate.
#[cfg(feature = "nearby-discovery")]
pub struct NearbyDiscoverySession {
    state: Arc<NearbyDiscoveryState>,
}

/// Sanitized carrier locator observation from a trusted-LAN browse session.
///
/// These events expose only Iroh endpoint identities. They carry no addresses,
/// user data, Aster mission identity, membership, or authorization result.
/// Discovery is untrusted locator input; callers must authenticate the carrier
/// and then complete the mandatory Aster mission handshake before exchanging
/// inventory or application frames.
#[cfg(feature = "nearby-discovery")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NearbyDiscoveryEvent {
    /// An endpoint identity was passively observed by the nearby locator.
    Discovered {
        /// Untrusted candidate carrier identity.
        endpoint_id: EndpointId,
    },
    /// The nearby locator expired an endpoint identity.
    Expired {
        /// Expired candidate carrier identity.
        endpoint_id: EndpointId,
    },
}

/// Exclusive, time-bounded browser for nearby carrier locator observations.
///
/// This is an evaluation mechanism for trusted LANs. Its bounded outward queue
/// does not make the underlying mDNS implementation a hostile-input boundary,
/// and its observations never authorize an Aster peer.
#[cfg(feature = "nearby-discovery")]
pub struct NearbyDiscoveryBrowser {
    session: NearbyDiscoverySession,
    events: tokio::sync::mpsc::Receiver<NearbyDiscoveryEvent>,
}

/// A subscribed nearby browser that has not installed its lookup provider yet.
///
/// Preparation reserves the endpoint-wide nearby-discovery slot and subscribes
/// to mDNS observations, but it does not advertise or resolve until
/// [`Self::install`] is called. Dropping an uninstalled preparation aborts its
/// event forwarder and releases the reservation. This split lets a caller make
/// the final provider installation synchronous with its own stop authority.
#[cfg(feature = "nearby-discovery")]
pub struct PreparedNearbyDiscoveryBrowser {
    prepared: Option<PreparedNearbyDiscovery>,
    window: Duration,
    events: Option<tokio::sync::mpsc::Receiver<NearbyDiscoveryEvent>>,
    event_forwarder: Option<tokio::task::AbortHandle>,
}

#[cfg(feature = "nearby-discovery")]
struct NearbyDiscoveryState {
    services: AddressLookupServices,
    lookup: Mutex<Option<NearbyAddressLookup>>,
    active: AtomicBool,
    endpoint_occupied: Arc<AtomicBool>,
    expiry: Mutex<Option<tokio::task::AbortHandle>>,
    event_forwarder: Mutex<Option<tokio::task::AbortHandle>>,
}

#[cfg(feature = "nearby-discovery")]
#[derive(Clone)]
enum NearbyAddressLookup {
    Official(MdnsAddressLookup),
    MultiInterface(MultiInterfaceNearbyAddressLookup),
}

#[cfg(feature = "nearby-discovery")]
impl fmt::Debug for NearbyAddressLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Official(_) => formatter.write_str("NearbyAddressLookup::Official"),
            Self::MultiInterface(lookup) => formatter
                .debug_tuple("NearbyAddressLookup::MultiInterface")
                .field(lookup)
                .finish(),
        }
    }
}

#[cfg(feature = "nearby-discovery")]
impl AddressLookup for NearbyAddressLookup {
    fn publish(&self, data: &EndpointData) {
        match self {
            Self::Official(lookup) => lookup.publish(data),
            Self::MultiInterface(lookup) => lookup.publish(data),
        }
    }

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<futures::stream::BoxStream<'static, Result<AddressLookupItem, AddressLookupError>>>
    {
        match self {
            Self::Official(lookup) => lookup.resolve(endpoint_id),
            Self::MultiInterface(lookup) => lookup.resolve(endpoint_id),
        }
    }
}

#[cfg(feature = "nearby-discovery")]
#[derive(Clone)]
struct MultiInterfaceNearbyAddressLookup {
    memory: MemoryLookup,
    discovery: Arc<Mutex<SwarmDiscoveryGuard>>,
    peers: MultiInterfaceNearbyPeerCache,
}

#[cfg(feature = "nearby-discovery")]
impl fmt::Debug for MultiInterfaceNearbyAddressLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MultiInterfaceNearbyAddressLookup")
            .field("retained_peers", &self.peers.retained_len())
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "nearby-discovery")]
impl MultiInterfaceNearbyAddressLookup {
    fn new(
        endpoint_id: EndpointId,
        interfaces: Vec<Ipv4Addr>,
        runtime: &tokio::runtime::Handle,
    ) -> Result<Self, CarrierError> {
        debug_assert!(!interfaces.is_empty());
        debug_assert!(interfaces.len() <= MAX_NEARBY_DISCOVERY_IPV4_INTERFACES);
        debug_assert!(interfaces.windows(2).all(|pair| pair[0] < pair[1]));

        let memory = MemoryLookup::with_provenance(MULTI_INTERFACE_NEARBY_PROVENANCE);
        let peers = MultiInterfaceNearbyPeerCache::new(endpoint_id, memory.clone());
        let callback_peers = peers.clone();
        let discoverer = SwarmDiscoverer::new_interactive(
            NEARBY_SERVICE_NAME.to_owned(),
            encode_nearby_endpoint_id_label(endpoint_id),
        )
        .with_ip_class(SwarmIpClass::V4Only)
        .with_multicast_interfaces_v4(interfaces)
        .with_callback(move |candidate, peer| callback_peers.observe(candidate, peer));
        let discovery = discoverer
            .spawn(runtime)
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        Ok(Self {
            memory,
            discovery: Arc::new(Mutex::new(discovery)),
            peers,
        })
    }

    fn subscribe(&self) -> tokio::sync::mpsc::Receiver<NearbyDiscoveryEvent> {
        self.peers.subscribe()
    }
}

#[cfg(feature = "nearby-discovery")]
impl AddressLookup for MultiInterfaceNearbyAddressLookup {
    fn publish(&self, data: &EndpointData) {
        let mut by_port = BTreeMap::<u16, Vec<IpAddr>>::new();
        for address in data.ip_addrs().take(MAX_MULTI_INTERFACE_LOCAL_ADDRS) {
            by_port
                .entry(address.port())
                .or_default()
                .push(address.ip());
        }
        let discovery = self
            .discovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        discovery.remove_all();
        for (port, addresses) in by_port {
            discovery.add(port, addresses);
        }
    }

    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<futures::stream::BoxStream<'static, Result<AddressLookupItem, AddressLookupError>>>
    {
        self.memory.resolve(endpoint_id)
    }
}

#[cfg(feature = "nearby-discovery")]
#[derive(Clone)]
struct MultiInterfaceNearbyPeerCache {
    local_endpoint_id: EndpointId,
    memory: MemoryLookup,
    retained: Arc<Mutex<BTreeSet<EndpointId>>>,
    subscribers: Arc<Mutex<Vec<tokio::sync::mpsc::Sender<NearbyDiscoveryEvent>>>>,
}

#[cfg(feature = "nearby-discovery")]
impl MultiInterfaceNearbyPeerCache {
    fn new(local_endpoint_id: EndpointId, memory: MemoryLookup) -> Self {
        Self {
            local_endpoint_id,
            memory,
            retained: Arc::new(Mutex::new(BTreeSet::new())),
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn retained_len(&self) -> usize {
        self.retained
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    fn subscribe(&self) -> tokio::sync::mpsc::Receiver<NearbyDiscoveryEvent> {
        let (sender, receiver) = tokio::sync::mpsc::channel(NEARBY_DISCOVERY_EVENT_BUFFER);
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(sender);
        receiver
    }

    fn observe(&self, candidate: &str, peer: &SwarmPeer) {
        let addresses = (!peer.is_expiry()).then(|| {
            peer.addrs()
                .iter()
                .take(MAX_MULTI_INTERFACE_NEARBY_ADDRS_PER_PEER)
                .map(|(ip, port)| SocketAddr::new(*ip, *port))
                .collect::<BTreeSet<_>>()
        });
        self.apply(candidate, addresses);
    }

    fn apply(&self, candidate: &str, addresses: Option<BTreeSet<SocketAddr>>) {
        let Some(endpoint_id) = decode_nearby_endpoint_id_label(candidate) else {
            return;
        };
        if endpoint_id == self.local_endpoint_id {
            return;
        }

        let event = if let Some(addresses) = addresses {
            let addresses = addresses
                .into_iter()
                .take(MAX_MULTI_INTERFACE_NEARBY_ADDRS_PER_PEER)
                .collect::<BTreeSet<_>>();
            if addresses.is_empty() {
                return;
            }
            let mut retained = self
                .retained
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !retained.contains(&endpoint_id) {
                if retained.len() >= MAX_MULTI_INTERFACE_NEARBY_PEERS {
                    return;
                }
                retained.insert(endpoint_id);
            }
            drop(retained);
            let data = EndpointData::from(addresses);
            debug_assert!(data.user_data().is_none());
            self.memory
                .set_endpoint_info(EndpointInfo::from_parts(endpoint_id, data));
            NearbyDiscoveryEvent::Discovered { endpoint_id }
        } else {
            let removed = self
                .retained
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&endpoint_id);
            if !removed {
                return;
            }
            self.memory.remove_endpoint_info(endpoint_id);
            NearbyDiscoveryEvent::Expired { endpoint_id }
        };
        self.notify(event);
    }

    fn notify(&self, event: NearbyDiscoveryEvent) {
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|subscriber| match subscriber.try_send(event) {
                Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => true,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => false,
            });
    }
}

#[cfg(feature = "nearby-discovery")]
impl NearbyDiscoveryState {
    fn stop(&self, abort_expiry: bool) {
        // Hold the ownership lock through provider destruction. Concurrent
        // stop calls therefore do not return before the first stop has
        // completed its synchronous clear.
        {
            let mut lookup = self
                .lookup
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(owned_lookup) = lookup.take() else {
                return;
            };
            self.services.clear();
            drop(owned_lookup);
            self.active.store(false, Ordering::Release);
            self.endpoint_occupied.store(false, Ordering::Release);
        }

        let expiry = self
            .expiry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let event_forwarder = self
            .event_forwarder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(event_forwarder) = event_forwarder {
            event_forwarder.abort();
        }
        if abort_expiry && let Some(expiry) = expiry {
            expiry.abort();
        }
    }
}

#[cfg(feature = "nearby-discovery")]
struct NearbyDiscoveryExpiryGuard {
    state: Arc<NearbyDiscoveryState>,
    completed: bool,
}

#[cfg(feature = "nearby-discovery")]
impl NearbyDiscoveryExpiryGuard {
    fn expire(mut self) {
        self.state.stop(false);
        self.completed = true;
    }
}

#[cfg(feature = "nearby-discovery")]
impl Drop for NearbyDiscoveryExpiryGuard {
    fn drop(&mut self) {
        if !self.completed {
            // Runtime cancellation must not strand endpoint singleton
            // ownership or leave a provider registered.
            self.state.stop(false);
        }
    }
}

#[cfg(feature = "nearby-discovery")]
struct NearbyDiscoveryReservation {
    endpoint_occupied: Arc<AtomicBool>,
    committed: bool,
}

#[cfg(feature = "nearby-discovery")]
struct PreparedNearbyDiscovery {
    runtime: tokio::runtime::Handle,
    reservation: NearbyDiscoveryReservation,
    services: AddressLookupServices,
    lookup: NearbyAddressLookup,
}

#[cfg(feature = "nearby-discovery")]
impl PreparedNearbyDiscovery {
    fn install(
        self,
        window: Duration,
        event_forwarder: Option<tokio::task::AbortHandle>,
    ) -> NearbyDiscoverySession {
        let Self {
            runtime,
            reservation,
            services,
            lookup,
        } = self;
        services.add(lookup.clone());
        let state = Arc::new(NearbyDiscoveryState {
            services,
            lookup: Mutex::new(Some(lookup)),
            active: AtomicBool::new(true),
            endpoint_occupied: reservation.endpoint_occupied.clone(),
            expiry: Mutex::new(None),
            event_forwarder: Mutex::new(event_forwarder),
        });
        let expiry_guard = NearbyDiscoveryExpiryGuard {
            state: state.clone(),
            completed: false,
        };
        let expiry = runtime.spawn(async move {
            tokio::time::sleep(window).await;
            expiry_guard.expire();
        });
        *state
            .expiry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(expiry.abort_handle());
        reservation.commit();
        NearbyDiscoverySession { state }
    }
}

#[cfg(feature = "nearby-discovery")]
impl NearbyDiscoveryReservation {
    fn acquire(endpoint_occupied: Arc<AtomicBool>) -> Result<Self, CarrierError> {
        endpoint_occupied
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                CarrierError::Configuration(
                    "only one nearby-discovery session may be active per endpoint".into(),
                )
            })?;
        Ok(Self {
            endpoint_occupied,
            committed: false,
        })
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

#[cfg(feature = "nearby-discovery")]
impl Drop for NearbyDiscoveryReservation {
    fn drop(&mut self) {
        if !self.committed {
            self.endpoint_occupied.store(false, Ordering::Release);
        }
    }
}

#[cfg(feature = "nearby-discovery")]
impl NearbyDiscoverySession {
    /// Returns a cloneable synchronous stop authority for this exact session.
    pub fn stop_handle(&self) -> NearbyDiscoveryStopHandle {
        NearbyDiscoveryStopHandle {
            state: self.state.clone(),
        }
    }

    /// Stops advertising and resolving nearby carrier address hints now.
    pub fn stop(self) {
        self.state.stop(true);
    }
}

#[cfg(feature = "nearby-discovery")]
impl NearbyDiscoveryBrowser {
    /// Waits for the next sanitized carrier locator observation.
    ///
    /// `None` means the browser was stopped, expired, or its provider ended.
    /// Delivery is best-effort; absence and expiry are not authorization facts.
    pub async fn next_event(&mut self) -> Option<NearbyDiscoveryEvent> {
        self.events.recv().await
    }

    /// Returns a cloneable synchronous stop authority for this exact browser.
    pub fn stop_handle(&self) -> NearbyDiscoveryStopHandle {
        self.session.stop_handle()
    }

    /// Stops the browser and clears its lookup provider now.
    pub fn stop(self) {
        self.session.stop();
    }
}

#[cfg(feature = "nearby-discovery")]
impl PreparedNearbyDiscoveryBrowser {
    /// Installs the subscribed provider and starts its bounded lifetime.
    pub fn install(mut self) -> NearbyDiscoveryBrowser {
        let prepared = self
            .prepared
            .take()
            .expect("nearby browser preparation installs exactly once");
        let events = self
            .events
            .take()
            .expect("nearby browser preparation owns one event receiver");
        let event_forwarder = self
            .event_forwarder
            .take()
            .expect("nearby browser preparation owns one event forwarder");
        let session = prepared.install(self.window, Some(event_forwarder));
        NearbyDiscoveryBrowser { session, events }
    }
}

#[cfg(feature = "nearby-discovery")]
impl Drop for PreparedNearbyDiscoveryBrowser {
    fn drop(&mut self) {
        if let Some(event_forwarder) = self.event_forwarder.take() {
            event_forwarder.abort();
        }
        // `PreparedNearbyDiscovery` releases the endpoint reservation on drop
        // whenever installation did not commit it.
    }
}

#[cfg(feature = "nearby-discovery")]
impl Drop for NearbyDiscoverySession {
    fn drop(&mut self) {
        self.state.stop(true);
    }
}

impl Endpoint {
    /// Binds a direct endpoint using a caller-supplied secret.
    pub async fn bind(secret: SecretKey, config: EndpointConfig) -> Result<Self, CarrierError> {
        Self::bind_with_security_profile(secret, config, CarrierSecurityProfile::default()).await
    }

    /// Binds a direct endpoint to exactly one carrier security profile.
    pub async fn bind_with_security_profile(
        secret: SecretKey,
        config: EndpointConfig,
        security_profile: CarrierSecurityProfile,
    ) -> Result<Self, CarrierError> {
        Self::bind_inner(secret, config, None, false, security_profile).await
    }

    /// Binds an endpoint to exactly one operator-pinned custom relay.
    pub async fn bind_with_relay(
        secret: SecretKey,
        config: EndpointConfig,
        relay: PinnedRelay,
    ) -> Result<Self, CarrierError> {
        Self::bind_with_relay_and_security_profile(
            secret,
            config,
            relay,
            CarrierSecurityProfile::default(),
        )
        .await
    }

    /// Binds an endpoint to one pinned relay and one carrier security profile.
    pub async fn bind_with_relay_and_security_profile(
        secret: SecretKey,
        config: EndpointConfig,
        relay: PinnedRelay,
        security_profile: CarrierSecurityProfile,
    ) -> Result<Self, CarrierError> {
        Self::bind_inner(secret, config, Some(relay), false, security_profile).await
    }

    /// Binds a relay-only endpoint with no direct IP transport.
    ///
    /// This is intended for an explicit operator-selected forced-relay mode.
    /// The endpoint cannot dial, listen, or hole-punch over a direct UDP path.
    pub async fn bind_relay_only(
        secret: SecretKey,
        config: EndpointConfig,
        relay: PinnedRelay,
    ) -> Result<Self, CarrierError> {
        Self::bind_relay_only_with_security_profile(
            secret,
            config,
            relay,
            CarrierSecurityProfile::default(),
        )
        .await
    }

    /// Binds a relay-only endpoint to exactly one carrier security profile.
    pub async fn bind_relay_only_with_security_profile(
        secret: SecretKey,
        config: EndpointConfig,
        relay: PinnedRelay,
        security_profile: CarrierSecurityProfile,
    ) -> Result<Self, CarrierError> {
        Self::bind_inner(secret, config, Some(relay), true, security_profile).await
    }

    async fn bind_inner(
        secret: SecretKey,
        config: EndpointConfig,
        relay: Option<PinnedRelay>,
        relay_only: bool,
        security_profile: CarrierSecurityProfile,
    ) -> Result<Self, CarrierError> {
        if config.connect_timeout.is_zero() {
            return Err(CarrierError::Configuration(
                "connect timeout must be nonzero".into(),
            ));
        }
        if config.exchange_timeout.is_zero() {
            return Err(CarrierError::Configuration(
                "exchange timeout must be nonzero".into(),
            ));
        }
        if config.max_exchange_bytes == 0 || config.max_exchange_bytes > u32::MAX as usize {
            return Err(CarrierError::Configuration(
                "max exchange bytes must be within 1..=u32::MAX".into(),
            ));
        }
        let window = config.max_exchange_bytes as u32;
        let mut transport = QuicTransportConfig::builder();
        if let Some(keepalive_interval) = connection_keepalive_interval(security_profile) {
            transport = transport
                .keep_alive_interval(keepalive_interval)
                .default_path_keep_alive_interval(keepalive_interval);
        }
        let transport = transport
            .max_concurrent_bidi_streams(VarInt::from_u32(16))
            // The role-ordered carrier state machine permits exactly one active uni turn.
            .max_concurrent_uni_streams(VarInt::from_u32(1))
            .stream_receive_window(VarInt::from_u32(window))
            .receive_window(VarInt::from_u32(window.saturating_mul(2)))
            .send_window(u64::from(window.saturating_mul(2)))
            .build();
        let relay_mode = relay.as_ref().map_or(RelayMode::Disabled, |relay| {
            RelayMode::Custom(IrohRelayConfig::new(relay.url.clone(), None).into())
        });
        let mut net_report_config = NetReportConfig::minimal();
        // With QUIC address discovery disabled on the exact relay config,
        // this bounded HTTPS probe is what lets Iroh select that relay.
        net_report_config.https_probes = relay.is_some();
        let mut builder = IrohEndpoint::builder(presets::Minimal)
            .dns_resolver(
                iroh::dns::DnsResolver::builder()
                    .with_system_defaults()
                    .disable_fallback()
                    .build(),
            )
            .secret_key(secret)
            .clear_address_lookup()
            .clear_relay_transports()
            .relay_mode(relay_mode)
            .portmapper_config(PortmapperConfig::Disabled)
            .net_report_config(net_report_config)
            .transport_config(transport)
            .clear_ip_transports()
            .alpns(vec![security_profile.alpn().to_vec()]);
        if !relay_only {
            builder = builder
                .bind_addr(config.bind)
                .map_err(|error| CarrierError::Configuration(error.to_string()))?;
        }
        if let Some(relay) = relay.as_ref()
            && !relay.ca_roots_der.is_empty()
        {
            builder = builder.ca_tls_config(CaTlsConfig::custom_roots(
                relay.ca_roots_der.iter().cloned().map(Into::into),
            ));
        }
        let inner = builder
            .bind()
            .await
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        Ok(Self {
            inner,
            config,
            relay_url: relay.map(|relay| relay.url),
            security_profile,
            #[cfg(feature = "nearby-discovery")]
            nearby_discovery_occupied: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Returns the authenticated endpoint identity.
    pub fn id(&self) -> EndpointId {
        self.inner.id()
    }

    /// Returns the exact carrier profile this endpoint advertises and dials.
    pub fn security_profile(&self) -> CarrierSecurityProfile {
        self.security_profile
    }

    /// Returns the actual local sockets after binding.
    pub fn bound_sockets(&self) -> Vec<SocketAddr> {
        self.inner.bound_sockets()
    }

    #[cfg(feature = "nearby-discovery")]
    fn prepare_nearby_discovery(
        &self,
        window: Duration,
        interfaces: Vec<Ipv4Addr>,
    ) -> Result<PreparedNearbyDiscovery, CarrierError> {
        if !(MIN_NEARBY_DISCOVERY_WINDOW..=MAX_NEARBY_DISCOVERY_WINDOW).contains(&window)
            || window.subsec_nanos() != 0
        {
            return Err(CarrierError::Configuration(format!(
                "nearby discovery window must be a whole number of seconds within {}..={}",
                MIN_NEARBY_DISCOVERY_WINDOW.as_secs(),
                MAX_NEARBY_DISCOVERY_WINDOW.as_secs()
            )));
        }
        let interfaces = normalize_nearby_ipv4_interfaces(interfaces)?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            CarrierError::Configuration("nearby discovery requires an active Tokio runtime".into())
        })?;
        let reservation =
            NearbyDiscoveryReservation::acquire(self.nearby_discovery_occupied.clone())?;
        let services = self
            .inner
            .address_lookup()
            .map_err(|error| CarrierError::Transport(error.to_string()))?
            .clone();
        if !services.is_empty() {
            return Err(CarrierError::Configuration(
                "nearby discovery requires an otherwise empty address-lookup registry".into(),
            ));
        }
        // `AddrFilter::ip_only` filters transport addresses, not lookup user
        // data. Clear user data explicitly before the sole provider is added
        // so future endpoint-builder changes cannot place mission/application
        // metadata in this demo/evaluation advertisement.
        self.inner.set_user_data_for_address_lookup(None);
        services.set_addr_filter(AddrFilter::ip_only());
        let lookup = if interfaces.is_empty() {
            NearbyAddressLookup::Official(
                MdnsAddressLookup::builder()
                    .service_name(NEARBY_SERVICE_NAME)
                    .addr_filter(AddrFilter::ip_only())
                    .build(self.id())
                    .map_err(|error| CarrierError::Transport(error.to_string()))?,
            )
        } else {
            NearbyAddressLookup::MultiInterface(MultiInterfaceNearbyAddressLookup::new(
                self.id(),
                interfaces,
                &runtime,
            )?)
        };
        Ok(PreparedNearbyDiscovery {
            runtime,
            reservation,
            services,
            lookup,
        })
    }

    /// Starts one exclusive, internally time-bounded nearby lookup session.
    ///
    /// This is an evaluation/demo mechanism, not an authorization source.
    /// It uses Iroh's official mDNS address-lookup provider, advertises direct
    /// IP addresses only, and carries no Aster metadata. The caller must still
    /// name the exact expected carrier identity before dialing, and the Aster
    /// mission handshake remains mandatory after carrier authentication. The
    /// provider stops no later than the caller-supplied one-to-thirty-second
    /// window even if the returned guard is leaked.
    #[cfg(feature = "nearby-discovery")]
    pub fn start_nearby_discovery(
        &self,
        window: Duration,
    ) -> Result<NearbyDiscoverySession, CarrierError> {
        Ok(self
            .prepare_nearby_discovery(window, Vec::new())?
            .install(window, None))
    }

    /// Starts nearby lookup on an explicit bounded set of local IPv4 interfaces.
    ///
    /// The interface list is sorted and deduplicated. An empty list is exactly
    /// equivalent to [`Self::start_nearby_discovery`] and retains the official
    /// provider's default-interface behavior. A nonempty list selects Aster's
    /// bounded adapter over the already-pinned `swarm-discovery` implementation;
    /// only direct IP endpoint data is advertised or retained.
    #[cfg(feature = "nearby-discovery")]
    pub fn start_nearby_discovery_on_ipv4_interfaces(
        &self,
        window: Duration,
        interfaces: Vec<Ipv4Addr>,
    ) -> Result<NearbyDiscoverySession, CarrierError> {
        Ok(self
            .prepare_nearby_discovery(window, interfaces)?
            .install(window, None))
    }

    /// Prepares one exclusive browser without installing its lookup provider.
    ///
    /// This trusted-LAN evaluation API subscribes before installing the mDNS
    /// provider, because the provider does not replay observations made before
    /// subscription. It exposes only endpoint identities; discovery supplies
    /// locator candidates, never Aster authorization. A caller may attempt
    /// carrier authentication with [`Self::connect_discovered`], but must then
    /// complete the mandatory Aster mission handshake before reading inventory
    /// or application frames.
    ///
    /// The browser shares the same endpoint-wide exclusivity and whole-second
    /// one-to-thirty-second lifetime as [`Self::start_nearby_discovery`].
    #[cfg(feature = "nearby-discovery")]
    pub async fn prepare_nearby_browser(
        &self,
        window: Duration,
    ) -> Result<PreparedNearbyDiscoveryBrowser, CarrierError> {
        self.prepare_nearby_browser_on_ipv4_interfaces(window, Vec::new())
            .await
    }

    /// Prepares a nearby browser on explicit local IPv4 multicast interfaces.
    ///
    /// Passing an empty list preserves [`Self::prepare_nearby_browser`] behavior.
    /// Nonempty lists are sorted, deduplicated, bounded, and used for both
    /// multicast send and receive sockets by the Aster-owned lookup adapter.
    #[cfg(feature = "nearby-discovery")]
    pub async fn prepare_nearby_browser_on_ipv4_interfaces(
        &self,
        window: Duration,
        interfaces: Vec<Ipv4Addr>,
    ) -> Result<PreparedNearbyDiscoveryBrowser, CarrierError> {
        let prepared = self.prepare_nearby_discovery(window, interfaces)?;

        // This order is security- and correctness-significant. The upstream
        // subscriber receives no replay of the provider's existing peer map.
        let (event_sender, event_receiver) =
            tokio::sync::mpsc::channel(NEARBY_DISCOVERY_EVENT_BUFFER);
        let event_forwarder = match &prepared.lookup {
            NearbyAddressLookup::Official(lookup) => {
                let mut source = lookup.subscribe().await;
                prepared.runtime.spawn(async move {
                    while let Some(event) = source.next().await {
                        let sanitized = match event {
                            MdnsDiscoveryEvent::Discovered { endpoint_info, .. } => {
                                NearbyDiscoveryEvent::Discovered {
                                    endpoint_id: endpoint_info.endpoint_id,
                                }
                            }
                            MdnsDiscoveryEvent::Expired { endpoint_id } => {
                                NearbyDiscoveryEvent::Expired { endpoint_id }
                            }
                            _ => continue,
                        };
                        if event_sender.send(sanitized).await.is_err() {
                            break;
                        }
                    }
                })
            }
            NearbyAddressLookup::MultiInterface(lookup) => {
                let mut source = lookup.subscribe();
                prepared.runtime.spawn(async move {
                    while let Some(event) = source.recv().await {
                        if event_sender.send(event).await.is_err() {
                            break;
                        }
                    }
                })
            }
        };
        Ok(PreparedNearbyDiscoveryBrowser {
            prepared: Some(prepared),
            window,
            events: Some(event_receiver),
            event_forwarder: Some(event_forwarder.abort_handle()),
        })
    }

    /// Starts one exclusive browser for nearby carrier locator observations.
    ///
    /// This convenience API composes [`Self::prepare_nearby_browser`] with
    /// synchronous provider installation. Callers that must serialize install
    /// with an external stop authority should use the split API directly.
    #[cfg(feature = "nearby-discovery")]
    pub async fn start_nearby_browser(
        &self,
        window: Duration,
    ) -> Result<NearbyDiscoveryBrowser, CarrierError> {
        Ok(self.prepare_nearby_browser(window).await?.install())
    }

    /// Starts one nearby browser on explicit local IPv4 multicast interfaces.
    ///
    /// An empty list preserves [`Self::start_nearby_browser`] behavior.
    #[cfg(feature = "nearby-discovery")]
    pub async fn start_nearby_browser_on_ipv4_interfaces(
        &self,
        window: Duration,
        interfaces: Vec<Ipv4Addr>,
    ) -> Result<NearbyDiscoveryBrowser, CarrierError> {
        Ok(self
            .prepare_nearby_browser_on_ipv4_interfaces(window, interfaces)
            .await?
            .install())
    }

    /// Waits, within the configured connection deadline, for the pinned relay
    /// registration to become usable.
    pub async fn wait_relay_ready(&self) -> Result<(), CarrierError> {
        if self.relay_url.is_none() {
            return Err(CarrierError::Configuration(
                "relay readiness requires a relay-enabled endpoint".into(),
            ));
        }
        timeout(self.config.connect_timeout, self.inner.online())
            .await
            .map_err(|_| CarrierError::Timeout("relay readiness"))
    }

    /// Connects to the exact expected identity at its explicit direct address.
    pub async fn connect(&self, peer: ExpectedPeer) -> Result<Connection, CarrierError> {
        let address = EndpointAddr::new(peer.id).with_ip_addr(peer.address);
        self.connect_address(address, peer.id).await
    }

    /// Resolves and connects to one exact carrier identity through the
    /// endpoint's explicitly installed address-lookup service.
    ///
    /// No identity is learned from discovery: callers must provision the
    /// expected endpoint ID before invoking this method. Carrier TLS and the
    /// independent Aster mission handshake remain separate mandatory gates.
    #[cfg(feature = "nearby-discovery")]
    pub async fn connect_discovered(
        &self,
        expected_id: EndpointId,
    ) -> Result<Connection, CarrierError> {
        self.connect_address(EndpointAddr::new(expected_id), expected_id)
            .await
    }

    /// Connects using the route's initial direct candidates and exact pinned relay.
    ///
    /// Iroh may probe initial paths in parallel and, after authenticating the
    /// exact endpoint ID, NAT negotiation may derive additional direct paths.
    /// The endpoint identity and sole configured relay remain exact; this API
    /// makes no temporal direct-first ordering promise.
    pub async fn connect_route(&self, route: &PeerRoute) -> Result<Connection, CarrierError> {
        match self.relay_url.as_ref() {
            Some(configured) if configured == route.relay_url() => {}
            Some(_) => {
                return Err(CarrierError::Configuration(
                    "peer route relay does not match the endpoint's pinned relay".into(),
                ));
            }
            None => {
                return Err(CarrierError::Configuration(
                    "controlled peer route requires a relay-enabled endpoint".into(),
                ));
            }
        }
        let address = EndpointAddr::new(route.id())
            .with_addrs(
                route
                    .direct_addresses()
                    .iter()
                    .copied()
                    .map(TransportAddr::Ip),
            )
            .with_relay_url(route.relay_url().clone());
        self.connect_address(address, route.id()).await
    }

    async fn connect_address(
        &self,
        address: EndpointAddr,
        expected_id: EndpointId,
    ) -> Result<Connection, CarrierError> {
        let inner = timeout(
            self.config.connect_timeout,
            self.inner.connect(address, self.security_profile.alpn()),
        )
        .await
        .map_err(|_| CarrierError::Timeout("connect"))?
        .map_err(|error| CarrierError::Transport(error.to_string()))?;
        if inner.remote_id() != expected_id {
            return Err(CarrierError::UnauthorizedPeer(inner.remote_id()));
        }
        self.ensure_negotiated_profile(&inner)?;
        Ok(Connection::new(
            inner,
            self.id(),
            self.config.exchange_timeout,
            self.config.max_exchange_bytes,
            self.security_profile,
            UniTurnRole::Dialer,
        ))
    }

    /// Accepts one connection and rejects identities outside `allowed` before
    /// any application frame is read.
    pub async fn accept(&self, allowed: &BTreeSet<EndpointId>) -> Result<Connection, CarrierError> {
        let inner = self.accept_carrier().await?;
        let remote = inner.remote_id();
        if !allowed.contains(&remote) {
            inner.close(1u8.into(), b"unauthorized peer");
            return Err(CarrierError::UnauthorizedPeer(remote));
        }
        self.finish_accepted_connection(inner)
    }

    /// Creates a stateful inbound acceptor for a fixed carrier roster.
    ///
    /// Reuse this value for the endpoint's complete accept loop so incomplete
    /// handshakes remain isolated from later inbound attempts.
    pub fn inbound_acceptor(&self, allowed: &BTreeSet<EndpointId>) -> InboundAcceptor {
        InboundAcceptor::new(
            self.clone(),
            InboundAuthorization::Rostered(Arc::new(allowed.clone())),
        )
    }

    /// Accepts one carrier-authenticated candidate without a carrier roster.
    ///
    /// The returned connection proves possession of its Iroh endpoint identity
    /// under this endpoint's selected ALPN only. This method performs no Aster
    /// mission identity, membership, scope, or application authorization. The
    /// caller must immediately complete the mandatory Aster mission handshake
    /// and reject an unprovisioned peer before reading inventory or application
    /// frames. Use [`Self::accept`] when the carrier roster is already known.
    pub async fn accept_candidate(&self) -> Result<Connection, CarrierError> {
        let inner = self.accept_carrier().await?;
        self.finish_accepted_connection(inner)
    }

    /// Creates a stateful acceptor for carrier-authenticated candidates that
    /// still require the mandatory Aster mission handshake and authorization.
    pub fn inbound_candidate_acceptor(&self) -> InboundAcceptor {
        InboundAcceptor::new(self.clone(), InboundAuthorization::Candidate)
    }

    async fn finish_incoming(
        &self,
        incoming: iroh::endpoint::Incoming,
        authorization: &InboundAuthorization,
    ) -> Result<Connection, CarrierError> {
        let inner = timeout(self.config.connect_timeout, incoming)
            .await
            .map_err(|_| CarrierError::Timeout("handshake"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        let remote = inner.remote_id();
        if let InboundAuthorization::Rostered(allowed) = authorization
            && !allowed.contains(&remote)
        {
            inner.close(1u8.into(), b"unauthorized peer");
            return Err(CarrierError::UnauthorizedPeer(remote));
        }
        self.finish_accepted_connection(inner)
    }

    async fn accept_carrier(&self) -> Result<iroh::endpoint::Connection, CarrierError> {
        let incoming = timeout(self.config.connect_timeout, self.inner.accept())
            .await
            .map_err(|_| CarrierError::Timeout("accept"))?
            .ok_or_else(|| CarrierError::Transport("endpoint stopped accepting".into()))?;
        timeout(self.config.connect_timeout, incoming)
            .await
            .map_err(|_| CarrierError::Timeout("handshake"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))
    }

    fn finish_accepted_connection(
        &self,
        inner: iroh::endpoint::Connection,
    ) -> Result<Connection, CarrierError> {
        self.ensure_negotiated_profile(&inner)?;
        Ok(Connection::new(
            inner,
            self.id(),
            self.config.exchange_timeout,
            self.config.max_exchange_bytes,
            self.security_profile,
            UniTurnRole::Acceptor,
        ))
    }

    fn ensure_negotiated_profile(
        &self,
        connection: &iroh::endpoint::Connection,
    ) -> Result<(), CarrierError> {
        if connection.alpn() == self.security_profile.alpn() {
            return Ok(());
        }
        connection.close(1u8.into(), b"carrier profile mismatch");
        Err(CarrierError::Transport(
            "negotiated carrier security profile mismatch".into(),
        ))
    }

    /// Closes the endpoint and waits for its background tasks.
    pub async fn close(&self) {
        self.inner.close().await;
    }
}

/// Selected network path kind observed for an authenticated connection.
///
/// This is diagnostic state only. It never establishes peer identity,
/// membership, authorization, receipt validity, or replication success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedPath {
    /// The most recently observed selected path used a direct IP transport.
    Direct,
    /// The most recently observed selected path used the pinned relay transport.
    Relay,
    /// No selected path has yet been observed, or observation lost continuity.
    Unknown,
}

/// Bounded observation of selected-path changes for one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathWitness {
    /// Most recently observed selected network path, retained across ordinary
    /// path closure after the connection completes.
    pub selected: SelectedPath,
    /// Number of observed path-kind transitions, capped at
    /// [`MAX_PATH_TRANSITIONS`].
    pub transition_count: u16,
    /// Whether events were lost or the transition count reached its cap.
    pub transitions_saturated: bool,
}

impl PathWitness {
    fn new(selected: SelectedPath) -> Self {
        Self {
            selected,
            transition_count: 0,
            transitions_saturated: false,
        }
    }

    fn observe(&mut self, selected: SelectedPath) {
        if self.selected == selected {
            return;
        }
        self.selected = selected;
        if self.transition_count < MAX_PATH_TRANSITIONS {
            self.transition_count += 1;
            if self.transition_count == MAX_PATH_TRANSITIONS {
                self.transitions_saturated = true;
            }
        } else {
            self.transitions_saturated = true;
        }
    }

    fn lose_continuity(&mut self) {
        self.selected = SelectedPath::Unknown;
        self.transitions_saturated = true;
    }
}

// Keep authorization and the first payload submission in one testable seam.
// The write closure is never invoked if authorization fails.
async fn checked_write<F, W, Fut, T, E>(before_write: F, write: W) -> Result<T, E>
where
    F: FnOnce() -> Result<T, E>,
    W: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), E>>,
{
    let checked = before_write()?;
    write().await?;
    Ok(checked)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UniTurnRole {
    Dialer,
    Acceptor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UniTurnPosition {
    First,
    Second,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UniTurnState {
    ExpectFirstSend,
    SendingFirst,
    ExpectFirstReceive,
    ReceivingFirst,
    ExpectSecondSend,
    SendingSecond,
    ExpectSecondReceive,
    ReceivingSecond,
    Complete,
}

impl UniTurnState {
    fn initial(role: UniTurnRole) -> Self {
        match role {
            UniTurnRole::Dialer => Self::ExpectFirstSend,
            UniTurnRole::Acceptor => Self::ExpectFirstReceive,
        }
    }

    fn begin_send(&mut self) -> Result<UniTurnPosition, CarrierError> {
        match *self {
            Self::ExpectFirstSend => {
                *self = Self::SendingFirst;
                Ok(UniTurnPosition::First)
            }
            Self::ExpectSecondSend => {
                *self = Self::SendingSecond;
                Ok(UniTurnPosition::Second)
            }
            _ => Err(CarrierError::Transport(
                "unidirectional turn send is concurrent, reordered, or extra".into(),
            )),
        }
    }

    fn begin_receive(&mut self) -> Result<UniTurnPosition, CarrierError> {
        match *self {
            Self::ExpectFirstReceive => {
                *self = Self::ReceivingFirst;
                Ok(UniTurnPosition::First)
            }
            Self::ExpectSecondReceive => {
                *self = Self::ReceivingSecond;
                Ok(UniTurnPosition::Second)
            }
            _ => Err(CarrierError::Transport(
                "unidirectional turn receive is concurrent, reordered, or extra".into(),
            )),
        }
    }

    fn finish_send(&mut self, position: UniTurnPosition) -> Result<(), CarrierError> {
        match (*self, position) {
            (Self::SendingFirst, UniTurnPosition::First) => {
                *self = Self::ExpectSecondReceive;
                Ok(())
            }
            (Self::SendingSecond, UniTurnPosition::Second) => {
                *self = Self::Complete;
                Ok(())
            }
            _ => Err(CarrierError::Transport(
                "unidirectional send turn completed out of phase".into(),
            )),
        }
    }

    fn finish_receive(&mut self, position: UniTurnPosition) -> Result<(), CarrierError> {
        match (*self, position) {
            (Self::ReceivingFirst, UniTurnPosition::First) => {
                *self = Self::ExpectSecondSend;
                Ok(())
            }
            (Self::ReceivingSecond, UniTurnPosition::Second) => {
                *self = Self::Complete;
                Ok(())
            }
            _ => Err(CarrierError::Transport(
                "unidirectional receive turn completed out of phase".into(),
            )),
        }
    }

    fn skip(&mut self) -> Result<(), CarrierError> {
        match *self {
            Self::ExpectFirstSend => {
                *self = Self::ExpectSecondReceive;
                Ok(())
            }
            Self::ExpectFirstReceive => {
                *self = Self::ExpectSecondSend;
                Ok(())
            }
            Self::ExpectSecondSend | Self::ExpectSecondReceive => {
                *self = Self::Complete;
                Ok(())
            }
            _ => Err(CarrierError::Transport(
                "unidirectional turn skip is concurrent or extra".into(),
            )),
        }
    }

    fn fail(&mut self) {
        *self = Self::Complete;
    }
}

fn lock_uni_turn_state(
    state: &Arc<Mutex<UniTurnState>>,
) -> Result<std::sync::MutexGuard<'_, UniTurnState>, CarrierError> {
    state
        .lock()
        .map_err(|_| CarrierError::Transport("unidirectional turn state is poisoned".into()))
}

/// Owned sender for one ordered, bounded unidirectional carrier turn.
pub struct SendUniTurn {
    stream: SendStream,
    deadline: Instant,
    max_frame_bytes: usize,
    max_turn_bytes: usize,
    written_bytes: usize,
    state: Arc<Mutex<UniTurnState>>,
    position: UniTurnPosition,
    complete: bool,
    started: bool,
}

/// Owned receiver for one ordered, bounded unidirectional carrier turn.
pub struct ReceiveUniTurn {
    stream: RecvStream,
    deadline: Instant,
    max_frame_bytes: usize,
    max_turn_bytes: usize,
    read_bytes: usize,
    state: Arc<Mutex<UniTurnState>>,
    position: UniTurnPosition,
    complete: bool,
    eof: bool,
}

const STREAM_DATA_MAGIC: &[u8; 8] = b"ASTRSD\x01\x01";
const STREAM_CONTROL_MAGIC: &[u8; 8] = b"ASTRSC\x01\x01";

/// Sender half of one bounded long-lived stream direction.
pub struct BoundedSendStream {
    stream: SendStream,
    deadline: Instant,
    magic: &'static [u8; 8],
    max_frame_bytes: usize,
    max_stream_bytes: usize,
    written_bytes: usize,
    started: bool,
    complete: bool,
}

/// Receiver half of one bounded long-lived stream direction.
pub struct BoundedReceiveStream {
    stream: RecvStream,
    deadline: Instant,
    magic: &'static [u8; 8],
    max_frame_bytes: usize,
    max_stream_bytes: usize,
    read_bytes: usize,
    started: bool,
    complete: bool,
    eof: bool,
}

/// Initiator's concurrent data-send and control-receive pair.
pub struct OpenedStreamPair {
    pub data: BoundedSendStream,
    pub control: BoundedReceiveStream,
}

/// Acceptor's concurrent data-receive and control-send pair.
pub struct AcceptedStreamPair {
    pub data: BoundedReceiveStream,
    pub control: BoundedSendStream,
}

/// Authenticated, bounded opaque exchange channel.
#[derive(Clone)]
pub struct Connection {
    inner: iroh::endpoint::Connection,
    local_id: EndpointId,
    exchange_timeout: Duration,
    max_exchange_bytes: usize,
    path_witness: Arc<Mutex<PathWitness>>,
    security_profile: CarrierSecurityProfile,
    uni_turn_state: Arc<Mutex<UniTurnState>>,
    additional_uni_pair: Arc<Mutex<Option<UniTurnRole>>>,
}

impl Connection {
    fn new(
        inner: iroh::endpoint::Connection,
        local_id: EndpointId,
        exchange_timeout: Duration,
        max_exchange_bytes: usize,
        security_profile: CarrierSecurityProfile,
        uni_turn_role: UniTurnRole,
    ) -> Self {
        // Subscribe before the snapshot. Path events are not replayed, so the
        // opposite order has a window in which a selection change can vanish.
        let mut events = inner.path_events();
        let weak = inner.weak_handle();
        let selected = selected_path_snapshot(&inner);
        let path_witness = Arc::new(Mutex::new(PathWitness::new(selected)));
        let observed = Arc::clone(&path_witness);
        tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if matches!(event, PathEvent::Lagged { .. }) {
                    if let Ok(mut witness) = observed.lock() {
                        witness.lose_continuity();
                    }
                    return;
                }
                let Some(connection) = weak.upgrade() else {
                    break;
                };
                // Re-snapshot rather than replaying the event's address. An
                // event queued before the initial snapshot may already be
                // stale by the time this task runs.
                let selected = selected_path_snapshot(&connection);
                drop(connection);
                let mut witness = match observed.lock() {
                    Ok(witness) => witness,
                    Err(poisoned) => {
                        let mut witness = poisoned.into_inner();
                        witness.lose_continuity();
                        break;
                    }
                };
                // A transient lack of a selected path during ordinary path
                // closure does not erase the last successfully observed
                // transport. Only a lag or poisoned state loses continuity.
                if selected != SelectedPath::Unknown {
                    witness.observe(selected);
                }
            }
        });
        Self {
            inner,
            local_id,
            exchange_timeout,
            max_exchange_bytes,
            path_witness,
            security_profile,
            uni_turn_state: Arc::new(Mutex::new(UniTurnState::initial(uni_turn_role))),
            additional_uni_pair: Arc::new(Mutex::new(Some(uni_turn_role))),
        }
    }

    /// Returns this connection's local carrier endpoint identity.
    ///
    /// This does not expose mission identity.
    pub fn local_id(&self) -> EndpointId {
        self.local_id
    }

    /// Starts the one optional additional role-ordered uni-turn pair.
    ///
    /// The caller must bilaterally negotiate this extension. Both original
    /// turns must have completed (or been explicitly skipped). Clones share
    /// admission; a third pair and reset of an active turn are rejected.
    pub fn begin_additional_uni_pair(&self) -> Result<(), CarrierError> {
        let mut state = lock_uni_turn_state(&self.uni_turn_state)?;
        if *state != UniTurnState::Complete {
            return Err(CarrierError::Transport(
                "previous uni-turn pair is incomplete".into(),
            ));
        }
        let mut admission = self
            .additional_uni_pair
            .lock()
            .map_err(|_| CarrierError::Transport("uni-turn pair admission lock poisoned".into()))?;
        let role = admission.take().ok_or_else(|| {
            CarrierError::Transport("additional uni-turn pair already admitted".into())
        })?;
        *state = UniTurnState::initial(role);
        Ok(())
    }

    /// Returns the authenticated remote endpoint identity.
    pub fn remote_id(&self) -> EndpointId {
        self.inner.remote_id()
    }

    /// Returns the exact carrier security profile negotiated for this connection.
    pub fn security_profile(&self) -> CarrierSecurityProfile {
        self.security_profile
    }

    /// Derives a domain-separated binding to this exact QUIC TLS session.
    ///
    /// The exporter label and output size are fixed by this crate. Callers can
    /// vary only a validated application context; the selected carrier ALPN is
    /// incorporated automatically. The returned bytes should be authenticated
    /// by the higher-layer mission transcript before application inventory is
    /// exchanged.
    pub fn channel_binding(
        &self,
        context: ChannelBindingContext<'_>,
    ) -> Result<ChannelBinding, CarrierError> {
        let application_context = context.as_bytes();
        let alpn = self.security_profile.alpn();
        let mut exporter_context = Vec::with_capacity(
            CHANNEL_BINDING_CONTEXT_DOMAIN.len()
                + 1
                + std::mem::size_of::<u16>()
                + alpn.len()
                + std::mem::size_of::<u32>()
                + application_context.len(),
        );
        exporter_context.extend_from_slice(CHANNEL_BINDING_CONTEXT_DOMAIN);
        exporter_context.push(0);
        exporter_context.extend_from_slice(
            &u16::try_from(alpn.len())
                .expect("carrier ALPN length is statically bounded")
                .to_be_bytes(),
        );
        exporter_context.extend_from_slice(alpn);
        exporter_context.extend_from_slice(
            &u32::try_from(application_context.len())
                .expect("validated channel-binding context fits u32")
                .to_be_bytes(),
        );
        exporter_context.extend_from_slice(application_context);

        let mut binding = [0u8; CHANNEL_BINDING_BYTES];
        self.inner
            .export_keying_material(
                &mut binding,
                CHANNEL_BINDING_EXPORTER_LABEL,
                &exporter_context,
            )
            .map_err(|_| {
                CarrierError::Transport("QUIC TLS channel-binding derivation failed".into())
            })?;
        Ok(ChannelBinding(binding))
    }

    /// Returns a bounded observation of the selected network path.
    ///
    /// The witness is never an authorization or delivery-success signal.
    pub fn path_witness(&self) -> PathWitness {
        match self.path_witness.lock() {
            Ok(witness) => *witness,
            Err(_) => {
                let mut witness = PathWitness::new(SelectedPath::Unknown);
                witness.lose_continuity();
                witness
            }
        }
    }

    /// Returns the exact protected-frame ceiling enforced for ordered uni turns.
    pub fn max_uni_frame_bytes(&self) -> usize {
        self.max_exchange_bytes.min(DEFAULT_MAX_EXCHANGE_BYTES)
    }

    /// Opens a long-lived data stream while concurrently accepting the reverse
    /// control stream. These streams are independent of the legacy ordered-turn
    /// state and remain open for the whole higher-layer attempt.
    pub async fn open_stream_pair(
        &self,
        deadline: Instant,
        max_data_bytes: usize,
        max_control_bytes: usize,
    ) -> Result<OpenedStreamPair, CarrierError> {
        let send = timeout_at(deadline, self.inner.open_uni())
            .await
            .map_err(|_| CarrierError::Timeout("stream pair open"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        let mut data = BoundedSendStream::new(
            send,
            deadline,
            STREAM_DATA_MAGIC,
            self.max_uni_frame_bytes(),
            max_data_bytes,
        );
        data.ensure_started().await?;
        let receive = timeout_at(deadline, self.inner.accept_uni())
            .await
            .map_err(|_| CarrierError::Timeout("stream pair open"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        Ok(OpenedStreamPair {
            data,
            control: BoundedReceiveStream::new(
                receive,
                deadline,
                STREAM_CONTROL_MAGIC,
                self.max_uni_frame_bytes(),
                max_control_bytes,
            ),
        })
    }

    /// Accepts the long-lived data stream while concurrently opening the
    /// reverse control stream.
    pub async fn accept_stream_pair(
        &self,
        deadline: Instant,
        max_data_bytes: usize,
        max_control_bytes: usize,
    ) -> Result<AcceptedStreamPair, CarrierError> {
        let send = timeout_at(deadline, self.inner.open_uni())
            .await
            .map_err(|_| CarrierError::Timeout("stream pair accept"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        let mut control = BoundedSendStream::new(
            send,
            deadline,
            STREAM_CONTROL_MAGIC,
            self.max_uni_frame_bytes(),
            max_control_bytes,
        );
        control.ensure_started().await?;
        let receive = timeout_at(deadline, self.inner.accept_uni())
            .await
            .map_err(|_| CarrierError::Timeout("stream pair accept"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        Ok(AcceptedStreamPair {
            data: BoundedReceiveStream::new(
                receive,
                deadline,
                STREAM_DATA_MAGIC,
                self.max_uni_frame_bytes(),
                max_data_bytes,
            ),
            control,
        })
    }

    /// Opens the dialer-to-acceptor or acceptor-to-dialer unidirectional turn
    /// required by the current carrier phase.
    ///
    /// `deadline` is absolute and retained by the returned turn. The aggregate
    /// bound includes each four-byte length prefix and protected frame body.
    pub async fn open_send_uni(
        &self,
        deadline: Instant,
        max_turn_bytes: usize,
    ) -> Result<SendUniTurn, CarrierError> {
        let position = {
            let mut state = lock_uni_turn_state(&self.uni_turn_state)?;
            state.begin_send()?
        };
        let stream = match timeout_at(deadline, self.inner.open_uni()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                if let Ok(mut state) = lock_uni_turn_state(&self.uni_turn_state) {
                    state.fail();
                }
                return Err(CarrierError::Transport(error.to_string()));
            }
            Err(_) => {
                if let Ok(mut state) = lock_uni_turn_state(&self.uni_turn_state) {
                    state.fail();
                }
                return Err(CarrierError::Timeout("uni turn open"));
            }
        };
        Ok(SendUniTurn {
            stream,
            deadline,
            max_frame_bytes: self.max_uni_frame_bytes(),
            max_turn_bytes,
            written_bytes: 0,
            state: Arc::clone(&self.uni_turn_state),
            position,
            complete: false,
            started: false,
        })
    }

    /// Accepts the exact unidirectional turn required by the current carrier phase.
    ///
    /// `deadline` is absolute and retained by the returned turn. The aggregate
    /// bound includes each four-byte length prefix and protected frame body.
    pub async fn accept_uni(
        &self,
        deadline: Instant,
        max_turn_bytes: usize,
    ) -> Result<ReceiveUniTurn, CarrierError> {
        let position = {
            let mut state = lock_uni_turn_state(&self.uni_turn_state)?;
            state.begin_receive()?
        };
        let stream = match timeout_at(deadline, self.inner.accept_uni()).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                if let Ok(mut state) = lock_uni_turn_state(&self.uni_turn_state) {
                    state.fail();
                }
                return Err(CarrierError::Transport(error.to_string()));
            }
            Err(_) => {
                if let Ok(mut state) = lock_uni_turn_state(&self.uni_turn_state) {
                    state.fail();
                }
                return Err(CarrierError::Timeout("uni turn accept"));
            }
        };
        let mut turn = ReceiveUniTurn {
            stream,
            deadline,
            max_frame_bytes: self.max_uni_frame_bytes(),
            max_turn_bytes,
            read_bytes: 0,
            state: Arc::clone(&self.uni_turn_state),
            position,
            complete: false,
            eof: false,
        };
        turn.read_preamble().await?;
        Ok(turn)
    }

    /// Advances one role-ordered uni-turn phase that the authenticated higher
    /// layer proved does not require a stream.
    pub fn skip_uni_turn(&self) -> Result<(), CarrierError> {
        lock_uni_turn_state(&self.uni_turn_state)?.skip()
    }

    /// Sends one opaque request and reads one opaque response.
    pub async fn request(&self, request: &[u8]) -> Result<Vec<u8>, CarrierError> {
        self.request_with_total_limit(request, usize::MAX).await
    }

    /// Sends one exchange whose combined request/response bytes cannot exceed
    /// `total_limit`, in addition to the carrier's per-frame bound.
    pub async fn request_with_total_limit(
        &self,
        request: &[u8],
        total_limit: usize,
    ) -> Result<Vec<u8>, CarrierError> {
        self.request_with_total_limit_checked(request, total_limit, || Ok::<_, CarrierError>(()))
            .await
            .map(|(response, ())| response)
    }

    /// Sends one bounded exchange after a synchronous, carrier-adjacent check.
    ///
    /// `before_write` runs after the bidirectional QUIC stream is available and
    /// immediately before the first application byte is written. If it fails,
    /// the stream is dropped without writing `request`. This lets a higher
    /// layer recheck short-lived authority without leaving an unbounded
    /// bidirectional-stream acquisition wait between that check and the
    /// carrier handoff.
    pub async fn request_with_total_limit_checked<F, T, E>(
        &self,
        request: &[u8],
        total_limit: usize,
        before_write: F,
    ) -> Result<(Vec<u8>, T), E>
    where
        F: FnOnce() -> Result<T, E>,
        E: From<CarrierError>,
    {
        let request_maximum = self.max_exchange_bytes.min(total_limit);
        ensure_frame_bound(request.len(), request_maximum).map_err(E::from)?;
        let response_maximum = self
            .max_exchange_bytes
            .min(total_limit.saturating_sub(request.len()));
        let result = timeout(self.exchange_timeout, async {
            let (mut send, mut receive) = self
                .inner
                .open_bi()
                .await
                .map_err(|error| E::from(CarrierError::Transport(error.to_string())))?;
            let checked = checked_write(before_write, || async {
                send.write_all(request)
                    .await
                    .map_err(|error| E::from(CarrierError::Transport(error.to_string())))
            })
            .await?;
            send.finish()
                .map_err(|error| E::from(CarrierError::Transport(error.to_string())))?;
            let response = receive
                .read_to_end(response_maximum)
                .await
                .map_err(|error| E::from(map_read_error(error, response_maximum)))?;
            Ok::<_, E>((response, checked))
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"exchange timeout");
                Err(E::from(CarrierError::Timeout("request/response")))
            }
        }
    }

    /// Accepts one opaque request, computes a synchronous response, and sends it.
    /// The returned boolean is the handler's explicit session-complete signal.
    pub async fn respond_once<F>(&self, handler: F) -> Result<bool, CarrierError>
    where
        F: FnOnce(&[u8]) -> Result<(Vec<u8>, bool), CarrierError>,
    {
        self.respond_once_with_total_limit(usize::MAX, handler)
            .await
    }

    /// Responds once while enforcing a combined request/response byte limit.
    pub async fn respond_once_with_total_limit<F>(
        &self,
        total_limit: usize,
        handler: F,
    ) -> Result<bool, CarrierError>
    where
        F: FnOnce(&[u8]) -> Result<(Vec<u8>, bool), CarrierError>,
    {
        let request_maximum = self.max_exchange_bytes.min(total_limit);
        let result = timeout(self.exchange_timeout, async {
            let (mut send, mut receive) = self
                .inner
                .accept_bi()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            let request = receive
                .read_to_end(request_maximum)
                .await
                .map_err(|error| map_read_error(error, request_maximum))?;
            let (response, complete) = handler(&request)?;
            let response_maximum = self
                .max_exchange_bytes
                .min(total_limit.saturating_sub(request.len()));
            ensure_frame_bound(response.len(), response_maximum)?;
            send.write_all(&response)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            send.finish()
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            match send
                .stopped()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?
            {
                None => {}
                Some(code) => {
                    return Err(CarrierError::Transport(format!(
                        "peer stopped response stream with code {code}"
                    )));
                }
            }
            Ok(complete)
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"exchange timeout");
                Err(CarrierError::Timeout("receive/respond"))
            }
        }
    }

    /// Signals that the initiator consumed the final response, then waits for
    /// the responder to close the completed connection.
    pub async fn finish_as_initiator(&self) -> Result<(), CarrierError> {
        let result = timeout(self.exchange_timeout, async {
            let (mut send, _receive) = self
                .inner
                .open_bi()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            send.write_all(RESPONSE_CONSUMED_MARKER)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            send.finish()
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            match self.inner.closed().await {
                ConnectionError::ApplicationClosed(close)
                    if close.error_code == 0u8.into() && close.reason.as_ref() == b"complete" =>
                {
                    Ok(())
                }
                error => Err(CarrierError::Transport(error.to_string())),
            }
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"completion timeout");
                Err(CarrierError::Timeout("initiator session completion"))
            }
        }
    }

    /// Waits for proof that the initiator consumed the final response, then
    /// closes the completed connection without racing that response's read.
    pub async fn finish_as_responder(&self) -> Result<(), CarrierError> {
        let result = timeout(self.exchange_timeout, async {
            let (_send, mut receive) = self
                .inner
                .accept_bi()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            let marker = receive
                .read_to_end(RESPONSE_CONSUMED_MARKER.len())
                .await
                .map_err(|error| map_read_error(error, RESPONSE_CONSUMED_MARKER.len()))?;
            if marker != RESPONSE_CONSUMED_MARKER {
                return Err(CarrierError::Transport(
                    "invalid session completion marker".into(),
                ));
            }
            self.inner.close(0u8.into(), b"complete");
            Ok(())
        })
        .await;
        match result {
            Ok(result) => result,
            Err(_) => {
                self.inner.close(2u8.into(), b"completion timeout");
                Err(CarrierError::Timeout("responder session completion"))
            }
        }
    }

    /// Closes this connection.
    pub fn close(&self) {
        self.inner.close(0u8.into(), b"complete");
    }
}

impl BoundedSendStream {
    fn new(
        stream: SendStream,
        deadline: Instant,
        magic: &'static [u8; 8],
        max_frame_bytes: usize,
        max_stream_bytes: usize,
    ) -> Self {
        Self {
            stream,
            deadline,
            magic,
            max_frame_bytes,
            max_stream_bytes,
            written_bytes: 0,
            started: false,
            complete: false,
        }
    }

    async fn ensure_started(&mut self) -> Result<(), CarrierError> {
        if self.started {
            return Ok(());
        }
        timeout_at(self.deadline, self.stream.write_all(self.magic))
            .await
            .map_err(|_| CarrierError::Timeout("stream pair send"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        self.started = true;
        Ok(())
    }

    pub async fn write_frame(&mut self, frame: &[u8]) -> Result<(), CarrierError> {
        self.write_frame_parts(frame, &[]).await
    }

    pub async fn write_frame_parts(
        &mut self,
        prefix: &[u8],
        body: &[u8],
    ) -> Result<(), CarrierError> {
        if self.complete {
            return Err(CarrierError::Transport(
                "stream direction is complete".into(),
            ));
        }
        let frame_len =
            prefix
                .len()
                .checked_add(body.len())
                .ok_or(CarrierError::FrameTooLarge {
                    actual: usize::MAX,
                    maximum: self.max_frame_bytes,
                })?;
        ensure_frame_bound(frame_len, self.max_frame_bytes)?;
        let encoded = 4usize
            .checked_add(frame_len)
            .ok_or(CarrierError::TurnTooLarge {
                actual: usize::MAX,
                maximum: self.max_stream_bytes,
            })?;
        let next = self
            .written_bytes
            .checked_add(encoded)
            .ok_or(CarrierError::TurnTooLarge {
                actual: usize::MAX,
                maximum: self.max_stream_bytes,
            })?;
        if next > self.max_stream_bytes {
            return Err(CarrierError::TurnTooLarge {
                actual: next,
                maximum: self.max_stream_bytes,
            });
        }
        self.ensure_started().await?;
        let length = u32::try_from(frame_len).map_err(|_| CarrierError::FrameTooLarge {
            actual: frame_len,
            maximum: u32::MAX as usize,
        })?;
        timeout_at(self.deadline, async {
            self.stream.write_all(&length.to_be_bytes()).await?;
            self.stream.write_all(prefix).await?;
            self.stream.write_all(body).await
        })
        .await
        .map_err(|_| CarrierError::Timeout("stream pair send"))?
        .map_err(|error| CarrierError::Transport(error.to_string()))?;
        self.written_bytes = next;
        Ok(())
    }

    pub async fn finish(&mut self) -> Result<(), CarrierError> {
        if self.complete {
            return Err(CarrierError::Transport(
                "stream direction is complete".into(),
            ));
        }
        self.ensure_started().await?;
        self.stream
            .finish()
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        match timeout_at(self.deadline, self.stream.stopped())
            .await
            .map_err(|_| CarrierError::Timeout("stream pair finish"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))?
        {
            None => {
                self.complete = true;
                Ok(())
            }
            Some(code) => Err(CarrierError::Transport(format!(
                "peer reset stream direction with code {code}"
            ))),
        }
    }

    pub fn reset(&mut self) -> Result<(), CarrierError> {
        self.stream
            .reset(2u8.into())
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        self.complete = true;
        Ok(())
    }
}

impl Drop for BoundedSendStream {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.stream.reset(2u8.into());
        }
    }
}

impl BoundedReceiveStream {
    fn new(
        stream: RecvStream,
        deadline: Instant,
        magic: &'static [u8; 8],
        max_frame_bytes: usize,
        max_stream_bytes: usize,
    ) -> Self {
        Self {
            stream,
            deadline,
            magic,
            max_frame_bytes,
            max_stream_bytes,
            read_bytes: 0,
            started: false,
            complete: false,
            eof: false,
        }
    }

    async fn read_some(&mut self, output: &mut [u8]) -> Result<Option<usize>, CarrierError> {
        timeout_at(self.deadline, self.stream.read(output))
            .await
            .map_err(|_| CarrierError::Timeout("stream pair receive"))?
            .map_err(|error| CarrierError::Transport(error.to_string()))
    }

    async fn ensure_started(&mut self) -> Result<(), CarrierError> {
        if self.started {
            return Ok(());
        }
        let mut observed = [0u8; 8];
        let mut offset = 0;
        while offset < observed.len() {
            let Some(read) = self.read_some(&mut observed[offset..]).await? else {
                return Err(CarrierError::Transport(
                    "truncated stream-pair preamble".into(),
                ));
            };
            offset += read;
        }
        if &observed != self.magic {
            return Err(CarrierError::Transport("stream-pair role mismatch".into()));
        }
        self.started = true;
        Ok(())
    }

    pub async fn read_frame(&mut self) -> Result<Option<Vec<u8>>, CarrierError> {
        if self.eof {
            return Ok(None);
        }
        if self.complete {
            return Err(CarrierError::Transport("stream direction failed".into()));
        }
        self.ensure_started().await?;
        let mut length = [0u8; 4];
        let mut offset = 0;
        while offset < length.len() {
            match self.read_some(&mut length[offset..]).await? {
                None if offset == 0 => {
                    self.eof = true;
                    self.complete = true;
                    return Ok(None);
                }
                None => {
                    return Err(CarrierError::Transport(
                        "truncated stream frame length".into(),
                    ));
                }
                Some(read) => offset += read,
            }
        }
        let frame_len = decode_uni_frame_length(length, self.max_frame_bytes)?;
        let encoded = 4usize
            .checked_add(frame_len)
            .ok_or(CarrierError::TurnTooLarge {
                actual: usize::MAX,
                maximum: self.max_stream_bytes,
            })?;
        let next = self
            .read_bytes
            .checked_add(encoded)
            .ok_or(CarrierError::TurnTooLarge {
                actual: usize::MAX,
                maximum: self.max_stream_bytes,
            })?;
        if next > self.max_stream_bytes {
            return Err(CarrierError::TurnTooLarge {
                actual: next,
                maximum: self.max_stream_bytes,
            });
        }
        let mut frame = vec![0u8; frame_len];
        let mut offset = 0;
        while offset < frame.len() {
            let Some(read) = self.read_some(&mut frame[offset..]).await? else {
                return Err(CarrierError::Transport(
                    "truncated stream frame body".into(),
                ));
            };
            offset += read;
        }
        self.read_bytes = next;
        Ok(Some(frame))
    }

    pub fn stop(&mut self) -> Result<(), CarrierError> {
        self.stream
            .stop(2u8.into())
            .map_err(|error| CarrierError::Transport(error.to_string()))?;
        self.complete = true;
        Ok(())
    }
}

impl Drop for BoundedReceiveStream {
    fn drop(&mut self) {
        if !self.complete {
            let _ = self.stream.stop(2u8.into());
        }
    }
}

impl SendUniTurn {
    /// Writes one nonempty length-delimited protected frame after a synchronous
    /// caller check. The metadata-free turn preamble is started first; a rejected
    /// check writes no frame-length prefix or frame body.
    pub async fn write_frame_checked<F, T, E>(
        &mut self,
        frame: &[u8],
        before_write: F,
    ) -> Result<T, E>
    where
        F: FnOnce() -> Result<T, E>,
        E: From<CarrierError>,
    {
        if self.complete {
            return Err(E::from(CarrierError::Transport(
                "unidirectional send turn is already complete".into(),
            )));
        }
        if frame.is_empty() {
            return Err(E::from(CarrierError::Transport(
                "unidirectional frame must be nonempty".into(),
            )));
        }
        ensure_frame_bound(frame.len(), self.max_frame_bytes).map_err(E::from)?;
        let encoded_bytes = std::mem::size_of::<u32>()
            .checked_add(frame.len())
            .ok_or_else(|| {
                E::from(CarrierError::TurnTooLarge {
                    actual: usize::MAX,
                    maximum: self.max_turn_bytes,
                })
            })?;
        let next_total = self
            .written_bytes
            .checked_add(encoded_bytes)
            .ok_or_else(|| {
                E::from(CarrierError::TurnTooLarge {
                    actual: usize::MAX,
                    maximum: self.max_turn_bytes,
                })
            })?;
        if next_total > self.max_turn_bytes {
            return Err(E::from(CarrierError::TurnTooLarge {
                actual: next_total,
                maximum: self.max_turn_bytes,
            }));
        }
        self.ensure_started().await.map_err(E::from)?;
        let checked = before_write()?;
        let length = u32::try_from(frame.len())
            .map_err(|_| {
                E::from(CarrierError::FrameTooLarge {
                    actual: frame.len(),
                    maximum: u32::MAX as usize,
                })
            })?
            .to_be_bytes();
        let written = timeout_at(self.deadline, async {
            self.stream
                .write_all(&length)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            self.stream
                .write_all(frame)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))
        })
        .await;
        match written {
            Ok(Ok(())) => {
                self.written_bytes = next_total;
                Ok(checked)
            }
            Ok(Err(error)) => {
                self.abort();
                Err(E::from(error))
            }
            Err(_) => {
                self.abort();
                Err(E::from(CarrierError::Timeout("uni turn send")))
            }
        }
    }

    async fn ensure_started(&mut self) -> Result<(), CarrierError> {
        if self.started {
            return Ok(());
        }
        let written = timeout_at(self.deadline, self.stream.write_all(UNI_TURN_MAGIC)).await;
        match written {
            Ok(Ok(())) => {
                self.started = true;
                Ok(())
            }
            Ok(Err(error)) => {
                let error = CarrierError::Transport(error.to_string());
                self.abort();
                Err(error)
            }
            Err(_) => {
                self.abort();
                Err(CarrierError::Timeout("uni turn send"))
            }
        }
    }

    /// Finishes this transport stream without waiting for a peer receipt.
    pub async fn finish(&mut self) -> Result<(), CarrierError> {
        if self.complete {
            return Err(CarrierError::Transport(
                "unidirectional send turn is already complete".into(),
            ));
        }
        self.ensure_started().await?;
        if Instant::now() >= self.deadline {
            self.abort();
            return Err(CarrierError::Timeout("uni turn finish"));
        }
        if let Err(error) = self.stream.finish() {
            self.abort();
            return Err(CarrierError::Transport(error.to_string()));
        }
        let result = lock_uni_turn_state(&self.state)?.finish_send(self.position);
        self.complete = true;
        result
    }

    fn abort(&mut self) {
        let _ = self.stream.reset(2u8.into());
        if let Ok(mut state) = lock_uni_turn_state(&self.state) {
            state.fail();
        }
        self.complete = true;
    }
}

impl Drop for SendUniTurn {
    fn drop(&mut self) {
        if !self.complete {
            self.abort();
        }
    }
}

impl ReceiveUniTurn {
    async fn read_preamble(&mut self) -> Result<(), CarrierError> {
        let mut magic = [0u8; UNI_TURN_MAGIC.len()];
        let mut read = 0usize;
        while read < magic.len() {
            match self.read_some(&mut magic[read..]).await? {
                Some(count) => read += count,
                None => {
                    return Err(self.fail_with(CarrierError::Transport(
                        "truncated unidirectional turn preamble".into(),
                    )));
                }
            }
        }
        validate_uni_turn_magic(&magic).map_err(|error| self.fail_with(error))
    }

    /// Reads the next complete protected frame, or `None` only after exact EOF.
    pub async fn read_frame(&mut self) -> Result<Option<Vec<u8>>, CarrierError> {
        if self.eof {
            return Ok(None);
        }
        if self.complete {
            return Err(CarrierError::Transport(
                "unidirectional receive turn failed before EOF".into(),
            ));
        }

        let mut length = [0u8; std::mem::size_of::<u32>()];
        let mut length_read = 0usize;
        while length_read < length.len() {
            match self.read_some(&mut length[length_read..]).await? {
                None if length_read == 0 => {
                    let result = lock_uni_turn_state(&self.state)?.finish_receive(self.position);
                    self.complete = true;
                    self.eof = true;
                    result?;
                    return Ok(None);
                }
                None => {
                    return Err(self
                        .fail_with(CarrierError::Transport("truncated uni frame length".into())));
                }
                Some(read) => length_read += read,
            }
        }

        let frame_len = decode_uni_frame_length(length, self.max_frame_bytes)
            .map_err(|error| self.fail_with(error))?;
        let encoded_bytes = std::mem::size_of::<u32>()
            .checked_add(frame_len)
            .ok_or_else(|| {
                self.fail_with(CarrierError::TurnTooLarge {
                    actual: usize::MAX,
                    maximum: self.max_turn_bytes,
                })
            })?;
        let next_total = self.read_bytes.checked_add(encoded_bytes).ok_or_else(|| {
            self.fail_with(CarrierError::TurnTooLarge {
                actual: usize::MAX,
                maximum: self.max_turn_bytes,
            })
        })?;
        if next_total > self.max_turn_bytes {
            return Err(self.fail_with(CarrierError::TurnTooLarge {
                actual: next_total,
                maximum: self.max_turn_bytes,
            }));
        }

        let mut frame = vec![0u8; frame_len];
        let mut frame_read = 0usize;
        while frame_read < frame.len() {
            match self.read_some(&mut frame[frame_read..]).await? {
                Some(read) => frame_read += read,
                None => {
                    return Err(
                        self.fail_with(CarrierError::Transport("truncated uni frame body".into()))
                    );
                }
            }
        }
        self.read_bytes = next_total;
        Ok(Some(frame))
    }

    async fn read_some(&mut self, output: &mut [u8]) -> Result<Option<usize>, CarrierError> {
        let read = timeout_at(self.deadline, self.stream.read(output)).await;
        match read {
            Ok(Ok(read)) => Ok(read),
            Ok(Err(error)) => Err(self.fail_with(CarrierError::Transport(error.to_string()))),
            Err(_) => Err(self.fail_with(CarrierError::Timeout("uni turn receive"))),
        }
    }

    fn fail_with(&mut self, error: CarrierError) -> CarrierError {
        self.abort();
        error
    }

    fn abort(&mut self) {
        let _ = self.stream.stop(2u8.into());
        if let Ok(mut state) = lock_uni_turn_state(&self.state) {
            state.fail();
        }
        self.complete = true;
    }
}

impl Drop for ReceiveUniTurn {
    fn drop(&mut self) {
        if !self.complete {
            self.abort();
        }
    }
}

fn selected_path(address: &TransportAddr) -> SelectedPath {
    if address.is_ip() {
        SelectedPath::Direct
    } else if address.is_relay() {
        SelectedPath::Relay
    } else {
        SelectedPath::Unknown
    }
}

fn selected_path_snapshot(connection: &iroh::endpoint::Connection) -> SelectedPath {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map_or(SelectedPath::Unknown, |path| {
            selected_path(path.remote_addr())
        })
}

fn validate_uni_turn_magic(magic: &[u8; UNI_TURN_MAGIC.len()]) -> Result<(), CarrierError> {
    if magic == UNI_TURN_MAGIC {
        Ok(())
    } else {
        Err(CarrierError::Transport(
            "invalid unidirectional turn preamble".into(),
        ))
    }
}

fn decode_uni_frame_length(
    encoded: [u8; std::mem::size_of::<u32>()],
    maximum: usize,
) -> Result<usize, CarrierError> {
    let actual = usize::try_from(u32::from_be_bytes(encoded))
        .map_err(|_| CarrierError::Transport("uni frame length overflows".into()))?;
    if actual == 0 {
        return Err(CarrierError::Transport(
            "unidirectional frame must be nonempty".into(),
        ));
    }
    ensure_frame_bound(actual, maximum)?;
    Ok(actual)
}

/// Exercises the production uni-turn preamble, length, frame, and aggregate
/// bounds for hostile-input fuzzing without opening a network connection.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_decode_uni_turn(input: &[u8], max_frame_bytes: usize, max_turn_bytes: usize) -> bool {
    let Some(magic) = input.get(..UNI_TURN_MAGIC.len()) else {
        return false;
    };
    let Ok(magic) = <&[u8; UNI_TURN_MAGIC.len()]>::try_from(magic) else {
        return false;
    };
    if validate_uni_turn_magic(magic).is_err() {
        return false;
    }
    let mut offset = UNI_TURN_MAGIC.len();
    let mut total = 0usize;
    while offset < input.len() {
        let Some(encoded) = input.get(offset..offset + std::mem::size_of::<u32>()) else {
            return false;
        };
        let encoded = <[u8; std::mem::size_of::<u32>()]>::try_from(encoded)
            .expect("length slice has the exact fixed width");
        let Ok(frame_len) = decode_uni_frame_length(encoded, max_frame_bytes) else {
            return false;
        };
        let Some(encoded_bytes) = std::mem::size_of::<u32>().checked_add(frame_len) else {
            return false;
        };
        let Some(next_total) = total.checked_add(encoded_bytes) else {
            return false;
        };
        if next_total > max_turn_bytes {
            return false;
        }
        offset += std::mem::size_of::<u32>();
        let Some(next_offset) = offset.checked_add(frame_len) else {
            return false;
        };
        if next_offset > input.len() {
            return false;
        }
        offset = next_offset;
        total = next_total;
    }
    true
}

fn ensure_frame_bound(actual: usize, maximum: usize) -> Result<(), CarrierError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(CarrierError::FrameTooLarge { actual, maximum })
    }
}

fn map_read_error(error: ReadToEndError, maximum: usize) -> CarrierError {
    match error {
        ReadToEndError::TooLong => CarrierError::FrameTooLarge {
            actual: maximum.saturating_add(1),
            maximum,
        },
        error => CarrierError::Transport(error.to_string()),
    }
}

/// Local, TLS-verifying relay support for integration tests.
#[cfg(feature = "test-utils")]
pub mod test_utils {
    use std::net::Ipv4Addr;

    use iroh_relay::server::{
        CertConfig, RelayConfig as RelayServerConfig, Server, ServerConfig, TlsConfig,
        testing::self_signed_tls_certs_and_config,
    };

    use super::{CarrierError, PinnedRelay, RelayUrl};

    /// A self-hosted relay whose self-signed root is exported for exact trust.
    #[derive(Debug)]
    pub struct RelayFixture {
        server: Option<Server>,
        relay: PinnedRelay,
    }

    impl RelayFixture {
        /// Starts an HTTPS relay on an operating-system-assigned loopback port.
        pub async fn spawn() -> Result<Self, CarrierError> {
            let (certificates, server_tls) = self_signed_tls_certs_and_config();
            let tls = TlsConfig::new(
                (Ipv4Addr::LOCALHOST, 0),
                CertConfig::Manual {
                    server_config: server_tls,
                },
            );
            let mut relay_config = RelayServerConfig::new((Ipv4Addr::LOCALHOST, 0));
            relay_config.tls = Some(tls);
            relay_config.key_cache_capacity = Some(1_024);
            let mut server_config = ServerConfig::default();
            server_config.relay = Some(relay_config);
            server_config.quic = None;
            let server = Server::spawn(server_config)
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))?;
            let address = server.https_addr().ok_or_else(|| {
                CarrierError::Transport("test relay did not bind an HTTPS socket".into())
            })?;
            let relay_url: RelayUrl = format!("https://127.0.0.1:{}/", address.port())
                .parse()
                .map_err(|error| {
                    CarrierError::Configuration(format!("invalid test relay URL: {error}"))
                })?;
            let relay = PinnedRelay::with_ca_roots(
                relay_url,
                certificates
                    .into_iter()
                    .map(|certificate| certificate.as_ref().to_vec()),
            )?;
            Ok(Self {
                server: Some(server),
                relay,
            })
        }

        /// Returns a clone of the endpoint-side relay pin and trust boundary.
        pub fn pinned_relay(&self) -> PinnedRelay {
            self.relay.clone()
        }

        /// Returns the relay URL for constructing exact peer routes.
        pub fn relay_url(&self) -> &RelayUrl {
            self.relay.url()
        }

        /// Returns the fixture's DER trust root for subprocess test setup.
        pub fn ca_roots_der(&self) -> &[Vec<u8>] {
            self.relay.ca_roots_der()
        }

        /// Stops the relay and waits for its tasks to exit.
        pub async fn shutdown(mut self) -> Result<(), CarrierError> {
            let server = self
                .server
                .take()
                .ok_or_else(|| CarrierError::Transport("test relay was already stopped".into()))?;
            server
                .shutdown()
                .await
                .map_err(|error| CarrierError::Transport(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "test-utils")]
    use super::test_utils::RelayFixture;

    fn loopback(endpoint: &Endpoint) -> SocketAddr {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("IPv4 loopback binding")
    }

    async fn connect_pair(server: &Endpoint, client: &Endpoint) -> (Connection, Connection) {
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.accept(&allowed).await.expect("accept") }
        });
        let client_connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(server),
            })
            .await
            .expect("connect");
        let server_connection = server_task.await.expect("server task");
        (server_connection, client_connection)
    }

    async fn direct_connection_pair() -> (Endpoint, Endpoint, Connection, Connection) {
        direct_connection_pair_with_config(EndpointConfig::direct(
            "127.0.0.1:0".parse().expect("address"),
        ))
        .await
    }

    async fn direct_connection_pair_with_config(
        config: EndpointConfig,
    ) -> (Endpoint, Endpoint, Connection, Connection) {
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("client");
        let (server_connection, client_connection) = connect_pair(&server, &client).await;
        (server, client, server_connection, client_connection)
    }

    fn uni_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_secs(2)
    }

    #[cfg(feature = "test-utils")]
    fn relay_test_config() -> EndpointConfig {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(4);
        config.exchange_timeout = Duration::from_secs(2);
        config
    }

    async fn wait_for_path(connection: &Connection, expected: SelectedPath) -> PathWitness {
        timeout(Duration::from_secs(4), async {
            loop {
                let witness = connection.path_witness();
                if witness.selected == expected {
                    return witness;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("selected path observation deadline")
    }

    #[cfg(feature = "test-utils")]
    fn large_valid_ca_root() -> Vec<u8> {
        let mut parameters = rcgen::CertificateParams::new(vec!["large-root.invalid".to_owned()])
            .expect("certificate parameters");
        parameters
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 55_555, 1],
                vec![0x5a; 48 * 1024],
            ));
        let key = rcgen::KeyPair::generate().expect("certificate key");
        parameters
            .self_signed(&key)
            .expect("self-signed certificate")
            .der()
            .to_vec()
    }

    #[cfg(feature = "test-utils")]
    fn unrelated_valid_ca_root() -> Vec<u8> {
        let mut parameters =
            rcgen::CertificateParams::new(vec!["unrelated-root.invalid".to_owned()])
                .expect("certificate parameters");
        parameters.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().expect("certificate key");
        parameters
            .self_signed(&key)
            .expect("self-signed CA certificate")
            .der()
            .to_vec()
    }

    #[tokio::test]
    async fn exact_peer_identity_exchanges_opaque_bytes() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("server");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("client");
        assert_eq!(
            server.security_profile(),
            CarrierSecurityProfile::HybridAsterRecordV1
        );
        assert_eq!(
            client.security_profile(),
            CarrierSecurityProfile::HybridAsterRecordV1
        );
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                assert!(
                    connection
                        .respond_once(|request| Ok((request.to_vec(), true)))
                        .await
                        .expect("respond")
                );
                let before_close = wait_for_path(&connection, SelectedPath::Direct).await;
                connection
                    .finish_as_responder()
                    .await
                    .expect("finish responder");
                tokio::time::sleep(Duration::from_millis(20)).await;
                (before_close, connection.path_witness())
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect");
        assert_eq!(connection.inner.alpn(), ALPN);
        assert_eq!(
            connection.security_profile(),
            CarrierSecurityProfile::HybridAsterRecordV1
        );
        assert_eq!(connection.request(b"ping").await.expect("request"), b"ping");
        wait_for_path(&connection, SelectedPath::Direct).await;
        connection
            .finish_as_initiator()
            .await
            .expect("finish initiator");
        let (before_close, after_close) = server_task.await.expect("server task");
        assert_eq!(before_close.selected, SelectedPath::Direct);
        assert_eq!(after_close.selected, SelectedPath::Direct);
        assert!(!after_close.transitions_saturated);
        client.close().await;
        server.close().await;
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn discovered_connect_uses_an_injected_lookup_without_a_socket_argument() {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(2);
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("client");

        let lookup = iroh::address_lookup::MemoryLookup::new();
        lookup.add_endpoint_info(EndpointAddr::new(server.id()).with_ip_addr(loopback(&server)));
        let services = client.inner.address_lookup().expect("lookup registry");
        assert!(services.is_empty(), "selected endpoints start lookup-free");
        services.add(lookup);

        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                assert!(
                    connection
                        .respond_once(|request| Ok((request.to_vec(), true)))
                        .await
                        .expect("respond")
                );
                connection
                    .finish_as_responder()
                    .await
                    .expect("finish responder");
            }
        });

        let connection = client
            .connect_discovered(server.id())
            .await
            .expect("connect by provisioned endpoint identity");
        assert_eq!(
            connection.request(b"lookup").await.expect("request"),
            b"lookup"
        );
        connection
            .finish_as_initiator()
            .await
            .expect("finish initiator");
        server_task.await.expect("server task");

        services.clear();
        client.close().await;
        server.close().await;
    }

    #[test]
    fn carrier_security_profile_alpns_are_exact_and_distinct() {
        assert_eq!(
            CarrierSecurityProfile::default(),
            CarrierSecurityProfile::HybridAsterRecordV1
        );
        assert_eq!(CarrierSecurityProfile::default().alpn(), ALPN);
        assert_eq!(CarrierSecurityProfile::IrohQuicV1.alpn(), IROH_QUIC_ALPN);
        assert_ne!(ALPN, IROH_QUIC_ALPN);
    }

    #[test]
    fn keepalives_are_limited_to_the_iroh_quic_security_profile() {
        assert_eq!(
            connection_keepalive_interval(CarrierSecurityProfile::HybridAsterRecordV1),
            None
        );
        assert_eq!(
            connection_keepalive_interval(CarrierSecurityProfile::IrohQuicV1),
            Some(CONNECTION_KEEPALIVE_INTERVAL)
        );
    }

    #[test]
    fn channel_binding_context_is_bounded_and_debug_values_are_redacted() {
        assert!(matches!(
            ChannelBindingContext::new(&[]),
            Err(CarrierError::Configuration(_))
        ));
        assert!(matches!(
            ChannelBindingContext::new(&vec![0; MAX_CHANNEL_BINDING_CONTEXT_BYTES + 1]),
            Err(CarrierError::Configuration(_))
        ));
        let context = ChannelBindingContext::new(b"context-secret-marker").expect("context");
        assert_eq!(
            format!("{context:?}"),
            "ChannelBindingContext { bytes: 21 }"
        );
        let binding = ChannelBinding([0x5a; CHANNEL_BINDING_BYTES]);
        assert_eq!(format!("{binding:?}"), "ChannelBinding([REDACTED])");
    }

    #[cfg(feature = "nearby-discovery")]
    #[test]
    fn nearby_endpoint_id_labels_are_dns_safe_reversible_and_strict() {
        for seed in [0u8, 1, 0x5a, 0xff] {
            let endpoint_id = SecretKey::from_bytes(&[seed; 32]).public();
            let label = encode_nearby_endpoint_id_label(endpoint_id);
            assert_eq!(label.len(), NEARBY_ENDPOINT_ID_LABEL_BYTES);
            assert!(
                label.len() <= 63,
                "DNS-SD instance label must fit one label"
            );
            assert!(
                label
                    .bytes()
                    .all(|byte| NEARBY_ENDPOINT_ID_BASE32_ALPHABET.contains(&byte))
            );
            assert_eq!(decode_nearby_endpoint_id_label(&label), Some(endpoint_id));
            assert_eq!(
                EndpointId::from_str(&label).expect("official Iroh base32 parser"),
                endpoint_id
            );
            assert!(
                decode_nearby_endpoint_id_label(&endpoint_id.to_string()).is_none(),
                "the 64-byte display form must never re-enter a DNS label"
            );
        }

        let valid = encode_nearby_endpoint_id_label(SecretKey::generate().public());
        let mut invalid_symbol = valid.clone().into_bytes();
        invalid_symbol[0] = b'0';
        let invalid_symbol = String::from_utf8(invalid_symbol).expect("ASCII test label");
        let uppercase = valid.to_ascii_uppercase();
        let too_long = format!("{valid}a");
        for malformed in [
            &valid[..valid.len() - 1],
            "a",
            too_long.as_str(),
            invalid_symbol.as_str(),
            uppercase.as_str(),
        ] {
            assert!(
                decode_nearby_endpoint_id_label(malformed).is_none(),
                "accepted malformed discovery label {malformed}"
            );
        }
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn multi_interface_provider_constructs_with_dns_safe_endpoint_label() {
        let endpoint_id = SecretKey::generate().public();
        assert_eq!(endpoint_id.to_string().len(), 64, "regression precondition");
        let lookup = MultiInterfaceNearbyAddressLookup::new(
            endpoint_id,
            vec![Ipv4Addr::LOCALHOST],
            &tokio::runtime::Handle::current(),
        )
        .expect("52-byte discovery label must construct the provider");
        drop(lookup);
    }

    #[cfg(feature = "nearby-discovery")]
    #[test]
    fn nearby_ipv4_interfaces_are_normalized_and_fail_closed() {
        assert_eq!(
            normalize_nearby_ipv4_interfaces(vec![
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
            ])
            .expect("concrete interfaces"),
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert!(normalize_nearby_ipv4_interfaces(Vec::new()).is_ok());
        for invalid in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(
                normalize_nearby_ipv4_interfaces(vec![invalid]).is_err(),
                "accepted invalid interface {invalid}"
            );
        }
        let too_many = (1..=MAX_NEARBY_DISCOVERY_IPV4_INTERFACES + 1)
            .map(|last| Ipv4Addr::new(10, 0, 0, u8::try_from(last).expect("test range")))
            .collect();
        assert!(normalize_nearby_ipv4_interfaces(too_many).is_err());
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn multi_interface_peer_cache_is_ip_only_bounded_and_expires() {
        let local = SecretKey::generate().public();
        let remote = SecretKey::generate().public();
        let memory = MemoryLookup::with_provenance(MULTI_INTERFACE_NEARBY_PROVENANCE);
        let cache = MultiInterfaceNearbyPeerCache::new(local, memory.clone());
        let mut events = cache.subscribe();
        let addresses = (1..=MAX_MULTI_INTERFACE_NEARBY_ADDRS_PER_PEER + 8)
            .map(|suffix| {
                SocketAddr::from((
                    [10, 1, 0, u8::try_from(suffix).expect("test address suffix")],
                    12_345,
                ))
            })
            .collect();

        let remote_label = encode_nearby_endpoint_id_label(remote);
        cache.apply(&remote_label, Some(addresses));
        assert_eq!(
            events.recv().await,
            Some(NearbyDiscoveryEvent::Discovered {
                endpoint_id: remote
            })
        );
        let retained = memory
            .get_endpoint_info(remote)
            .expect("discovered endpoint retained");
        assert_eq!(
            retained.data.ip_addrs().count(),
            MAX_MULTI_INTERFACE_NEARBY_ADDRS_PER_PEER
        );
        assert!(retained.data.user_data().is_none());
        assert_eq!(retained.data.relay_urls().count(), 0);

        cache.apply(&remote_label, None);
        assert_eq!(
            events.recv().await,
            Some(NearbyDiscoveryEvent::Expired {
                endpoint_id: remote
            })
        );
        assert!(memory.get_endpoint_info(remote).is_none());
        assert_eq!(cache.retained_len(), 0);
    }

    #[cfg(feature = "nearby-discovery")]
    #[test]
    fn multi_interface_peer_cache_caps_retained_endpoint_identities() {
        let local = SecretKey::generate().public();
        let memory = MemoryLookup::with_provenance(MULTI_INTERFACE_NEARBY_PROVENANCE);
        let cache = MultiInterfaceNearbyPeerCache::new(local, memory.clone());
        let address = BTreeSet::from([SocketAddr::from(([10, 2, 0, 1], 12_345))]);
        for _ in 0..MAX_MULTI_INTERFACE_NEARBY_PEERS {
            let endpoint_id = SecretKey::generate().public();
            cache.apply(
                &encode_nearby_endpoint_id_label(endpoint_id),
                Some(address.clone()),
            );
        }
        assert_eq!(cache.retained_len(), MAX_MULTI_INTERFACE_NEARBY_PEERS);

        let rejected = SecretKey::generate().public();
        cache.apply(&encode_nearby_endpoint_id_label(rejected), Some(address));
        assert_eq!(cache.retained_len(), MAX_MULTI_INTERFACE_NEARBY_PEERS);
        assert!(memory.get_endpoint_info(rejected).is_none());
        cache.apply(&"x".repeat(NEARBY_ENDPOINT_ID_LABEL_BYTES + 1), None);
        assert_eq!(cache.retained_len(), MAX_MULTI_INTERFACE_NEARBY_PEERS);
    }

    #[tokio::test]
    async fn matching_peers_derive_the_same_exact_quic_channel_binding() {
        let config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("server");
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("client");
        assert_eq!(
            server.security_profile(),
            CarrierSecurityProfile::IrohQuicV1
        );
        assert_eq!(
            client.security_profile(),
            CarrierSecurityProfile::IrohQuicV1
        );

        let (server_connection, client_connection) = connect_pair(&server, &client).await;
        assert_eq!(server_connection.local_id(), server.id());
        assert_eq!(server_connection.remote_id(), client.id());
        assert_eq!(client_connection.local_id(), client.id());
        assert_eq!(client_connection.remote_id(), server.id());
        assert_eq!(server_connection.inner.alpn(), IROH_QUIC_ALPN);
        assert_eq!(client_connection.inner.alpn(), IROH_QUIC_ALPN);
        assert_eq!(
            server_connection.security_profile(),
            CarrierSecurityProfile::IrohQuicV1
        );
        assert_eq!(
            client_connection.security_profile(),
            CarrierSecurityProfile::IrohQuicV1
        );

        let context = ChannelBindingContext::new(b"canonical-mission-contact-context")
            .expect("binding context");
        let server_binding = server_connection
            .channel_binding(context)
            .expect("server binding");
        let client_binding = client_connection
            .channel_binding(context)
            .expect("client binding");
        assert_eq!(server_binding, client_binding);
        assert_ne!(server_binding.as_bytes(), &[0u8; CHANNEL_BINDING_BYTES]);

        server_connection.close();
        client_connection.close();
        client.close().await;
        server.close().await;
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn nearby_discovery_refuses_to_stack_with_an_existing_lookup() {
        let endpoint = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("endpoint");
        let services = endpoint.inner.address_lookup().expect("lookup registry");
        services.add(iroh::address_lookup::MemoryLookup::new());

        let error = match endpoint.start_nearby_discovery(MIN_NEARBY_DISCOVERY_WINDOW) {
            Ok(_) => panic!("stacked lookup must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CarrierError::Configuration(message)
                if message.contains("otherwise empty address-lookup registry")
        ));

        services.clear();
        endpoint
            .start_nearby_discovery(MIN_NEARBY_DISCOVERY_WINDOW)
            .expect("failed start rolls endpoint singleton reservation back")
            .stop();
        endpoint.close().await;
    }

    #[cfg(feature = "nearby-discovery")]
    #[test]
    fn nearby_discovery_requires_an_entered_tokio_runtime() {
        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let endpoint = runtime
            .block_on(Endpoint::bind(
                SecretKey::generate(),
                EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
            ))
            .expect("endpoint");

        let error = match endpoint.start_nearby_discovery(MIN_NEARBY_DISCOVERY_WINDOW) {
            Ok(_) => panic!("nearby discovery outside an entered runtime must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CarrierError::Configuration(message)
                if message.contains("active Tokio runtime")
        ));

        runtime.block_on(endpoint.close());
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn nearby_discovery_window_requires_bounded_whole_seconds() {
        let endpoint = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("endpoint");

        for invalid in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(1_500),
            MAX_NEARBY_DISCOVERY_WINDOW + Duration::from_nanos(1),
        ] {
            let error = match endpoint.start_nearby_discovery(invalid) {
                Ok(_) => panic!("invalid nearby window must fail: {invalid:?}"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                CarrierError::Configuration(message)
                    if message.contains("whole number of seconds")
            ));
        }
        assert!(
            !endpoint.nearby_discovery_occupied.load(Ordering::Acquire),
            "invalid windows cannot reserve endpoint singleton ownership"
        );

        endpoint.close().await;
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn nearby_browser_reuses_bounded_window_validation() {
        let endpoint = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("endpoint");

        for invalid in [
            Duration::ZERO,
            Duration::from_millis(1_500),
            MAX_NEARBY_DISCOVERY_WINDOW + Duration::from_secs(1),
        ] {
            let error = match endpoint.start_nearby_browser(invalid).await {
                Ok(_) => panic!("invalid nearby browser window must fail: {invalid:?}"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                CarrierError::Configuration(message)
                    if message.contains("whole number of seconds")
            ));
        }
        assert!(
            !endpoint.nearby_discovery_occupied.load(Ordering::Acquire),
            "invalid browser windows cannot reserve endpoint singleton ownership"
        );

        endpoint.close().await;
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn nearby_browser_shares_exclusivity_and_stops_without_multicast_events() {
        let endpoint = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("endpoint");
        let services = endpoint.inner.address_lookup().expect("lookup registry");
        let mut browser = endpoint
            .start_nearby_browser(MAX_NEARBY_DISCOVERY_WINDOW)
            .await
            .expect("browser");
        let browser_stop = browser.stop_handle();
        assert!(browser_stop.is_active());
        assert_eq!(services.len(), 1);

        let error = match endpoint.start_nearby_discovery(MIN_NEARBY_DISCOVERY_WINDOW) {
            Ok(_) => panic!("browser and rostered lookup must not stack"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CarrierError::Configuration(message)
                if message.contains("only one nearby-discovery session")
        ));

        browser_stop.stop();
        assert!(!browser_stop.is_active());
        assert!(services.is_empty());
        timeout(Duration::from_secs(1), async {
            while browser.next_event().await.is_some() {}
        })
        .await
        .expect("stopped browser event stream closes");

        let later = endpoint
            .start_nearby_discovery(MAX_NEARBY_DISCOVERY_WINDOW)
            .expect("stop releases endpoint singleton ownership");
        let later_stop = later.stop_handle();
        drop(browser);
        assert!(
            later_stop.is_active(),
            "dropping an old browser cannot stop a later lookup generation"
        );
        later.stop();
        endpoint.close().await;
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn concurrent_nearby_starts_install_exactly_one_provider() {
        let endpoint = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("endpoint");
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let first = tokio::spawn({
            let endpoint = endpoint.clone();
            let barrier = barrier.clone();
            async move {
                barrier.wait().await;
                endpoint.start_nearby_discovery(MAX_NEARBY_DISCOVERY_WINDOW)
            }
        });
        let second = tokio::spawn({
            let endpoint = endpoint.clone();
            let barrier = barrier.clone();
            async move {
                barrier.wait().await;
                endpoint.start_nearby_discovery(MAX_NEARBY_DISCOVERY_WINDOW)
            }
        });
        barrier.wait().await;

        let mut sessions = Vec::new();
        let mut errors = Vec::new();
        for result in [
            first.await.expect("first start task"),
            second.await.expect("second start task"),
        ] {
            match result {
                Ok(session) => sessions.push(session),
                Err(error) => errors.push(error),
            }
        }
        assert_eq!(sessions.len(), 1, "exactly one concurrent start succeeds");
        assert_eq!(errors.len(), 1, "exactly one concurrent start is rejected");
        assert!(matches!(
            &errors[0],
            CarrierError::Configuration(message)
                if message.contains("only one nearby-discovery session")
        ));
        assert_eq!(
            endpoint
                .inner
                .address_lookup()
                .expect("lookup registry")
                .len(),
            1,
            "the winning session installs one provider"
        );

        sessions.pop().expect("winning session").stop();
        assert!(
            endpoint
                .inner
                .address_lookup()
                .expect("lookup registry")
                .is_empty()
        );
        endpoint.close().await;
    }

    #[cfg(feature = "nearby-discovery")]
    #[tokio::test]
    async fn nearby_stop_is_synchronous_generation_bound_and_expires() {
        let endpoint = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("endpoint");
        let services = endpoint.inner.address_lookup().expect("lookup registry");

        let first = endpoint
            .start_nearby_discovery(MAX_NEARBY_DISCOVERY_WINDOW)
            .expect("first nearby session");
        let old_stop = first.stop_handle();
        assert!(old_stop.is_active());
        old_stop.stop();
        assert!(!old_stop.is_active());
        assert!(
            services.is_empty(),
            "stop synchronously clears the provider"
        );

        let second = endpoint
            .start_nearby_discovery(MAX_NEARBY_DISCOVERY_WINDOW)
            .expect("second nearby session");
        let second_stop = second.stop_handle();
        old_stop.stop();
        drop(first);
        assert!(
            second_stop.is_active(),
            "an old stop handle cannot clear a later session"
        );
        assert_eq!(services.len(), 1);
        second_stop.stop();
        assert!(!second_stop.is_active());
        assert!(services.is_empty());
        drop(second);

        let expiring = endpoint
            .start_nearby_discovery(MIN_NEARBY_DISCOVERY_WINDOW)
            .expect("expiring nearby session");
        let expiring_stop = expiring.stop_handle();
        timeout(Duration::from_secs(3), async {
            while expiring_stop.is_active() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("internal nearby expiry deadline");
        assert!(services.is_empty(), "expiry clears the provider registry");
        assert!(
            !endpoint.nearby_discovery_occupied.load(Ordering::Acquire),
            "expiry releases endpoint singleton ownership"
        );

        drop(expiring);
        endpoint.close().await;
    }

    #[tokio::test]
    async fn channel_bindings_separate_contexts_and_fresh_quic_connections() {
        let config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("server");
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("client");
        let first_context =
            ChannelBindingContext::new(b"mission-contact-context-1").expect("first context");
        let second_context =
            ChannelBindingContext::new(b"mission-contact-context-2").expect("second context");

        let (first_server, first_client) = connect_pair(&server, &client).await;
        let first_binding = first_client
            .channel_binding(first_context)
            .expect("first binding");
        let other_context_binding = first_client
            .channel_binding(second_context)
            .expect("other-context binding");
        assert_ne!(first_binding, other_context_binding);
        assert_eq!(
            first_binding,
            first_server
                .channel_binding(first_context)
                .expect("matching first binding")
        );
        first_client.close();
        first_server.close();

        let (second_server, second_client) = connect_pair(&server, &client).await;
        let second_connection_binding = second_client
            .channel_binding(first_context)
            .expect("second-connection binding");
        assert_eq!(
            second_connection_binding,
            second_server
                .channel_binding(first_context)
                .expect("matching second binding")
        );
        assert_ne!(first_binding, second_connection_binding);

        second_client.close();
        second_server.close();
        client.close().await;
        server.close().await;
    }

    async fn assert_mixed_profiles_fail(
        server_profile: CarrierSecurityProfile,
        client_profile: CarrierSecurityProfile,
    ) {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(2);
        let server =
            Endpoint::bind_with_security_profile(SecretKey::generate(), config, server_profile)
                .await
                .expect("server");
        let client =
            Endpoint::bind_with_security_profile(SecretKey::generate(), config, client_profile)
                .await
                .expect("client");
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = timeout(config.connect_timeout, server.inner.accept())
                    .await
                    .expect("server observed incoming before deadline")
                    .expect("server remained open");
                observed_tx.send(()).expect("observation receiver open");
                timeout(config.connect_timeout, incoming).await
            }
        });

        let result = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await;
        assert!(
            matches!(result, Err(CarrierError::Transport(_))),
            "mixed profile unexpectedly connected or failed outside the handshake"
        );
        timeout(config.connect_timeout, observed_rx)
            .await
            .expect("server observation deadline")
            .expect("server observation sender");
        let handshake = server_task.await.expect("server task");
        assert!(
            matches!(handshake, Ok(Err(_))),
            "server handshake accepted a mixed carrier profile"
        );
        assert!(
            timeout(Duration::from_millis(250), server.inner.accept())
                .await
                .is_err(),
            "client retried or fell back after the profile mismatch"
        );

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn mixed_carrier_profiles_fail_without_retry_or_fallback() {
        assert_mixed_profiles_fail(
            CarrierSecurityProfile::HybridAsterRecordV1,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await;
        assert_mixed_profiles_fail(
            CarrierSecurityProfile::IrohQuicV1,
            CarrierSecurityProfile::HybridAsterRecordV1,
        )
        .await;
    }

    #[tokio::test]
    async fn rejected_check_never_invokes_payload_submission() {
        let invoked = std::cell::Cell::new(false);
        let rejected = checked_write(
            || Err::<(), _>("rejected"),
            || {
                invoked.set(true);
                async { Ok(()) }
            },
        )
        .await;
        assert_eq!(rejected, Err("rejected"));
        assert!(!invoked.get());
        // Positive control: the same seam really invokes the writer and
        // propagates its failure after successful authorization.
        let failed = checked_write(
            || Ok("authorized"),
            || {
                invoked.set(true);
                async { Err("write failed") }
            },
        )
        .await;
        assert!(invoked.get());
        assert_eq!(failed, Err("write failed"));
    }

    #[tokio::test]
    async fn carrier_adjacent_check_failure_writes_no_application_bytes() {
        #[derive(Debug)]
        enum CheckedError {
            Carrier,
            Rejected,
        }

        impl From<CarrierError> for CheckedError {
            fn from(_: CarrierError) -> Self {
                Self::Carrier
            }
        }

        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.exchange_timeout = Duration::from_secs(10);
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("client");
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                // A subsequent successful request is the observation fence.
                // Read incrementally: read_to_end could discard already-read
                // payload when a later reset or timeout occurs.
                timeout(Duration::from_secs(10), async {
                    loop {
                        let (mut send, mut receive) =
                            connection.inner.accept_bi().await.expect("fence stream");
                        let mut observed = Vec::new();
                        let mut buffer = [0; 64];
                        loop {
                            match receive.read(&mut buffer).await {
                                Ok(Some(count)) => {
                                    observed.extend_from_slice(&buffer[..count]);
                                    assert!(
                                        b"authorized-fence".starts_with(&observed),
                                        "rejected payload escaped: {observed:?}"
                                    );
                                }
                                Ok(None) => break,
                                Err(error) if observed.is_empty() => {
                                    assert!(
                                        matches!(error, iroh::endpoint::ReadError::Reset(_)),
                                        "unexpected receive failure: {error}"
                                    );
                                    break;
                                }
                                Err(error) => {
                                    panic!("incomplete observation: {error}; bytes={observed:?}")
                                }
                            }
                        }
                        if observed.is_empty() {
                            continue;
                        }
                        assert_eq!(observed, b"authorized-fence");
                        send.write_all(b"observed").await.expect("fence response");
                        send.finish().expect("finish fence response");
                        assert_eq!(send.stopped().await.expect("fence consumed"), None);
                        break;
                    }
                })
                .await
                .expect("rejected-request observation must complete");
                connection
                    .finish_as_responder()
                    .await
                    .expect("responder completion");
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect");
        let callback_ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = callback_ran.clone();
        let result: Result<(Vec<u8>, ()), CheckedError> = connection
            .request_with_total_limit_checked(b"must-not-escape", usize::MAX, move || {
                observed.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(CheckedError::Rejected)
            })
            .await;
        assert!(matches!(result, Err(CheckedError::Rejected)));
        assert!(callback_ran.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            connection
                .request(b"authorized-fence")
                .await
                .expect("fence request"),
            b"observed"
        );
        connection
            .finish_as_initiator()
            .await
            .expect("initiator completion");
        server_task.await.expect("server task");
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn combined_exchange_limit_is_exact_and_enforced_by_the_responder() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("server");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("client");
        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                assert!(
                    connection
                        .respond_once_with_total_limit(8, |request| {
                            assert_eq!(request, b"ping");
                            Ok((b"pong".to_vec(), true))
                        })
                        .await
                        .expect("exact combined limit")
                );
                match connection
                    .respond_once_with_total_limit(7, |request| {
                        assert_eq!(request, b"ping");
                        Ok((b"pong".to_vec(), true))
                    })
                    .await
                {
                    Err(CarrierError::FrameTooLarge {
                        actual: 4,
                        maximum: 3,
                    }) => {}
                    Err(error) => panic!("combined limit failed at the wrong stage: {error}"),
                    Ok(_) => panic!("response exceeded the combined exchange limit"),
                }
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect");
        assert_eq!(
            connection
                .request_with_total_limit(b"ping", 8)
                .await
                .expect("exact combined limit"),
            b"pong"
        );
        assert!(
            connection
                .request_with_total_limit(b"ping", 8)
                .await
                .is_err()
        );
        server_task.await.expect("server task");
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn wrong_expected_identity_fails_before_an_application_exchange() {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(2);
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("client");

        // Drive the actual server-side handshake and record that the client's
        // datagram reached the intended socket. Without this task, a timeout or
        // an idle server could make a weak `is_err()` assertion false-pass.
        let (observed_tx, observed_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = timeout(config.connect_timeout, server.inner.accept())
                    .await
                    .expect("server observed incoming before deadline")
                    .expect("server remained open");
                observed_tx.send(()).expect("observation receiver open");
                timeout(config.connect_timeout, incoming).await
            }
        });

        let result = client
            .connect(ExpectedPeer {
                id: SecretKey::generate().public(),
                address: loopback(&server),
            })
            .await;
        match result {
            Err(CarrierError::Transport(_)) => {}
            Err(error) => panic!("wrong identity failed at the wrong stage: {error}"),
            Ok(_) => panic!("wrong identity authenticated"),
        }
        timeout(config.connect_timeout, observed_rx)
            .await
            .expect("server observation deadline")
            .expect("server observation sender");
        let handshake = server_task.await.expect("server task");
        assert!(
            matches!(handshake, Ok(Err(_))),
            "server handshake should reject the client's wrong expected identity"
        );

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn inbound_identity_is_rejected_before_a_connection_is_returned() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("server");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("client");
        let client_id = client.id();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.accept(&BTreeSet::new()).await }
        });

        let _client_result = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await;
        match server_task.await.expect("server task") {
            Err(CarrierError::UnauthorizedPeer(peer)) => assert_eq!(peer, client_id),
            Err(error) => panic!("unexpected rejection stage: {error}"),
            Ok(_) => panic!("unlisted peer was accepted"),
        }

        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn accept_candidate_returns_an_unrostered_authenticated_carrier() {
        let server = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("server");
        let client = Endpoint::bind(
            SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("address")),
        )
        .await
        .expect("client");
        let client_id = client.id();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move { server.accept_candidate().await.expect("candidate accept") }
        });

        let client_connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect");
        let server_connection = server_task.await.expect("server task");
        assert_eq!(server_connection.remote_id(), client_id);
        assert_eq!(
            server_connection.security_profile(),
            server.security_profile()
        );

        server_connection.close();
        client_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn stalled_inbound_handshake_does_not_block_a_later_valid_connection() {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(2);
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let stalled_client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("stalled client");
        let valid_client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("valid client");
        let allowed = BTreeSet::from([stalled_client.id(), valid_client.id()]);
        let mut acceptor = server.inbound_acceptor(&allowed);
        let (stalled_entered_send, stalled_entered_receive) = tokio::sync::oneshot::channel();
        let (_stalled_release_send, stalled_release_receive) = tokio::sync::oneshot::channel();
        acceptor.test_handshake_gates.push_back(TestHandshakeGate {
            entered: stalled_entered_send,
            release: stalled_release_receive,
        });

        let server_task = tokio::spawn(async move {
            timeout(Duration::from_secs(2), acceptor.accept())
                .await
                .expect("later connection accepted before stalled handshake deadline")
                .expect("accept later connection")
        });
        let stalled_task = tokio::spawn({
            let stalled_client = stalled_client.clone();
            let server = server.clone();
            async move {
                stalled_client
                    .connect(ExpectedPeer {
                        id: server.id(),
                        address: loopback(&server),
                    })
                    .await
            }
        });
        timeout(Duration::from_secs(2), stalled_entered_receive)
            .await
            .expect("stalled handshake admitted")
            .expect("stalled handshake observation sender");

        let valid_connection = valid_client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("valid client connects while earlier handshake is stalled");
        let accepted = server_task.await.expect("server task");
        assert_eq!(accepted.remote_id(), valid_client.id());

        stalled_task.abort();
        accepted.close();
        valid_connection.close();
        stalled_client.close().await;
        valid_client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn saturated_stalled_handshakes_retire_the_oldest_and_admit_a_later_peer() {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.connect_timeout = Duration::from_secs(10);
        let server = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("server");
        let mut stalled_clients = Vec::new();
        for _ in 0..MAX_PENDING_INBOUND_HANDSHAKES {
            stalled_clients.push(
                Endpoint::bind(SecretKey::generate(), config)
                    .await
                    .expect("stalled client"),
            );
        }
        let valid_client = Endpoint::bind(SecretKey::generate(), config)
            .await
            .expect("valid client");
        let mut allowed = stalled_clients
            .iter()
            .map(Endpoint::id)
            .collect::<BTreeSet<_>>();
        allowed.insert(valid_client.id());
        let mut acceptor = server.inbound_acceptor(&allowed);
        let mut entered_receivers = Vec::new();
        let mut release_senders = Vec::new();
        for _ in 0..MAX_PENDING_INBOUND_HANDSHAKES {
            let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
            let (release_send, release_receive) = tokio::sync::oneshot::channel();
            acceptor.test_handshake_gates.push_back(TestHandshakeGate {
                entered: entered_send,
                release: release_receive,
            });
            entered_receivers.push(entered_receive);
            release_senders.push(release_send);
        }

        let server_task = tokio::spawn(async move {
            let accepted = timeout(Duration::from_secs(10), acceptor.accept())
                .await
                .expect("later connection accepted before handshake deadline")
                .expect("accept later connection");
            (accepted, acceptor)
        });
        let mut stalled_tasks = Vec::new();
        for (client, entered) in stalled_clients.iter().zip(entered_receivers) {
            stalled_tasks.push(tokio::spawn({
                let client = client.clone();
                let server = server.clone();
                async move {
                    client
                        .connect(ExpectedPeer {
                            id: server.id(),
                            address: loopback(&server),
                        })
                        .await
                }
            }));
            timeout(Duration::from_secs(2), entered)
                .await
                .expect("stalled handshake admitted")
                .expect("stalled handshake observation sender");
        }

        let valid_connection = valid_client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("valid client connects after saturation");
        let (accepted, acceptor) = server_task.await.expect("server task");
        assert_eq!(accepted.remote_id(), valid_client.id());
        assert!(
            release_senders.remove(0).send(()).is_err(),
            "the oldest stalled handshake was not retired"
        );
        drop(acceptor);

        for task in stalled_tasks {
            task.abort();
        }
        accepted.close();
        valid_connection.close();
        for client in stalled_clients {
            client.close().await;
        }
        valid_client.close().await;
        server.close().await;
    }

    #[test]
    fn controlled_route_and_trust_bounds_are_exact() {
        let id = SecretKey::generate().public();
        let relay_url: RelayUrl = "https://relay.example.invalid/".parse().expect("relay URL");
        let route = PeerRoute::new(
            id,
            [
                "127.0.0.1:4002".parse().expect("address"),
                "127.0.0.1:4001".parse().expect("address"),
            ],
            relay_url.clone(),
        )
        .expect("route");
        assert_eq!(
            route.direct_addresses(),
            &[
                "127.0.0.1:4001".parse().expect("address"),
                "127.0.0.1:4002".parse().expect("address"),
            ]
        );
        assert_eq!(
            route.to_string().parse::<PeerRoute>().expect("round trip"),
            route
        );

        let relay_only = PeerRoute::new(id, [], relay_url.clone()).expect("relay only");
        assert_eq!(
            relay_only
                .to_string()
                .parse::<PeerRoute>()
                .expect("relay-only round trip"),
            relay_only
        );
        assert!(matches!(
            PeerRoute::new(
                id,
                (0..=MAX_DIRECT_ADDRESSES)
                    .map(|port| SocketAddr::from(([127, 0, 0, 1], 10_000 + port as u16))),
                relay_url.clone(),
            ),
            Err(CarrierError::Configuration(_))
        ));
        let too_many_direct = (0..=MAX_DIRECT_ADDRESSES)
            .map(|port| SocketAddr::from(([127, 0, 0, 1], 20_000 + port as u16)).to_string())
            .collect::<Vec<_>>()
            .join(",");
        let too_many_encoded = format!("{id}@{too_many_direct}#{relay_url}");
        assert!(matches!(
            too_many_encoded.parse::<PeerRoute>(),
            Err(CarrierError::Configuration(message))
                if message.contains("more than 8 direct addresses")
        ));
        let oversized_relay = format!("{id}@#https://{}/", "a".repeat(MAX_RELAY_URL_BYTES));
        assert!(matches!(
            oversized_relay.parse::<PeerRoute>(),
            Err(CarrierError::Configuration(message))
                if message.contains("relay URL exceeds")
        ));
        assert!(matches!(
            "x".repeat(MAX_PEER_ROUTE_TEXT_BYTES + 1).parse::<PeerRoute>(),
            Err(CarrierError::Configuration(message))
                if message.contains("peer route exceeds")
        ));
        assert!(matches!(
            PeerRoute::new(
                id,
                [
                    "127.0.0.1:4001".parse().expect("address"),
                    "127.0.0.1:4001".parse().expect("address"),
                ],
                relay_url.clone(),
            ),
            Err(CarrierError::Configuration(_))
        ));

        for invalid in [
            "http://relay.example.invalid/",
            "https://operator@relay.example.invalid/",
            "https://relay.example.invalid/private-token",
            "https://relay.example.invalid/?token=secret",
            "https://relay.example.invalid/#fragment",
        ] {
            let invalid_url: RelayUrl = invalid.parse().expect("syntactically valid URL");
            assert!(matches!(
                PeerRoute::new(id, [], invalid_url),
                Err(CarrierError::Configuration(_))
            ));
        }

        assert!(matches!(
            PinnedRelay::with_ca_roots(relay_url.clone(), Vec::<Vec<u8>>::new()),
            Err(CarrierError::Configuration(_))
        ));
        assert!(matches!(
            PinnedRelay::with_ca_roots(relay_url.clone(), [vec![0u8; MAX_RELAY_CA_ROOT_BYTES + 1]],),
            Err(CarrierError::Configuration(_))
        ));
        assert!(matches!(
            PinnedRelay::with_ca_roots(relay_url, [vec![1, 2, 3]]),
            Err(CarrierError::Configuration(message))
                if message.contains("invalid relay CA root DER certificate")
        ));

        let mut witness = PathWitness::new(SelectedPath::Relay);
        for index in 0..=usize::from(MAX_PATH_TRANSITIONS) {
            witness.observe(if index % 2 == 0 {
                SelectedPath::Direct
            } else {
                SelectedPath::Relay
            });
        }
        assert_eq!(witness.transition_count, MAX_PATH_TRANSITIONS);
        assert!(witness.transitions_saturated);

        let mut continuity_lost = PathWitness::new(SelectedPath::Direct);
        continuity_lost.observe(SelectedPath::Relay);
        continuity_lost.lose_continuity();
        assert_eq!(continuity_lost.selected, SelectedPath::Unknown);
        assert_eq!(continuity_lost.transition_count, 1);
        assert!(continuity_lost.transitions_saturated);
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn relay_only_exact_peer_succeeds_with_pinned_tls_trust() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let valid_root = fixture.ca_roots_der()[0].clone();
        assert!(matches!(
            PinnedRelay::with_ca_roots(
                fixture.relay_url().clone(),
                [valid_root.clone(), vec![1, 2, 3]],
            ),
            Err(CarrierError::Configuration(message))
                if message.contains("invalid relay CA root DER certificate")
        ));
        assert!(matches!(
            PinnedRelay::with_ca_roots(
                fixture.relay_url().clone(),
                (0..=MAX_RELAY_CA_ROOTS).map(|_| valid_root.clone()),
            ),
            Err(CarrierError::Configuration(_))
        ));
        let large_root = large_valid_ca_root();
        assert!(large_root.len() <= MAX_RELAY_CA_ROOT_BYTES);
        let copies = MAX_RELAY_CA_ROOT_TOTAL_BYTES / large_root.len() + 1;
        assert!(copies <= MAX_RELAY_CA_ROOTS);
        assert!(matches!(
            PinnedRelay::with_ca_roots(
                fixture.relay_url().clone(),
                (0..copies).map(|_| large_root.clone()),
            ),
            Err(CarrierError::Configuration(_))
        ));
        let pinned = fixture.pinned_relay();
        let cloned = pinned.clone();
        assert!(std::ptr::eq(pinned.ca_roots_der(), cloned.ca_roots_der()));
        let config = relay_test_config();
        let server =
            Endpoint::bind_relay_only(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("relay-only server");
        let client =
            Endpoint::bind_relay_only(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("relay-only client");
        server.wait_relay_ready().await.expect("server relay ready");
        client.wait_relay_ready().await.expect("client relay ready");
        assert!(server.bound_sockets().is_empty());
        assert!(client.bound_sockets().is_empty());

        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                connection
                    .respond_once(|request| Ok((request.to_vec(), true)))
                    .await
                    .expect("respond");
                wait_for_path(&connection, SelectedPath::Relay).await
            }
        });
        let route = PeerRoute::new(
            server.id(),
            ["127.0.0.1:9".parse().expect("unreachable direct address")],
            fixture.relay_url().clone(),
        )
        .expect("route");
        let connection = client.connect_route(&route).await.expect("relay connect");
        assert_eq!(
            connection.request(b"relay").await.expect("request"),
            b"relay"
        );
        let client_witness = wait_for_path(&connection, SelectedPath::Relay).await;
        assert!(!client_witness.transitions_saturated);
        let server_witness = server_task.await.expect("server task");
        assert_eq!(server_witness.selected, SelectedPath::Relay);

        connection.close();
        client.close().await;
        server.close().await;
        fixture.shutdown().await.expect("relay shutdown");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn relay_tls_rejects_a_valid_but_unrelated_ca_without_fallback() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let relay =
            PinnedRelay::with_ca_roots(fixture.relay_url().clone(), [unrelated_valid_ca_root()])
                .expect("valid unrelated CA root");
        let mut config = relay_test_config();
        config.connect_timeout = Duration::from_secs(1);
        let endpoint = Endpoint::bind_relay_only(SecretKey::generate(), config, relay)
            .await
            .expect("relay-only endpoint");

        assert!(matches!(
            endpoint.wait_relay_ready().await,
            Err(CarrierError::Timeout("relay readiness"))
        ));
        assert!(endpoint.bound_sockets().is_empty());

        endpoint.close().await;
        fixture.shutdown().await.expect("relay shutdown");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn usable_exact_direct_candidate_becomes_selected() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let config = relay_test_config();
        let server =
            Endpoint::bind_with_relay(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("server");
        let client =
            Endpoint::bind_with_relay(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("client");
        server.wait_relay_ready().await.expect("server relay ready");
        client.wait_relay_ready().await.expect("client relay ready");

        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                connection
                    .respond_once(|request| Ok((request.to_vec(), true)))
                    .await
                    .expect("respond");
            }
        });
        let route = PeerRoute::new(
            server.id(),
            [loopback(&server)],
            fixture.relay_url().clone(),
        )
        .expect("route");
        let connection = client.connect_route(&route).await.expect("connect");
        let initial_witness = connection.path_witness();
        assert_eq!(
            connection.request(b"direct").await.expect("request"),
            b"direct"
        );
        let witness = wait_for_path(&connection, SelectedPath::Direct).await;
        assert!(!witness.transitions_saturated);
        if initial_witness.selected != SelectedPath::Direct {
            assert!(
                witness.transition_count > initial_witness.transition_count,
                "a non-direct initial path must transition to the usable direct candidate"
            );
        }

        server_task.await.expect("server task");
        connection.close();
        client.close().await;
        server.close().await;
        fixture.shutdown().await.expect("relay shutdown");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn dead_pinned_relay_still_allows_the_exact_direct_candidate() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let relay_url = fixture.relay_url().clone();
        let relay = fixture.pinned_relay();
        fixture.shutdown().await.expect("stop relay before bind");
        let config = relay_test_config();
        let server = Endpoint::bind_with_relay(SecretKey::generate(), config, relay.clone())
            .await
            .expect("server");
        let client = Endpoint::bind_with_relay(SecretKey::generate(), config, relay)
            .await
            .expect("client");

        let allowed = BTreeSet::from([client.id()]);
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                connection
                    .respond_once(|request| Ok((request.to_vec(), true)))
                    .await
                    .expect("respond");
            }
        });
        let route = PeerRoute::new(server.id(), [loopback(&server)], relay_url).expect("route");
        let connection = client.connect_route(&route).await.expect("direct connect");
        assert_eq!(
            connection.request(b"direct").await.expect("request"),
            b"direct"
        );
        wait_for_path(&connection, SelectedPath::Direct).await;

        server_task.await.expect("server task");
        connection.close();
        client.close().await;
        server.close().await;
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn controlled_route_rejects_the_wrong_authenticated_identity() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let mut config = relay_test_config();
        config.connect_timeout = Duration::from_secs(2);
        let server =
            Endpoint::bind_with_relay(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("server");
        let client =
            Endpoint::bind_with_relay(SecretKey::generate(), config, fixture.pinned_relay())
                .await
                .expect("client");
        server.wait_relay_ready().await.expect("server relay ready");
        client.wait_relay_ready().await.expect("client relay ready");
        let substituted_relay: RelayUrl = "https://substitute.example.invalid/"
            .parse()
            .expect("relay URL");
        let substituted_route =
            PeerRoute::new(server.id(), [], substituted_relay).expect("substituted route");
        assert!(matches!(
            client.connect_route(&substituted_route).await,
            Err(CarrierError::Configuration(_))
        ));

        let wrong_id = SecretKey::generate().public();
        let route = PeerRoute::new(wrong_id, [loopback(&server)], fixture.relay_url().clone())
            .expect("route");
        assert!(matches!(
            client.connect_route(&route).await,
            Err(CarrierError::Transport(_) | CarrierError::Timeout(_))
        ));

        client.close().await;
        server.close().await;
        fixture.shutdown().await.expect("relay shutdown");
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn relay_loss_is_bounded_and_has_no_public_relay_substitution() {
        let fixture = RelayFixture::spawn().await.expect("relay fixture");
        let relay_url = fixture.relay_url().clone();
        let relay = fixture.pinned_relay();
        let config = relay_test_config();
        let server = Endpoint::bind_relay_only(SecretKey::generate(), config, relay.clone())
            .await
            .expect("server");
        let client = Endpoint::bind_relay_only(SecretKey::generate(), config, relay)
            .await
            .expect("client");
        server.wait_relay_ready().await.expect("server relay ready");
        client.wait_relay_ready().await.expect("client relay ready");

        let allowed = BTreeSet::from([client.id()]);
        let (first_complete_tx, first_complete_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                assert!(
                    !connection
                        .respond_once(|request| Ok((request.to_vec(), false)))
                        .await
                        .expect("first response")
                );
                first_complete_tx
                    .send(())
                    .expect("first-response observer open");
                connection
                    .respond_once(|request| Ok((request.to_vec(), true)))
                    .await
            }
        });
        let route = PeerRoute::new(server.id(), [], relay_url).expect("route");
        let connection = client.connect_route(&route).await.expect("connect");
        assert_eq!(
            connection.request(b"before").await.expect("request"),
            b"before"
        );
        first_complete_rx
            .await
            .expect("first response completed before relay loss");
        wait_for_path(&connection, SelectedPath::Relay).await;
        fixture.shutdown().await.expect("stop relay");

        let failed = timeout(Duration::from_secs(3), connection.request(b"after"))
            .await
            .expect("carrier-enforced relay-loss deadline");
        assert!(
            failed.is_err(),
            "request unexpectedly escaped the dead relay"
        );
        let witness = connection.path_witness();
        assert_eq!(witness.selected, SelectedPath::Relay);
        assert!(witness.transition_count <= MAX_PATH_TRANSITIONS);
        assert!(!witness.transitions_saturated);
        assert!(client.bound_sockets().is_empty());
        assert!(server.bound_sockets().is_empty());
        assert!(server_task.await.expect("server task").is_err());

        connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn additional_uni_pair_requires_completed_first_pair_and_is_single_use() {
        let (server, client, receiver, sender) = direct_connection_pair().await;
        assert!(sender.begin_additional_uni_pair().is_err());
        for connection in [&sender, &receiver] {
            connection.skip_uni_turn().unwrap();
            connection.skip_uni_turn().unwrap();
            connection.begin_additional_uni_pair().unwrap();
            assert!(connection.clone().begin_additional_uni_pair().is_err());
            connection.skip_uni_turn().unwrap();
            connection.skip_uni_turn().unwrap();
            assert!(connection.begin_additional_uni_pair().is_err());
        }
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_preserves_frame_order_and_reports_exact_eof() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let receive = tokio::spawn(async move {
            let mut turn = receiver_connection
                .accept_uni(uni_deadline(), 64)
                .await
                .expect("accept uni turn");
            assert_eq!(
                turn.read_frame().await.expect("first frame"),
                Some(b"first".to_vec())
            );
            assert_eq!(
                turn.read_frame().await.expect("second frame"),
                Some(b"second".to_vec())
            );
            assert_eq!(turn.read_frame().await.expect("exact EOF"), None);
            assert_eq!(turn.read_frame().await.expect("stable EOF"), None);
            receiver_connection
        });

        let mut turn = sender_connection
            .open_send_uni(uni_deadline(), 64)
            .await
            .expect("open uni turn");
        turn.write_frame_checked(b"first", || Ok::<_, CarrierError>(()))
            .await
            .expect("first frame");
        turn.write_frame_checked(b"second", || Ok::<_, CarrierError>(()))
            .await
            .expect("second frame");
        turn.finish().await.expect("finish uni turn");
        let receiver_connection = receive.await.expect("receive task");

        receiver_connection.close();
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_concurrent_stream_pair_keeps_reverse_control_live() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let receiver = tokio::spawn(async move {
            let mut pair = receiver_connection
                .accept_stream_pair(uni_deadline(), 64, 64)
                .await
                .expect("accept concurrent pair");
            assert_eq!(
                pair.data.read_frame().await.unwrap(),
                Some(b"extent".to_vec())
            );
            pair.control.write_frame(b"checkpoint").await.unwrap();
            pair.control.finish().await.unwrap();
            assert_eq!(pair.data.read_frame().await.unwrap(), None);
        });
        let mut pair = sender_connection
            .open_stream_pair(uni_deadline(), 64, 64)
            .await
            .expect("open concurrent pair");
        pair.data.write_frame(b"extent").await.unwrap();
        assert_eq!(
            pair.control.read_frame().await.unwrap(),
            Some(b"checkpoint".to_vec())
        );
        assert_eq!(pair.control.read_frame().await.unwrap(), None);
        pair.data.finish().await.unwrap();
        receiver.await.unwrap();
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn concurrent_stream_pair_writes_one_frame_from_two_owned_parts() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let receiver = tokio::spawn(async move {
            let mut pair = receiver_connection
                .accept_stream_pair(uni_deadline(), 64, 64)
                .await
                .expect("accept concurrent pair");
            assert_eq!(
                pair.data.read_frame().await.expect("read parts frame"),
                Some(b"headerbody".to_vec())
            );
            assert_eq!(pair.data.read_frame().await.expect("exact EOF"), None);
        });
        let mut pair = sender_connection
            .open_stream_pair(uni_deadline(), 64, 64)
            .await
            .expect("open concurrent pair");
        pair.data
            .write_frame_parts(b"header", b"body")
            .await
            .expect("write parts frame");
        assert!(matches!(
            pair.data.write_frame_parts(&[0; 40], &[0; 25]).await,
            Err(CarrierError::TurnTooLarge {
                actual: 83,
                maximum: 64
            })
        ));
        pair.data.finish().await.expect("finish data");
        receiver.await.expect("receiver task");
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_zero_frame_and_prewrite_rejection_emit_no_frame_bytes() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let receive = tokio::spawn(async move {
            let mut turn = receiver_connection
                .accept_uni(uni_deadline(), 64)
                .await
                .expect("accept first uni turn");
            assert_eq!(
                turn.read_frame().await.expect("visible frame"),
                Some(b"visible".to_vec())
            );
            assert_eq!(turn.read_frame().await.expect("first EOF"), None);

            let mut zero = receiver_connection
                .open_send_uni(uni_deadline(), 0)
                .await
                .expect("open reverse zero-frame turn");
            zero.finish().await.expect("finish zero-frame turn");
            receiver_connection
        });

        let mut turn = sender_connection
            .open_send_uni(uni_deadline(), 64)
            .await
            .expect("open first uni turn");
        let rejected: Result<(), CarrierError> = turn
            .write_frame_checked(b"hidden", || {
                Err(CarrierError::Configuration("test rejection".into()))
            })
            .await;
        assert!(matches!(rejected, Err(CarrierError::Configuration(_))));
        turn.write_frame_checked(b"visible", || Ok::<_, CarrierError>(()))
            .await
            .expect("visible frame");
        turn.finish().await.expect("finish first uni turn");

        let mut zero = sender_connection
            .accept_uni(uni_deadline(), 0)
            .await
            .expect("accept reverse zero-frame turn");
        assert_eq!(zero.read_frame().await.expect("zero-frame EOF"), None);
        let receiver_connection = receive.await.expect("receive task");

        receiver_connection.close();
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_enforces_per_frame_and_aggregate_bounds_without_partial_writes() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let receive = tokio::spawn(async move {
            let mut empty = receiver_connection
                .accept_uni(uni_deadline(), usize::MAX)
                .await
                .expect("accept bounded first turn");
            assert_eq!(
                empty.read_frame().await.expect("oversize emitted no frame"),
                None
            );

            let mut aggregate = receiver_connection
                .open_send_uni(uni_deadline(), 8)
                .await
                .expect("open aggregate turn");
            aggregate
                .write_frame_checked(b"four", || Ok::<_, CarrierError>(()))
                .await
                .expect("exact aggregate bound");
            assert!(matches!(
                aggregate
                    .write_frame_checked(b"x", || Ok::<_, CarrierError>(()))
                    .await,
                Err(CarrierError::TurnTooLarge {
                    actual: 13,
                    maximum: 8
                })
            ));
            aggregate.finish().await.expect("finish aggregate turn");
            receiver_connection
        });

        let mut bounded = sender_connection
            .open_send_uni(uni_deadline(), usize::MAX)
            .await
            .expect("open bounded first turn");
        let oversized = vec![0; DEFAULT_MAX_EXCHANGE_BYTES + 1];
        assert!(matches!(
            bounded
                .write_frame_checked(&oversized, || Ok::<_, CarrierError>(()))
                .await,
            Err(CarrierError::FrameTooLarge {
                actual,
                maximum: DEFAULT_MAX_EXCHANGE_BYTES
            }) if actual == DEFAULT_MAX_EXCHANGE_BYTES + 1
        ));
        bounded.finish().await.expect("finish bounded first turn");

        let mut aggregate = sender_connection
            .accept_uni(uni_deadline(), 8)
            .await
            .expect("accept aggregate turn");
        assert_eq!(
            aggregate
                .read_frame()
                .await
                .expect("bounded aggregate frame"),
            Some(b"four".to_vec())
        );
        assert_eq!(
            aggregate
                .read_frame()
                .await
                .expect("rejected frame emitted no bytes"),
            None
        );
        let receiver_connection = receive.await.expect("receive task");

        receiver_connection.close();
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_rejects_truncated_length() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let mut raw = sender_connection
            .inner
            .open_uni()
            .await
            .expect("raw uni stream");
        raw.write_all(UNI_TURN_MAGIC).await.expect("turn preamble");
        raw.write_all(&[0, 0]).await.expect("partial length");
        raw.finish().expect("finish partial length");

        let mut turn = receiver_connection
            .accept_uni(uni_deadline(), 64)
            .await
            .expect("accept malformed turn");
        assert!(matches!(
            turn.read_frame().await,
            Err(CarrierError::Transport(message)) if message.contains("truncated uni frame length")
        ));

        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_rejects_truncated_body_and_trailing_partial_length() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let mut raw = sender_connection
            .inner
            .open_uni()
            .await
            .expect("raw uni stream");
        raw.write_all(UNI_TURN_MAGIC).await.expect("turn preamble");
        raw.write_all(&5u32.to_be_bytes())
            .await
            .expect("body length");
        raw.write_all(b"ab").await.expect("partial body");
        raw.finish().expect("finish partial body");
        let mut turn = receiver_connection
            .accept_uni(uni_deadline(), 64)
            .await
            .expect("accept truncated body");
        assert!(matches!(
            turn.read_frame().await,
            Err(CarrierError::Transport(message)) if message.contains("truncated uni frame body")
        ));
        sender_connection.close();
        client.close().await;
        server.close().await;

        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let mut raw = sender_connection
            .inner
            .open_uni()
            .await
            .expect("raw uni stream");
        raw.write_all(UNI_TURN_MAGIC).await.expect("turn preamble");
        raw.write_all(&1u32.to_be_bytes())
            .await
            .expect("valid length");
        raw.write_all(b"x").await.expect("valid body");
        raw.write_all(&[0]).await.expect("trailing partial length");
        raw.finish().expect("finish trailing partial length");
        let mut turn = receiver_connection
            .accept_uni(uni_deadline(), 64)
            .await
            .expect("accept trailing partial length");
        assert_eq!(
            turn.read_frame().await.expect("valid first frame"),
            Some(b"x".to_vec())
        );
        assert!(matches!(
            turn.read_frame().await,
            Err(CarrierError::Transport(message)) if message.contains("truncated uni frame length")
        ));
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_uses_one_absolute_deadline_and_reports_peer_reset() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let raw_connection = sender_connection.inner.clone();
        let stalled = tokio::spawn(async move {
            let mut raw = raw_connection.open_uni().await.expect("raw stalled stream");
            raw.write_all(UNI_TURN_MAGIC).await.expect("turn preamble");
            for byte in [0, 0, 0, 1] {
                if raw.write_all(&[byte]).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            let _ = raw.write_all(b"x").await;
        });
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let mut turn = receiver_connection
            .accept_uni(deadline, 64)
            .await
            .expect("accept stalled turn");
        assert!(matches!(
            turn.read_frame().await,
            Err(CarrierError::Timeout("uni turn receive"))
        ));
        stalled.abort();
        sender_connection.close();
        client.close().await;
        server.close().await;

        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let mut raw = sender_connection
            .inner
            .open_uni()
            .await
            .expect("raw reset stream");
        raw.write_all(UNI_TURN_MAGIC).await.expect("turn preamble");
        raw.write_all(&4u32.to_be_bytes())
            .await
            .expect("reset length");
        raw.reset(9u8.into()).expect("reset stream");
        match receiver_connection.accept_uni(uni_deadline(), 64).await {
            Ok(mut turn) => assert!(matches!(
                turn.read_frame().await,
                Err(CarrierError::Transport(_))
            )),
            Err(CarrierError::Transport(_)) => {}
            Err(error) => panic!("peer reset failed at the wrong stage: {error}"),
        }
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_uses_the_lower_configured_frame_bound() {
        let mut config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        config.max_exchange_bytes = 8;
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair_with_config(config).await;
        assert_eq!(receiver_connection.max_uni_frame_bytes(), 8);
        assert_eq!(sender_connection.max_uni_frame_bytes(), 8);
        let receive = tokio::spawn(async move {
            let mut turn = receiver_connection
                .accept_uni(uni_deadline(), 64)
                .await
                .expect("accept lower-bound turn");
            assert_eq!(turn.read_frame().await.expect("exact EOF"), None);
            receiver_connection
        });

        let mut turn = sender_connection
            .open_send_uni(uni_deadline(), 64)
            .await
            .expect("open lower-bound turn");
        assert!(matches!(
            turn.write_frame_checked(b"123456789", || Ok::<_, CarrierError>(()))
                .await,
            Err(CarrierError::FrameTooLarge {
                actual: 9,
                maximum: 8
            })
        ));
        turn.finish().await.expect("finish lower-bound turn");
        let receiver_connection = receive.await.expect("receive task");

        receiver_connection.close();
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_receiver_rejects_remote_frame_and_aggregate_overflow() {
        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let mut raw = sender_connection
            .inner
            .open_uni()
            .await
            .expect("raw oversized stream");
        raw.write_all(UNI_TURN_MAGIC).await.expect("turn preamble");
        raw.write_all(
            &u32::try_from(DEFAULT_MAX_EXCHANGE_BYTES + 1)
                .unwrap()
                .to_be_bytes(),
        )
        .await
        .expect("oversized length");
        raw.finish().expect("finish oversized stream");
        let mut turn = receiver_connection
            .accept_uni(uni_deadline(), usize::MAX)
            .await
            .expect("accept oversized stream");
        assert!(matches!(
            turn.read_frame().await,
            Err(CarrierError::FrameTooLarge {
                actual,
                maximum: DEFAULT_MAX_EXCHANGE_BYTES
            }) if actual == DEFAULT_MAX_EXCHANGE_BYTES + 1
        ));
        sender_connection.close();
        client.close().await;
        server.close().await;

        let (server, client, receiver_connection, sender_connection) =
            direct_connection_pair().await;
        let mut raw = sender_connection
            .inner
            .open_uni()
            .await
            .expect("raw aggregate stream");
        raw.write_all(UNI_TURN_MAGIC).await.expect("turn preamble");
        raw.write_all(&4u32.to_be_bytes())
            .await
            .expect("first length");
        raw.write_all(b"four").await.expect("first frame");
        raw.write_all(&1u32.to_be_bytes())
            .await
            .expect("second length");
        raw.write_all(b"x").await.expect("second frame");
        raw.finish().expect("finish aggregate stream");
        let mut turn = receiver_connection
            .accept_uni(uni_deadline(), 8)
            .await
            .expect("accept aggregate stream");
        assert_eq!(
            turn.read_frame().await.expect("first frame"),
            Some(b"four".to_vec())
        );
        assert!(matches!(
            turn.read_frame().await,
            Err(CarrierError::TurnTooLarge {
                actual: 13,
                maximum: 8
            })
        ));
        sender_connection.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_rejects_concurrent_reordered_and_extra_phases() {
        let (server, client, responder, initiator) = direct_connection_pair().await;
        assert!(responder.open_send_uni(uni_deadline(), 8).await.is_err());
        assert!(initiator.accept_uni(uni_deadline(), 8).await.is_err());

        let mut first = initiator
            .open_send_uni(uni_deadline(), 8)
            .await
            .expect("open first phase");
        assert!(initiator.open_send_uni(uni_deadline(), 8).await.is_err());
        assert!(initiator.accept_uni(uni_deadline(), 8).await.is_err());
        first.finish().await.expect("finish first phase");
        assert!(initiator.open_send_uni(uni_deadline(), 8).await.is_err());

        let mut first = responder
            .accept_uni(uni_deadline(), 8)
            .await
            .expect("accept first phase");
        assert_eq!(first.read_frame().await.expect("first EOF"), None);
        assert!(responder.accept_uni(uni_deadline(), 8).await.is_err());

        let mut second = responder
            .open_send_uni(uni_deadline(), 8)
            .await
            .expect("open second phase");
        second.finish().await.expect("finish second phase");
        let mut second = initiator
            .accept_uni(uni_deadline(), 8)
            .await
            .expect("accept second phase");
        assert_eq!(second.read_frame().await.expect("second EOF"), None);

        assert!(initiator.open_send_uni(uni_deadline(), 8).await.is_err());
        assert!(initiator.accept_uni(uni_deadline(), 8).await.is_err());
        assert!(responder.open_send_uni(uni_deadline(), 8).await.is_err());
        assert!(responder.accept_uni(uni_deadline(), 8).await.is_err());

        initiator.close();
        client.close().await;
        server.close().await;
    }

    #[tokio::test]
    async fn uni_turn_skip_advances_an_omitted_first_phase_without_opening_a_stream() {
        let (server, client, responder, initiator) = direct_connection_pair().await;
        initiator
            .skip_uni_turn()
            .expect("skip initiator send phase");
        responder
            .skip_uni_turn()
            .expect("skip responder receive phase");

        let mut second = responder
            .open_send_uni(uni_deadline(), 8)
            .await
            .expect("open second phase");
        second.finish().await.expect("finish second phase");
        let mut second = initiator
            .accept_uni(uni_deadline(), 8)
            .await
            .expect("accept second phase");
        assert_eq!(second.read_frame().await.expect("second EOF"), None);
        assert!(initiator.skip_uni_turn().is_err());
        assert!(responder.skip_uni_turn().is_err());

        initiator.close();
        client.close().await;
        server.close().await;
    }

    #[test]
    fn frame_bound_errors_preserve_the_enforced_limit() {
        assert!(ensure_frame_bound(8, 8).is_ok());
        assert!(matches!(
            ensure_frame_bound(9, 8),
            Err(CarrierError::FrameTooLarge {
                actual: 9,
                maximum: 8
            })
        ));
        assert!(matches!(
            map_read_error(ReadToEndError::TooLong, 8),
            CarrierError::FrameTooLarge {
                actual: 9,
                maximum: 8
            }
        ));
    }

    /// Measurement-only ceiling for the profile-5 long-lived data/control shape.
    #[tokio::test]
    #[ignore = "explicit 1 GiB loopback performance measurement"]
    async fn concurrent_stream_ceiling_transfers_one_gib_with_reverse_checkpoints() {
        const TOTAL: u64 = 1 << 30;
        const EXTENT: usize = 1 << 20;
        const CHECKPOINT: u64 = 8 << 20;

        let (server, client, receiver, sender) = direct_connection_pair().await;
        let receiver_inner = receiver.inner.clone();
        let receive_task = tokio::spawn(async move {
            let mut data = receiver_inner
                .accept_uni()
                .await
                .expect("accept data stream");
            let mut control = receiver_inner
                .open_uni()
                .await
                .expect("open control stream");
            let mut buffer = vec![0u8; EXTENT];
            let mut received = 0u64;
            let mut next_checkpoint = CHECKPOINT;
            while received < TOTAL {
                let count = data
                    .read(&mut buffer)
                    .await
                    .expect("read data stream")
                    .expect("data EOF after declared length");
                received += u64::try_from(count).expect("read count fits u64");
                if received >= next_checkpoint || received == TOTAL {
                    control
                        .write_all(&received.to_be_bytes())
                        .await
                        .expect("write checkpoint");
                    next_checkpoint = received.saturating_add(CHECKPOINT);
                }
            }
            assert_eq!(data.read(&mut buffer).await.expect("read EOF"), None);
            control.finish().expect("finish control stream");
            received
        });

        let started = std::time::Instant::now();
        let mut data = sender.inner.open_uni().await.expect("open data stream");
        let sender_inner = sender.inner.clone();
        let checkpoint_task = tokio::spawn(async move {
            let mut control = sender_inner
                .accept_uni()
                .await
                .expect("accept control stream");
            let mut buffer = [0u8; 8];
            let mut observed = 0u64;
            loop {
                let mut filled = 0;
                while filled < buffer.len() {
                    match control
                        .read(&mut buffer[filled..])
                        .await
                        .expect("read checkpoint")
                    {
                        Some(count) => filled += count,
                        None if filled == 0 => return observed,
                        None => panic!("checkpoint record was truncated"),
                    }
                }
                observed = u64::from_be_bytes(buffer);
            }
        });
        let extent = vec![0xa5; EXTENT];
        for _ in 0..TOTAL / EXTENT as u64 {
            data.write_all(&extent).await.expect("write extent");
        }
        data.finish().expect("finish data stream");
        let received = receive_task.await.expect("receive task");
        let checkpoint = checkpoint_task.await.expect("checkpoint task");
        let elapsed = started.elapsed();
        assert_eq!(received, TOTAL);
        assert_eq!(checkpoint, TOTAL);
        let mib_per_second = TOTAL as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
        eprintln!(
            "stream_ceiling bytes={TOTAL} elapsed_ns={} mib_per_second={mib_per_second:.3}",
            elapsed.as_nanos()
        );

        sender.close();
        client.close().await;
        server.close().await;
    }
}
