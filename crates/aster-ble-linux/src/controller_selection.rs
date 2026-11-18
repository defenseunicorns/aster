use bluer::{Address, AddressType};
use std::fmt;

/// Maximum number of controller candidates retained from one BlueZ sweep.
pub(crate) const MAX_CONTROLLER_CANDIDATES: usize = 8;

/// Maximum UTF-8 byte length of one canonical BlueZ adapter name.
const MAX_ADAPTER_NAME_BYTES: usize = 64;

/// Maximum support or safety rows retained by one admission policy.
const MAX_ADMISSION_ROWS: usize = 32;

/// Closed reason attached to a controller probe or admission result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbeReason {
    /// The controller address family is not an LE address family.
    UnsupportedAddressFamily,
    /// The controller protocol is unavailable.
    UnsupportedProtocol,
    /// LE L2CAP CoC is unavailable.
    UnsupportedLeCoc,
    /// BlueZ or its D-Bus session was unavailable.
    BluezUnavailable,
    /// The controller was not powered during evaluation.
    ControllerUnpowered,
    /// BlueZ denied the operation.
    PermissionDenied,
    /// A bounded platform resource was exhausted.
    ResourceExhausted,
    /// A bounded operation exceeded its deadline.
    DeadlineExceeded,
    /// The caller cancelled the operation.
    Cancelled,
    /// The platform returned an unknown typed failure.
    UnknownPlatformError,
    /// Local policy requires an exact qualified support row.
    QualifiedOnly,
    /// An exact immutable known-unsafe rule matched.
    KnownUnsafe,
    /// A known-unsafe rule could overlap missing fingerprint fields.
    AmbiguousUnsafeOverlap,
}

/// Result of one bounded controller compatibility attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProbeDisposition {
    /// Every required compatibility preflight gate passed.
    Compatible,
    /// The controller cannot provide a required protocol capability.
    Incompatible(ProbeReason),
    /// Immutable package or local policy prevents activation.
    Blocked(ProbeReason),
    /// The attempt did not establish compatibility or incompatibility.
    Indeterminate(ProbeReason),
}

/// Release-evidence tag for a compatible controller fingerprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SupportTag {
    /// The exact fingerprint has retained release evidence.
    Qualified,
    /// No exact retained release evidence exists.
    Unqualified,
}

const MAX_FINGERPRINT_FIELD_BYTES: usize = 64;

/// Bounded compatibility identity used for support and safety matching.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ControllerFingerprint {
    os: Option<String>,
    architecture: Option<String>,
    kernel: Option<String>,
    bluez: Option<String>,
    vendor: Option<String>,
    product: Option<String>,
    revision: Option<String>,
    firmware: Option<String>,
    driver: Option<String>,
}

impl ControllerFingerprint {
    /// Creates a bounded typed fingerprint from platform-provided fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        os: Option<&str>,
        architecture: Option<&str>,
        kernel: Option<&str>,
        bluez: Option<&str>,
        vendor: Option<&str>,
        product: Option<&str>,
        revision: Option<&str>,
        firmware: Option<&str>,
        driver: Option<&str>,
    ) -> Self {
        Self {
            os: bounded_field(os),
            architecture: bounded_field(architecture),
            kernel: bounded_field(kernel),
            bluez: bounded_field(bluez),
            vendor: bounded_field(vendor),
            product: bounded_field(product),
            revision: bounded_field(revision),
            firmware: bounded_field(firmware),
            driver: bounded_field(driver),
        }
    }

    /// Replaces the optional firmware identity with a bounded value.
    #[cfg(test)]
    pub(crate) fn set_firmware(&mut self, firmware: Option<&str>) {
        self.firmware = bounded_field(firmware);
    }

    /// Whether every field used to identify this fingerprint is present.
    pub(crate) fn is_complete(&self) -> bool {
        [
            &self.os,
            &self.architecture,
            &self.kernel,
            &self.bluez,
            &self.vendor,
            &self.product,
            &self.revision,
            &self.firmware,
            &self.driver,
        ]
        .iter()
        .all(|field| field.is_some())
    }
}

impl fmt::Debug for ControllerFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerFingerprint")
            .field("fields", &self.present_field_count())
            .finish()
    }
}

impl ControllerFingerprint {
    fn present_field_count(&self) -> usize {
        [
            &self.os,
            &self.architecture,
            &self.kernel,
            &self.bluez,
            &self.vendor,
            &self.product,
            &self.revision,
            &self.firmware,
            &self.driver,
        ]
        .iter()
        .filter(|field| field.is_some())
        .count()
    }
}

fn bounded_field(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| !value.is_empty() && value.len() <= MAX_FINGERPRINT_FIELD_BYTES)
        .map(str::to_owned)
}

/// Immutable exact support evidence row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerSupportRow {
    fingerprint: ControllerFingerprint,
}

impl ControllerSupportRow {
    /// Creates an exact support row for one fingerprint.
    pub fn exact(fingerprint: ControllerFingerprint) -> Self {
        Self { fingerprint }
    }
}

/// Immutable package-bound known-unsafe fingerprint rule.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerUnsafeRule {
    fingerprint: ControllerFingerprint,
}

impl ControllerUnsafeRule {
    /// Creates an exact rule; missing candidate fields overlap ambiguously.
    pub fn exact(fingerprint: ControllerFingerprint) -> Self {
        Self { fingerprint }
    }
}

/// Admission result kept separate from compatibility probing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ControllerAdmission {
    support: SupportTag,
    disposition: ProbeDisposition,
}

impl ControllerAdmission {
    /// Support evidence tag.
    pub(crate) const fn support(self) -> SupportTag {
        self.support
    }

    /// Policy disposition.
    pub(crate) const fn disposition(self) -> ProbeDisposition {
        self.disposition
    }
}

/// Local admission policy with bounded immutable package-owned tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerAdmissionPolicy {
    qualified_only: bool,
    support_rows: BoundedRows<ControllerSupportRow>,
    unsafe_rules: BoundedRows<ControllerUnsafeRule>,
    unsafe_overflowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundedRows<T> {
    rows: [Option<T>; MAX_ADMISSION_ROWS],
}

impl<T> BoundedRows<T> {
    fn from_vec(values: Vec<T>) -> Self {
        let mut rows = std::array::from_fn(|_| None);
        for (index, value) in values.into_iter().take(MAX_ADMISSION_ROWS).enumerate() {
            rows[index] = Some(value);
        }
        Self { rows }
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.rows.iter().filter_map(Option::as_ref)
    }
}

impl Default for ControllerAdmissionPolicy {
    fn default() -> Self {
        Self {
            qualified_only: false,
            support_rows: BoundedRows::from_vec(Vec::new()),
            unsafe_rules: BoundedRows::from_vec(Vec::new()),
            unsafe_overflowed: false,
        }
    }
}

impl ControllerAdmissionPolicy {
    /// Creates a policy from package-owned rows, retaining at most 32 rows per table.
    ///
    /// Missing support evidence remains unqualified. Missing safety evidence fails closed for
    /// every controller because an omitted unsafe row cannot be distinguished from a match.
    pub fn new(
        qualified_only: bool,
        support_rows: Vec<ControllerSupportRow>,
        unsafe_rules: Vec<ControllerUnsafeRule>,
    ) -> Self {
        let unsafe_overflowed = unsafe_rules.len() > MAX_ADMISSION_ROWS;
        Self {
            qualified_only,
            support_rows: BoundedRows::from_vec(support_rows),
            unsafe_rules: BoundedRows::from_vec(unsafe_rules),
            unsafe_overflowed,
        }
    }

    /// Evaluates support and safety policy for a typed fingerprint.
    pub(crate) fn admit(&self, fingerprint: &ControllerFingerprint) -> ControllerAdmission {
        let support = if self.support_rows.iter().any(|row| {
            row.fingerprint.is_complete()
                && fingerprint.is_complete()
                && exact_match(&row.fingerprint, fingerprint)
        }) {
            SupportTag::Qualified
        } else {
            SupportTag::Unqualified
        };

        let mut exact_unsafe = false;
        let mut ambiguous_unsafe = false;
        for rule in self.unsafe_rules.iter() {
            match overlap(&rule.fingerprint, fingerprint) {
                MatchKind::Exact => exact_unsafe = true,
                MatchKind::Ambiguous => ambiguous_unsafe = true,
                MatchKind::None => {}
            }
        }
        let disposition = if self.unsafe_overflowed {
            ProbeDisposition::Blocked(ProbeReason::AmbiguousUnsafeOverlap)
        } else if exact_unsafe {
            ProbeDisposition::Blocked(ProbeReason::KnownUnsafe)
        } else if ambiguous_unsafe {
            ProbeDisposition::Blocked(ProbeReason::AmbiguousUnsafeOverlap)
        } else if self.qualified_only && support == SupportTag::Unqualified {
            ProbeDisposition::Blocked(ProbeReason::QualifiedOnly)
        } else {
            ProbeDisposition::Compatible
        };

        ControllerAdmission {
            support,
            disposition,
        }
    }
}

#[derive(Clone, Copy)]
enum MatchKind {
    None,
    Exact,
    Ambiguous,
}

fn exact_match(expected: &ControllerFingerprint, actual: &ControllerFingerprint) -> bool {
    expected == actual
}

fn overlap(expected: &ControllerFingerprint, actual: &ControllerFingerprint) -> MatchKind {
    let fields = [
        (&expected.os, &actual.os),
        (&expected.architecture, &actual.architecture),
        (&expected.kernel, &actual.kernel),
        (&expected.bluez, &actual.bluez),
        (&expected.vendor, &actual.vendor),
        (&expected.product, &actual.product),
        (&expected.revision, &actual.revision),
        (&expected.firmware, &actual.firmware),
        (&expected.driver, &actual.driver),
    ];
    let mut ambiguous = false;
    for (expected, actual) in fields {
        match (expected, actual) {
            (Some(expected), Some(actual)) if expected != actual => return MatchKind::None,
            (Some(_), None) => ambiguous = true,
            _ => {}
        }
    }
    if ambiguous {
        MatchKind::Ambiguous
    } else {
        MatchKind::Exact
    }
}

/// Typed address snapshot associated with one controller candidate.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ControllerSnapshot {
    address: Address,
    address_type: AddressType,
}

impl fmt::Debug for ControllerSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerSnapshot")
            .field("address", &"[REDACTED]")
            .field("address_type", &self.address_type)
            .finish()
    }
}

impl ControllerSnapshot {
    /// Creates a snapshot from typed BlueZ properties.
    pub(crate) const fn new(address: Address, address_type: AddressType) -> Self {
        Self {
            address,
            address_type,
        }
    }

    /// Exact transient controller address.
    pub(crate) const fn address(self) -> Address {
        self.address
    }

    /// Exact typed controller address family.
    pub(crate) const fn address_type(self) -> AddressType {
        self.address_type
    }
}

/// Candidate retained from a bounded BlueZ inventory.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ControllerCandidate {
    name: String,
    snapshot: Option<ControllerSnapshot>,
}

impl ControllerCandidate {
    /// Creates a candidate with an exact typed controller address snapshot.
    #[cfg(test)]
    pub(crate) fn new(name: String, address: Address, address_type: AddressType) -> Self {
        Self {
            name,
            snapshot: Some(ControllerSnapshot::new(address, address_type)),
        }
    }

    /// Creates a candidate from a snapshot without widening its fields.
    pub(crate) fn from_snapshot(name: String, snapshot: ControllerSnapshot) -> Self {
        Self {
            name,
            snapshot: Some(snapshot),
        }
    }

    fn named(name: String) -> Self {
        Self {
            name,
            snapshot: None,
        }
    }

    /// Canonical epoch-local adapter name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Exact transient controller address, when a property snapshot is present.
    pub(crate) fn address(&self) -> Option<Address> {
        self.snapshot.map(ControllerSnapshot::address)
    }

    /// Exact typed controller address family, when present.
    pub(crate) fn address_type(&self) -> Option<AddressType> {
        self.snapshot.map(ControllerSnapshot::address_type)
    }

    /// Current typed property snapshot, if one has been read.
    pub(crate) const fn snapshot(&self) -> Option<ControllerSnapshot> {
        self.snapshot
    }
}

impl fmt::Debug for ControllerCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerCandidate")
            .field("identity", &"[REDACTED]")
            .field("has_snapshot", &self.snapshot.is_some())
            .finish()
    }
}

/// Bounded canonical controller inventory for one BlueZ sweep.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ControllerInventory {
    candidates: Vec<ControllerCandidate>,
}

impl ControllerInventory {
    /// Retained candidates in deterministic preference order.
    pub(crate) fn candidates(&self) -> &[ControllerCandidate] {
        &self.candidates
    }

    /// Retained names, useful for deterministic diagnostics and tests.
    #[cfg(test)]
    fn names(&self) -> Vec<&str> {
        self.candidates
            .iter()
            .map(ControllerCandidate::name)
            .collect()
    }
}

impl fmt::Debug for ControllerInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControllerInventory")
            .field("retained", &self.candidates.len())
            .finish()
    }
}

/// Canonicalizes, deduplicates, orders, and bounds one already-materialized BlueZ name vector.
pub(crate) fn normalize_controller_inventory(
    adapter_names: Vec<String>,
    selected: Option<&str>,
    diagnostic_override: Option<&str>,
) -> ControllerInventory {
    let selected = selected.and_then(canonical_name);
    let diagnostic_override = diagnostic_override.and_then(canonical_name);
    let mut retained = Vec::with_capacity(MAX_CONTROLLER_CANDIDATES);

    for raw_name in adapter_names {
        let Some(name) = canonical_name(&raw_name) else {
            continue;
        };
        if retained
            .iter()
            .any(|candidate: &ControllerCandidate| candidate.name == name)
        {
            continue;
        }

        let preferred = selected.as_deref() == Some(name.as_str())
            || diagnostic_override.as_deref() == Some(name.as_str());
        if retained.len() < MAX_CONTROLLER_CANDIDATES {
            retained.push(ControllerCandidate::named(name));
            continue;
        }

        let evict = if preferred {
            retained
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    selected.as_deref() != Some(candidate.name.as_str())
                        && diagnostic_override.as_deref() != Some(candidate.name.as_str())
                })
                .max_by(|(_, left), (_, right)| left.name.cmp(&right.name))
                .map(|(index, _)| index)
        } else {
            retained
                .iter()
                .enumerate()
                .filter(|(_, candidate)| {
                    selected.as_deref() != Some(candidate.name.as_str())
                        && diagnostic_override.as_deref() != Some(candidate.name.as_str())
                })
                .filter(|(_, candidate)| name < candidate.name)
                .max_by(|(_, left), (_, right)| left.name.cmp(&right.name))
                .map(|(index, _)| index)
        };

        if let Some(index) = evict {
            retained[index] = ControllerCandidate::named(name);
        }
    }

    retained.sort_by(|left, right| {
        preference_rank(
            left.name(),
            selected.as_deref(),
            diagnostic_override.as_deref(),
        )
        .cmp(&preference_rank(
            right.name(),
            selected.as_deref(),
            diagnostic_override.as_deref(),
        ))
        .then_with(|| left.name.cmp(&right.name))
    });

    ControllerInventory {
        candidates: retained,
    }
}

fn canonical_name(raw_name: &str) -> Option<String> {
    let name = raw_name.trim();
    if name.is_empty() || name.len() > MAX_ADAPTER_NAME_BYTES {
        return None;
    }
    let index = name.strip_prefix("hci")?;
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if index.len() > 1 && index.starts_with('0') {
        return None;
    }
    Some(name.to_owned())
}

fn preference_rank(name: &str, selected: Option<&str>, override_name: Option<&str>) -> u8 {
    if selected == Some(name) {
        0
    } else if override_name == Some(name) {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint() -> ControllerFingerprint {
        ControllerFingerprint::new(
            Some("linux"),
            Some("x86_64"),
            Some("6.12"),
            Some("5.72"),
            Some("vendor"),
            Some("product"),
            Some("revision"),
            Some("firmware"),
            Some("driver"),
        )
    }

    #[test]
    fn inventory_canonicalizes_deduplicates_and_orders_names() {
        let inventory = normalize_controller_inventory(
            vec![
                "hci2".to_owned(),
                "hci0".to_owned(),
                "hci2".to_owned(),
                " hci1 ".to_owned(),
                "hci0".to_owned(),
            ],
            None,
            None,
        );

        assert_eq!(inventory.names(), &["hci0", "hci1", "hci2"]);
    }

    #[test]
    fn inventory_retains_selected_and_override_before_remaining_slots() {
        let inventory = normalize_controller_inventory(
            (0..=10).map(|index| format!("hci{index}")).collect(),
            Some("hci10"),
            Some("hci9"),
        );

        assert_eq!(
            inventory.names(),
            &[
                "hci10", "hci9", "hci0", "hci1", "hci2", "hci3", "hci4", "hci5"
            ]
        );
    }

    #[test]
    fn huge_inventory_bounds_retained_names() {
        let inventory = normalize_controller_inventory(
            (0..50_000).map(|index| format!("hci{index}")).collect(),
            None,
            None,
        );

        assert!(inventory.candidates().len() <= MAX_CONTROLLER_CANDIDATES);
        assert!(
            inventory
                .candidates()
                .iter()
                .all(|candidate| candidate.name().len() <= MAX_ADAPTER_NAME_BYTES)
        );
    }

    #[test]
    fn inventory_rejects_empty_overlong_and_noncanonical_names() {
        let overlong = format!("hci{}", "9".repeat(MAX_ADAPTER_NAME_BYTES));
        let inventory = normalize_controller_inventory(
            vec![
                "".to_owned(),
                "HCI0".to_owned(),
                "hci-1".to_owned(),
                "hci01".to_owned(),
                overlong,
                "hci0".to_owned(),
            ],
            None,
            None,
        );

        assert_eq!(inventory.names(), &["hci0"]);
    }

    #[test]
    fn missing_support_row_is_unqualified_not_blocked() {
        let policy = ControllerAdmissionPolicy::default();
        let admission = policy.admit(&fingerprint());

        assert_eq!(admission.support(), SupportTag::Unqualified);
        assert_eq!(admission.disposition(), ProbeDisposition::Compatible);
    }

    #[test]
    fn qualified_only_blocks_unqualified_candidate() {
        let policy = ControllerAdmissionPolicy::new(true, Vec::new(), Vec::new());
        let admission = policy.admit(&fingerprint());

        assert_eq!(admission.support(), SupportTag::Unqualified);
        assert_eq!(
            admission.disposition(),
            ProbeDisposition::Blocked(ProbeReason::QualifiedOnly)
        );
    }

    #[test]
    fn qualification_requires_complete_support_and_observed_fingerprints() {
        let complete = fingerprint();
        let mut partial_observed = complete.clone();
        partial_observed.set_firmware(None);
        let mut partial_row = complete.clone();
        partial_row.set_firmware(None);

        assert_eq!(
            ControllerAdmissionPolicy::new(
                false,
                vec![ControllerSupportRow::exact(complete.clone())],
                Vec::new(),
            )
            .admit(&partial_observed)
            .support(),
            SupportTag::Unqualified
        );
        assert_eq!(
            ControllerAdmissionPolicy::new(
                false,
                vec![ControllerSupportRow::exact(partial_row.clone())],
                Vec::new(),
            )
            .admit(&partial_row)
            .support(),
            SupportTag::Unqualified
        );
        assert_eq!(
            ControllerAdmissionPolicy::new(
                false,
                vec![ControllerSupportRow::exact(complete.clone())],
                Vec::new(),
            )
            .admit(&complete)
            .support(),
            SupportTag::Qualified
        );
    }

    #[test]
    fn unsafe_row_overflow_blocks_every_controller() {
        let candidate = fingerprint();
        let mut non_matching = candidate.clone();
        non_matching.set_firmware(Some("other-firmware"));
        let mut unsafe_rules = vec![ControllerUnsafeRule::exact(non_matching); MAX_ADMISSION_ROWS];
        unsafe_rules.push(ControllerUnsafeRule::exact(candidate.clone()));

        let policy = ControllerAdmissionPolicy::new(false, vec![], unsafe_rules);
        let mut unrelated = candidate.clone();
        unrelated.set_firmware(Some("unrelated"));

        assert_eq!(
            policy.admit(&candidate).disposition(),
            ProbeDisposition::Blocked(ProbeReason::AmbiguousUnsafeOverlap)
        );
        assert_eq!(
            policy.admit(&unrelated).disposition(),
            ProbeDisposition::Blocked(ProbeReason::AmbiguousUnsafeOverlap)
        );
    }

    #[test]
    fn exact_unsafe_rule_blocks_candidate() {
        let fingerprint = fingerprint();
        let policy = ControllerAdmissionPolicy::new(
            false,
            vec![],
            vec![ControllerUnsafeRule::exact(fingerprint.clone())],
        );
        let admission = policy.admit(&fingerprint);

        assert_eq!(
            admission.disposition(),
            ProbeDisposition::Blocked(ProbeReason::KnownUnsafe)
        );
    }

    #[test]
    fn ambiguous_unsafe_overlap_fails_closed() {
        let mut candidate = fingerprint();
        candidate.set_firmware(None);
        let policy = ControllerAdmissionPolicy::new(
            false,
            vec![],
            vec![ControllerUnsafeRule::exact(fingerprint())],
        );
        let admission = policy.admit(&candidate);

        assert_eq!(
            admission.disposition(),
            ProbeDisposition::Blocked(ProbeReason::AmbiguousUnsafeOverlap)
        );
    }

    #[test]
    fn inventory_candidates_do_not_fabricate_address_identity() {
        let inventory = normalize_controller_inventory(vec!["hci0".to_owned()], None, None);
        let candidate = &inventory.candidates()[0];

        assert_eq!(candidate.address(), None);
        assert_eq!(candidate.address_type(), None);
        assert_eq!(candidate.snapshot(), None);
    }
}
