//! Replaceable protection boundary for local provisioning artifacts.
//!
//! The mesh protocol does not define an at-rest provisioning format. The
//! canonical `ASTRPB03` bytes are an unprotected inner representation; an
//! operational deployment supplies separate [`ProvisioningProtector`] and
//! [`ProvisioningUnprotector`] implementations which own the outer artifact
//! format and its key custody. Persistent custody is a separate capability:
//! [`ProvisioningSecretInstaller`], [`ProvisioningSecretLoader`], and
//! [`ProvisioningSecretDestroyer`] use bounded opaque references as durable
//! identifiers; install and load still transfer owned zeroizing plaintext at
//! the in-process capability boundary. A reference may itself be a sensitive
//! store capability and must not be logged. Successful destruction records
//! only the trusted backend's contract assertion and never implies
//! physical-media erasure.

use std::error::Error;
use std::fmt;
use std::sync::Arc as Shared;
use zeroize::Zeroize;

const UNPROTECTED_PROVISIONING_MAGIC: &[u8; 8] = b"ASTRPB03";
const PROVISIONING_SECRET_REF_MAGIC: &[u8; 8] = b"ASTRSREF";
const PROVISIONING_SECRET_REF_VERSION: u16 = 1;
const PROVISIONING_SECRET_REF_HEADER_BYTES: usize = 8 + 2 + 4;
const MAX_PROVISIONING_SECRET_REF_OPAQUE_BYTES: usize =
    MAX_PROVISIONING_SECRET_REF_BYTES - PROVISIONING_SECRET_REF_HEADER_BYTES;

/// Fixed length of a caller-chosen persistent-secret operation identifier.
pub const PROVISIONING_SECRET_OPERATION_ID_BYTES: usize = 32;

/// Maximum canonical encoded length of one opaque persistent-secret reference.
///
/// The bound includes the Aster reference header. The payload is a
/// backend-defined persistent locator or capability, not provisioning
/// plaintext. Opacity does not make it public: callers must persist and handle
/// it according to the configured backend's confidentiality requirements.
pub const MAX_PROVISIONING_SECRET_REF_BYTES: usize = 8 * 1024;

/// Exact maximum length of a canonical `ASTRPB03` plaintext bundle.
///
/// This follows from the fixed v3 key/signature sizes, the 256 route-grant and
/// 256 content-grant limits, and 128-byte scope/topic names.
pub const MAX_UNPROTECTED_PROVISIONING_BYTES: usize = 125_877;

/// Maximum accepted size of one provider-owned protected artifact.
///
/// Outer formats may carry recipient and recovery metadata, but node opening
/// remains a bounded operation. Providers needing more than one MiB must first
/// justify and revise this public contract.
pub const MAX_PROTECTED_PROVISIONING_BYTES: usize = 1024 * 1024;

/// Sanitized failure from a local provisioning-protection provider.
///
/// Variants intentionally carry no provider strings, paths, recipient names,
/// key identifiers, or plaintext details because this error may cross logging
/// and language-binding boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningProtectionError {
    /// The configured provider, credential, hardware, or key store is not
    /// currently available.
    Unavailable,
    /// The artifact was malformed, unauthenticated, or not addressed to an
    /// available recipient.
    Rejected,
    /// A protected artifact or recovered plaintext exceeded its public bound.
    TooLarge,
}

impl fmt::Display for ProvisioningProtectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("provisioning protection is unavailable"),
            Self::Rejected => formatter.write_str("protected provisioning artifact was rejected"),
            Self::TooLarge => formatter.write_str("provisioning artifact exceeds its size limit"),
        }
    }
}

impl Error for ProvisioningProtectionError {}

/// Typed, sanitized failure while importing or exporting a protected bundle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProtectedProvisioningError {
    /// The provider failed with a safe public category.
    Protection(ProvisioningProtectionError),
    /// The canonical inner bundle was invalid or already zeroized.
    InvalidBundle,
}

impl fmt::Display for ProtectedProvisioningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protection(error) => fmt::Display::fmt(error, formatter),
            Self::InvalidBundle => formatter.write_str("provisioning bundle is invalid"),
        }
    }
}

impl Error for ProtectedProvisioningError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protection(error) => Some(error),
            Self::InvalidBundle => None,
        }
    }
}

impl From<ProvisioningProtectionError> for ProtectedProvisioningError {
    fn from(error: ProvisioningProtectionError) -> Self {
        Self::Protection(error)
    }
}

/// Owned plaintext provisioning bytes which are erased on zeroize and drop.
///
/// This type deliberately does not implement `Clone`, `Deref`, `Display`,
/// serialization, or equality. Calling [`Self::expose`] is an explicit secret
/// access operation intended for protection providers and bounded ingestion.
pub struct UnprotectedProvisioning {
    bytes: Vec<u8>,
    #[cfg(test)]
    zeroization_observer: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl UnprotectedProvisioning {
    /// Takes ownership of a nonempty, bounded plaintext bundle buffer.
    ///
    /// Rejected input is erased before the error is returned.
    pub fn new(mut bytes: Vec<u8>) -> Result<Self, ProvisioningProtectionError> {
        if bytes.is_empty() {
            bytes.zeroize();
            return Err(ProvisioningProtectionError::Rejected);
        }
        if bytes.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
            bytes.zeroize();
            return Err(ProvisioningProtectionError::TooLarge);
        }
        Ok(Self {
            bytes,
            #[cfg(test)]
            zeroization_observer: None,
        })
    }

    /// Explicitly exposes the plaintext for immediate protection or ingestion.
    pub fn expose(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the bounded plaintext length without exposing its contents.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether explicit zeroization has emptied the owned buffer.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Reports whether explicit zeroization has emptied the owned buffer.
    pub fn is_zeroized(&self) -> bool {
        self.is_empty()
    }

    /// Erases and empties the owned plaintext buffer immediately.
    pub fn zeroize(&mut self) {
        self.bytes.zeroize();
        #[cfg(test)]
        if let Some(observer) = &self.zeroization_observer {
            observer.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[cfg(test)]
    fn with_zeroization_observer(
        bytes: Vec<u8>,
        observer: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Self, ProvisioningProtectionError> {
        let mut plaintext = Self::new(bytes)?;
        plaintext.zeroization_observer = Some(observer);
        Ok(plaintext)
    }
}

impl fmt::Debug for UnprotectedProvisioning {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnprotectedProvisioning([REDACTED])")
    }
}

impl Drop for UnprotectedProvisioning {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Eq, Hash, PartialEq)]
struct ProvisioningSecretRefInner {
    opaque: Vec<u8>,
}

impl Drop for ProvisioningSecretRefInner {
    fn drop(&mut self) {
        self.opaque.zeroize();
    }
}

/// Versioned, bounded, backend-owned reference to persisted provisioning secrets.
///
/// The payload is deliberately distinct from provisioning plaintext, but may
/// be a sensitive locator or bearer capability. Debug output is therefore
/// always redacted. The configured backend must authenticate or otherwise
/// validate the payload before loading or destroying anything; canonical
/// decoding alone does not make a reference trustworthy. Clones share one
/// immutable backing allocation, which is zeroized when its last clone drops.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ProvisioningSecretRef {
    inner: Shared<ProvisioningSecretRefInner>,
}

impl ProvisioningSecretRef {
    /// Wraps one nonempty backend reference payload.
    ///
    /// Rejected input is erased before returning. Provisioning plaintext must
    /// never be embedded in this persistent reference.
    pub fn from_opaque(mut opaque: Vec<u8>) -> Result<Self, ProvisioningSecretStoreError> {
        if opaque.is_empty() {
            opaque.zeroize();
            return Err(ProvisioningSecretStoreError::InvalidReference);
        }
        if opaque.len() > MAX_PROVISIONING_SECRET_REF_OPAQUE_BYTES {
            opaque.zeroize();
            return Err(ProvisioningSecretStoreError::TooLarge);
        }
        Ok(Self {
            inner: Shared::new(ProvisioningSecretRefInner { opaque }),
        })
    }

    /// Decodes one exact canonical Aster opaque-reference encoding.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, ProvisioningSecretStoreError> {
        if encoded.len() > MAX_PROVISIONING_SECRET_REF_BYTES {
            return Err(ProvisioningSecretStoreError::TooLarge);
        }
        if encoded.len() < PROVISIONING_SECRET_REF_HEADER_BYTES
            || &encoded[..8] != PROVISIONING_SECRET_REF_MAGIC
            || u16::from_be_bytes(
                encoded[8..10]
                    .try_into()
                    .map_err(|_| ProvisioningSecretStoreError::InvalidReference)?,
            ) != PROVISIONING_SECRET_REF_VERSION
        {
            return Err(ProvisioningSecretStoreError::InvalidReference);
        }
        let opaque_len = usize::try_from(u32::from_be_bytes(
            encoded[10..14]
                .try_into()
                .map_err(|_| ProvisioningSecretStoreError::InvalidReference)?,
        ))
        .map_err(|_| ProvisioningSecretStoreError::InvalidReference)?;
        if opaque_len == 0
            || opaque_len > MAX_PROVISIONING_SECRET_REF_OPAQUE_BYTES
            || PROVISIONING_SECRET_REF_HEADER_BYTES.checked_add(opaque_len) != Some(encoded.len())
        {
            return Err(ProvisioningSecretStoreError::InvalidReference);
        }
        Self::from_opaque(encoded[PROVISIONING_SECRET_REF_HEADER_BYTES..].to_vec())
    }

    /// Encodes this reference canonically for caller-managed persistence.
    ///
    /// The returned buffer may contain a bearer capability. Its caller owns
    /// both its persistence policy and any required memory erasure.
    pub fn to_bytes(&self) -> Vec<u8> {
        let opaque_len = u32::try_from(self.inner.opaque.len())
            .expect("bounded provisioning secret reference length fits in u32");
        let mut encoded =
            Vec::with_capacity(PROVISIONING_SECRET_REF_HEADER_BYTES + self.inner.opaque.len());
        encoded.extend_from_slice(PROVISIONING_SECRET_REF_MAGIC);
        encoded.extend_from_slice(&PROVISIONING_SECRET_REF_VERSION.to_be_bytes());
        encoded.extend_from_slice(&opaque_len.to_be_bytes());
        encoded.extend_from_slice(&self.inner.opaque);
        encoded
    }

    /// Explicitly exposes the backend-owned opaque locator or capability.
    ///
    /// Callers should pass this only to the configured secret-store backend and
    /// must not log it.
    pub fn expose_opaque(&self) -> &[u8] {
        &self.inner.opaque
    }

    /// Returns the canonical encoded reference length.
    pub fn encoded_len(&self) -> usize {
        PROVISIONING_SECRET_REF_HEADER_BYTES + self.inner.opaque.len()
    }
}

impl TryFrom<&[u8]> for ProvisioningSecretRef {
    type Error = ProvisioningSecretStoreError;

    fn try_from(encoded: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(encoded)
    }
}

impl fmt::Debug for ProvisioningSecretRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningSecretRef([REDACTED])")
    }
}

/// Caller-chosen identity of one logical persistent-secret install operation.
///
/// Operation identities are scoped to one persistent backend namespace and to
/// this operation kind; they are not authentication credentials or globally
/// unique identifiers. The caller must use a fresh identity for each logical
/// install and retain it across retries. Once created, the backend must retain
/// the operation-to-install binding until that namespace is explicitly retired.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProvisioningInstallId([u8; PROVISIONING_SECRET_OPERATION_ID_BYTES]);

impl ProvisioningInstallId {
    /// Constructs an install-operation identity from exact caller-owned bytes.
    pub const fn new(bytes: [u8; PROVISIONING_SECRET_OPERATION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact operation identity.
    pub const fn as_bytes(&self) -> &[u8; PROVISIONING_SECRET_OPERATION_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ProvisioningInstallId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningInstallId([REDACTED])")
    }
}

/// Caller-chosen identity of one logical persistent-secret load operation.
///
/// Operation identities are scoped to one persistent backend namespace and to
/// this operation kind; they are not authentication credentials or globally
/// unique identifiers. The caller must use a fresh identity for each logical
/// load and retain it across retries. The backend must retain the first
/// operation-to-reference binding, including one whose load fails, until that
/// namespace is explicitly retired.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProvisioningLoadId([u8; PROVISIONING_SECRET_OPERATION_ID_BYTES]);

impl ProvisioningLoadId {
    /// Constructs a load-operation identity from exact caller-owned bytes.
    pub const fn new(bytes: [u8; PROVISIONING_SECRET_OPERATION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact operation identity.
    pub const fn as_bytes(&self) -> &[u8; PROVISIONING_SECRET_OPERATION_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ProvisioningLoadId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningLoadId([REDACTED])")
    }
}

/// Caller-chosen identity of one logical persistent-secret destroy operation.
///
/// Operation identities are scoped to one persistent backend namespace and to
/// this operation kind; they are not authentication credentials or globally
/// unique identifiers. The caller must use a fresh identity for each logical
/// destruction and retain it across retries. The backend must retain the first
/// operation-to-reference binding, including one whose destruction fails,
/// until that namespace is explicitly retired.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ProvisioningDestroyId([u8; PROVISIONING_SECRET_OPERATION_ID_BYTES]);

impl ProvisioningDestroyId {
    /// Constructs a destroy-operation identity from exact caller-owned bytes.
    pub const fn new(bytes: [u8; PROVISIONING_SECRET_OPERATION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the exact operation identity.
    pub const fn as_bytes(&self) -> &[u8; PROVISIONING_SECRET_OPERATION_ID_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ProvisioningDestroyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProvisioningDestroyId([REDACTED])")
    }
}

/// Sanitized failure from persistent provisioning-secret custody.
///
/// Variants contain no backend text, locator, operation identity, path, or
/// credential detail. In particular, [`Self::NotFound`] is indeterminate and
/// must never be treated as evidence that destruction completed. Only
/// [`Self::Destroyed`] or a [`ProvisioningDestroyReceipt`] records the trusted
/// backend's assertion that its destruction contract was satisfied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProvisioningSecretStoreError {
    /// The configured persistent store or its credential is unavailable.
    Unavailable,
    /// The backend rejected or could not authenticate the request.
    Rejected,
    /// The opaque reference encoding is empty, malformed, or unsupported.
    InvalidReference,
    /// A bounded reference or recovered plaintext exceeded its public limit.
    TooLarge,
    /// One operation identity was reused for a different logical request.
    OperationConflict,
    /// The reference is unknown; destruction is indeterminate, not confirmed.
    NotFound,
    /// The trusted backend reports an authenticated destruction tombstone.
    Destroyed,
}

impl ProvisioningSecretStoreError {
    /// Reports an unknown reference whose destruction state is indeterminate.
    pub const fn is_indeterminate_not_found(self) -> bool {
        matches!(self, Self::NotFound)
    }

    /// Reports that the trusted backend returned its destroyed category.
    ///
    /// This classifies the backend response; it does not independently prove
    /// persistence, media sanitization, or physical erasure.
    pub const fn is_backend_reported_destroyed(self) -> bool {
        matches!(self, Self::Destroyed)
    }
}

impl fmt::Display for ProvisioningSecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("provisioning secret store is unavailable"),
            Self::Rejected => formatter.write_str("provisioning secret store rejected the request"),
            Self::InvalidReference => {
                formatter.write_str("provisioning secret reference is invalid")
            }
            Self::TooLarge => {
                formatter.write_str("provisioning secret value exceeds its size limit")
            }
            Self::OperationConflict => formatter
                .write_str("provisioning secret operation conflicts with its durable record"),
            Self::NotFound => formatter.write_str("provisioning secret reference was not found"),
            Self::Destroyed => {
                formatter.write_str("provisioning secret store reports the secret destroyed")
            }
        }
    }
}

impl Error for ProvisioningSecretStoreError {}

/// Durable disposition of a persistent-secret install operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningInstallDisposition {
    /// This call installed the secret for the first time.
    Installed,
    /// The exact logical operation was already durably installed.
    Existing,
}

/// Durable receipt for one exact persistent-secret install operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningInstallReceipt {
    operation: ProvisioningInstallId,
    secret_ref: ProvisioningSecretRef,
    disposition: ProvisioningInstallDisposition,
}

impl ProvisioningInstallReceipt {
    /// Constructs a receipt after a backend has durably installed the secret.
    pub fn installed(operation: ProvisioningInstallId, secret_ref: ProvisioningSecretRef) -> Self {
        Self {
            operation,
            secret_ref,
            disposition: ProvisioningInstallDisposition::Installed,
        }
    }

    /// Reconstructs the receipt for an exact already-installed operation.
    pub fn existing(operation: ProvisioningInstallId, secret_ref: ProvisioningSecretRef) -> Self {
        Self {
            operation,
            secret_ref,
            disposition: ProvisioningInstallDisposition::Existing,
        }
    }

    /// Exact logical operation named by this receipt.
    pub const fn operation(&self) -> ProvisioningInstallId {
        self.operation
    }

    /// Opaque reference durably bound to the operation.
    pub const fn secret_ref(&self) -> &ProvisioningSecretRef {
        &self.secret_ref
    }

    /// Whether this call installed or recovered an existing operation.
    pub const fn disposition(&self) -> ProvisioningInstallDisposition {
        self.disposition
    }

    /// Consumes the receipt and returns its opaque reference.
    pub fn into_secret_ref(self) -> ProvisioningSecretRef {
        self.secret_ref
    }
}

/// Ephemeral successful load result carrying Aster-owned plaintext.
pub struct ProvisioningLoadReceipt {
    operation: ProvisioningLoadId,
    secret_ref: ProvisioningSecretRef,
    plaintext: UnprotectedProvisioning,
}

impl ProvisioningLoadReceipt {
    /// Constructs a load result after authenticating the exact reference.
    pub fn new(
        operation: ProvisioningLoadId,
        secret_ref: ProvisioningSecretRef,
        plaintext: UnprotectedProvisioning,
    ) -> Self {
        Self {
            operation,
            secret_ref,
            plaintext,
        }
    }

    /// Exact logical operation named by this result.
    pub const fn operation(&self) -> ProvisioningLoadId {
        self.operation
    }

    /// Exact authenticated reference loaded by the backend.
    pub const fn secret_ref(&self) -> &ProvisioningSecretRef {
        &self.secret_ref
    }

    /// Explicitly exposes the loaded plaintext for immediate bounded ingestion.
    pub fn plaintext(&self) -> &UnprotectedProvisioning {
        &self.plaintext
    }

    /// Transfers the Aster-owned zeroizing plaintext to the caller.
    pub fn into_plaintext(self) -> UnprotectedProvisioning {
        self.plaintext
    }
}

impl fmt::Debug for ProvisioningLoadReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisioningLoadReceipt")
            .field("operation", &self.operation)
            .field("secret_ref", &self.secret_ref)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

/// Durable disposition of a persistent-secret destruction operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProvisioningDestroyDisposition {
    /// The backend reports that this call destroyed the secret and committed its tombstone.
    Destroyed,
    /// The backend reports an existing tombstone for the exact secret.
    AlreadyDestroyed,
}

/// Durable backend receipt for destruction of one exact secret reference.
///
/// The receipt records the configured backend's assertion of logical
/// destruction and its required durable tombstone. Aster can validate the
/// echoed operation and reference, but cannot independently prove the
/// backend's durability. The receipt makes no claim about physical flash,
/// snapshots, backups, swap, remanence, or media sanitization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningDestroyReceipt {
    operation: ProvisioningDestroyId,
    secret_ref: ProvisioningSecretRef,
    disposition: ProvisioningDestroyDisposition,
}

impl ProvisioningDestroyReceipt {
    /// Records the backend's first-destruction and tombstone-commit assertion.
    pub fn destroyed(operation: ProvisioningDestroyId, secret_ref: ProvisioningSecretRef) -> Self {
        Self {
            operation,
            secret_ref,
            disposition: ProvisioningDestroyDisposition::Destroyed,
        }
    }

    /// Records the backend's assertion from an authenticated existing tombstone.
    pub fn already_destroyed(
        operation: ProvisioningDestroyId,
        secret_ref: ProvisioningSecretRef,
    ) -> Self {
        Self {
            operation,
            secret_ref,
            disposition: ProvisioningDestroyDisposition::AlreadyDestroyed,
        }
    }

    /// Exact logical operation named by this receipt.
    pub const fn operation(&self) -> ProvisioningDestroyId {
        self.operation
    }

    /// Exact opaque reference whose tombstone was authenticated.
    pub const fn secret_ref(&self) -> &ProvisioningSecretRef {
        &self.secret_ref
    }

    /// Whether this call destroyed or recovered an existing tombstone.
    pub const fn disposition(&self) -> ProvisioningDestroyDisposition {
        self.disposition
    }

    /// Physical-media erasure is never claimed by this provider-neutral receipt.
    pub const fn claims_physical_media_erasure(&self) -> bool {
        false
    }
}

/// Capability to durably install newly recovered provisioning plaintext.
///
/// The backend takes ownership of the zeroizing plaintext. Repeating the same
/// operation identity with the same plaintext must return the same reference
/// with [`ProvisioningInstallDisposition::Existing`]; reusing it for different
/// plaintext must return [`ProvisioningSecretStoreError::OperationConflict`].
/// A destroyed existing operation must return
/// [`ProvisioningSecretStoreError::Destroyed`] and must never resurrect it.
/// Callers should use [`install_provisioning_secret`] so a zeroized payload is
/// rejected before invocation and the receipt operation is checked.
pub trait ProvisioningSecretInstaller {
    /// Durably installs one logical provisioning secret operation.
    ///
    /// Implementations must reject an already-zeroized plaintext without
    /// creating an operation binding. Normal callers should still use
    /// [`install_provisioning_secret`] so this precondition is enforced before
    /// the backend capability is invoked.
    fn install(
        &mut self,
        operation: ProvisioningInstallId,
        plaintext: UnprotectedProvisioning,
    ) -> Result<ProvisioningInstallReceipt, ProvisioningSecretStoreError>;
}

/// Capability to load provisioning plaintext from an authenticated opaque reference.
///
/// Once it can update its persistent namespace, a backend must bind a load
/// operation identity to its exact reference before returning a
/// reference-specific outcome, including `NotFound`, `Destroyed`, or
/// authenticated rejection. Reuse for a different reference must fail with
/// [`ProvisioningSecretStoreError::OperationConflict`]. Unknown references
/// return indeterminate [`ProvisioningSecretStoreError::NotFound`]; references
/// with authenticated durable tombstones return
/// [`ProvisioningSecretStoreError::Destroyed`]. An `Unavailable` result may
/// precede binding when the namespace cannot be reached. Callers should use
/// [`load_provisioning_secret`] so exact receipt echoes are checked.
pub trait ProvisioningSecretLoader {
    /// Loads one exact reference into an Aster-owned zeroizing result.
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError>;
}

/// Capability to durably destroy one exact provisioning-secret reference.
///
/// The backend must commit an authenticated tombstone before returning a
/// receipt. Repeating the same operation and reference is idempotent. Reusing
/// an operation identity for another reference is a conflict. Once the backend
/// can update its namespace, it must retain that binding even when the exact
/// reference returns `NotFound`, `Destroyed`, or another reference-specific
/// failure; `Unavailable` may precede binding. An unknown reference returns
/// indeterminate [`ProvisioningSecretStoreError::NotFound`] and must never be
/// promoted to a destruction receipt. Callers should use
/// [`destroy_provisioning_secret`] so exact receipt echoes are checked. This
/// interface makes no provider-independent physical-media erasure claim.
pub trait ProvisioningSecretDestroyer {
    /// Destroys one exact secret or recovers its durable tombstone receipt.
    fn destroy(
        &mut self,
        operation: ProvisioningDestroyId,
        secret_ref: &ProvisioningSecretRef,
    ) -> Result<ProvisioningDestroyReceipt, ProvisioningSecretStoreError>;
}

/// Installs one provisioning secret and checks the backend's receipt echo.
///
/// A zeroized plaintext is rejected without invoking `installer`. On backend
/// success, the receipt must echo the exact caller-selected operation. A
/// mismatched receipt is rejected as a backend contract violation; that error
/// does not imply that backend side effects were rolled back.
pub fn install_provisioning_secret<I>(
    operation: ProvisioningInstallId,
    plaintext: UnprotectedProvisioning,
    installer: &mut I,
) -> Result<ProvisioningInstallReceipt, ProvisioningSecretStoreError>
where
    I: ProvisioningSecretInstaller + ?Sized,
{
    if plaintext.is_zeroized() {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    let receipt = installer.install(operation, plaintext)?;
    if receipt.operation() != operation {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(receipt)
}

/// Loads one provisioning secret and checks the backend's exact receipt echo.
///
/// The successful receipt must echo both the caller-selected operation and the
/// exact persistent reference. A mismatched receipt and its zeroizing plaintext
/// are discarded with [`ProvisioningSecretStoreError::Rejected`].
pub fn load_provisioning_secret<L>(
    operation: ProvisioningLoadId,
    secret_ref: &ProvisioningSecretRef,
    loader: &mut L,
) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError>
where
    L: ProvisioningSecretLoader + ?Sized,
{
    let receipt = loader.load(operation, secret_ref)?;
    if receipt.operation() != operation || receipt.secret_ref() != secret_ref {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(receipt)
}

/// Destroys one provisioning secret and checks the backend's exact receipt echo.
///
/// A successful typed receipt carries either the backend's first-destruction or
/// already-destroyed disposition and must echo both the caller-selected
/// operation and reference. The helper validates those echoes; it trusts, but
/// cannot independently prove, the backend's tombstone/durability assertion.
/// Receipt rejection does not imply that backend side effects were rolled back.
pub fn destroy_provisioning_secret<D>(
    operation: ProvisioningDestroyId,
    secret_ref: &ProvisioningSecretRef,
    destroyer: &mut D,
) -> Result<ProvisioningDestroyReceipt, ProvisioningSecretStoreError>
where
    D: ProvisioningSecretDestroyer + ?Sized,
{
    let receipt = destroyer.destroy(operation, secret_ref)?;
    if receipt.operation() != operation || receipt.secret_ref() != secret_ref {
        return Err(ProvisioningSecretStoreError::Rejected);
    }
    Ok(receipt)
}

/// Provider-owned outer protection for newly issued local provisioning artifacts.
///
/// Issuing authorities normally hold only recipient public material. Keeping
/// this capability separate from [`ProvisioningUnprotector`] avoids requiring
/// one object to hold both recipient and identity/private-key capabilities.
pub trait ProvisioningProtector {
    /// Protects one canonical plaintext bundle for local storage or transfer.
    fn protect(
        &mut self,
        plaintext: &UnprotectedProvisioning,
    ) -> Result<Vec<u8>, ProvisioningProtectionError>;
}

/// Provider-owned opening of an existing local provisioning artifact.
///
/// Implementations may use an admitted file-envelope library, a platform key
/// store, hardware-backed keys, or a deployment service. They must authenticate
/// before releasing plaintext, honor `max_plaintext_len` while reading, return
/// only sanitized errors, and never fall back to interpreting `protected` as
/// plaintext. This boundary does not define a mesh wire format.
pub trait ProvisioningUnprotector {
    /// Authenticates and opens one protected artifact into an owned secret.
    fn unprotect(
        &mut self,
        protected: &[u8],
        max_plaintext_len: usize,
    ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError>;
}

/// Invokes one protection provider and validates its bounded outer artifact.
pub fn protect_provisioning_artifact<P>(
    plaintext: &UnprotectedProvisioning,
    protector: &mut P,
) -> Result<Vec<u8>, ProvisioningProtectionError>
where
    P: ProvisioningProtector + ?Sized,
{
    let mut protected = protector.protect(plaintext)?;
    if let Err(error) = validate_protected_artifact(&protected) {
        protected.zeroize();
        return Err(error);
    }
    Ok(protected)
}

/// Validates and opens one provider-owned artifact at most once.
///
/// Empty, oversized, and raw `ASTRPB03` inputs are rejected before provider
/// invocation. A nonempty bounded outer artifact invokes the provider exactly
/// once, then independently rechecks the recovered plaintext bound.
pub fn unprotect_provisioning_artifact<P>(
    protected: &[u8],
    unprotector: &mut P,
) -> Result<UnprotectedProvisioning, ProvisioningProtectionError>
where
    P: ProvisioningUnprotector + ?Sized,
{
    validate_protected_artifact(protected)?;
    let mut plaintext = unprotector.unprotect(protected, MAX_UNPROTECTED_PROVISIONING_BYTES)?;
    if plaintext.is_empty() {
        plaintext.zeroize();
        return Err(ProvisioningProtectionError::Rejected);
    }
    if plaintext.len() > MAX_UNPROTECTED_PROVISIONING_BYTES {
        plaintext.zeroize();
        return Err(ProvisioningProtectionError::TooLarge);
    }
    Ok(plaintext)
}

pub(crate) fn validate_protected_artifact(
    protected: &[u8],
) -> Result<(), ProvisioningProtectionError> {
    if protected.is_empty() || protected.starts_with(UNPROTECTED_PROVISIONING_MAGIC) {
        return Err(ProvisioningProtectionError::Rejected);
    }
    if protected.len() > MAX_PROTECTED_PROVISIONING_BYTES {
        return Err(ProvisioningProtectionError::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::HashMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    struct OutputProtector(Option<Vec<u8>>);

    impl ProvisioningProtector for OutputProtector {
        fn protect(
            &mut self,
            _plaintext: &UnprotectedProvisioning,
        ) -> Result<Vec<u8>, ProvisioningProtectionError> {
            self.0
                .take()
                .ok_or(ProvisioningProtectionError::Unavailable)
        }
    }

    struct EchoUnprotector {
        calls: usize,
    }

    impl ProvisioningUnprotector for EchoUnprotector {
        fn unprotect(
            &mut self,
            protected: &[u8],
            _max_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.calls += 1;
            UnprotectedProvisioning::new(protected.to_vec())
        }
    }

    // Test-only installer used to observe plaintext ownership and zeroization.
    #[derive(Default)]
    struct PersistentTestSecretState {
        installs: HashMap<ProvisioningInstallId, TestInstallRecord>,
        entries: HashMap<ProvisioningSecretRef, TestSecretEntry>,
    }

    #[derive(Clone)]
    struct TestInstallRecord {
        secret_ref: ProvisioningSecretRef,
    }

    struct TestSecretEntry {
        plaintext: UnprotectedProvisioning,
    }

    struct PersistentTestSecretStore {
        state: Arc<Mutex<PersistentTestSecretState>>,
    }

    impl PersistentTestSecretStore {
        fn open(state: Arc<Mutex<PersistentTestSecretState>>) -> Self {
            Self { state }
        }
    }

    impl ProvisioningSecretInstaller for PersistentTestSecretStore {
        fn install(
            &mut self,
            operation: ProvisioningInstallId,
            plaintext: UnprotectedProvisioning,
        ) -> Result<ProvisioningInstallReceipt, ProvisioningSecretStoreError> {
            if plaintext.is_zeroized() {
                return Err(ProvisioningSecretStoreError::Rejected);
            }
            let mut state = self.state.lock().expect("test secret state");
            if let Some(existing) = state.installs.get(&operation).cloned() {
                let entry = state
                    .entries
                    .get(&existing.secret_ref)
                    .ok_or(ProvisioningSecretStoreError::Rejected)?;
                if entry.plaintext.expose() != plaintext.expose() {
                    return Err(ProvisioningSecretStoreError::OperationConflict);
                }
                return Ok(ProvisioningInstallReceipt::existing(
                    operation,
                    existing.secret_ref,
                ));
            }

            let mut opaque = b"cfg-test-secret-ref/".to_vec();
            opaque.extend_from_slice(operation.as_bytes());
            let secret_ref = ProvisioningSecretRef::from_opaque(opaque)?;
            state
                .entries
                .insert(secret_ref.clone(), TestSecretEntry { plaintext });
            state.installs.insert(
                operation,
                TestInstallRecord {
                    secret_ref: secret_ref.clone(),
                },
            );
            Ok(ProvisioningInstallReceipt::installed(operation, secret_ref))
        }
    }

    struct EchoingInstaller {
        calls: usize,
        returned_operation: ProvisioningInstallId,
        returned_ref: ProvisioningSecretRef,
    }

    impl ProvisioningSecretInstaller for EchoingInstaller {
        fn install(
            &mut self,
            _operation: ProvisioningInstallId,
            _plaintext: UnprotectedProvisioning,
        ) -> Result<ProvisioningInstallReceipt, ProvisioningSecretStoreError> {
            self.calls += 1;
            Ok(ProvisioningInstallReceipt::installed(
                self.returned_operation,
                self.returned_ref.clone(),
            ))
        }
    }

    struct EchoingLoader {
        calls: usize,
        returned_operation: ProvisioningLoadId,
        returned_ref: ProvisioningSecretRef,
        plaintext: Option<UnprotectedProvisioning>,
    }

    impl ProvisioningSecretLoader for EchoingLoader {
        fn load(
            &mut self,
            _operation: ProvisioningLoadId,
            _secret_ref: &ProvisioningSecretRef,
        ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
            self.calls += 1;
            Ok(ProvisioningLoadReceipt::new(
                self.returned_operation,
                self.returned_ref.clone(),
                self.plaintext
                    .take()
                    .ok_or(ProvisioningSecretStoreError::Unavailable)?,
            ))
        }
    }

    struct EchoingDestroyer {
        calls: usize,
        returned_operation: ProvisioningDestroyId,
        returned_ref: ProvisioningSecretRef,
        disposition: ProvisioningDestroyDisposition,
    }

    impl ProvisioningSecretDestroyer for EchoingDestroyer {
        fn destroy(
            &mut self,
            _operation: ProvisioningDestroyId,
            _secret_ref: &ProvisioningSecretRef,
        ) -> Result<ProvisioningDestroyReceipt, ProvisioningSecretStoreError> {
            self.calls += 1;
            Ok(match self.disposition {
                ProvisioningDestroyDisposition::Destroyed => ProvisioningDestroyReceipt::destroyed(
                    self.returned_operation,
                    self.returned_ref.clone(),
                ),
                ProvisioningDestroyDisposition::AlreadyDestroyed => {
                    ProvisioningDestroyReceipt::already_destroyed(
                        self.returned_operation,
                        self.returned_ref.clone(),
                    )
                }
            })
        }
    }

    #[test]
    fn unprotected_provisioning_is_redacted_and_explicitly_erased() {
        let canary = b"provisioning-secret-canary".to_vec();
        let mut plaintext = UnprotectedProvisioning::new(canary.clone()).unwrap();

        let debug = format!("{plaintext:?}");
        assert_eq!(debug, "UnprotectedProvisioning([REDACTED])");
        assert!(
            !debug
                .as_bytes()
                .windows(canary.len())
                .any(|part| part == canary)
        );
        assert_eq!(plaintext.expose(), canary);

        plaintext.zeroize();
        assert!(plaintext.is_zeroized());
        assert!(plaintext.expose().is_empty());
    }

    #[test]
    fn provisioning_artifact_bounds_fail_closed() {
        assert!(UnprotectedProvisioning::new(vec![0; MAX_UNPROTECTED_PROVISIONING_BYTES]).is_ok());
        assert_eq!(
            UnprotectedProvisioning::new(Vec::new()).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );
        assert_eq!(
            UnprotectedProvisioning::new(vec![0; MAX_UNPROTECTED_PROVISIONING_BYTES + 1])
                .unwrap_err(),
            ProvisioningProtectionError::TooLarge
        );
        assert_eq!(
            validate_protected_artifact(&[]).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );
        assert_eq!(
            validate_protected_artifact(b"ASTRPB03raw-bundle").unwrap_err(),
            ProvisioningProtectionError::Rejected
        );
        assert!(validate_protected_artifact(&vec![0; MAX_PROTECTED_PROVISIONING_BYTES]).is_ok());
        assert_eq!(
            validate_protected_artifact(&vec![0; MAX_PROTECTED_PROVISIONING_BYTES + 1])
                .unwrap_err(),
            ProvisioningProtectionError::TooLarge
        );
    }

    #[test]
    fn empty_oversized_and_echo_protection_are_rejected() {
        let plaintext = UnprotectedProvisioning::new(b"ASTRPB03inner-secret".to_vec()).unwrap();

        let mut empty = OutputProtector(Some(Vec::new()));
        assert_eq!(
            protect_provisioning_artifact(&plaintext, &mut empty).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );

        let mut oversized = OutputProtector(Some(vec![0; MAX_PROTECTED_PROVISIONING_BYTES + 1]));
        assert_eq!(
            protect_provisioning_artifact(&plaintext, &mut oversized).unwrap_err(),
            ProvisioningProtectionError::TooLarge
        );

        let mut echo = OutputProtector(Some(plaintext.expose().to_vec()));
        assert_eq!(
            protect_provisioning_artifact(&plaintext, &mut echo).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );

        let mut echo_opener = EchoUnprotector { calls: 0 };
        assert_eq!(
            unprotect_provisioning_artifact(plaintext.expose(), &mut echo_opener).unwrap_err(),
            ProvisioningProtectionError::Rejected
        );
        assert_eq!(echo_opener.calls, 0);
    }

    #[test]
    fn secret_reference_is_bounded_canonical_versioned_and_redacted() {
        use std::hash::{DefaultHasher, Hash as _, Hasher as _};

        let canary = b"backend-key-slot-secret-canary";
        let secret_ref = ProvisioningSecretRef::from_opaque(canary.to_vec()).unwrap();
        let debug = format!("{secret_ref:?}");
        assert_eq!(debug, "ProvisioningSecretRef([REDACTED])");
        assert!(!debug.contains("backend-key-slot-secret-canary"));

        let encoded = secret_ref.to_bytes();
        assert_eq!(secret_ref.encoded_len(), encoded.len());
        assert_eq!(
            ProvisioningSecretRef::from_bytes(&encoded).unwrap(),
            secret_ref
        );
        assert_eq!(
            ProvisioningSecretRef::try_from(encoded.as_slice()).unwrap(),
            secret_ref
        );
        let shared = secret_ref.clone();
        assert!(Shared::ptr_eq(&secret_ref.inner, &shared.inner));
        let mut original_hash = DefaultHasher::new();
        secret_ref.hash(&mut original_hash);
        let mut shared_hash = DefaultHasher::new();
        shared.hash(&mut shared_hash);
        assert_eq!(original_hash.finish(), shared_hash.finish());
        drop(shared);
        assert_eq!(secret_ref.expose_opaque(), canary);
        assert_eq!(secret_ref.to_bytes(), encoded);

        let maximum = ProvisioningSecretRef::from_opaque(vec![
            0x5a;
            MAX_PROVISIONING_SECRET_REF_OPAQUE_BYTES
        ])
        .unwrap();
        assert_eq!(maximum.to_bytes().len(), MAX_PROVISIONING_SECRET_REF_BYTES);
        assert_eq!(
            ProvisioningSecretRef::from_opaque(vec![
                0x5a;
                MAX_PROVISIONING_SECRET_REF_OPAQUE_BYTES + 1
            ])
            .unwrap_err(),
            ProvisioningSecretStoreError::TooLarge
        );

        assert_eq!(
            ProvisioningSecretRef::from_opaque(Vec::new()).unwrap_err(),
            ProvisioningSecretStoreError::InvalidReference
        );
        assert_eq!(
            ProvisioningSecretRef::from_bytes(&[]).unwrap_err(),
            ProvisioningSecretStoreError::InvalidReference
        );
        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert_eq!(
            ProvisioningSecretRef::from_bytes(&wrong_magic).unwrap_err(),
            ProvisioningSecretStoreError::InvalidReference
        );
        let mut wrong_version = encoded.clone();
        wrong_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert_eq!(
            ProvisioningSecretRef::from_bytes(&wrong_version).unwrap_err(),
            ProvisioningSecretStoreError::InvalidReference
        );
        let mut zero_length = encoded.clone();
        zero_length[10..14].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(
            ProvisioningSecretRef::from_bytes(&zero_length).unwrap_err(),
            ProvisioningSecretStoreError::InvalidReference
        );
        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(
            ProvisioningSecretRef::from_bytes(&truncated).unwrap_err(),
            ProvisioningSecretStoreError::InvalidReference
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            ProvisioningSecretRef::from_bytes(&trailing).unwrap_err(),
            ProvisioningSecretStoreError::InvalidReference
        );
        assert_eq!(
            ProvisioningSecretRef::from_bytes(&vec![0; MAX_PROVISIONING_SECRET_REF_BYTES + 1])
                .unwrap_err(),
            ProvisioningSecretStoreError::TooLarge
        );
    }

    #[test]
    fn checked_install_rejects_zeroized_input_before_call_and_wrong_operation_echo() {
        let operation = ProvisioningInstallId::new([0x91; 32]);
        let secret_ref =
            ProvisioningSecretRef::from_opaque(b"checked-install-ref".to_vec()).unwrap();
        let mut installer = EchoingInstaller {
            calls: 0,
            returned_operation: ProvisioningInstallId::new([0x92; 32]),
            returned_ref: secret_ref.clone(),
        };

        let mut zeroized =
            UnprotectedProvisioning::new(b"ASTRPB03zeroized-before-install".to_vec()).unwrap();
        zeroized.zeroize();
        assert_eq!(
            install_provisioning_secret(operation, zeroized, &mut installer).unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(installer.calls, 0);

        let dropped = Arc::new(AtomicBool::new(false));
        let plaintext = UnprotectedProvisioning::with_zeroization_observer(
            b"ASTRPB03live-install".to_vec(),
            Arc::clone(&dropped),
        )
        .unwrap();
        assert_eq!(
            install_provisioning_secret(operation, plaintext, &mut installer).unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(installer.calls, 1);
        assert!(dropped.load(Ordering::SeqCst));

        let mut exact = EchoingInstaller {
            calls: 0,
            returned_operation: operation,
            returned_ref: secret_ref.clone(),
        };
        let receipt = install_provisioning_secret(
            operation,
            UnprotectedProvisioning::new(b"ASTRPB03exact-install".to_vec()).unwrap(),
            &mut exact,
        )
        .unwrap();
        assert_eq!(receipt.operation(), operation);
        assert_eq!(receipt.secret_ref(), &secret_ref);
        assert_eq!(exact.calls, 1);
    }

    #[test]
    fn checked_load_requires_exact_operation_and_reference_echoes() {
        let operation = ProvisioningLoadId::new([0xa1; 32]);
        let secret_ref = ProvisioningSecretRef::from_opaque(b"checked-load-ref".to_vec()).unwrap();
        let other_ref = ProvisioningSecretRef::from_opaque(b"other-load-ref".to_vec()).unwrap();

        let wrong_operation_dropped = Arc::new(AtomicBool::new(false));
        let mut wrong_operation = EchoingLoader {
            calls: 0,
            returned_operation: ProvisioningLoadId::new([0xa2; 32]),
            returned_ref: secret_ref.clone(),
            plaintext: Some(
                UnprotectedProvisioning::with_zeroization_observer(
                    b"ASTRPB03wrong-load-operation".to_vec(),
                    Arc::clone(&wrong_operation_dropped),
                )
                .unwrap(),
            ),
        };
        assert_eq!(
            load_provisioning_secret(operation, &secret_ref, &mut wrong_operation).unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(wrong_operation.calls, 1);
        assert!(wrong_operation_dropped.load(Ordering::SeqCst));

        let wrong_ref_dropped = Arc::new(AtomicBool::new(false));
        let mut wrong_ref = EchoingLoader {
            calls: 0,
            returned_operation: operation,
            returned_ref: other_ref,
            plaintext: Some(
                UnprotectedProvisioning::with_zeroization_observer(
                    b"ASTRPB03wrong-load-ref".to_vec(),
                    Arc::clone(&wrong_ref_dropped),
                )
                .unwrap(),
            ),
        };
        assert_eq!(
            load_provisioning_secret(operation, &secret_ref, &mut wrong_ref).unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(wrong_ref.calls, 1);
        assert!(wrong_ref_dropped.load(Ordering::SeqCst));

        let exact_dropped = Arc::new(AtomicBool::new(false));
        let mut exact = EchoingLoader {
            calls: 0,
            returned_operation: operation,
            returned_ref: secret_ref.clone(),
            plaintext: Some(
                UnprotectedProvisioning::with_zeroization_observer(
                    b"ASTRPB03exact-load".to_vec(),
                    Arc::clone(&exact_dropped),
                )
                .unwrap(),
            ),
        };
        let receipt = load_provisioning_secret(operation, &secret_ref, &mut exact).unwrap();
        assert_eq!(receipt.operation(), operation);
        assert_eq!(receipt.secret_ref(), &secret_ref);
        assert!(!exact_dropped.load(Ordering::SeqCst));
        drop(receipt);
        assert!(exact_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn checked_destroy_requires_exact_echoes_and_accepts_backend_success_dispositions() {
        let operation = ProvisioningDestroyId::new([0xb1; 32]);
        let secret_ref =
            ProvisioningSecretRef::from_opaque(b"checked-destroy-ref".to_vec()).unwrap();
        let other_ref = ProvisioningSecretRef::from_opaque(b"other-destroy-ref".to_vec()).unwrap();

        let mut wrong_operation = EchoingDestroyer {
            calls: 0,
            returned_operation: ProvisioningDestroyId::new([0xb2; 32]),
            returned_ref: secret_ref.clone(),
            disposition: ProvisioningDestroyDisposition::Destroyed,
        };
        assert_eq!(
            destroy_provisioning_secret(operation, &secret_ref, &mut wrong_operation).unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(wrong_operation.calls, 1);

        let mut wrong_ref = EchoingDestroyer {
            calls: 0,
            returned_operation: operation,
            returned_ref: other_ref,
            disposition: ProvisioningDestroyDisposition::Destroyed,
        };
        assert_eq!(
            destroy_provisioning_secret(operation, &secret_ref, &mut wrong_ref).unwrap_err(),
            ProvisioningSecretStoreError::Rejected
        );
        assert_eq!(wrong_ref.calls, 1);

        for disposition in [
            ProvisioningDestroyDisposition::Destroyed,
            ProvisioningDestroyDisposition::AlreadyDestroyed,
        ] {
            let mut exact = EchoingDestroyer {
                calls: 0,
                returned_operation: operation,
                returned_ref: secret_ref.clone(),
                disposition,
            };
            let receipt = destroy_provisioning_secret(operation, &secret_ref, &mut exact).unwrap();
            assert_eq!(receipt.operation(), operation);
            assert_eq!(receipt.secret_ref(), &secret_ref);
            assert_eq!(receipt.disposition(), disposition);
            assert_eq!(exact.calls, 1);
        }
    }

    #[test]
    fn load_receipt_redacts_plaintext() {
        let loaded = ProvisioningLoadReceipt::new(
            ProvisioningLoadId::new([0x22; 32]),
            ProvisioningSecretRef::from_opaque(b"test-secret-ref".to_vec()).unwrap(),
            UnprotectedProvisioning::new(b"ASTRPB03persistent-test-secret".to_vec()).unwrap(),
        );
        assert!(!format!("{loaded:?}").contains("persistent-test-secret"));
    }

    #[test]
    fn installer_owns_plaintext_until_backend_drop_and_zeroizes_conflicts() {
        let state = Arc::new(Mutex::new(PersistentTestSecretState::default()));
        let mut store = PersistentTestSecretStore::open(state);
        let operation = ProvisioningInstallId::new([0x33; 32]);

        let success_observer = Arc::new(AtomicBool::new(false));
        let plaintext = UnprotectedProvisioning::with_zeroization_observer(
            b"ASTRPB03owned-success".to_vec(),
            Arc::clone(&success_observer),
        )
        .unwrap();
        store.install(operation, plaintext).unwrap();
        assert!(!success_observer.load(Ordering::SeqCst));

        let failure_observer = Arc::new(AtomicBool::new(false));
        let conflicting = UnprotectedProvisioning::with_zeroization_observer(
            b"ASTRPB03owned-conflict".to_vec(),
            Arc::clone(&failure_observer),
        )
        .unwrap();
        assert_eq!(
            store.install(operation, conflicting).unwrap_err(),
            ProvisioningSecretStoreError::OperationConflict
        );
        assert!(failure_observer.load(Ordering::SeqCst));
        drop(store);
        assert!(success_observer.load(Ordering::SeqCst));
    }

    #[test]
    fn destroy_receipt_does_not_claim_physical_erasure() {
        let destroyed = ProvisioningDestroyReceipt::destroyed(
            ProvisioningDestroyId::new([0x55; 32]),
            ProvisioningSecretRef::from_opaque(b"test-secret-ref".to_vec()).unwrap(),
        );
        assert!(!destroyed.claims_physical_media_erasure());
    }

    #[test]
    fn missing_secrets_are_indeterminate_not_backend_reported_destroyed() {
        assert!(ProvisioningSecretStoreError::Destroyed.is_backend_reported_destroyed());
        let missing = ProvisioningSecretStoreError::NotFound;
        assert!(missing.is_indeterminate_not_found());
        assert!(!missing.is_backend_reported_destroyed());
    }
}
