use age::secrecy::ExposeSecret;
use age_core::format::{FileKey, Stanza};
use aster_mesh::{
    MAX_PROTECTED_PROVISIONING_BYTES, MAX_UNPROTECTED_PROVISIONING_BYTES, ProvisioningAccess,
    ProvisioningBundle, ProvisioningProtectionError, ProvisioningProtector,
    ProvisioningUnprotector, ReferenceProvisioner, Scope, Topic, UnprotectedProvisioning,
};
use aster_node::application::{ApplicationErrorKind, SelectedEventNode};
use aster_provisioning_age::{
    AgeIdentity, AgeProviderConfigError, AgeRecipient, AgeX25519Protector, AgeX25519Unprotector,
    MAX_AGE_HEADER_BYTES, MAX_AGE_HEADER_LINES, MAX_AGE_IDENTITIES, MAX_AGE_RECIPIENTS,
    SecretString,
};
use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

const AGE_MAGIC: &[u8] = b"age-encryption.org/v1\n";

struct SyntheticExtensionRecipient {
    stanza_count: usize,
}

impl age::Recipient for SyntheticExtensionRecipient {
    fn wrap_file_key(
        &self,
        _file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let stanzas = (0..self.stanza_count)
            .map(|index| Stanza {
                tag: format!("aster-test-extension-{index}"),
                args: Vec::new(),
                body: Vec::new(),
            })
            .collect();
        Ok((stanzas, HashSet::new()))
    }
}

fn protector_for(identity: &AgeIdentity) -> AgeX25519Protector {
    AgeX25519Protector::new([identity.to_public()])
        .unwrap_or_else(|error| panic!("valid recipient configuration failed: {error}"))
}

fn unprotector_for(identity: AgeIdentity) -> AgeX25519Unprotector {
    AgeX25519Unprotector::new([identity])
        .unwrap_or_else(|error| panic!("valid identity configuration failed: {error}"))
}

fn protect(
    protector: &mut AgeX25519Protector,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProvisioningProtectionError> {
    let plaintext = UnprotectedProvisioning::new(plaintext.to_vec())?;
    protector.protect(&plaintext)
}

fn unprotect(
    unprotector: &mut AgeX25519Unprotector,
    protected: &[u8],
    max_plaintext_len: usize,
) -> Result<Vec<u8>, ProvisioningProtectionError> {
    let plaintext = unprotector.unprotect(protected, max_plaintext_len)?;
    Ok(plaintext.expose().to_vec())
}

fn assert_rejected(result: Result<Vec<u8>, ProvisioningProtectionError>, label: &str) {
    assert!(
        matches!(result, Err(ProvisioningProtectionError::Rejected)),
        "{label} did not fail closed: {result:?}"
    );
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap_or_else(|| {
            panic!(
                "age test artifact lacked {:?}",
                String::from_utf8_lossy(needle)
            )
        })
}

fn header_end(protected: &[u8]) -> usize {
    let footer = find(protected, b"\n--- ") + 1;
    footer
        + protected[footer..]
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or_else(|| panic!("age test artifact lacked a complete header footer"))
        + 1
}

fn test_directory(label: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "aster-age-{label}-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn age_artifacts_are_authenticated_randomized_and_provider_instances_are_reusable() {
    let identity = AgeIdentity::generate();
    let mut protector = protector_for(&identity);
    let mut unprotector = unprotector_for(identity);
    let plaintext = b"ASTRPB03-age-provider-secret-canary-2d9f90e6";

    let first = protect(&mut protector, plaintext).unwrap();
    let second = protect(&mut protector, plaintext).unwrap();
    let third = protect(&mut protector, plaintext).unwrap();

    assert!(first.starts_with(AGE_MAGIC));
    assert!(second.starts_with(AGE_MAGIC));
    assert!(third.starts_with(AGE_MAGIC));
    assert_ne!(first, second);
    assert_ne!(first, third);
    assert_ne!(second, third);
    for artifact in [&first, &second, &third] {
        assert!(
            !artifact
                .windows(plaintext.len())
                .any(|window| window == plaintext),
            "protected artifact exposed the plaintext canary"
        );
        assert_eq!(
            unprotect(&mut unprotector, artifact, plaintext.len()).unwrap(),
            plaintext
        );
    }
}

#[test]
fn every_configured_recipient_can_open_and_mixed_identities_find_the_match() {
    let identities = [
        AgeIdentity::generate(),
        AgeIdentity::generate(),
        AgeIdentity::generate(),
    ];
    let recipients = identities
        .iter()
        .map(AgeIdentity::to_public)
        .collect::<Vec<_>>();
    let mut protector = AgeX25519Protector::new(recipients).unwrap();
    let plaintext = b"ASTRPB03-multiple-recipient-artifact";
    let protected = protect(&mut protector, plaintext).unwrap();

    for identity in identities {
        let mut unprotector = unprotector_for(identity);
        assert_eq!(
            unprotect(&mut unprotector, &protected, plaintext.len()).unwrap(),
            plaintext
        );
    }

    let wrong = AgeIdentity::generate();
    let matching = AgeIdentity::generate();
    let mut protector = protector_for(&matching);
    let protected = protect(&mut protector, plaintext).unwrap();
    let mut unprotector = AgeX25519Unprotector::new([wrong, matching]).unwrap();
    assert_eq!(
        unprotect(&mut unprotector, &protected, plaintext.len()).unwrap(),
        plaintext
    );
}

#[test]
fn recipient_and_identity_configuration_is_bounded_and_sanitized() {
    assert_eq!(
        AgeX25519Protector::new(Vec::<AgeRecipient>::new()).err(),
        Some(AgeProviderConfigError::NoRecipients)
    );
    assert_eq!(
        AgeX25519Unprotector::new(Vec::<AgeIdentity>::new()).err(),
        Some(AgeProviderConfigError::NoIdentities)
    );

    let recipients = (0..MAX_AGE_RECIPIENTS)
        .map(|_| AgeIdentity::generate().to_public())
        .collect::<Vec<_>>();
    assert_eq!(
        AgeX25519Protector::new(recipients)
            .unwrap()
            .recipient_count(),
        MAX_AGE_RECIPIENTS
    );

    let recipients = (0..=MAX_AGE_RECIPIENTS)
        .map(|_| AgeIdentity::generate().to_public())
        .collect::<Vec<_>>();
    assert_eq!(
        AgeX25519Protector::new(recipients).err(),
        Some(AgeProviderConfigError::TooManyRecipients)
    );

    let identities = (0..MAX_AGE_IDENTITIES)
        .map(|_| AgeIdentity::generate())
        .collect::<Vec<_>>();
    assert_eq!(
        AgeX25519Unprotector::new(identities)
            .unwrap()
            .identity_count(),
        MAX_AGE_IDENTITIES
    );

    let identities = (0..=MAX_AGE_IDENTITIES)
        .map(|_| AgeIdentity::generate())
        .collect::<Vec<_>>();
    assert_eq!(
        AgeX25519Unprotector::new(identities).err(),
        Some(AgeProviderConfigError::TooManyIdentities)
    );

    let duplicate_identity = AgeIdentity::generate();
    let duplicate_recipient = duplicate_identity.to_public();
    assert_eq!(
        AgeX25519Protector::new([duplicate_recipient.clone(), duplicate_recipient]).err(),
        Some(AgeProviderConfigError::DuplicateRecipient)
    );
    assert_eq!(
        AgeX25519Unprotector::new([duplicate_identity.clone(), duplicate_identity]).err(),
        Some(AgeProviderConfigError::DuplicateIdentity)
    );

    let recipient_canary = "age1invalid-project-recipient-canary";
    let recipient_error = AgeX25519Protector::parse(recipient_canary)
        .err()
        .unwrap_or_else(|| panic!("malformed recipient configuration was accepted"));
    assert!(!recipient_error.to_string().contains(recipient_canary));
    assert!(!format!("{recipient_error:?}").contains(recipient_canary));

    let identity_canary = "AGE-SECRET-KEY-INVALID-PROJECT-IDENTITY-CANARY";
    let identity_secret = SecretString::from(identity_canary);
    let identity_error = AgeX25519Unprotector::parse(&identity_secret)
        .err()
        .unwrap_or_else(|| panic!("malformed identity configuration was accepted"));
    assert!(!identity_error.to_string().contains(identity_canary));
    assert!(!format!("{identity_error:?}").contains(identity_canary));

    let identity = AgeIdentity::generate();
    let recipient_text = identity.to_public().to_string();
    let identity_text = identity.to_string();
    let protector = AgeX25519Protector::parse(&recipient_text).unwrap();
    let unprotector = AgeX25519Unprotector::parse(&identity_text).unwrap();
    let protector_debug = format!("{protector:?}");
    let unprotector_debug = format!("{unprotector:?}");
    assert!(unprotector_debug.contains("REDACTED"));
    assert!(!protector_debug.contains(&recipient_text));
    assert!(!unprotector_debug.contains(identity_text.expose_secret()));
}

#[test]
fn wrong_identity_tamper_truncation_and_trailing_data_fail_closed() {
    let identity = AgeIdentity::generate();
    let mut protector = protector_for(&identity);
    let mut unprotector = unprotector_for(identity);
    let plaintext = b"ASTRPB03-authenticated-age-payload-with-several-blocks-0123456789";
    let protected = protect(&mut protector, plaintext).unwrap();

    let mut wrong = unprotector_for(AgeIdentity::generate());
    assert_rejected(
        unprotect(&mut wrong, &protected, plaintext.len()),
        "wrong identity",
    );

    let footer = find(&protected, b"\n--- ") + 1;
    let stanza_tag = find(&protected, b"X25519");
    let stanza_line_end = stanza_tag
        + protected[stanza_tag..]
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap();
    let stanza_body = stanza_line_end + 1;
    let mac = footer + b"--- ".len();
    let body = header_end(&protected);
    assert!(body < protected.len());

    let mutations = [
        ("version header", 0),
        ("recipient stanza tag", stanza_tag),
        ("recipient stanza body", stanza_body),
        ("header MAC", mac),
        ("payload first byte", body),
        ("payload middle byte", body + (protected.len() - body) / 2),
        ("payload final byte", protected.len() - 1),
    ];
    for (label, offset) in mutations {
        let mut damaged = protected.clone();
        damaged[offset] ^= 1;
        assert_rejected(
            unprotect(&mut unprotector, &damaged, plaintext.len()),
            label,
        );
    }

    let mut truncations = BTreeSet::from([
        0,
        1,
        AGE_MAGIC.len() - 1,
        AGE_MAGIC.len(),
        stanza_tag,
        stanza_body,
        footer,
        body - 1,
        body,
        body + 1,
        protected.len() / 2,
        protected.len() - 17,
        protected.len() - 1,
    ]);
    truncations.retain(|cut| *cut < protected.len());
    for cut in truncations {
        assert_rejected(
            unprotect(&mut unprotector, &protected[..cut], plaintext.len()),
            &format!("truncation at {cut}"),
        );
    }

    let mut trailing = protected.clone();
    trailing.extend_from_slice(b"unauthenticated-trailing-data");
    assert_rejected(
        unprotect(&mut unprotector, &trailing, plaintext.len()),
        "trailing data",
    );
}

#[test]
fn incoming_artifacts_enforce_the_x25519_recipient_profile() {
    let identities = (0..=MAX_AGE_RECIPIENTS)
        .map(|_| AgeIdentity::generate())
        .collect::<Vec<_>>();
    let recipients = identities
        .iter()
        .map(AgeIdentity::to_public)
        .collect::<Vec<_>>();
    let recipient_refs = recipients
        .iter()
        .map(|recipient| recipient as &dyn age::Recipient);
    let encryptor = age::Encryptor::with_recipients(recipient_refs).unwrap();
    let mut protected = Vec::new();
    let mut writer = encryptor.wrap_output(&mut protected).unwrap();
    writer.write_all(b"ASTRPB03-too-many-recipients").unwrap();
    writer.finish().unwrap();

    let mut unprotector = unprotector_for(identities.into_iter().next().unwrap());
    assert_rejected(
        unprotect(
            &mut unprotector,
            &protected,
            MAX_UNPROTECTED_PROVISIONING_BYTES,
        ),
        "over-limit recipient stanza set",
    );

    let passphrase = SecretString::from("synthetic-age-profile-test-passphrase");
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut protected = Vec::new();
    let mut writer = encryptor.wrap_output(&mut protected).unwrap();
    writer.write_all(b"ASTRPB03-passphrase-profile").unwrap();
    writer.finish().unwrap();

    assert_rejected(
        unprotect(
            &mut unprotector,
            &protected,
            MAX_UNPROTECTED_PROVISIONING_BYTES,
        ),
        "non-X25519 recipient profile",
    );

    let extension_only = SyntheticExtensionRecipient { stanza_count: 0 };
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&extension_only as &dyn age::Recipient))
            .unwrap();
    let mut protected = Vec::new();
    let mut writer = encryptor.wrap_output(&mut protected).unwrap();
    writer.write_all(b"ASTRPB03-no-X25519-stanza").unwrap();
    writer.finish().unwrap();

    assert_rejected(
        unprotect(
            &mut unprotector,
            &protected,
            MAX_UNPROTECTED_PROVISIONING_BYTES,
        ),
        "artifact without an X25519 stanza",
    );

    let identity = AgeIdentity::generate();
    let recipient = identity.to_public();
    let extension = SyntheticExtensionRecipient { stanza_count: 1 };
    let recipients: [&dyn age::Recipient; 2] = [&recipient, &extension];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter()).unwrap();
    let mut protected = Vec::new();
    let mut writer = encryptor.wrap_output(&mut protected).unwrap();
    writer
        .write_all(b"ASTRPB03-multiple-extension-stanzas")
        .unwrap();
    writer.finish().unwrap();
    let mut extension_unprotector = unprotector_for(identity);

    assert_rejected(
        unprotect(
            &mut extension_unprotector,
            &protected,
            MAX_UNPROTECTED_PROVISIONING_BYTES,
        ),
        "artifact with multiple extension stanzas",
    );
}

#[test]
fn incoming_artifact_and_header_work_bounds_are_enforced_before_age_parsing() {
    let mut unprotector = unprotector_for(AgeIdentity::generate());
    let oversized_artifact = vec![0; MAX_PROTECTED_PROVISIONING_BYTES + 1];
    assert!(matches!(
        unprotect(
            &mut unprotector,
            &oversized_artifact,
            MAX_UNPROTECTED_PROVISIONING_BYTES,
        ),
        Err(ProvisioningProtectionError::TooLarge)
    ));

    let mut excessive_lines = AGE_MAGIC.to_vec();
    for _ in 0..MAX_AGE_HEADER_LINES {
        excessive_lines.extend_from_slice(b"-> X\n\n");
    }
    excessive_lines.extend_from_slice(b"--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    assert!(excessive_lines.len() < MAX_PROTECTED_PROVISIONING_BYTES);
    assert_rejected(
        unprotect(
            &mut unprotector,
            &excessive_lines,
            MAX_UNPROTECTED_PROVISIONING_BYTES,
        ),
        "pathological many-line age header",
    );

    let mut excessive_bytes = AGE_MAGIC.to_vec();
    excessive_bytes.resize(MAX_AGE_HEADER_BYTES, b'A');
    excessive_bytes.extend_from_slice(b"\n--- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
    assert!(excessive_bytes.len() < MAX_PROTECTED_PROVISIONING_BYTES);
    assert_rejected(
        unprotect(
            &mut unprotector,
            &excessive_bytes,
            MAX_UNPROTECTED_PROVISIONING_BYTES,
        ),
        "pathological oversized age header",
    );
}

#[test]
fn recovered_plaintext_honors_caller_and_global_bounds() {
    let identity = AgeIdentity::generate();
    let mut protector = protector_for(&identity);
    let mut unprotector = unprotector_for(identity);
    let plaintext = vec![0x5a; MAX_UNPROTECTED_PROVISIONING_BYTES];
    let protected = protect(&mut protector, &plaintext).unwrap();

    assert!(matches!(
        unprotect(
            &mut unprotector,
            &protected,
            MAX_UNPROTECTED_PROVISIONING_BYTES - 1
        ),
        Err(ProvisioningProtectionError::TooLarge)
    ));
    assert_eq!(
        unprotect(
            &mut unprotector,
            &protected,
            MAX_UNPROTECTED_PROVISIONING_BYTES
        )
        .unwrap(),
        plaintext
    );

    let small_plaintext = b"bounded";
    let protected = protect(&mut protector, small_plaintext).unwrap();
    assert!(matches!(
        unprotect(&mut unprotector, &protected, 0),
        Err(ProvisioningProtectionError::TooLarge)
    ));
    assert_eq!(
        unprotect(&mut unprotector, &protected, small_plaintext.len()).unwrap(),
        small_plaintext
    );
}

#[test]
fn real_bundle_roundtrips_and_opens_an_application_node() {
    let scope = Scope::new("mission/age-provider").unwrap();
    let topic = Topic::new("provisioning.age").unwrap();
    let access = ProvisioningAccess::member(scope, vec![0, 1], vec![topic]).unwrap();
    let mut provisioner = ReferenceProvisioner::from_seed([0xa6; 32]).unwrap();
    let bundle = provisioner.issue_node(1, &[access]).unwrap();

    let identity = AgeIdentity::generate();
    let mut protector = protector_for(&identity);
    let protected = bundle.to_protected_bytes(&mut protector).unwrap();
    let mut expected = bundle.to_bytes().unwrap();

    let mut bundle_unprotector = unprotector_for(identity.clone());
    let restored =
        ProvisioningBundle::from_protected_bytes(&protected, &mut bundle_unprotector).unwrap();
    let mut actual = restored.to_bytes().unwrap();
    assert_eq!(actual, expected);
    actual.zeroize();
    expected.zeroize();

    let root = test_directory("application-open");
    fs::create_dir(&root).unwrap();
    let rejected_path = root.join("wrong-identity");
    let mut wrong = unprotector_for(AgeIdentity::generate());
    let error = SelectedEventNode::from_protected_bytes(&rejected_path, &protected, &mut wrong)
        .err()
        .unwrap_or_else(|| panic!("wrong identity unexpectedly opened an application node"));
    assert_eq!(error.kind(), ApplicationErrorKind::Provisioning);
    assert!(!rejected_path.exists());

    let state_path = root.join("node");
    let mut node_unprotector = unprotector_for(identity);
    let node =
        SelectedEventNode::from_protected_bytes(&state_path, &protected, &mut node_unprotector)
            .unwrap();
    assert_ne!(node.identity(), [0; 32]);
    assert!(state_path.join("mesh.redb").is_file());
    drop(node);
    fs::remove_dir_all(root).unwrap();
}
