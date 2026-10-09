use aster_compose_credentials::{
    ComposeActivation, ComposeClientToken, ComposeCredentialGeneration, ComposeCredentialReason,
    ComposeProvisioningLoader, PROVIDER_CONTRACT, encode_activation, encode_client_token,
    encode_provisioning_envelope, provisioning_secret_ref,
};
use aster_mesh::{
    ClassicalProvisioner, ClassicalProvisioningAccess, ProfileProvisioningBundle,
    ProvisioningLoadId, ProvisioningSecretLoader, ProvisioningSecretRef, Scope, Topic,
    UnprotectedProvisioning,
};
use zeroize::Zeroizing;

const GENERATION: ComposeCredentialGeneration = ComposeCredentialGeneration::new([0x41; 32]);
const OPERATION: ProvisioningLoadId = ProvisioningLoadId::new([0x52; 32]);
const REFERENCE_ID: [u8; 32] = [0x63; 32];
const PROVIDER_REFERENCE_BYTES: usize = 8 + 2 + 2 + 32 + 32;
const ASTER_REFERENCE_HEADER_BYTES: usize = 8 + 2 + 4;
const CANONICAL_REFERENCE_BYTES: usize = ASTER_REFERENCE_HEADER_BYTES + PROVIDER_REFERENCE_BYTES;
const ACTIVATION_HEADER_BYTES: usize = 8 + 2 + 2 + 32 + 4;
const ENVELOPE_HEADER_BYTES: usize = 8 + 2 + 2 + 32 + 4 + 4;
const TOKEN_HEADER_BYTES: usize = 8 + 2 + 2 + 32 + 4;
const TOKEN: &[u8] = b"0123456789abcdef0123456789abcdef";

struct Fixture {
    secret_ref: ProvisioningSecretRef,
    activation: Zeroizing<Vec<u8>>,
    envelope: Zeroizing<Vec<u8>>,
    bundle: &'static [u8],
}

fn fixture() -> Fixture {
    let secret_ref = provisioning_secret_ref(GENERATION, REFERENCE_ID).expect("provider ref");
    let activation = encode_activation(GENERATION, OPERATION, &secret_ref).expect("activation");
    let bundle = include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
    ProfileProvisioningBundle::from_bytes(bundle).expect("canonical fixture");
    let plaintext = UnprotectedProvisioning::new(bundle.to_vec()).expect("owned fixture");
    let envelope = encode_provisioning_envelope(GENERATION, OPERATION, &secret_ref, &plaintext)
        .expect("envelope");
    Fixture {
        secret_ref,
        activation,
        envelope,
        bundle,
    }
}

fn classical_bundle() -> Vec<u8> {
    let access = ClassicalProvisioningAccess::member(
        Scope::new("mission/compose-review").expect("scope"),
        vec![1],
        vec![Topic::new("credential.boundary").expect("topic")],
    )
    .expect("classical access");
    let mut provisioner = ClassicalProvisioner::from_seed([0x91; 32], 1).expect("provisioner");
    let bytes = provisioner
        .issue_node(1, &[access])
        .expect("classical bundle")
        .to_bytes()
        .expect("encode classical bundle");
    assert_eq!(&bytes[..8], b"ASTRPB04");
    ProfileProvisioningBundle::from_bytes(&bytes).expect("valid profile bundle");
    bytes
}

#[test]
fn canonical_formats_round_trip_with_exact_bytes() {
    // Break caught: changing any canonical field layout makes generated
    // Compose generations unreadable or weakens exact cross-file binding.
    assert_eq!(PROVIDER_CONTRACT, "aster-compose-secret-store/v1");
    let Fixture {
        secret_ref,
        activation,
        envelope,
        bundle,
    } = fixture();
    let opaque = secret_ref.expose_opaque();
    assert_eq!(opaque.len(), PROVIDER_REFERENCE_BYTES);
    assert_eq!(&opaque[..8], b"ASTRCSRF");
    assert_eq!(&opaque[8..10], &1_u16.to_be_bytes());
    assert_eq!(&opaque[10..12], &0_u16.to_be_bytes());
    assert_eq!(&opaque[12..44], GENERATION.as_bytes());
    assert_eq!(&opaque[44..76], &REFERENCE_ID);

    assert_eq!(&activation[..8], b"ASTRCSAC");
    assert_eq!(&activation[8..10], &1_u16.to_be_bytes());
    assert_eq!(&activation[10..12], &0_u16.to_be_bytes());
    assert_eq!(&activation[12..44], OPERATION.as_bytes());
    assert_eq!(
        u32::from_be_bytes(activation[44..48].try_into().expect("reference length")),
        CANONICAL_REFERENCE_BYTES as u32
    );
    assert_eq!(&activation[48..], secret_ref.to_bytes());

    assert_eq!(&envelope[..8], b"ASTRCSEN");
    assert_eq!(&envelope[8..10], &1_u16.to_be_bytes());
    assert_eq!(&envelope[10..12], &0_u16.to_be_bytes());
    assert_eq!(&envelope[12..44], OPERATION.as_bytes());
    assert_eq!(
        u32::from_be_bytes(envelope[44..48].try_into().expect("reference length")),
        CANONICAL_REFERENCE_BYTES as u32
    );
    assert_eq!(
        u32::from_be_bytes(envelope[48..52].try_into().expect("bundle length")),
        bundle.len() as u32
    );

    let parsed = ComposeActivation::from_bytes(&activation).expect("parse activation");
    assert_eq!(parsed.generation(), GENERATION);
    assert_eq!(parsed.operation(), OPERATION);
    assert_eq!(parsed.secret_ref(), &secret_ref);
    let mut loader =
        ComposeProvisioningLoader::from_envelope(parsed, envelope).expect("validated loader");
    let receipt = loader.load(OPERATION, &secret_ref).expect("load once");
    assert_eq!(receipt.operation(), OPERATION);
    assert_eq!(receipt.secret_ref(), &secret_ref);
    assert_eq!(receipt.plaintext().expose(), bundle);
}

#[test]
fn canonical_token_envelope_round_trips_and_binds_to_activation() {
    // Break caught: writing an unbound raw bearer token allows a token from
    // generation A to compose with generation-B activation and envelope.
    let encoded = encode_client_token(GENERATION, TOKEN).expect("token envelope");
    assert_eq!(&encoded[..8], b"ASTRCSTK");
    assert_eq!(&encoded[8..10], &1_u16.to_be_bytes());
    assert_eq!(&encoded[10..12], &0_u16.to_be_bytes());
    assert_eq!(&encoded[12..44], GENERATION.as_bytes());
    assert_eq!(&encoded[44..48], &(TOKEN.len() as u32).to_be_bytes());
    assert_eq!(&encoded[TOKEN_HEADER_BYTES..], TOKEN);

    let activation = ComposeActivation::from_bytes(&fixture().activation).expect("activation");
    let parsed = ComposeClientToken::from_bytes(&encoded).expect("parse token envelope");
    assert_eq!(parsed.generation(), GENERATION);
    assert_eq!(format!("{parsed:?}"), "ComposeClientToken([REDACTED])");
    assert_eq!(
        parsed
            .into_token_for_activation(&activation)
            .expect("matching generation")
            .as_slice(),
        TOKEN
    );
}

#[test]
fn token_envelope_rejects_noncanonical_and_mixed_generation_inputs() {
    // Break caught: permissive token framing or delayed generation checks can
    // admit malformed bytes or construct a bearer from a mixed generation.
    let canonical = encode_client_token(GENERATION, TOKEN).expect("canonical token");
    let mut cases = Vec::new();

    let mut magic = canonical.clone();
    magic[0] ^= 1;
    cases.push(("magic", magic, ComposeCredentialReason::InvalidToken));
    let mut version = canonical.clone();
    version[8..10].copy_from_slice(&2_u16.to_be_bytes());
    cases.push(("version", version, ComposeCredentialReason::InvalidToken));
    let mut reserved = canonical.clone();
    reserved[11] = 1;
    cases.push(("reserved", reserved, ComposeCredentialReason::InvalidToken));
    let mut zero_generation = canonical.clone();
    zero_generation[12..44].fill(0);
    cases.push((
        "zero generation",
        zero_generation,
        ComposeCredentialReason::GenerationMismatch,
    ));
    let mut empty = canonical.clone();
    empty[44..48].fill(0);
    empty.truncate(TOKEN_HEADER_BYTES);
    cases.push(("empty", empty, ComposeCredentialReason::InvalidToken));
    let mut oversized = canonical.clone();
    oversized[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    cases.push(("oversized", oversized, ComposeCredentialReason::TooLarge));
    cases.push((
        "truncated",
        Zeroizing::new(canonical[..canonical.len() - 1].to_vec()),
        ComposeCredentialReason::InvalidToken,
    ));
    let mut trailing = canonical.clone();
    trailing.push(0);
    cases.push(("trailing", trailing, ComposeCredentialReason::InvalidToken));

    for (name, bytes, reason) in cases {
        assert_eq!(
            ComposeClientToken::from_bytes(&bytes)
                .expect_err(name)
                .reason(),
            reason,
            "case {name}"
        );
    }

    assert_eq!(
        encode_client_token(ComposeCredentialGeneration::new([0; 32]), TOKEN)
            .expect_err("zero generation")
            .reason(),
        ComposeCredentialReason::GenerationMismatch
    );
    assert_eq!(
        encode_client_token(GENERATION, b"")
            .expect_err("empty token")
            .reason(),
        ComposeCredentialReason::InvalidToken
    );
    assert_eq!(
        encode_client_token(GENERATION, &[0x55; 257])
            .expect_err("oversized token")
            .reason(),
        ComposeCredentialReason::TooLarge
    );

    let other_generation = ComposeCredentialGeneration::new([0x74; 32]);
    let other_ref = provisioning_secret_ref(other_generation, [0x75; 32]).expect("other ref");
    let other_activation = encode_activation(
        other_generation,
        ProvisioningLoadId::new([0x76; 32]),
        &other_ref,
    )
    .expect("other activation");
    let other_activation =
        ComposeActivation::from_bytes(&other_activation).expect("parse other activation");
    let other_plaintext =
        UnprotectedProvisioning::new(fixture().bundle.to_vec()).expect("generation-B bundle");
    let other_envelope = encode_provisioning_envelope(
        other_generation,
        ProvisioningLoadId::new([0x76; 32]),
        &other_ref,
        &other_plaintext,
    )
    .expect("valid generation-B envelope");
    let _other_loader =
        ComposeProvisioningLoader::from_envelope(other_activation.clone(), other_envelope)
            .expect("validated generation-B loader");
    let token = ComposeClientToken::from_bytes(&canonical).expect("valid generation-A token");
    assert_eq!(
        token
            .into_token_for_activation(&other_activation)
            .expect_err("generation-A token with generation-B activation/envelope")
            .reason(),
        ComposeCredentialReason::GenerationMismatch
    );
}

#[test]
fn verifier_releases_token_only_for_the_manifest_generation() {
    // Break caught: a verifier that authenticates with a token from another
    // generation could attest the selected manifest while querying with stale
    // credentials.
    let encoded = encode_client_token(GENERATION, TOKEN).expect("token envelope");
    let token = ComposeClientToken::from_bytes(&encoded).expect("valid token");
    assert_eq!(
        &*token
            .into_token_for_generation(GENERATION)
            .expect("matching manifest generation"),
        TOKEN
    );
    let token = ComposeClientToken::from_bytes(&encoded).expect("valid token");
    assert_eq!(
        token
            .into_token_for_generation(ComposeCredentialGeneration::new([0x99; 32]))
            .expect_err("mismatched manifest generation")
            .reason(),
        ComposeCredentialReason::GenerationMismatch
    );
}

#[test]
fn activation_rejects_each_noncanonical_boundary_with_fixed_reasons() {
    // Break caught: accepting malformed activation framing could pair an
    // envelope with a noncanonical or attacker-selected reference.
    let canonical = fixture().activation;
    let mut cases = Vec::new();

    let mut wrong_magic = canonical.clone();
    wrong_magic[0] ^= 1;
    cases.push((
        "magic",
        wrong_magic,
        ComposeCredentialReason::InvalidActivation,
    ));
    let mut version = canonical.clone();
    version[8..10].copy_from_slice(&2_u16.to_be_bytes());
    cases.push((
        "version",
        version,
        ComposeCredentialReason::InvalidActivation,
    ));
    let mut reserved = canonical.clone();
    reserved[11] = 1;
    cases.push((
        "reserved",
        reserved,
        ComposeCredentialReason::InvalidActivation,
    ));
    let mut zero_length = canonical.clone();
    zero_length[44..48].fill(0);
    cases.push((
        "zero length",
        zero_length,
        ComposeCredentialReason::InvalidActivation,
    ));
    let mut oversized_length = canonical.clone();
    oversized_length[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    cases.push((
        "oversized length",
        oversized_length,
        ComposeCredentialReason::InvalidActivation,
    ));
    cases.push((
        "truncated",
        Zeroizing::new(canonical[..canonical.len() - 1].to_vec()),
        ComposeCredentialReason::InvalidActivation,
    ));
    let mut trailing = canonical.clone();
    trailing.push(0);
    cases.push((
        "trailing",
        trailing,
        ComposeCredentialReason::InvalidActivation,
    ));
    let mut wrong_provider = canonical.clone();
    wrong_provider[ACTIVATION_HEADER_BYTES + ASTER_REFERENCE_HEADER_BYTES] ^= 1;
    cases.push((
        "wrong provider",
        wrong_provider,
        ComposeCredentialReason::ProviderMismatch,
    ));
    let mut provider_version = canonical.clone();
    provider_version[ACTIVATION_HEADER_BYTES + ASTER_REFERENCE_HEADER_BYTES + 8
        ..ACTIVATION_HEADER_BYTES + ASTER_REFERENCE_HEADER_BYTES + 10]
        .copy_from_slice(&2_u16.to_be_bytes());
    cases.push((
        "provider version",
        provider_version,
        ComposeCredentialReason::ProviderMismatch,
    ));
    let mut provider_reserved = canonical.clone();
    provider_reserved[ACTIVATION_HEADER_BYTES + ASTER_REFERENCE_HEADER_BYTES + 11] = 1;
    cases.push((
        "provider reserved",
        provider_reserved,
        ComposeCredentialReason::ProviderMismatch,
    ));
    let mut zero_generation = canonical.clone();
    zero_generation[ACTIVATION_HEADER_BYTES + ASTER_REFERENCE_HEADER_BYTES + 12
        ..ACTIVATION_HEADER_BYTES + ASTER_REFERENCE_HEADER_BYTES + 44]
        .fill(0);
    cases.push((
        "zero generation",
        zero_generation,
        ComposeCredentialReason::GenerationMismatch,
    ));

    for (name, encoded, reason) in cases {
        let error = ComposeActivation::from_bytes(&encoded).expect_err(name);
        assert_eq!(error.reason(), reason, "case {name}");
        assert!(!format!("{error:?}").contains("/run/"), "case {name}");
    }
}

#[test]
fn envelope_rejects_every_noncanonical_or_mismatched_boundary() {
    // Break caught: accepting malformed or mismatched envelope fields would
    // release unbound or noncanonical provisioning plaintext.
    let Fixture {
        secret_ref,
        activation: activation_bytes,
        envelope: canonical,
        ..
    } = fixture();
    let activation = ComposeActivation::from_bytes(&activation_bytes).expect("activation");
    let other_ref =
        provisioning_secret_ref(ComposeCredentialGeneration::new([0x74; 32]), [0x75; 32])
            .expect("other ref");
    let other_activation = encode_activation(
        ComposeCredentialGeneration::new([0x74; 32]),
        ProvisioningLoadId::new([0x76; 32]),
        &other_ref,
    )
    .expect("other activation");
    let other_activation = ComposeActivation::from_bytes(&other_activation).expect("other parsed");

    let mut cases = Vec::new();
    let mut wrong_magic = canonical.clone();
    wrong_magic[0] ^= 1;
    cases.push((
        "magic",
        wrong_magic,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidEnvelope,
    ));
    let mut version = canonical.clone();
    version[8..10].copy_from_slice(&2_u16.to_be_bytes());
    cases.push((
        "version",
        version,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidEnvelope,
    ));
    let mut reserved = canonical.clone();
    reserved[11] = 1;
    cases.push((
        "reserved",
        reserved,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidEnvelope,
    ));
    let mut zero_ref = canonical.clone();
    zero_ref[44..48].fill(0);
    cases.push((
        "zero reference",
        zero_ref,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidEnvelope,
    ));
    let mut oversized_ref = canonical.clone();
    oversized_ref[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    cases.push((
        "oversized reference",
        oversized_ref,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidEnvelope,
    ));
    let mut zero_bundle = canonical.clone();
    zero_bundle[48..52].fill(0);
    cases.push((
        "zero bundle",
        zero_bundle,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidEnvelope,
    ));
    let mut oversized_bundle = canonical.clone();
    oversized_bundle[48..52].copy_from_slice(&u32::MAX.to_be_bytes());
    cases.push((
        "oversized bundle",
        oversized_bundle,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::TooLarge,
    ));
    cases.push((
        "truncated",
        Zeroizing::new(canonical[..canonical.len() - 1].to_vec()),
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidEnvelope,
    ));
    let mut trailing = canonical.clone();
    trailing.push(0);
    cases.push((
        "trailing",
        trailing,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidEnvelope,
    ));
    let mut invalid_bundle = canonical.clone();
    invalid_bundle[ENVELOPE_HEADER_BYTES + CANONICAL_REFERENCE_BYTES] ^= 1;
    cases.push((
        "invalid bundle",
        invalid_bundle,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::InvalidBundle,
    ));
    let mut wrong_provider = canonical.clone();
    wrong_provider[ENVELOPE_HEADER_BYTES + ASTER_REFERENCE_HEADER_BYTES] ^= 1;
    cases.push((
        "wrong provider",
        wrong_provider,
        activation.clone(),
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::ProviderMismatch,
    ));
    cases.push((
        "wrong activation",
        canonical.clone(),
        other_activation,
        OPERATION,
        secret_ref.clone(),
        ComposeCredentialReason::GenerationMismatch,
    ));
    cases.push((
        "wrong reference",
        canonical.clone(),
        activation.clone(),
        OPERATION,
        other_ref,
        ComposeCredentialReason::ReferenceMismatch,
    ));
    cases.push((
        "wrong operation",
        canonical.clone(),
        activation,
        ProvisioningLoadId::new([0x77; 32]),
        secret_ref,
        ComposeCredentialReason::OperationMismatch,
    ));

    for (name, envelope, activation, operation, secret_ref, reason) in cases {
        let error = match ComposeProvisioningLoader::from_envelope(activation, envelope) {
            Ok(mut loader) => loader
                .load_with_reason(operation, &secret_ref)
                .expect_err(name),
            Err(error) => error,
        };
        assert_eq!(error.reason(), reason, "case {name}");
    }
}

#[test]
fn loader_consumes_one_envelope_and_debug_is_redacted() {
    // Break caught: retaining a reusable envelope or exposing credential bytes
    // in Debug would violate one-shot loading and diagnostic secrecy.
    let Fixture {
        secret_ref,
        activation,
        envelope,
        ..
    } = fixture();
    let activation = ComposeActivation::from_bytes(&activation).expect("activation");
    let mut loader = ComposeProvisioningLoader::from_envelope(activation.clone(), envelope)
        .expect("validated loader");
    assert_eq!(
        format!("{GENERATION:?}"),
        "ComposeCredentialGeneration([REDACTED])"
    );
    assert_eq!(format!("{activation:?}"), "ComposeActivation([REDACTED])");
    assert_eq!(
        format!("{loader:?}"),
        "ComposeProvisioningLoader([REDACTED])"
    );

    loader
        .load_with_reason(OPERATION, &secret_ref)
        .expect("first load");
    assert_eq!(
        loader
            .load_with_reason(OPERATION, &secret_ref)
            .expect_err("second load")
            .reason(),
        ComposeCredentialReason::AlreadyConsumed
    );
}

#[test]
fn encoder_rejects_a_valid_astrpb04_bundle() {
    // Break caught: using the profile dispatcher here widens the fixed
    // Compose envelope contract from ASTRPB03 to ASTRPB03-or-ASTRPB04.
    let Fixture { secret_ref, .. } = fixture();
    let plaintext = UnprotectedProvisioning::new(classical_bundle()).expect("owned ASTRPB04");
    assert_eq!(
        encode_provisioning_envelope(GENERATION, OPERATION, &secret_ref, &plaintext)
            .expect_err("Compose encoding must reject ASTRPB04")
            .reason(),
        ComposeCredentialReason::InvalidBundle
    );
}

#[test]
fn loader_rejects_an_envelope_containing_a_valid_astrpb04_bundle() {
    // Break caught: profile-dispatch decoding would release canonical
    // ASTRPB04 plaintext despite the Compose contract requiring ASTRPB03.
    let Fixture {
        activation,
        mut envelope,
        ..
    } = fixture();
    let classical = classical_bundle();
    envelope.truncate(ENVELOPE_HEADER_BYTES + CANONICAL_REFERENCE_BYTES);
    envelope[48..52].copy_from_slice(&(classical.len() as u32).to_be_bytes());
    envelope.extend_from_slice(&classical);
    let activation = ComposeActivation::from_bytes(&activation).expect("activation");
    assert_eq!(
        ComposeProvisioningLoader::from_envelope(activation, envelope)
            .expect_err("Compose loader construction must reject ASTRPB04")
            .reason(),
        ComposeCredentialReason::InvalidBundle
    );
}
