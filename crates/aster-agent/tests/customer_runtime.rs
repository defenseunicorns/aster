#![cfg(unix)]

use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    sync::mpsc as std_mpsc,
    time::Duration,
};

#[cfg(feature = "sdk-test-support")]
use aster_agent::runtime::{
    BtleRuntimeOwner, BtleRuntimeOwnerError, BtleRuntimeStartup, run_customer_agent_with_btle,
};
use aster_agent::{
    ClientToken,
    config::{ValidatedBtlePolicy, check_config, load_and_validate_config},
    credentials::{
        CredentialGeneration, StartupCredentials, load_startup_credentials, open_node_config,
    },
    lifecycle::FailureReason,
    proto::aster::application::v1alpha1 as api,
    runtime::{
        AgentExit, AgentRuntimeError, AgentSignal, TokenReloadPolicy, run_customer_agent,
        run_customer_agent_with_credentials,
    },
};
use aster_mesh::{
    ProvisioningLoadId, ProvisioningLoadReceipt, ProvisioningSecretLoader, ProvisioningSecretRef,
    ProvisioningSecretStoreError, UnprotectedProvisioning,
};
use aster_node::application::{Scope, Topic};
#[cfg(feature = "sdk-test-support")]
use aster_node::{
    EventAdapterControl, EventAdapterSnapshot, EventAdapterState, EventAttemptReceiver,
    EventPeerEligibility, EventTransportKind, RunningAutomaticEventTransportHandle,
};
use aster_node::{MutableSourceInterests, SourceInterestSelector};
use buffa::Message as _;
#[cfg(feature = "sdk-test-support")]
use futures::future::BoxFuture;
#[cfg(feature = "sdk-test-support")]
use std::sync::{Arc, Mutex, atomic::AtomicBool};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_validates_credentials_before_binding_any_listener() {
    // Break caught: moving credential validation after listener binding exposes
    // health or application sockets for an invalid startup configuration.
    let fixture = CustomerFixture::new();
    fixture.write_token(b"invalid");
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (_signals, receiver) = tokio::sync::mpsc::channel(4);
    let mut loader = RecordingLoader::new();

    let result = run_customer_agent(config, &mut loader, receiver).await;
    assert_eq!(
        result,
        Err(AgentRuntimeError::Credential(
            aster_agent::credentials::CredentialReason::InvalidToken,
        ))
    );
    assert_eq!(loader.calls(), 0);
    if socket_access_available() {
        std::net::TcpListener::bind(fixture.application()).expect("application was never bound");
        std::net::TcpListener::bind(fixture.health()).expect("health was never bound");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_runtime_rejects_configured_btle_instead_of_silently_disabling_it() {
    // Break caught: accepting BTLE policy through the legacy composition root
    // would silently start an IP-only process while the operator expects the
    // configured adapter authority to be active.
    let fixture = CustomerFixture::new();
    fixture.enable_btle_policy();
    let config = load_and_validate_config(fixture.config_path()).expect("validated BTLE config");
    let (_signals, receiver) = tokio::sync::mpsc::channel(4);
    let mut loader = RecordingLoader::new();

    assert_eq!(
        run_customer_agent(config, &mut loader, receiver).await,
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
    assert_eq!(loader.calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_runtime_rejects_configured_btle_without_a_composed_owner() {
    // Break caught: the lower-level credential entry point must not bypass the
    // same composition check and silently discard validated BTLE authority.
    let fixture = CustomerFixture::new();
    fixture.enable_btle_policy();
    let config = load_and_validate_config(fixture.config_path()).expect("validated BTLE config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    let (runtime, _) = config.into_parts();
    let (_signals, receiver) = tokio::sync::mpsc::channel(4);
    let mut loader = RecordingLoader::new();

    assert_eq!(
        run_customer_agent_with_credentials(
            runtime,
            credentials,
            &mut loader,
            receiver,
            TokenReloadPolicy::Disabled,
        )
        .await,
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
    assert_eq!(loader.calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn btle_runtime_rejects_disabled_startup_for_configured_policy_before_credentials() {
    let fixture = CustomerFixture::new();
    fixture.enable_btle_policy();
    let config = load_and_validate_config(fixture.config_path()).expect("validated BTLE config");
    let (signals, receiver) = tokio::sync::mpsc::channel(4);
    signals
        .send(AgentSignal::Terminate)
        .await
        .expect("queue termination");
    let mut loader = RecordingLoader::new();

    assert_eq!(
        run_customer_agent_with_btle(
            config,
            &mut loader,
            receiver,
            BtleRuntimeStartup::disabled(),
        )
        .await,
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
    assert_eq!(loader.calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn btle_runtime_rejects_owner_without_configured_policy_before_credentials() {
    let fixture = CustomerFixture::new();
    let foreign = CustomerFixture::new();
    let foreign_policy = foreign.enable_btle_policy();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (signals, receiver) = tokio::sync::mpsc::channel(4);
    signals
        .send(AgentSignal::Terminate)
        .await
        .expect("queue termination");
    let mut loader = RecordingLoader::new();

    assert_eq!(
        run_customer_agent_with_btle(
            config,
            &mut loader,
            receiver,
            BtleRuntimeStartup::radio_inert_with_test_observer((), foreign_policy).0,
        )
        .await,
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
    assert_eq!(loader.calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn btle_runtime_rejects_owner_bound_to_a_different_policy_before_credentials() {
    let fixture = CustomerFixture::new();
    fixture.enable_btle_policy();
    let foreign = CustomerFixture::new();
    let foreign_policy = foreign.enable_btle_policy_with_priority(200);
    let config = load_and_validate_config(fixture.config_path()).expect("validated BTLE config");
    let (signals, receiver) = tokio::sync::mpsc::channel(4);
    signals
        .send(AgentSignal::Terminate)
        .await
        .expect("queue termination");
    let mut loader = RecordingLoader::new();

    assert_eq!(
        run_customer_agent_with_btle(
            config,
            &mut loader,
            receiver,
            BtleRuntimeStartup::radio_inert_with_test_observer((), foreign_policy).0,
        )
        .await,
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
    assert_eq!(loader.calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn btle_runtime_rejects_owner_bound_to_a_different_state_before_credentials() {
    let fixture = CustomerFixture::new();
    let policy = fixture.enable_btle_policy();
    let config = load_and_validate_config(fixture.config_path()).expect("validated BTLE config");
    let foreign = CustomerFixture::new();
    let (signals, receiver) = tokio::sync::mpsc::channel(4);
    signals
        .send(AgentSignal::Terminate)
        .await
        .expect("queue termination");
    let mut loader = RecordingLoader::new();
    let btle = BtleRuntimeStartup::radio_inert_with_test_observer((), policy)
        .0
        .with_authority_state_root_for_test(&foreign.root.join("state"));

    assert_eq!(
        run_customer_agent_with_btle(config, &mut loader, receiver, btle).await,
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
    assert_eq!(loader.calls(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_bootstrap_finishes_before_any_listener_is_bound() {
    // Break caught: binding even the health listener before the protected
    // bundle is authenticated violates D06's fail-before-side-effects boundary.
    let sockets_available = socket_access_available();
    let fixture = CustomerFixture::new();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (entered_send, mut entered_receive) = tokio::sync::mpsc::unbounded_channel();
    let (release_send, release_receive) = std_mpsc::channel();
    let (signals, receiver) = tokio::sync::mpsc::channel(4);
    let task = tokio::spawn(async move {
        let mut loader = BlockingLoader {
            entered: entered_send,
            release: release_receive,
        };
        run_customer_agent(config, &mut loader, receiver).await
    });

    tokio::time::timeout(Duration::from_secs(2), entered_receive.recv())
        .await
        .expect("protected loader entry deadline")
        .expect("protected loader entered before listener bind");
    if sockets_available {
        let application_probe = std::net::TcpListener::bind(fixture.application())
            .expect("application remains unbound");
        let health_probe =
            std::net::TcpListener::bind(fixture.health()).expect("health remains unbound");
        drop((application_probe, health_probe));
    }
    release_send.send(()).expect("release protected bootstrap");
    if !sockets_available {
        assert_eq!(
            task.await.expect("runtime task joins"),
            Err(AgentRuntimeError::Listener(FailureReason::Startup))
        );
        return;
    }
    wait_until_ready(&fixture).await;
    assert_eq!(
        application_status(fixture.application(), fixture.token_bytes()).await,
        200
    );

    signals
        .send(AgentSignal::Terminate)
        .await
        .expect("request clean stop");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("clean stop deadline")
            .expect("runtime task joins")
            .expect("runtime result"),
        AgentExit::Clean
    );
    assert!(
        tokio::net::TcpStream::connect(fixture.health())
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_protected_bootstrap_leaves_no_listener_or_state_side_effect() {
    // Break caught: recovering from a rejected provider only after opening
    // listeners or durable node state exposes a partially started service.
    let sockets_available = socket_access_available();
    let fixture = CustomerFixture::new();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (_signals, receiver) = tokio::sync::mpsc::channel(4);
    let mut loader = RejectingLoader;

    assert_eq!(
        run_customer_agent(config, &mut loader, receiver).await,
        Err(AgentRuntimeError::Bootstrap(
            aster_node::NodeBootstrapErrorKind::Rejected,
        ))
    );
    if sockets_available {
        std::net::TcpListener::bind(fixture.application()).expect("application was never bound");
        std::net::TcpListener::bind(fixture.health()).expect("health was never bound");
    }
    assert!(
        fs::read_dir(fixture.root.join("state"))
            .expect("inspect state directory")
            .next()
            .is_none(),
        "protected bootstrap failure must not create durable state"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_only_starts_ready_and_accepts_local_publication() {
    // Break caught: parsing receive_only without wiring it through customer
    // startup can either fail readiness or accidentally disable the local API.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    fixture.set_emission_policy("receive_only");
    let running = RunningFixture::start(&fixture).await;

    assert_eq!(
        publish_event_status(fixture.application(), fixture.token_bytes()).await,
        200
    );
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    running.stop_clean().await;
}

#[test]
fn compose_generation_is_reported_only_by_authenticated_status_and_ready_lifecycle() {
    // Break caught: dropping, reshaping, or over-sharing the public generation
    // prevents operators from verifying one exact Compose activation.
    const CHILD: &str = "ASTER_TEST_COMPOSE_GENERATION_CHILD";
    const GENERATION: [u8; 32] = [0x3a; 32];
    const GENERATION_HEX: &str = "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "compose_generation_is_reported_only_by_authenticated_status_and_ready_lifecycle",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("start Compose generation test process");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("UTF-8 child output");
        for forbidden in [
            "customer-provider-capability",
            "/client-token",
            "/mission-reference",
            "0123456789abcdef0123456789abcdef",
            "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL",
        ] {
            assert!(!stdout.contains(forbidden), "lifecycle exposed {forbidden}");
        }
        let records = stdout
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|record| record.get("lifecycle_state").is_some())
            .collect::<Vec<_>>();
        let generation_records = records
            .iter()
            .filter(|record| record.get("credential_generation").is_some())
            .collect::<Vec<_>>();
        assert_eq!(
            records
                .iter()
                .filter(|record| record["operation"] == "readiness")
                .count(),
            1,
            "{records:?}"
        );
        assert_eq!(generation_records.len(), 1, "{records:?}");
        assert_eq!(generation_records[0]["lifecycle_state"], "ready");
        assert_eq!(generation_records[0]["operation"], "readiness");
        assert_eq!(
            generation_records[0]["credential_generation"],
            GENERATION_HEX
        );
        assert_eq!(
            generation_records[0]["credential_generation"]
                .as_str()
                .expect("generation string")
                .len(),
            64
        );
        assert!(
            GENERATION_HEX
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        return;
    }

    assert!(socket_access_available(), "child requires loopback sockets");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let fixture = CustomerFixture::new();
        let config = load_and_validate_config(fixture.config_path()).expect("validated config");
        let (runtime, _) = config.into_parts();
        let credentials = StartupCredentials::new(
            ClientToken::from_bytes(fixture.token_bytes().to_vec()).expect("test token"),
            fixture.reference(),
            ProvisioningLoadId::new([b'L'; 32]),
            Some(CredentialGeneration::new(GENERATION)),
        );
        let (signals, receiver) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(async move {
            let mut loader = RecordingLoader::new();
            run_customer_agent_with_credentials(
                runtime,
                credentials,
                &mut loader,
                receiver,
                TokenReloadPolicy::Disabled,
            )
            .await
        });
        wait_until_ready(&fixture).await;
        let status = authenticated_status(fixture.application(), fixture.token_bytes()).await;
        assert_eq!(status.credential_generation, GENERATION);
        assert_eq!(status.credential_generation.len(), 32);
        let encoded_status = status.encode_to_vec();
        let token_path = fixture.token.display().to_string();
        let reference_path = fixture.mission_reference.display().to_string();
        for forbidden in [
            fixture.token_bytes(),
            b"customer-provider-capability".as_slice(),
            b"LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL".as_slice(),
            token_path.as_bytes(),
            reference_path.as_bytes(),
        ] {
            assert!(
                !encoded_status
                    .windows(forbidden.len())
                    .any(|window| window == forbidden),
                "status exposed credential-adjacent bytes"
            );
        }
        signals
            .send(AgentSignal::Terminate)
            .await
            .expect("clean stop");
        assert_eq!(finish_runtime(task).await, AgentExit::Clean);
    });
}

#[test]
fn absent_generation_is_empty_in_status_and_omitted_from_every_lifecycle_record() {
    // Break caught: compatibility startup accidentally serializes an empty or
    // synthetic generation instead of preserving the absent-generation shape.
    const CHILD: &str = "ASTER_TEST_ABSENT_GENERATION_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "absent_generation_is_empty_in_status_and_omitted_from_every_lifecycle_record",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("start absent-generation test process");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let records = String::from_utf8(output.stdout)
            .expect("UTF-8 child output")
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|record| record.get("lifecycle_state").is_some())
            .collect::<Vec<_>>();
        assert!(!records.is_empty());
        assert_eq!(
            records
                .iter()
                .filter(|record| record["operation"] == "readiness")
                .count(),
            1,
            "{records:?}"
        );
        assert!(
            records
                .iter()
                .all(|record| record.get("credential_generation").is_none()),
            "{records:?}"
        );
        return;
    }

    assert!(socket_access_available(), "child requires loopback sockets");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let fixture = CustomerFixture::new();
        let config = load_and_validate_config(fixture.config_path()).expect("validated config");
        let (runtime, _) = config.into_parts();
        let credentials = StartupCredentials::new(
            ClientToken::from_bytes(fixture.token_bytes().to_vec()).expect("test token"),
            fixture.reference(),
            ProvisioningLoadId::new([b'N'; 32]),
            None,
        );
        let token_path = fixture.token.clone();
        let (signals, receiver) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(async move {
            let mut loader = RecordingLoader::new();
            run_customer_agent_with_credentials(
                runtime,
                credentials,
                &mut loader,
                receiver,
                TokenReloadPolicy::ReloadFrom(token_path),
            )
            .await
        });
        wait_until_ready(&fixture).await;
        let status = authenticated_status(fixture.application(), fixture.token_bytes()).await;
        assert!(status.credential_generation.is_empty());
        signals
            .send(AgentSignal::Terminate)
            .await
            .expect("clean stop");
        assert_eq!(finish_runtime(task).await, AgentExit::Clean);
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn customer_operation_limits_process_preserves_over_limit_reopen() {
    // Break caught: customer startup defaults the selected quota, consumes its
    // emergency reserve, or treats a smaller reopen quota as ledger corruption.
    const CHILD: &str = "ASTER_TEST_OPERATION_LIMITS_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "customer_operation_limits_process_preserves_over_limit_reopen",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .expect("start customer runtime test process");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert!(
        socket_access_available(),
        "this process test requires loopback sockets"
    );
    for (records, bytes, ordinary, lower_records, lower_bytes) in [
        (8, 2_000, 4, 7, 2_000), // record quota, then retained count above the new maximum
        (20, 828, 2, 20, 662),   // byte quota, then retained bytes above the new maximum
    ] {
        // This test exercises quota preservation, not the minimum shutdown
        // deadline. Leave enough grace for a loaded CI runner to flush the
        // reopened over-limit ledger without turning a clean stop into a
        // timing-dependent forced stop.
        let fixture = CustomerFixture::with_shutdown_grace(5_000);
        fixture.set_operation_limits(records, bytes, 2);
        let running = RunningFixture::start(&fixture).await;
        for id in ["bw==", "ZQ=="] {
            claim_publication_fixture(fixture.application(), fixture.token_bytes(), id, 0).await;
        }
        let mut session = 1;
        let mut originals = Vec::new();
        for key in 0..ordinary {
            let (status, response) =
                publish_operation(&fixture, key, false, false, session, ordinary).await;
            assert_eq!(status, 200, "{response}");
            assert_eq!(response["inserted"], true);
            originals.push(response);
        }
        let (status, response) =
            publish_operation(&fixture, 8, false, false, session, ordinary).await;
        assert_eq!(status, 429, "{response}");
        assert_eq!(response["message"], "durable operation capacity exhausted");
        for key in ordinary..ordinary + 2 {
            let (status, response) =
                publish_operation(&fixture, key, true, false, session, ordinary).await;
            assert_eq!(status, 200, "reserved tombstone: {response}");
            originals.push(response);
        }
        let (status, response) =
            publish_operation(&fixture, 9, true, false, session, ordinary).await;
        assert_eq!(status, 429, "{response}");
        assert_eq!(response["message"], "durable operation capacity exhausted");
        running.stop_clean().await;

        fixture.set_operation_limits(lower_records, lower_bytes, 2);
        let running = RunningFixture::start(&fixture).await;
        for id in ["bw==", "ZQ=="] {
            claim_publication_fixture(fixture.application(), fixture.token_bytes(), id, 1).await;
        }
        session = 2;
        for (key, original) in originals.iter().enumerate() {
            let (status, response) =
                publish_operation(&fixture, key, key >= ordinary, false, session, ordinary).await;
            assert_eq!(status, 200, "exact retained retry: {response}");
            assert_eq!(
                response["result"]["receipt"]["eventId"],
                original["result"]["receipt"]["eventId"]
            );
            assert_eq!(
                response["result"]["receipt"]["acceptanceMarker"],
                original["result"]["receipt"]["acceptanceMarker"]
            );
            // Proto JSON omits the default false value.
            assert!(!response["inserted"].as_bool().unwrap_or(false));
        }
        let (status, response) =
            publish_operation(&fixture, 0, false, true, session, ordinary).await;
        assert_eq!(status, 409, "{response}");
        assert_eq!(
            response["message"],
            "operation key conflicts with an existing request"
        );
        for emergency in [false, true] {
            let (status, response) =
                publish_operation(&fixture, 8, emergency, false, session, ordinary).await;
            assert_eq!(status, 429, "{response}");
            assert_eq!(response["message"], "durable operation capacity exhausted");
        }
        assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
        running.stop_clean().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_hangup_keeps_the_old_token_and_readiness() {
    // Break caught: destructive or non-atomic reload revokes the working token
    // or drops readiness when the replacement file is invalid.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let running = RunningFixture::start(&fixture).await;

    fixture.write_token(b"invalid");
    running
        .signals
        .send(AgentSignal::Hangup)
        .await
        .expect("request failed reload");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        application_status(fixture.application(), fixture.token_bytes()).await,
        200
    );
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    running.stop_clean().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_hangup_reloads_only_the_client_token_atomically() {
    // Break caught: reload reopens mission material or exposes a window where
    // neither the old nor fully validated replacement token authorizes.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let old_token = fixture.token_bytes().to_vec();
    let running = RunningFixture::start(&fixture).await;
    fixture.write_reference(b"invalid-reference-canary");
    let replacement = b"replacement-client-token-00000001";
    fixture.write_token(replacement);

    running
        .signals
        .send(AgentSignal::Hangup)
        .await
        .expect("request token reload");
    wait_for_application_status(fixture.application(), replacement, 200).await;
    assert_eq!(
        application_status(fixture.application(), &old_token).await,
        401
    );
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    running.stop_clean().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_hangup_retains_the_current_token() {
    // Break caught: the Compose runtime must not reopen or replace a bind-
    // mounted token on SIGHUP, but must remain ready with the original token.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let old_token = fixture.token_bytes().to_vec();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (runtime, paths) = config.into_parts();
    let credentials = load_startup_credentials(&paths).expect("startup credentials");
    let (signals, receiver) = tokio::sync::mpsc::channel(4);
    let task = tokio::spawn(async move {
        let mut loader = RecordingLoader::new();
        run_customer_agent_with_credentials(
            runtime,
            credentials,
            &mut loader,
            receiver,
            TokenReloadPolicy::Disabled,
        )
        .await
    });
    wait_until_ready(&fixture).await;

    let replacement = b"replacement-client-token-00000002";
    fixture.write_token(replacement);
    signals
        .send(AgentSignal::Hangup)
        .await
        .expect("send hangup");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        application_status(fixture.application(), &old_token).await,
        200
    );
    assert_eq!(
        application_status(fixture.application(), replacement).await,
        401
    );
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    signals
        .send(AgentSignal::Terminate)
        .await
        .expect("stop runtime");
    assert_eq!(finish_runtime(task).await, AgentExit::Clean);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn second_terminate_forces_a_blocked_graceful_drain() {
    // Break caught: ignoring the second termination signal can strand an
    // operator behind an in-flight connection until the whole grace expires.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::with_shutdown_grace(5_000);
    let running = RunningFixture::start(&fixture).await;
    let stalled = fill_unauthenticated_admission(fixture.application()).await;

    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    wait_for_health_status(fixture.health(), "/readyz", 503).await;
    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("force drain");
    assert_eq!(running.finish().await, AgentExit::Forced);
    drop(stalled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grace_expiry_forces_a_blocked_graceful_drain() {
    // Break caught: waiting indefinitely for a stalled connection violates the
    // configured process shutdown bound.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::with_shutdown_grace(50);
    let running = RunningFixture::start(&fixture).await;
    let stalled = fill_unauthenticated_admission(fixture.application()).await;

    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    assert_eq!(running.finish().await, AgentExit::Forced);
    drop(stalled);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_publish_finishes_before_node_shutdown() {
    // Break caught: starting selected-node shutdown concurrently with HTTP
    // drain can reject a mutating unary request that already passed the
    // pre-body admission gate but has not finished decoding its body.
    if !socket_access_available() {
        return;
    }
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let fixture = CustomerFixture::with_shutdown_grace(2_000);
    let running = RunningFixture::start(&fixture).await;
    claim_publication_fixture(fixture.application(), fixture.token_bytes(), "bw==", 0).await;
    let request = aster_agent::proto::aster::application::v1alpha1::PublishNumberedEventRequest {
        client_id: b"o".to_vec(),
        session: 1,
        operation_sequence: 1,
        topic: "chat.events".to_owned(),
        scope: "mission/team/alpha".to_owned(),
        priority: aster_agent::proto::aster::application::v1alpha1::Priority::Immediate.into(),
        logical_key: b"drain-message".to_vec(),
        payload: b"accepted before shutdown".to_vec(),
        ..Default::default()
    };
    let body = request.encode_to_vec();
    let mut connection = tokio::net::TcpStream::connect(fixture.application())
        .await
        .expect("connect admitted publish");
    connection
        .write_all(
            format!(
                "POST /aster.application.v1alpha1.AsterApplicationService/PublishNumberedEvent HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/proto\r\nConnect-Protocol-Version: 1\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
                String::from_utf8_lossy(fixture.token_bytes()),
                body.len(),
            )
            .as_bytes(),
        )
        .await
        .expect("write admitted publish headers");

    // Wait for body polling before issuing a competing one-slot status probe.
    // Otherwise that probe can win admission and reject the publish itself.
    let mut interim = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !interim.ends_with(b"\r\n\r\n") {
            interim.push(connection.read_u8().await.expect("continue response byte"));
            assert!(interim.len() <= 1024);
        }
    })
    .await
    .expect("continue response deadline");
    assert!(interim.starts_with(b"HTTP/1.1 100"));

    // With one global in-flight slot, a rejected status probe proves the
    // Publish headers passed the gate and its permit is held before draining.
    wait_for_application_status(fixture.application(), fixture.token_bytes(), 429).await;
    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    wait_for_health_status(fixture.health(), "/readyz", 503).await;
    connection
        .write_all(&body)
        .await
        .expect("finish admitted publish body");

    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(2),
        connection.read_to_end(&mut response),
    )
    .await
    .expect("admitted publish response deadline")
    .expect("read admitted publish response");
    assert_eq!(
        http_response_status(&response),
        200,
        "admitted publish response: {}",
        String::from_utf8_lossy(&response)
    );
    let response_body = chunked_response_body(&response);
    let published =
        aster_agent::proto::aster::application::v1alpha1::PublishNumberedEventResponse::decode_from_slice(
            &response_body,
        )
        .expect("decode admitted publish response");
    assert!(published.inserted);
    assert_eq!(running.finish().await, AgentExit::Clean);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_signal_task_propagates_only_a_bounded_failure_reason() {
    // Break caught: losing the signal task without a terminal transition can
    // leave the process serving forever or expose an internal channel error.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let running = RunningFixture::start(&fixture).await;
    let RunningFixture { signals, task } = running;
    drop(signals);
    assert_eq!(
        finish_runtime(task).await,
        AgentExit::Failed(FailureReason::Runtime)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn radio_inert_btle_lane_stays_unselected_for_real_durable_work() {
    // Break caught: retaining an Unavailable BLE lane must never consume or
    // dispatch a real eligible durable attempt while the service remains ready.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let prepared_dropped = Arc::new(AtomicBool::new(false));
    let policy = fixture.enable_btle_policy();
    let (btle, automatic) = BtleRuntimeStartup::radio_inert_with_test_observer(
        PreparedBtleProbe(Arc::clone(&prepared_dropped)),
        policy,
    );
    let running = start_with_optional_btle(&fixture, btle).await;
    let automatic = automatic.await.expect("radio-inert registration observed");
    let mission = aster_node::mission::UnprotectedReferenceMission::from_bytes(
        include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle").to_vec(),
    )
    .expect("public test mission");
    let peer = [0x5a; 32];

    assert_eq!(
        automatic.replace_eligibility(vec![
            EventPeerEligibility::provisioned_exact_peer(
                mission.mission_authority_id(),
                peer,
                EventTransportKind::BLE_L2CAP_V1,
                true,
                1,
                0,
                None,
            ),
            EventPeerEligibility::provisioned_exact_peer(
                mission.mission_authority_id(),
                peer,
                EventTransportKind::IROH_QUIC_V1,
                true,
                1,
                0,
                None,
            ),
        ]),
        Some(aster_node::AutomaticEventRosterStatus::Scheduled)
    );
    assert_eq!(
        publish_event_status(fixture.application(), fixture.token_bytes()).await,
        200
    );
    let (_iroh_control, mut iroh_attempts) = automatic
        .register(EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            0,
            EventAdapterState::Available,
            true,
            1,
        ))
        .expect("register available comparison lane");
    let selected = tokio::time::timeout(Duration::from_secs(2), iroh_attempts.recv())
        .await
        .expect("pending work selects the available lane")
        .expect("available lane remains registered");
    assert_eq!(selected.transport_kind(), EventTransportKind::IROH_QUIC_V1);
    assert_eq!(selected.peer(), peer);
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    assert!(!prepared_dropped.load(Ordering::Acquire));

    running.stop_clean().await;
    assert!(prepared_dropped.load(Ordering::Acquire));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn unavailable_btle_and_availability_changes_do_not_gate_readyz() {
    // Break caught: coupling adapter availability to service readiness makes a
    // missing controller or later hotplug take the durable application down.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let (btle, control, prepared_dropped) = injected_btle_runtime(&fixture, JoinBehavior::Complete);
    let running = start_with_optional_btle(&fixture, btle).await;

    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    control.publish(1, EventAdapterState::Available);
    tokio::task::yield_now().await;
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);
    control.publish(2, EventAdapterState::Unavailable);
    tokio::task::yield_now().await;
    assert_eq!(health_status(fixture.health(), "/readyz").await, 200);

    control
        .completion
        .send(true)
        .expect("announce unexpected completion");
    assert_eq!(
        running.finish().await,
        AgentExit::Failed(FailureReason::Runtime)
    );
    assert!(control.state.cancelled.load(Ordering::Acquire));
    assert!(control.state.joined.load(Ordering::Acquire));
    assert!(prepared_dropped.load(Ordering::Acquire));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn btle_cleanup_starts_after_node_attempt_admission_is_closed() {
    // Break caught: leaving automatic/contact admission open while cancelling
    // the adapter can delegate fresh work into an owner that is already draining.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let (btle, control, _) = injected_btle_runtime(&fixture, JoinBehavior::Complete);
    let running = start_with_optional_btle(&fixture, btle).await;

    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    assert_eq!(running.finish().await, AgentExit::Clean);
    assert!(control.state.cancelled.load(Ordering::Acquire));
    assert!(control.state.joined.load(Ordering::Acquire));
    assert_eq!(
        *control
            .state
            .trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        [
            "admission_closed",
            "cancel",
            "join_started",
            "join_completed",
            "node_shutdown_started",
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn completed_btle_owner_prevents_ready_startup() {
    // Break caught: an owner already reporting terminal completion must fail
    // startup rather than briefly publishing Ready and then failing at runtime.
    assert_pre_ready_btle_terminal(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn dropped_btle_completion_sender_prevents_ready_startup() {
    // Break caught: losing the owner's completion sender before Ready is a
    // terminal startup failure even when it never publishes `true`.
    assert_pre_ready_btle_terminal(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn startup_deadline_aborts_blocked_btle_cleanup() {
    // Break caught: timing out an awaited JoinHandle detaches the task unless
    // the supervisor explicitly aborts and retires it.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::with_shutdown_grace(100);
    let (btle, control, prepared_dropped) = injected_btle_runtime(&fixture, JoinBehavior::Block);
    control
        .completion
        .send(true)
        .expect("complete owner before startup");

    assert_eq!(
        run_with_optional_btle(&fixture, btle).await,
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
    assert!(prepared_dropped.load(Ordering::Acquire));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn btle_owner_construction_failure_closes_and_releases_node() {
    // Break caught: returning directly from failed owner construction could
    // leak startup-closed admission, listeners, or state custody.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let policy = fixture.enable_btle_policy();
    let prepared_dropped = Arc::new(AtomicBool::new(false));
    let prepared = PreparedBtleProbe(Arc::clone(&prepared_dropped));
    let (entered_send, entered_receive) = tokio::sync::oneshot::channel();
    let (release_send, release_receive) = std_mpsc::channel();
    let btle = BtleRuntimeStartup::prepared(policy, prepared, move |_prepared, automatic| {
        let _ = entered_send.send(automatic);
        release_receive.recv().expect("release owner construction");
        Err(BtleRuntimeOwnerError::Startup)
    });
    let (_signals, task) = spawn_with_optional_btle(&fixture, btle);
    let automatic = tokio::time::timeout(Duration::from_secs(2), entered_receive)
        .await
        .expect("owner construction entry deadline")
        .expect("owner construction entered");

    assert_eq!(health_status(fixture.health(), "/readyz").await, 503);
    let application_probe =
        std::net::TcpListener::bind(fixture.application()).expect("application remains unbound");
    drop(application_probe);
    release_send.send(()).expect("release owner construction");

    assert_eq!(
        task.await.expect("customer task"),
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
    assert!(prepared_dropped.load(Ordering::Acquire));
    assert!(
        automatic
            .register_paired(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                0,
                EventAdapterState::Unavailable,
                true,
                1,
            ))
            .is_none(),
        "failed startup must terminally close transport admission"
    );
    std::net::TcpListener::bind(fixture.application()).expect("application listener released");
    std::net::TcpListener::bind(fixture.health()).expect("health listener released");

    let (btle, control, _) = injected_btle_runtime(&fixture, JoinBehavior::Complete);
    let (signals, mut restarted) = spawn_with_optional_btle(&fixture, btle);
    tokio::select! {
        result = &mut restarted => panic!("restart failed before Ready: {result:?}"),
        () = wait_until_ready(&fixture) => {}
    }
    signals
        .send(AgentSignal::Terminate)
        .await
        .expect("stop restarted node");
    assert_eq!(
        restarted
            .await
            .expect("restarted customer task")
            .expect("restarted customer result"),
        AgentExit::Clean
    );
    assert!(control.state.joined.load(Ordering::Acquire));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn btle_cleanup_failure_returns_only_the_fixed_shutdown_category() {
    // Break caught: forwarding owner cleanup detail could disclose controller,
    // credential, or path data through the process result.
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let (btle, control, _) = injected_btle_runtime(&fixture, JoinBehavior::Fail);
    let running = start_with_optional_btle(&fixture, btle).await;

    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    assert_eq!(
        running.finish().await,
        AgentExit::Failed(FailureReason::Shutdown)
    );
    assert!(control.state.joined.load(Ordering::Acquire));
}

#[cfg(feature = "sdk-test-support")]
async fn assert_pre_ready_btle_terminal(drop_sender: bool) {
    if !socket_access_available() {
        return;
    }
    let fixture = CustomerFixture::new();
    let (btle, control, _) = injected_btle_runtime(&fixture, JoinBehavior::Complete);
    if drop_sender {
        drop(control);
    } else {
        control
            .completion
            .send(true)
            .expect("complete owner before startup");
    }

    assert_eq!(
        run_with_optional_btle(&fixture, btle).await,
        Err(AgentRuntimeError::Lifecycle(FailureReason::Startup))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn second_terminate_forces_blocked_btle_cleanup() {
    // Break caught: a stuck adapter join must not make the existing second-
    // signal forcing contract wait for the entire grace period.
    assert_forced_btle_cleanup(true, DrainForce::SecondSignal).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn grace_expiry_forces_blocked_btle_cleanup() {
    // Break caught: adapter cleanup must share the process shutdown deadline
    // instead of adding an unbounded or sequential platform grace period.
    assert_forced_btle_cleanup(true, DrainForce::GraceExpiry).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn second_terminate_does_not_repoll_completed_btle_cleanup() {
    // Break caught: forcing a still-draining application after BTLE cleanup
    // completed must not poll the completed JoinHandle a second time and panic.
    assert_forced_btle_cleanup(false, DrainForce::SecondSignal).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(feature = "sdk-test-support")]
async fn grace_expiry_does_not_repoll_completed_btle_cleanup() {
    // Break caught: grace expiry while only the application remains draining
    // must not await the already-completed BTLE JoinHandle again.
    assert_forced_btle_cleanup(false, DrainForce::GraceExpiry).await;
}

#[cfg(feature = "sdk-test-support")]
#[derive(Clone, Copy)]
enum DrainForce {
    SecondSignal,
    GraceExpiry,
}

#[cfg(feature = "sdk-test-support")]
async fn assert_forced_btle_cleanup(block_join: bool, force: DrainForce) {
    if !socket_access_available() {
        return;
    }
    let grace = match force {
        DrainForce::SecondSignal => 5_000,
        DrainForce::GraceExpiry => 100,
    };
    let fixture = CustomerFixture::with_shutdown_grace(grace);
    let join_behavior = if block_join {
        JoinBehavior::Block
    } else {
        JoinBehavior::Complete
    };
    let (btle, control, prepared_dropped) = injected_btle_runtime(&fixture, join_behavior);
    let running = start_with_optional_btle(&fixture, btle).await;
    let stalled = if block_join {
        None
    } else {
        Some(fill_unauthenticated_admission(fixture.application()).await)
    };

    running
        .signals
        .send(AgentSignal::Terminate)
        .await
        .expect("begin drain");
    wait_for_atomic(if block_join {
        &control.state.cancelled
    } else {
        &control.state.cleanup_retired
    })
    .await;
    if matches!(force, DrainForce::SecondSignal) {
        running
            .signals
            .send(AgentSignal::Terminate)
            .await
            .expect("force drain");
    }
    assert_eq!(running.finish().await, AgentExit::Forced);
    assert!(prepared_dropped.load(Ordering::Acquire));
    drop(stalled);
}

#[test]
fn config_check_is_pure_and_bootstrap_uses_exact_reference() {
    // Break caught: configuration checking must not read credentials or touch
    // platform services; bootstrap must still enforce file custody and use the
    // exact mission reference and operation.
    let fixture = CustomerFixture::new();
    let expected_reference = fixture.reference();
    let expected_operation = ProvisioningLoadId::new([0x11; 32]);
    let mut loader = RecordingLoader::new();

    check_config(fixture.config_path()).expect("valid customer configuration");
    assert_eq!(loader.calls(), 0);

    fixture.chmod_reference(0o640);
    check_config(fixture.config_path()).expect("pure configuration check");
    assert_eq!(loader.calls(), 0);
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    assert!(load_startup_credentials(config.credential_paths()).is_err());
    fixture.chmod_reference(0o600);

    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    open_node_config(config.runtime(), &credentials, &mut loader).expect("protected node config");
    assert_eq!(loader.calls(), 1);
    assert_eq!(loader.last_reference(), Some(&expected_reference));
    assert_eq!(loader.last_operation(), Some(expected_operation));
}

#[test]
fn blob_receive_selectors_reach_the_opened_node_config() {
    // Break caught: configuration validation succeeds but protected bootstrap
    // opens a node with the default empty Blob receive interests.
    let fixture = CustomerFixture::new();
    fixture.set_blob_receive(&["imagery@alpha/team", "maps@bravo"], 33_554_432, 4_096, 64);
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    let mut loader = RecordingLoader::new();
    let node = open_node_config(config.runtime(), &credentials, &mut loader)
        .expect("protected node config");

    assert_eq!(
        node.mutable_interests,
        MutableSourceInterests::default().with_blob(vec![
            SourceInterestSelector::new(
                Topic::new("imagery").expect("literal topic"),
                Scope::new("alpha/team").expect("literal scope"),
                false,
            ),
            SourceInterestSelector::new(
                Topic::new("maps").expect("literal topic"),
                Scope::new("bravo").expect("literal scope"),
                false,
            ),
        ])
    );
}

#[test]
fn legacy_customer_config_opens_with_no_blob_receive_interests() {
    // Break caught: the additive configuration change silently enables Blob
    // receipt for an existing systemd-v1 customer file.
    let fixture = CustomerFixture::new();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    let mut loader = RecordingLoader::new();
    let node = open_node_config(config.runtime(), &credentials, &mut loader)
        .expect("protected node config");
    assert_eq!(node.mutable_interests, MutableSourceInterests::default());
}

#[test]
fn bootstrap_failure_redacts_the_provider_reference() {
    // Break caught: forwarding provider detail or the opaque reference from a
    // failed bootstrap would expose a customer credential in diagnostics.
    let fixture = CustomerFixture::new();
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let credentials =
        load_startup_credentials(config.credential_paths()).expect("startup credentials");
    let mut loader = RejectingLoader;

    let error = open_node_config(config.runtime(), &credentials, &mut loader)
        .expect_err("provider rejection must not become a node configuration");
    let rendered = format!("{error:?} {error}");
    assert_eq!(error.kind(), aster_node::NodeBootstrapErrorKind::Rejected);
    assert!(!rendered.contains("customer-provider-capability"));
    assert!(!rendered.contains(&fixture.mission_reference.display().to_string()));
}

#[cfg(feature = "sdk-test-support")]
struct PreparedBtleProbe(Arc<AtomicBool>);

#[cfg(feature = "sdk-test-support")]
impl Drop for PreparedBtleProbe {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(feature = "sdk-test-support")]
struct InjectedBtleState {
    adapter: Mutex<Option<EventAdapterControl>>,
    cancelled: AtomicBool,
    joined: AtomicBool,
    cleanup_retired: AtomicBool,
    trace: Mutex<Vec<&'static str>>,
}

#[cfg(feature = "sdk-test-support")]
impl InjectedBtleState {
    fn trace(&self, event: &'static str) {
        self.trace
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event);
    }
}

#[cfg(feature = "sdk-test-support")]
struct InjectedBtleControl {
    completion: tokio::sync::watch::Sender<bool>,
    state: Arc<InjectedBtleState>,
    _blocked_join: Option<tokio::sync::oneshot::Sender<()>>,
}

#[cfg(feature = "sdk-test-support")]
impl InjectedBtleControl {
    fn publish(&self, epoch: u64, state: EventAdapterState) {
        let guard = self
            .state
            .adapter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            guard
                .as_ref()
                .expect("active adapter control")
                .publish_availability(EventAdapterSnapshot::new(
                    EventTransportKind::BLE_L2CAP_V1,
                    epoch,
                    state,
                    true,
                    1,
                ))
        );
    }
}

#[cfg(feature = "sdk-test-support")]
struct InjectedBtleOwner {
    completion: tokio::sync::watch::Receiver<bool>,
    state: Arc<InjectedBtleState>,
    _attempts: EventAttemptReceiver,
    automatic: RunningAutomaticEventTransportHandle,
    blocked_join: Option<tokio::sync::oneshot::Receiver<()>>,
    fail_join: bool,
    _prepared: PreparedBtleProbe,
}

#[cfg(feature = "sdk-test-support")]
impl BtleRuntimeOwner for InjectedBtleOwner {
    fn completion(&self) -> tokio::sync::watch::Receiver<bool> {
        self.completion.clone()
    }

    fn cancel(&self) {
        let registration = self.automatic.register_paired(EventAdapterSnapshot::new(
            EventTransportKind::IROH_QUIC_V1,
            0,
            EventAdapterState::Unavailable,
            true,
            1,
        ));
        if registration.is_none() {
            self.state.trace("admission_closed");
        }
        drop(registration);
        self.state.trace("cancel");
        self.state.cancelled.store(true, Ordering::Release);
    }

    fn join(self: Box<Self>) -> BoxFuture<'static, Result<(), BtleRuntimeOwnerError>> {
        Box::pin(async move {
            self.state.trace("join_started");
            if let Some(blocked_join) = self.blocked_join {
                let _ = blocked_join.await;
            }
            self.state
                .adapter
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            self.state.trace("join_completed");
            self.state.joined.store(true, Ordering::Release);
            if self.fail_join {
                Err(BtleRuntimeOwnerError::Cleanup)
            } else {
                Ok(())
            }
        })
    }
}

#[cfg(feature = "sdk-test-support")]
#[derive(Clone, Copy)]
enum JoinBehavior {
    Complete,
    Block,
    Fail,
}

#[cfg(feature = "sdk-test-support")]
fn injected_btle_runtime(
    fixture: &CustomerFixture,
    join_behavior: JoinBehavior,
) -> (BtleRuntimeStartup, InjectedBtleControl, Arc<AtomicBool>) {
    let policy = fixture.enable_btle_policy();
    let prepared_dropped = Arc::new(AtomicBool::new(false));
    let prepared = PreparedBtleProbe(Arc::clone(&prepared_dropped));
    let (completion_send, completion_receive) = tokio::sync::watch::channel(false);
    let state = Arc::new(InjectedBtleState {
        adapter: Mutex::new(None),
        cancelled: AtomicBool::new(false),
        joined: AtomicBool::new(false),
        cleanup_retired: AtomicBool::new(false),
        trace: Mutex::new(Vec::new()),
    });
    let (blocked_join_send, blocked_join_receive) = tokio::sync::oneshot::channel();
    let block_join = matches!(join_behavior, JoinBehavior::Block);
    let blocked_join = block_join.then_some(blocked_join_receive);
    let blocked_join_hold = block_join.then_some(blocked_join_send);

    let control = InjectedBtleControl {
        completion: completion_send,
        state: Arc::clone(&state),
        _blocked_join: blocked_join_hold,
    };
    let node_shutdown_state = Arc::clone(&state);
    let cleanup_retired_state = Arc::clone(&state);
    let btle = BtleRuntimeStartup::prepared(policy, prepared, move |prepared, automatic| {
        let registration = automatic
            .register_paired(EventAdapterSnapshot::new(
                EventTransportKind::BLE_L2CAP_V1,
                0,
                EventAdapterState::Unavailable,
                true,
                1,
            ))
            .ok_or(BtleRuntimeOwnerError::Startup)?;
        let (_, adapter_control, attempts) = registration.into_parts();
        *state
            .adapter
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(adapter_control);
        Ok(Box::new(InjectedBtleOwner {
            completion: completion_receive,
            state,
            _attempts: attempts,
            automatic,
            blocked_join,
            fail_join: matches!(join_behavior, JoinBehavior::Fail),
            _prepared: prepared,
        }))
    })
    .with_cleanup_retired_observer(move || {
        cleanup_retired_state
            .cleanup_retired
            .store(true, Ordering::Release);
    })
    .with_node_shutdown_observer(move || node_shutdown_state.trace("node_shutdown_started"));
    (btle, control, prepared_dropped)
}

#[cfg(feature = "sdk-test-support")]
async fn start_with_optional_btle(
    fixture: &CustomerFixture,
    btle: BtleRuntimeStartup,
) -> RunningFixture {
    let (signals, task) = spawn_with_optional_btle(fixture, btle);
    wait_until_ready(fixture).await;
    RunningFixture { signals, task }
}

#[cfg(feature = "sdk-test-support")]
async fn run_with_optional_btle(
    fixture: &CustomerFixture,
    btle: BtleRuntimeStartup,
) -> Result<AgentExit, AgentRuntimeError> {
    let (_signals, task) = spawn_with_optional_btle(fixture, btle);
    task.await.expect("customer task")
}

#[cfg(feature = "sdk-test-support")]
fn spawn_with_optional_btle(
    fixture: &CustomerFixture,
    btle: BtleRuntimeStartup,
) -> (
    tokio::sync::mpsc::Sender<AgentSignal>,
    tokio::task::JoinHandle<Result<AgentExit, AgentRuntimeError>>,
) {
    let config = load_and_validate_config(fixture.config_path()).expect("validated config");
    let (signals, receiver) = tokio::sync::mpsc::channel(4);
    let task = tokio::spawn(async move {
        let mut loader = RecordingLoader::new();
        run_customer_agent_with_btle(config, &mut loader, receiver, btle).await
    });
    (signals, task)
}

#[cfg(feature = "sdk-test-support")]
async fn wait_for_atomic(value: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !value.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("atomic observation deadline");
}

struct CustomerFixture {
    root: PathBuf,
    config: PathBuf,
    token: PathBuf,
    mission_reference: PathBuf,
    reference: ProvisioningSecretRef,
    application: SocketAddr,
    health: SocketAddr,
}

impl CustomerFixture {
    fn new() -> Self {
        Self::with_shutdown_grace(1_000)
    }

    fn with_shutdown_grace(shutdown_grace_ms: u64) -> Self {
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "aster-agent-customer-runtime-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("protect fixture root");
        let state = root.join("state");
        fs::create_dir(&state).expect("create fixture state directory");
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700))
            .expect("protect fixture state directory");

        let token = root.join("client-token");
        fs::write(&token, b"0123456789abcdef0123456789abcdef\n").expect("write token");
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).expect("protect token");

        let mission_reference = root.join("mission-reference");
        let reference =
            ProvisioningSecretRef::from_opaque(b"customer-provider-capability".to_vec())
                .expect("valid reference");
        fs::write(&mission_reference, reference.to_bytes()).expect("write reference");
        fs::set_permissions(&mission_reference, fs::Permissions::from_mode(0o600))
            .expect("protect reference");

        let application = unused_address();
        let health = unused_address();
        assert_ne!(application, health);
        let config = root.join("agent.json");
        fs::write(
            &config,
            format!(
                r#"{{"schema_version":1,"state":{{"directory":"{}"}},"application":{{"listen":"{application}"}},"health":{{"listen":"{health}"}},"mesh":{{"bind":"127.0.0.1:0","sync_interval_ms":500,"emission_policy":"normal","peers":[]}},"credentials":{{"client_token_file":"{}","mission_secret_ref_file":"{}","mission_load_id":"{}"}},"storage":{{"max_items":10000,"max_payload_bytes":67108864,"operations":{{"max_records":1000000,"max_logical_bytes":201326592,"emergency_reserve":10000}}}},"limits":{{"max_in_flight_requests":1,"shutdown_grace_ms":{shutdown_grace_ms}}}}}"#,
                state.display(),
                token.display(),
                mission_reference.display(),
                "11".repeat(32),
            ),
        )
        .expect("write customer configuration");

        Self {
            root,
            config,
            token,
            mission_reference,
            reference,
            application,
            health,
        }
    }

    fn config_path(&self) -> &Path {
        &self.config
    }

    fn reference(&self) -> ProvisioningSecretRef {
        self.reference.clone()
    }

    fn application(&self) -> SocketAddr {
        self.application
    }

    fn health(&self) -> SocketAddr {
        self.health
    }

    fn token_bytes(&self) -> &[u8] {
        b"0123456789abcdef0123456789abcdef"
    }

    fn write_token(&self, token: &[u8]) {
        fs::write(&self.token, token).expect("replace token");
        fs::set_permissions(&self.token, fs::Permissions::from_mode(0o600))
            .expect("protect replacement token");
    }

    fn write_reference(&self, reference: &[u8]) {
        fs::write(&self.mission_reference, reference).expect("replace mission reference");
        fs::set_permissions(&self.mission_reference, fs::Permissions::from_mode(0o600))
            .expect("protect replacement mission reference");
    }

    fn set_emission_policy(&self, policy: &str) {
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.config).expect("read customer config"))
                .expect("parse customer config");
        config["mesh"]["emission_policy"] = policy.into();
        fs::write(
            &self.config,
            serde_json::to_vec(&config).expect("encode customer config"),
        )
        .expect("write customer config");
    }

    fn enable_btle_policy(&self) -> ValidatedBtlePolicy {
        self.enable_btle_policy_with_priority(100)
    }

    fn enable_btle_policy_with_priority(&self, priority: u16) -> ValidatedBtlePolicy {
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.config).expect("read customer config"))
                .expect("parse customer config");
        config["btle"] = serde_json::json!({
            "peer": "aa".repeat(32),
            "deployment_scope_id": "42".repeat(32),
            "policy": "rostered",
            "emission_policy": "normal",
            "priority": priority,
            "credential": "aster-btle-roster"
        });
        fs::write(
            &self.config,
            serde_json::to_vec(&config).expect("encode customer config"),
        )
        .expect("write customer config");
        *load_and_validate_config(&self.config)
            .expect("validated BTLE config")
            .runtime()
            .btle_policy()
            .expect("configured BTLE policy")
    }

    fn chmod_reference(&self, mode: u32) {
        fs::set_permissions(&self.mission_reference, fs::Permissions::from_mode(mode))
            .expect("change reference permissions");
    }

    fn set_operation_limits(&self, records: u64, bytes: u64, reserve: u64) {
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.config).unwrap()).unwrap();
        config["storage"]["operations"] = serde_json::json!({
            "max_records": records, "max_logical_bytes": bytes, "emergency_reserve": reserve,
        });
        fs::write(&self.config, serde_json::to_vec(&config).unwrap()).unwrap();
    }

    fn set_blob_receive(
        &self,
        interests: &[&str],
        max_bytes: u64,
        max_chunks: u64,
        max_variants: u64,
    ) {
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&self.config).unwrap()).unwrap();
        config["mesh"]["blob_interests"] = serde_json::json!(interests);
        config["storage"]["blob_depot"] = serde_json::json!({
            "max_bytes": max_bytes,
            "max_chunks": max_chunks,
            "max_variants": max_variants,
        });
        fs::write(&self.config, serde_json::to_vec(&config).unwrap()).unwrap();
    }
}

fn unused_address() -> SocketAddr {
    static NEXT_PORT: AtomicU64 = AtomicU64::new(40_000);
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener.local_addr().expect("test address"),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed) as u16;
            SocketAddr::from(([127, 0, 0, 1], port))
        }
        Err(error) => panic!("reserve test address: {error}"),
    }
}

fn socket_access_available() -> bool {
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("SKIP live customer runtime: loopback sockets denied by sandbox");
            false
        }
        Err(error) => panic!("probe loopback socket access: {error}"),
    }
}

struct RunningFixture {
    signals: tokio::sync::mpsc::Sender<AgentSignal>,
    task: tokio::task::JoinHandle<Result<AgentExit, AgentRuntimeError>>,
}

impl RunningFixture {
    async fn start(fixture: &CustomerFixture) -> Self {
        let config = load_and_validate_config(fixture.config_path()).expect("validated config");
        let (signals, receiver) = tokio::sync::mpsc::channel(4);
        let task = tokio::spawn(async move {
            let mut loader = RecordingLoader::new();
            run_customer_agent(config, &mut loader, receiver).await
        });
        wait_until_ready(fixture).await;
        Self { signals, task }
    }

    async fn stop_clean(self) {
        self.signals
            .send(AgentSignal::Terminate)
            .await
            .expect("request clean stop");
        assert_eq!(self.finish().await, AgentExit::Clean);
    }

    async fn finish(self) -> AgentExit {
        finish_runtime(self.task).await
    }
}

async fn finish_runtime(
    task: tokio::task::JoinHandle<Result<AgentExit, AgentRuntimeError>>,
) -> AgentExit {
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("runtime completion deadline")
        .expect("runtime task joins")
        .expect("runtime result")
}

struct BlockingLoader {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: std_mpsc::Receiver<()>,
}

impl ProvisioningSecretLoader for BlockingLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        reference: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.entered.send(()).expect("announce loader entry");
        self.release.recv().expect("wait for loader release");
        test_load_receipt(operation, reference)
    }
}

async fn wait_until_ready(fixture: &CustomerFixture) {
    wait_for_health_status(fixture.health(), "/readyz", 200).await;
}

async fn fill_unauthenticated_admission(address: SocketAddr) -> Vec<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let limit = aster_agent::config::AgentLimits::default().max_unauthenticated_connections();
    let mut admitted = Vec::with_capacity(limit);
    for _ in 0..limit {
        let mut stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("open admitted incomplete connection");
        stream
            .write_all(b"G")
            .await
            .expect("start incomplete request");
        admitted.push(stream);
    }

    let mut refused = tokio::net::TcpStream::connect(address)
        .await
        .expect("kernel accepts saturation probe");
    refused
        .write_all(b"G")
        .await
        .expect("write saturation probe");
    let mut byte = [0_u8; 1];
    match tokio::time::timeout(Duration::from_secs(1), refused.read(&mut byte))
        .await
        .expect("saturation probe is refused promptly")
    {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        Ok(read) => panic!("saturation probe received {read} response bytes"),
        Err(error) => panic!("unexpected saturation refusal: {error}"),
    }
    admitted
}

async fn wait_for_health_status(address: SocketAddr, path: &str, expected: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("health endpoint did not reach {expected}");
        }
        if health_status(address, path).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_application_status(address: SocketAddr, token: &[u8], expected: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tokio::time::Instant::now() >= deadline {
            panic!("application endpoint did not reach {expected}");
        }
        if application_status(address, token).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

async fn health_status(address: SocketAddr, path: &str) -> u16 {
    http_status(
        address,
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
}

async fn application_status(address: SocketAddr, token: &[u8]) -> u16 {
    http_status(
        address,
        format!(
            "POST /aster.application.v1alpha1.AsterApplicationService/GetStatus HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/proto\r\nConnect-Protocol-Version: 1\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            String::from_utf8_lossy(token),
        )
        .as_bytes(),
    )
    .await
}

async fn authenticated_status(address: SocketAddr, token: &[u8]) -> api::GetStatusResponse {
    let response = http_response(
        address,
        format!(
            "POST /aster.application.v1alpha1.AsterApplicationService/GetStatus HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/proto\r\nConnect-Protocol-Version: 1\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            String::from_utf8_lossy(token),
        )
        .as_bytes(),
    )
    .await;
    assert_eq!(http_response_status(&response), 200);
    let offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response body")
        + 4;
    let body = if String::from_utf8_lossy(&response[..offset])
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        chunked_response_body(&response)
    } else {
        response[offset..].to_vec()
    };
    api::GetStatusResponse::decode_from_slice(&body).expect("protobuf status response")
}

async fn publish_event_status(address: SocketAddr, token: &[u8]) -> u16 {
    claim_publication_fixture(address, token, "bw==", 0).await;
    let body = serde_json::to_vec(&serde_json::json!({
        "clientId": "bw==", "session": "1", "operationSequence": "1",
        "topic": "chat.events",
        "scope": "mission/team/alpha",
        "priority": "PRIORITY_IMMEDIATE",
        "logicalKey": "cmVjZWl2ZS1vbmx5LWxvY2FsLWtleQ==",
        "payload": "YWNjZXB0ZWQgd2l0aG91dCBvdXRib3VuZCBlbWlzc2lvbg=="
    }))
    .expect("encode publication request");
    http_status(
        address,
        format!(
            "POST /aster.application.v1alpha1.AsterApplicationService/PublishNumberedEvent HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            String::from_utf8_lossy(token),
            body.len(),
            String::from_utf8_lossy(&body),
        )
        .as_bytes(),
    )
    .await
}

async fn http_status(address: SocketAddr, request: &[u8]) -> u16 {
    let response = http_response(address, request).await;
    if response.is_empty() {
        return 0;
    }
    http_response_status(&response)
}

async fn publish_operation(
    fixture: &CustomerFixture,
    key: usize,
    tombstone: bool,
    changed: bool,
    session: u64,
    ordinary: usize,
) -> (u16, serde_json::Value) {
    // Two fixed producer identities with independent contiguous sequences; logical keys remain application data.
    let keys = [
        "AA==", "AQ==", "Ag==", "Aw==", "BA==", "BQ==", "Bg==", "Bw==", "CA==", "CQ==",
    ];
    let body = serde_json::json!({
        "clientId": if tombstone { "ZQ==" } else { "bw==" },
        "session": session.to_string(),
        "operationSequence": (if key < ordinary { key + 1 } else if key < ordinary + 2 { key - ordinary + 1 } else if tombstone { 3 } else { ordinary + 1 }).to_string(),
        "topic": "chat.events", "scope": "mission/team/alpha",
        "priority": "PRIORITY_IMMEDIATE", "logicalKey": keys[key],
        "payload": if tombstone { "" } else if changed { "dHdv" } else { "b25l" },
        "tombstone": tombstone,
    })
    .to_string();
    let request = format!(
        "POST /aster.application.v1alpha1.AsterApplicationService/PublishNumberedEvent HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        String::from_utf8_lossy(fixture.token_bytes()),
        body.len(),
        body,
    );
    let response = http_response(fixture.application(), request.as_bytes()).await;
    let offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let body = if String::from_utf8_lossy(&response[..offset])
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        chunked_response_body(&response)
    } else {
        response[offset..].to_vec()
    };
    (
        http_response_status(&response),
        serde_json::from_slice(&body).expect("publication response"),
    )
}

async fn http_response(address: SocketAddr, request: &[u8]) -> Vec<u8> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let Ok(mut stream) = tokio::net::TcpStream::connect(address).await else {
        return Vec::new();
    };
    stream.write_all(request).await.expect("write HTTP request");
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("HTTP response deadline")
        .expect("read HTTP response");
    response
}

fn http_response_status(response: &[u8]) -> u16 {
    String::from_utf8_lossy(response)
        .split_whitespace()
        .nth(1)
        .expect("HTTP status")
        .parse()
        .expect("numeric HTTP status")
}

fn chunked_response_body(response: &[u8]) -> Vec<u8> {
    let body_offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .expect("HTTP response body");
    let mut encoded = &response[body_offset..];
    let mut decoded = Vec::new();
    loop {
        let size_end = encoded
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size terminator");
        let size = usize::from_str_radix(
            std::str::from_utf8(&encoded[..size_end]).expect("ASCII chunk size"),
            16,
        )
        .expect("hexadecimal chunk size");
        encoded = &encoded[size_end + 2..];
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&encoded[..size]);
        encoded = &encoded[size + 2..];
    }
    decoded
}

impl Drop for CustomerFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct RecordingLoader {
    calls: usize,
    operation: Option<ProvisioningLoadId>,
    reference: Option<ProvisioningSecretRef>,
}

impl RecordingLoader {
    fn new() -> Self {
        Self {
            calls: 0,
            operation: None,
            reference: None,
        }
    }

    fn calls(&self) -> usize {
        self.calls
    }

    fn last_operation(&self) -> Option<ProvisioningLoadId> {
        self.operation
    }

    fn last_reference(&self) -> Option<&ProvisioningSecretRef> {
        self.reference.as_ref()
    }
}

impl ProvisioningSecretLoader for RecordingLoader {
    fn load(
        &mut self,
        operation: ProvisioningLoadId,
        reference: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        self.calls += 1;
        self.operation = Some(operation);
        self.reference = Some(reference.clone());
        test_load_receipt(operation, reference)
    }
}

fn test_load_receipt(
    operation: ProvisioningLoadId,
    reference: &ProvisioningSecretRef,
) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
    let bundle = include_bytes!("../../../bindings/testdata/non-production-provisioning.bundle");
    Ok(ProvisioningLoadReceipt::new(
        operation,
        reference.clone(),
        UnprotectedProvisioning::new(bundle.to_vec())
            .expect("bounded disposable public test provisioning"),
    ))
}

struct RejectingLoader;

impl ProvisioningSecretLoader for RejectingLoader {
    fn load(
        &mut self,
        _operation: ProvisioningLoadId,
        _reference: &ProvisioningSecretRef,
    ) -> Result<ProvisioningLoadReceipt, ProvisioningSecretStoreError> {
        Err(ProvisioningSecretStoreError::Rejected)
    }
}

async fn claim_publication_fixture(
    address: SocketAddr,
    token: &[u8],
    client_id: &str,
    expected: u64,
) {
    let response = publication_rpc_json(address, token, "BeginEventPublicationSession", serde_json::json!({
        "clientId": client_id, "expectedSession": expected.to_string(),
        "claimNonce": if expected == 0 { "aW5pdGlhbC1jbGFpbQ==" } else { "cmVzdGFydC1jbGFpbQ==" },
    })).await;
    let session = response["session"].as_str().unwrap();
    assert_eq!(session.parse::<u64>().unwrap(), expected + 1);
    publication_rpc_json(address, token, "CompleteEventPublicationRecovery", serde_json::json!({
        "clientId": client_id, "session": session, "snapshotRevision": response["snapshotRevision"],
    })).await;
}

async fn publication_rpc_json(
    address: SocketAddr,
    token: &[u8],
    operation: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let body = body.to_string();
    let request = format!(
        "POST /aster.application.v1alpha1.AsterApplicationService/{operation} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        String::from_utf8_lossy(token),
        body.len(),
        body
    );
    let response = http_response(address, request.as_bytes()).await;
    assert_eq!(
        http_response_status(&response),
        200,
        "{}",
        String::from_utf8_lossy(&response)
    );
    let offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 4;
    let body = if String::from_utf8_lossy(&response[..offset])
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        chunked_response_body(&response)
    } else {
        response[offset..].to_vec()
    };
    serde_json::from_slice(&body).unwrap()
}
