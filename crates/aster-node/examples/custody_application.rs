//! Public selected-custody API example.
//!
//! Finite TTL requires Linux's suspend-inclusive boot clock. On other
//! platforms this example prints an explicit marker and publishes the same
//! Event durably so the rest of the lifecycle remains runnable.

use std::{env, error::Error, net::SocketAddr, path::PathBuf, time::Duration};

use aster_node::{
    CustodyQuota, EventEmissionPolicy, NodeApplication, NodeConfig, SelectedForwardingConfig,
    StoreLimits,
    application::{EventPublishOptions, Priority, Scope, Topic},
    mission::UnprotectedReferenceMission,
    start_node_with_forwarding,
};

use aster_node::publication_journal as numbered;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "custody_application".into());
    let Some(state) = arguments.next().map(PathBuf::from) else {
        return Err(usage(&program).into());
    };
    let Some(mission_bundle) = arguments.next().map(PathBuf::from) else {
        return Err(usage(&program).into());
    };
    let Some(scope) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Err(usage(&program).into());
    };
    let Some(topic) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Err(usage(&program).into());
    };
    let initialize = match arguments.next() {
        None => false,
        Some(value) if value == "--initialize-publication-journal" => true,
        Some(_) => {
            return Err("unknown argument; expected --initialize-publication-journal".into());
        }
    };
    if arguments.next().is_some() {
        return Err(usage(&program).into());
    }

    let journal_path = state.join("custody_application-publication.redb");
    if initialize {
        numbered::Journal::initialize(&journal_path, b"native.custody-application.v1")?;
    }
    let mut journal = numbered::Journal::open(&journal_path, b"native.custody-application.v1")?;
    let scope = Scope::new(scope)?;
    let topic = Topic::new(topic)?;
    let mission = UnprotectedReferenceMission::load(mission_bundle)?;
    let limits = StoreLimits::new(10_000, 32 * 1024 * 1024)?;
    let forwarding =
        SelectedForwardingConfig::new(EventEmissionPolicy::at_least(Priority::Priority), limits)
            .with_scope_quota(CustodyQuota::for_scope(
                scope.clone(),
                1_024,
                8 * 1024 * 1024,
            )?)?;
    let running = start_node_with_forwarding(
        NodeConfig {
            state,
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            mission,
            peers: Vec::new(),
            mutable_interests: Default::default(),
            sync_interval: Duration::from_millis(250),
            run_for: None,
            application: NodeApplication::Relay,
        },
        forwarding,
    )
    .await?;

    let (initial_policy, initial_revision) = running.event_emission_policy()?;
    let events = running.selected_events();
    journal
        .recover(&mut numbered::Backend::Live(&events))
        .await?;
    let (options, ttl_status) = if cfg!(target_os = "linux") {
        (
            EventPublishOptions::finite_ttl_ms(60_000)?,
            "finite_ttl_ms=60000",
        )
    } else {
        (
            EventPublishOptions::durable(),
            "finite_ttl=unsupported_on_this_platform,durable_fallback=true",
        )
    };
    let intent = numbered::Intent {
        predecessor: None,
        topic: topic.as_str().into(),
        scope: scope.as_str().into(),
        priority: Priority::Immediate as u8,
        logical_key: b"custody-example".to_vec(),
        payload: b"selected semantic-v3 custody".to_vec(),
        tombstone: false,
        ttl_ms: options.ttl_ms(),
    };
    if let Some((_, pending)) = journal.pending()
        && pending != &intent
    {
        return Err("retained intent differs; explicit repair is required".into());
    }
    let outcome = journal
        .publish(&mut numbered::Backend::Live(&events), intent.clone())
        .await?;
    let publication = numbered::Backend::Live(&events)
        .metadata(&intent, &outcome)
        .await?;

    let updated_revision = running.set_event_emission_policy(EventEmissionPolicy::Normal)?;
    let (updated_policy, observed_revision) = running.event_emission_policy()?;
    journal
        .acknowledge(&mut numbered::Backend::Live(&events))
        .await?;
    let receipt = running.shutdown().await?;
    println!(
        "CUSTODY_APPLICATION {ttl_status} id={} inserted={} authenticated_ttl_ms={:?} \
         initial_policy={initial_policy:?} initial_revision={initial_revision} \
         updated_policy={updated_policy:?} updated_revision={updated_revision} \
         observed_revision={observed_revision} events={}",
        publication.id, publication.inserted, publication.ttl_ms, receipt.events,
    );
    Ok(())
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} STATE_DIRECTORY MISSION_BUNDLE SCOPE TOPIC [--initialize-publication-journal]\n\
         example: cargo run -p aster-node --example custody_application -- \
         /tmp/aster-custody node.bundle mission/apps ops.alpha"
    )
}
