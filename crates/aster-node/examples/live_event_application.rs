use std::{env, error::Error, net::SocketAddr, path::PathBuf, time::Duration};

use aster_node::{
    NodeApplication, NodeConfig,
    application::{
        EventGapQuery, EventPollRequest, EventQuery, EventSubscriptionRequest, Priority, Scope,
        Topic,
    },
    mission::UnprotectedReferenceMission,
    start_node,
};

#[path = "support/numbered.rs"]
mod numbered;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "live_event_application".into());
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
    let journal_path = state.join("live_event_application-publication.redb");
    if initialize {
        numbered::Journal::initialize(&journal_path, b"native.live-event-application.v1")?;
    }
    let mut journal = numbered::Journal::open(&journal_path, b"native.live-event-application.v1")?;
    let scope = Scope::new(scope)?;
    let topic = Topic::new(topic)?;
    let mission = UnprotectedReferenceMission::load(mission_bundle)?;
    let running = start_node(NodeConfig {
        state,
        bind: SocketAddr::from(([127, 0, 0, 1], 0)),
        mission,
        peers: Vec::new(),
        mutable_interests: Default::default(),
        sync_interval: Duration::from_millis(250),
        run_for: None,
        application: NodeApplication::Relay,
    })
    .await?;
    let events = running.selected_events();
    journal
        .recover(&mut numbered::Backend::Live(&events))
        .await?;

    let subscription = events
        .subscribe(EventSubscriptionRequest {
            operation_key: b"aster.example.live/receive".to_vec(),
            topic: topic.clone(),
            scope: scope.clone(),
            include_descendant_scopes: false,
        })
        .await?;
    let intent = numbered::Intent {
        predecessor: None,
        topic: topic.as_str().into(),
        scope: scope.as_str().into(),
        priority: Priority::Priority as u8,
        logical_key: b"hello".to_vec(),
        payload: b"hello from the live selected Event API".to_vec(),
        tombstone: false,
        ttl_ms: None,
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

    let page = events
        .query(EventQuery {
            publisher: Some(events.identity()),
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            limit: 16,
            ..EventQuery::default()
        })
        .await?;
    let deliveries = events
        .poll(EventPollRequest {
            subscription: subscription.id,
            delivery_limit: 16,
            scan_limit: 16,
        })
        .await?;
    for delivery in &deliveries.deliveries {
        events
            .acknowledge(subscription.id, delivery.event.id)
            .await?;
    }
    let gaps = events
        .gaps(EventGapQuery {
            publisher: events.identity(),
            topic,
            scope,
            after_sequence: 0,
            scan_limit: 16,
        })
        .await?;
    let status = events.status().await?;
    println!(
        "LIVE_EVENT id={} inserted={} query_items={} deliveries={} gaps={} scanned_through={} sync={:?}",
        publication.id,
        publication.inserted,
        page.items.len(),
        deliveries.deliveries.len(),
        gaps.gaps.len(),
        gaps.scanned_through_sequence,
        status.sync,
    );
    events.unsubscribe(subscription.id).await?;
    journal
        .acknowledge(&mut numbered::Backend::Live(&events))
        .await?;
    running.shutdown().await?;
    Ok(())
}

fn usage(program: &str) -> String {
    format!(
        "usage: {program} STATE_DIRECTORY MISSION_BUNDLE SCOPE TOPIC [--initialize-publication-journal]\n\
         example: cargo run -p aster-node --example live_event_application -- \
         /tmp/aster-live node.bundle mission/apps ops.alpha"
    )
}
