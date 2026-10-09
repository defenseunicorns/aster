//! Minimal selected Event application example.
//!
//! Run with a state directory and its explicitly unprotected reference mission
//! bundle. The example uses only the high-level selected Event application API.

use std::{env, error::Error, path::PathBuf};

use aster_node::application::{
    EventPollRequest, EventQuery, EventSubscriptionRequest, Priority, Scope, SelectedEventNode,
    Topic,
};

use aster_node::publication_journal as numbered;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut arguments = env::args_os().skip(1);
    let state = arguments.next().map(PathBuf::from).ok_or(
        "usage: event_application STATE_DIR MISSION_BUNDLE [--initialize-publication-journal]",
    )?;
    let mission = arguments.next().map(PathBuf::from).ok_or(
        "usage: event_application STATE_DIR MISSION_BUNDLE [--initialize-publication-journal]",
    )?;
    let initialize = match arguments.next() {
        None => false,
        Some(value) if value == "--initialize-publication-journal" => true,
        Some(_) => {
            return Err("unknown argument; expected --initialize-publication-journal".into());
        }
    };
    if arguments.next().is_some() {
        return Err(
            "usage: event_application STATE_DIR MISSION_BUNDLE [--initialize-publication-journal]"
                .into(),
        );
    }

    // The capability-tour fixture provisions this topic/scope. Operational
    // applications choose values admitted by their own mission provider.
    let topic = Topic::new("mesh.ping-pong")?;
    let scope = Scope::new("demo/mesh")?;
    let journal_path = state.join("event-application-publication.redb");
    if initialize {
        numbered::Journal::initialize(&journal_path, b"native.event-application.v1")?;
    }
    let mut journal = numbered::Journal::open(&journal_path, b"native.event-application.v1")?;
    let mut node = SelectedEventNode::open_unprotected_reference(&state, &mission)?;
    journal
        .recover(&mut numbered::Backend::Stopped(&mut node))
        .await?;
    let intent = numbered::Intent {
        predecessor: None,
        topic: topic.as_str().into(),
        scope: scope.as_str().into(),
        priority: Priority::Priority as u8,
        logical_key: b"asset-7".to_vec(),
        payload: b"ready".to_vec(),
        tombstone: false,
        ttl_ms: None,
    };
    // Recover the exact retained intent before accepting new application work.
    if let Some((_, pending)) = journal.pending()
        && pending != &intent
    {
        return Err("retained intent differs; explicit repair is required".into());
    }
    let result = journal
        .publish(&mut numbered::Backend::Stopped(&mut node), intent.clone())
        .await?;
    let published = numbered::Backend::Stopped(&mut node)
        .metadata(&intent, &result)
        .await?;
    println!(
        "published id={} sequence={} inserted={}",
        published.id, published.event_sequence, published.inserted
    );

    let page = node.query(EventQuery {
        topic: Some(topic.clone()),
        scope: Some(scope.clone()),
        logical_key: Some(b"asset-7".to_vec()),
        ..EventQuery::default()
    })?;
    for item in page.items {
        println!(
            "event id={} sequence={} key={} payload={}",
            item.id,
            item.event_sequence,
            String::from_utf8_lossy(&item.logical_key),
            String::from_utf8_lossy(&item.payload),
        );
    }

    let subscription = node.subscribe(EventSubscriptionRequest {
        operation_key: b"example/mesh-ping-pong/consume".to_vec(),
        topic,
        scope,
        include_descendant_scopes: false,
    })?;
    let deliveries = node.poll(EventPollRequest {
        subscription: subscription.id,
        delivery_limit: 128,
        scan_limit: 128,
    })?;
    let mut published_delivery = None;
    for delivery in deliveries.deliveries {
        if delivery.event.id == published.id {
            published_delivery = Some(delivery.attempt);
        }
        node.acknowledge(subscription.id, delivery.event.id)?;
    }
    let disposition = match published_delivery {
        Some(attempt) => format!("delivered-attempt-{attempt}"),
        None => format!("{:?}", node.acknowledge(subscription.id, published.id)?),
    };
    println!(
        "subscription id={} inserted={} published_event={disposition}",
        subscription.id, subscription.inserted
    );
    journal
        .acknowledge(&mut numbered::Backend::Stopped(&mut node))
        .await?;
    Ok(())
}
