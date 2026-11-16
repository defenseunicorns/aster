use super::empty_handle;
use super::{
    AsterAckRequest, AsterBlobPublishOptions, AsterBlobReadRequest, AsterBlobWriterInfo,
    AsterBytes, AsterCompleteRecoveryRequest, AsterControlReceipt, AsterDeliveryStatus, AsterEntry,
    AsterEventResultRequest, AsterItem, AsterOwnedBuffer, AsterPeerRequest, AsterPeerSnapshot,
    AsterPollRequest, AsterPublishReceipt, AsterPublishRequest, AsterQueryRequest, AsterRecovery,
    AsterRecoveryRequest, AsterRekeyRequest, AsterResolveRequest, AsterResultInfo,
    AsterSubscribeRequest, AsterSubscription, AsterUnsubscribeRequest, AuthenticatedPeerStatus,
    BlobDeliveryItem, BlobDeliveryToken, BlobId, BlobPollRequest, BlobPublicationId,
    BlobPublishOptions, BlobPublishRequest, BlobPublishResult, BlobPublishStreamRequest,
    BlobReadPageRequest, BlobReadRequest, BlobRetirementReason, BlobSubscriptionId,
    BlobSubscriptionRequest, CommittedEventContent, ContactSyncStatus, Entry, EventEmissionPolicy,
    EventId, EventItem, EventPollRequest, EventPublishOptions, EventQuery, EventSubscriptionId,
    EventSubscriptionRequest, FfiError, Item, MAX_SELECTED_BLOB_PAGE_BYTES,
    MAX_SELECTED_EVENT_PAGE, MAX_SELECTED_REKEY_RECIPIENTS, MAX_SELECTED_REKEY_TOPIC_GRANTS,
    NumberedEventPublishRequest, NumberedEventResult, OutputBuffers, PeerAuthorization, Reader,
    RecordDeliveryToken, RecordItem, RecordPollRequest, RecordProjection, RecordProjectionId,
    RecordPublishRequest, RecordQuery, RecordResolveRequest, RecordSubscriptionId,
    RecordSubscriptionRequest, RecordVersionDisposition, RegistryGenerationWitness,
    STATUS_NOT_FOUND, STATUS_OK, STATUS_STALE_CONFLICT, ScopeRekeyRequest, Snapshot,
    StateDeliveryToken, StateId, StateItem, StatePollRequest, StatePublishRequest, StateQuery,
    StateSubscriptionId, StateSubscriptionRequest, StateVersionDisposition, Writer, Zeroizing,
    boolean, boundary, boundary_preserve_error, bounded, capacity, check_mut_pointer, client,
    client_id, closed, emission, fixed, input_array, input_bytes, input_scope, input_string,
    input_topic, new_handle, owned_buffer, priority, release_buffer, require_empty_buffer,
    sequence, take_handle, versioned, versioned_mut, wait, with_node, write_output,
};

fn numbered_receipt(r: NumberedEventResult, inserted: bool) -> AsterPublishReceipt {
    AsterPublishReceipt {
        item_id: *r.receipt.semantic_id.as_bytes(),
        sequence: r.sequence.get(),
        acceptance_marker: r.receipt.acceptance_marker,
        inserted: u8::from(inserted),
        content_retired: u8::from(matches!(r.content, CommittedEventContent::Retired(_))),
        ..Default::default()
    }
}
fn blob_receipt(r: &BlobPublishResult) -> AsterPublishReceipt {
    AsterPublishReceipt {
        item_id: r.publication_id.map_or([0; 32], |id| *id.as_bytes()),
        blob_id: *r.id.as_bytes(),
        publisher: r.publisher,
        publisher_counter: r.publisher_counter,
        acceptance_marker: r.acceptance_marker,
        total_len: r.total_len,
        ttl_ms: r.ttl_ms.unwrap_or(0),
        has_ttl: u8::from(r.ttl_ms.is_some()),
        inserted: u8::from(r.inserted),
        ..Default::default()
    }
}
fn state_item(i: StateItem) -> Item {
    Item {
        id: *i.id.as_bytes(),
        publisher: i.publisher,
        counter: i.publisher_counter,
        class: 0,
        priority: i.priority as u32,
        disposition: match i.disposition {
            StateVersionDisposition::Current => 0,
            StateVersionDisposition::Concurrent => 1,
            StateVersionDisposition::Superseded => 2,
        },
        marker: i.acceptance_marker,
        tombstone: i.tombstone,
        topic: i.topic.as_str().into(),
        scope: i.scope.as_str().into(),
        key: i.logical_key,
        payload: Zeroizing::new(i.payload),
        ..Default::default()
    }
}
fn record_item(i: RecordItem) -> Item {
    Item {
        id: *i.id.as_bytes(),
        publisher: i.publisher,
        counter: i.publisher_counter,
        class: 2,
        priority: i.priority as u32,
        disposition: match i.disposition {
            RecordVersionDisposition::Current => 0,
            RecordVersionDisposition::Concurrent => 1,
            RecordVersionDisposition::Superseded => 2,
        },
        marker: i.acceptance_marker,
        tombstone: i.tombstone,
        topic: i.topic.as_str().into(),
        scope: i.scope.as_str().into(),
        key: i.logical_key,
        payload: Zeroizing::new(i.payload),
        ..Default::default()
    }
}
fn event_item(i: EventItem) -> Item {
    Item {
        id: *i.id.as_bytes(),
        publisher: i.publisher,
        counter: i.publisher_counter,
        class: 1,
        priority: i.priority as u32,
        sequence: i.event_sequence,
        marker: i.acceptance_marker,
        ttl: i.ttl_ms,
        tombstone: i.tombstone,
        topic: i.topic.as_str().into(),
        scope: i.scope.as_str().into(),
        key: i.logical_key,
        payload: Zeroizing::new(i.payload),
        ..Default::default()
    }
}
fn one(item: Item) -> Entry {
    Entry {
        id: item.id,
        topic: item.topic.clone(),
        scope: item.scope.clone(),
        key: item.key.clone(),
        items: vec![item],
        ..Default::default()
    }
}
fn record_entry(p: RecordProjection) -> Entry {
    let mut entry = Entry::default();
    if let Some(c) = p.conflict {
        entry.siblings = c.siblings.iter().flat_map(|i| *i.as_bytes()).collect();
        entry.guard = Some(c.resolution_guard);
    }
    entry.items = p
        .current
        .into_iter()
        .chain(p.concurrent)
        .chain(p.superseded)
        .map(record_item)
        .collect();
    entry
}

#[unsafe(no_mangle)]
pub extern "C" fn aster_node_begin_recovery(
    node: u64,
    request: *const AsterRecoveryRequest,
    out: *mut AsterRecovery,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "recovery")?;
        let out = versioned_mut(out, "recovery output")?;
        if out.results != 0 {
            return Err(FfiError::invalid("recovery results must be empty"));
        }
        let id = client_id(r.client.client_id)?;
        let nonce = input_bytes(r.claim_nonce, "claim_nonce")?.to_vec();
        with_node(node, |n| {
            capacity(n.results.len())?;
            let events = n.running()?.selected_events();
            let recovered =
                n.wait(events.begin_publication_session(id, r.client.session, nonce))??;
            let handle = n.insert(Snapshot {
                receipts: recovered
                    .outstanding
                    .into_iter()
                    .map(|r| numbered_receipt(r, false))
                    .collect(),
                ..Default::default()
            })?;
            *out = AsterRecovery {
                session: recovered.session.get(),
                allocated_through: recovered.allocated_through,
                snapshot_revision: recovered.snapshot_revision,
                results: handle,
                ..Default::default()
            };
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_complete_recovery(
    node: u64,
    request: *const AsterCompleteRecoveryRequest,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "complete recovery")?;
        let c = client(r.client)?;
        with_node(node, |n| {
            n.wait(
                n.running()?
                    .selected_events()
                    .complete_publication_recovery(c.client_id, c.session, r.snapshot_revision),
            )??;
            Ok(())
        })
    })
}
fn event_result(node: u64, request: *const AsterEventResultRequest, abandon: bool) -> u32 {
    boundary(|| {
        let r = versioned(request, "publication result")?;
        let c = client(r.client)?;
        let seq = sequence(r.sequence)?;
        with_node(node, |n| {
            let e = n.running()?.selected_events();
            if abandon {
                n.wait(e.abandon_publication(c.client_id, c.session, seq))??;
            } else {
                n.wait(e.acknowledge_publication_result(c.client_id, c.session, seq))??;
            }
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_acknowledge_publication(
    node: u64,
    r: *const AsterEventResultRequest,
) -> u32 {
    event_result(node, r, false)
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_abandon_publication(
    node: u64,
    r: *const AsterEventResultRequest,
) -> u32 {
    event_result(node, r, true)
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_lines)] // Keep the four class dispatch and validation together.
pub extern "C" fn aster_node_publish(
    node: u64,
    request: *const AsterPublishRequest,
    out: *mut AsterPublishReceipt,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "publish")?;
        let out = versioned_mut(out, "receipt")?;
        let topic = input_topic(r.topic, "topic")?;
        let scope = input_scope(r.scope, "scope")?;
        let pri = priority(r.priority)?;
        let key = input_bytes(r.logical_key, "logical_key")?.to_vec();
        let payload = input_bytes(r.payload, "payload")?.to_vec();
        let tombstone = boolean(r.tombstone, "tombstone")?;
        let ttl = boolean(r.has_ttl, "has_ttl")?;
        let predecessor = boolean(r.has_predecessor, "has_predecessor")?;
        if r.data_class != 1
            && (ttl
                || predecessor
                || r.sequence != 0
                || r.client.session != 0
                || r.client.client_id.len != 0)
        {
            return Err(FfiError::invalid(
                "State/Record have no TTL, predecessor, or numbered client fields",
            ));
        }
        if r.data_class == 1 && r.operation_key.len != 0 {
            return Err(FfiError::invalid(
                "Events use client/session/sequence, not operation_key",
            ));
        }
        with_node(node, |n| {
            *out = match r.data_class {
                0 => {
                    let v =
                        n.wait(n.running()?.selected_state().publish(StatePublishRequest {
                            operation_key: input_bytes(r.operation_key, "operation_key")?.to_vec(),
                            topic,
                            scope,
                            priority: pri,
                            logical_key: key,
                            payload,
                            tombstone,
                        }))??;
                    AsterPublishReceipt {
                        item_id: *v.id.as_bytes(),
                        publisher: v.publisher,
                        publisher_counter: v.publisher_counter,
                        acceptance_marker: v.acceptance_marker,
                        inserted: u8::from(v.inserted),
                        ..Default::default()
                    }
                }
                2 => {
                    let v = n.wait(n.running()?.selected_records().publish(
                        RecordPublishRequest {
                            operation_key: input_bytes(r.operation_key, "operation_key")?.to_vec(),
                            topic,
                            scope,
                            priority: pri,
                            logical_key: key,
                            payload,
                            tombstone,
                        },
                    ))??;
                    AsterPublishReceipt {
                        item_id: *v.id.as_bytes(),
                        publisher: v.publisher,
                        publisher_counter: v.publisher_counter,
                        acceptance_marker: v.acceptance_marker,
                        inserted: u8::from(v.inserted),
                        ..Default::default()
                    }
                }
                1 => {
                    let c = client(r.client)?;
                    let options = if ttl {
                        EventPublishOptions::finite_ttl_ms(r.ttl_ms)?
                    } else {
                        EventPublishOptions::durable()
                    };
                    let v = n.wait(n.running()?.selected_events().publish_numbered(
                        NumberedEventPublishRequest {
                            client_id: c.client_id,
                            session: c.session,
                            sequence: sequence(r.sequence)?,
                            predecessor: predecessor.then(|| EventId::from_bytes(r.predecessor)),
                            topic,
                            scope,
                            priority: pri,
                            logical_key: key,
                            payload,
                            tombstone,
                        },
                        options,
                    ))??;
                    numbered_receipt(v.result, v.inserted)
                }
                _ => {
                    return Err(FfiError::invalid(
                        "publish requires State, Event or Record; use a Blob writer for Blob",
                    ));
                }
            };
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
#[allow(clippy::too_many_lines)] // Keep the four class dispatch and validation together.
pub extern "C" fn aster_node_query(
    node: u64,
    request: *const AsterQueryRequest,
    out: *mut u64,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "query")?;
        empty_handle(out, "result")?;
        let descendants = boolean(r.include_descendant_scopes, "include_descendant_scopes")?;
        let history = boolean(
            r.include_recoverable_versions,
            "include_recoverable_versions",
        )?;
        with_node(node, |n| {
            capacity(n.results.len())?;
            let page = match r.data_class {
                0 | 2 => {
                    if descendants
                        || r.after_acceptance_marker != 0
                        || r.before_acceptance_marker != 0
                        || r.limit != 0
                    {
                        return Err(FfiError::invalid(
                            "State/Record queries require one exact key and cannot truncate projections",
                        ));
                    }
                    let topic = input_topic(r.topic, "topic")?;
                    let scope = input_scope(r.scope, "scope")?;
                    let logical_key = input_bytes(r.logical_key, "logical_key")?.to_vec();
                    let mut entry = if r.data_class == 0 {
                        let p = n.wait(n.running()?.selected_state().query(StateQuery {
                            topic: topic.clone(),
                            scope: scope.clone(),
                            logical_key: logical_key.clone(),
                            include_recoverable_versions: history,
                        }))??;
                        Entry {
                            items: p
                                .current
                                .into_iter()
                                .chain(p.recoverable)
                                .map(state_item)
                                .collect(),
                            ..Default::default()
                        }
                    } else {
                        record_entry(n.wait(n.running()?.selected_records().query(
                            RecordQuery {
                                topic: topic.clone(),
                                scope: scope.clone(),
                                logical_key: logical_key.clone(),
                                include_superseded_versions: history,
                            },
                        ))??)
                    };
                    entry.topic = topic.as_str().into();
                    entry.scope = scope.as_str().into();
                    entry.key = logical_key;
                    Snapshot {
                        entries: vec![entry],
                        ..Default::default()
                    }
                }
                1 => {
                    if history {
                        return Err(FfiError::invalid(
                            "Event queries have no recoverable-version option",
                        ));
                    }
                    let p =
                        n.wait(
                            n.running()?.selected_events().query(EventQuery {
                                publisher: None,
                                topic: if r.topic.len == 0 {
                                    None
                                } else {
                                    Some(input_topic(r.topic, "topic")?)
                                },
                                scope: if r.scope.len == 0 {
                                    None
                                } else {
                                    Some(input_scope(r.scope, "scope")?)
                                },
                                logical_key: if r.logical_key.len == 0 {
                                    None
                                } else {
                                    Some(input_bytes(r.logical_key, "logical_key")?.to_vec())
                                },
                                include_descendant_scopes: descendants,
                                after_acceptance_marker: r.after_acceptance_marker,
                                before_acceptance_marker: (r.before_acceptance_marker != 0)
                                    .then_some(r.before_acceptance_marker),
                                limit: bounded(r.limit, MAX_SELECTED_EVENT_PAGE, "query limit")?,
                            }),
                        )??;
                    Snapshot {
                        entries: p.items.into_iter().map(event_item).map(one).collect(),
                        marker: p.scanned_through,
                        more: p.has_more,
                        ..Default::default()
                    }
                }
                3 => {
                    if descendants
                        || history
                        || r.after_acceptance_marker != 0
                        || r.before_acceptance_marker != 0
                        || r.limit != 0
                    {
                        return Err(FfiError::invalid(
                            "Blob query requires exact topic/scope/content ID",
                        ));
                    }
                    let p = n.wait(n.running()?.selected_blobs().read_page(
                        BlobReadPageRequest {
                            blob: BlobReadRequest {
                                id: BlobId::from_bytes(fixed(r.logical_key, "Blob ID")?),
                                topic: input_topic(r.topic, "topic")?,
                                scope: input_scope(r.scope, "scope")?,
                            },
                            offset: 0,
                            max_bytes: 1,
                        },
                    ))??;
                    Snapshot {
                        entries: vec![one(Item {
                            blob_id: *p.id.as_bytes(),
                            publisher: p.publisher,
                            counter: p.publisher_counter,
                            class: 3,
                            priority: p.priority as u32,
                            marker: p.acceptance_marker,
                            total_len: p.total_len,
                            ttl: p.ttl_ms,
                            topic: input_string(r.topic, "topic")?,
                            scope: input_string(r.scope, "scope")?,
                            key: p.id.as_bytes().to_vec(),
                            media: p.media_type.clone().unwrap_or_default(),
                            schema: p.schema_id.clone(),
                            ..Default::default()
                        })],
                        ..Default::default()
                    }
                }
                _ => return Err(FfiError::invalid("query requires an explicit data class")),
            };
            let id = n.insert(page)?;
            write_output(out, id, "result")
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_conflicts(
    node: u64,
    r: *const AsterQueryRequest,
    out: *mut u64,
) -> u32 {
    // Conflict lookup shares the exact Record query contract and returns its
    // complete verified projection, including the retained resolution guard.
    let status = boundary(|| {
        if versioned(r, "query")?.data_class != 2 {
            return Err(FfiError::invalid("conflicts requires Record"));
        }
        Ok(())
    });
    if status == STATUS_OK {
        aster_node_query(node, r, out)
    } else {
        status
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_resolve(
    node: u64,
    request: *const AsterResolveRequest,
    out: *mut AsterPublishReceipt,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "resolve")?;
        let out = versioned_mut(out, "receipt")?;
        with_node(node, |n| {
            let guard = n
                .results
                .get(&r.guard)
                .and_then(|p| p.entries.get(usize::try_from(r.entry).ok()?))
                .and_then(|e| e.guard.clone())
                .ok_or_else(|| {
                    FfiError::new(
                        STATUS_STALE_CONFLICT,
                        "resolution requires this node's retained Record query guard",
                    )
                })?;
            let v = n.wait(
                n.running()?
                    .selected_records()
                    .resolve(RecordResolveRequest {
                        operation_key: input_bytes(r.operation_key, "operation_key")?.to_vec(),
                        resolution_guard: guard,
                        priority: priority(r.priority)?,
                        payload: input_bytes(r.payload, "payload")?.to_vec(),
                        tombstone: boolean(r.tombstone, "tombstone")?,
                    }),
            )??;
            *out = AsterPublishReceipt {
                item_id: *v.id.as_bytes(),
                publisher: v.publisher,
                publisher_counter: v.publisher_counter,
                acceptance_marker: v.acceptance_marker,
                inserted: u8::from(v.inserted),
                ..Default::default()
            };
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_subscribe(
    node: u64,
    request: *const AsterSubscribeRequest,
    out: *mut AsterSubscription,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "subscribe")?;
        check_mut_pointer(out, "subscription")?;
        let operation_key = input_bytes(r.operation_key, "operation_key")?.to_vec();
        let topic = input_topic(r.topic, "topic")?;
        let scope = input_scope(r.scope, "scope")?;
        let descendants = boolean(r.include_descendant_scopes, "include_descendant_scopes")?;
        with_node(node, |n| {
            let id =
                match r.data_class {
                    0 => {
                        *n.wait(n.running()?.selected_state().subscribe(
                            StateSubscriptionRequest {
                                operation_key,
                                topic,
                                scope,
                                include_descendant_scopes: descendants,
                            },
                        ))??
                        .id
                        .as_bytes()
                    }
                    1 => *n
                        .wait(n.running()?.selected_events().subscribe(
                            EventSubscriptionRequest {
                                client: client(r.client)?,
                                operation_key,
                                topic,
                                scope,
                                include_descendant_scopes: descendants,
                            },
                        ))??
                        .id
                        .as_bytes(),
                    2 => *n
                        .wait(n.running()?.selected_records().subscribe(
                            RecordSubscriptionRequest {
                                operation_key,
                                topic,
                                scope,
                                include_descendant_scopes: descendants,
                            },
                        ))??
                        .id
                        .as_bytes(),
                    3 => {
                        *n.wait(n.running()?.selected_blobs().subscribe(
                            BlobSubscriptionRequest {
                                operation_key,
                                topic,
                                scope,
                                include_descendant_scopes: descendants,
                            },
                        ))??
                        .id
                        .as_bytes()
                    }
                    _ => {
                        return Err(FfiError::invalid(
                            "subscribe requires an explicit data class",
                        ));
                    }
                };
            write_output(
                out,
                AsterSubscription {
                    id,
                    data_class: r.data_class,
                },
                "subscription",
            )
        })
    })
}
#[unsafe(no_mangle)]
#[allow(clippy::too_many_lines)] // Keep the four class dispatch and validation together.
pub extern "C" fn aster_node_poll(
    node: u64,
    request: *const AsterPollRequest,
    out: *mut u64,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "poll")?;
        empty_handle(out, "result")?;
        let delivery_limit = bounded(r.delivery_limit, 64, "delivery_limit")?;
        let scan_limit = bounded(r.scan_limit, 4096, "scan_limit")?;
        with_node(node, |n| {
            capacity(n.results.len())?;
            let (entries, more) = match r.subscription.data_class {
                0 => {
                    let p = n.wait(n.running()?.selected_state().poll(StatePollRequest {
                        subscription: StateSubscriptionId::from_bytes(r.subscription.id),
                        delivery_limit,
                        scan_limit,
                    }))??;
                    (
                        p.deliveries
                            .into_iter()
                            .map(|d| {
                                let mut e = one(state_item(d.state));
                                e.attempt = d.attempt;
                                e.token = d.token.as_bytes().to_vec();
                                e
                            })
                            .collect(),
                        p.has_more,
                    )
                }
                1 => {
                    let p = n.wait(n.running()?.selected_events().poll(EventPollRequest {
                        client: client(r.client)?,
                        subscription: EventSubscriptionId::from_bytes(r.subscription.id),
                        delivery_limit,
                        scan_limit,
                    }))??;
                    (
                        p.deliveries
                            .into_iter()
                            .map(|d| {
                                let mut e = one(event_item(d.event));
                                e.attempt = d.attempt;
                                e
                            })
                            .collect(),
                        p.has_more,
                    )
                }
                2 => {
                    let p = n.wait(n.running()?.selected_records().poll(RecordPollRequest {
                        subscription: RecordSubscriptionId::from_bytes(r.subscription.id),
                        delivery_limit,
                        scan_limit,
                    }))??;
                    (
                        p.deliveries
                            .into_iter()
                            .map(|d| Entry {
                                items: d
                                    .projection
                                    .current
                                    .into_iter()
                                    .chain(d.projection.concurrent)
                                    .map(record_item)
                                    .collect(),
                                id: *d.projection_id.as_bytes(),
                                attempt: d.attempt,
                                token: d.token.as_bytes().to_vec(),
                                siblings: d.projection.conflict.map_or_else(Vec::new, |c| {
                                    c.siblings.iter().flat_map(|i| *i.as_bytes()).collect()
                                }),
                                topic: d.key.topic.as_str().into(),
                                scope: d.key.scope.as_str().into(),
                                key: d.key.logical_key,
                                ..Default::default()
                            })
                            .collect(),
                        p.has_more,
                    )
                }
                3 => {
                    let p = n.wait(n.running()?.selected_blobs().poll(BlobPollRequest {
                        subscription: BlobSubscriptionId::from_bytes(r.subscription.id),
                        delivery_limit,
                        scan_limit,
                    }))??;
                    (
                        p.deliveries
                            .into_iter()
                            .map(|d| match d {
                                BlobDeliveryItem::Content(d) => {
                                    let mut e = one(Item {
                                        id: *d.publication.as_bytes(),
                                        blob_id: *d.id.as_bytes(),
                                        publisher: d.publisher,
                                        counter: d.publisher_counter,
                                        class: 3,
                                        priority: d.priority as u32,
                                        marker: d.acceptance_marker,
                                        total_len: d.total_len,
                                        ttl: d.ttl_ms,
                                        topic: d.topic.as_str().into(),
                                        scope: d.scope.as_str().into(),
                                        key: d.id.as_bytes().to_vec(),
                                        media: d.media_type.unwrap_or_default(),
                                        schema: d.schema_id,
                                        ..Default::default()
                                    });
                                    e.attempt = d.attempt;
                                    e.token = d.token.as_bytes().to_vec();
                                    e
                                }
                                BlobDeliveryItem::Retirement(d) => {
                                    let mut e = one(Item {
                                        id: *d.publication.as_bytes(),
                                        blob_id: *d.id.as_bytes(),
                                        publisher: d.publisher,
                                        counter: d.publisher_counter,
                                        class: 3,
                                        priority: d.priority as u32,
                                        marker: d.acceptance_marker,
                                        ttl: d.ttl_ms,
                                        topic: d.topic.as_str().into(),
                                        scope: d.scope.as_str().into(),
                                        key: d.id.as_bytes().to_vec(),
                                        ..Default::default()
                                    });
                                    e.attempt = d.attempt;
                                    e.token = d.token.as_bytes().to_vec();
                                    e.kind = 1;
                                    e.retirement_reason = match d.reason {
                                        BlobRetirementReason::Expired => 1,
                                        BlobRetirementReason::Invalidated => 2,
                                        BlobRetirementReason::Evicted => 3,
                                    };
                                    e.retirement_generation = d.retirement_generation;
                                    e
                                }
                            })
                            .collect(),
                        p.has_more,
                    )
                }
                _ => return Err(FfiError::invalid("unknown subscription class")),
            };
            let id = n.insert(Snapshot {
                entries,
                more,
                ..Default::default()
            })?;
            write_output(out, id, "result")
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_acknowledge(node: u64, request: *const AsterAckRequest) -> u32 {
    boundary(|| {
        let r = versioned(request, "acknowledge")?;
        with_node(node, |n| {
            match r.subscription.data_class {
                0 => {
                    n.wait(n.running()?.selected_state().acknowledge(
                        StateSubscriptionId::from_bytes(r.subscription.id),
                        StateId::from_bytes(r.id),
                        StateDeliveryToken::from_bytes(fixed(r.token, "State token")?)?,
                    ))??;
                }
                1 => {
                    if r.token.len != 0 {
                        return Err(FfiError::invalid("Events do not use delivery tokens"));
                    }
                    n.wait(n.running()?.selected_events().acknowledge(
                        client(r.client)?,
                        EventSubscriptionId::from_bytes(r.subscription.id),
                        EventId::from_bytes(r.id),
                    ))??;
                }
                2 => {
                    n.wait(n.running()?.selected_records().acknowledge(
                        RecordSubscriptionId::from_bytes(r.subscription.id),
                        RecordProjectionId::from_bytes(r.id),
                        RecordDeliveryToken::from_bytes(fixed(r.token, "Record token")?)?,
                    ))??;
                }
                3 => {
                    n.wait(n.running()?.selected_blobs().acknowledge(
                        BlobSubscriptionId::from_bytes(r.subscription.id),
                        BlobPublicationId::from_bytes(r.id),
                        BlobDeliveryToken::from_bytes(fixed(r.token, "Blob token")?)?,
                    ))??;
                }
                _ => return Err(FfiError::invalid("unknown subscription class")),
            }
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_unsubscribe(
    node: u64,
    request: *const AsterUnsubscribeRequest,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "unsubscribe")?;
        with_node(node, |n| {
            match r.subscription.data_class {
                0 => {
                    n.wait(
                        n.running()?
                            .selected_state()
                            .unsubscribe(StateSubscriptionId::from_bytes(r.subscription.id)),
                    )??;
                }
                1 => {
                    n.wait(n.running()?.selected_events().unsubscribe(
                        client(r.client)?,
                        EventSubscriptionId::from_bytes(r.subscription.id),
                    ))??;
                }
                2 => {
                    n.wait(
                        n.running()?
                            .selected_records()
                            .unsubscribe(RecordSubscriptionId::from_bytes(r.subscription.id)),
                    )??;
                }
                3 => {
                    n.wait(
                        n.running()?
                            .selected_blobs()
                            .unsubscribe(BlobSubscriptionId::from_bytes(r.subscription.id)),
                    )??;
                }
                _ => return Err(FfiError::invalid("unknown subscription class")),
            }
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_delivery_status(
    node: u64,
    class: u32,
    out: *mut AsterDeliveryStatus,
) -> u32 {
    boundary(|| {
        let out = versioned_mut(out, "delivery status")?;
        with_node(node, |n| {
            macro_rules! status {
                ($d:expr) => {{
                    let d = $d;
                    AsterDeliveryStatus {
                        subscriptions: d.subscriptions,
                        pending_deliveries: d.pending_deliveries,
                        acknowledged_deliveries: d.acknowledged_deliveries,
                        delivery_cursors: d.delivery_cursors,
                        selector_generation: d.selector_generation,
                        ..Default::default()
                    }
                }};
            }
            *out = match class {
                0 => status!(n.wait(n.running()?.selected_state().delivery_status())??),
                2 => status!(n.wait(n.running()?.selected_records().delivery_status())??),
                3 => status!(n.wait(n.running()?.selected_blobs().delivery_status())??),
                _ => {
                    return Err(FfiError::invalid(
                        "delivery status requires State, Record or Blob",
                    ));
                }
            };
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_blob_writer_open(
    node: u64,
    options: *const AsterBlobPublishOptions,
    out: *mut AsterBlobWriterInfo,
) -> u32 {
    boundary(|| {
        let o = versioned(options, "Blob options")?;
        let out = versioned_mut(out, "writer info")?;
        if out.writer != 0 {
            return Err(FfiError::invalid("writer output must be empty"));
        }
        let request = BlobPublishStreamRequest {
            publication: BlobPublishRequest {
                operation_key: input_bytes(o.operation_key, "operation_key")?.to_vec(),
                topic: input_topic(o.topic, "topic")?,
                scope: input_scope(o.scope, "scope")?,
                priority: priority(o.priority)?,
                media_type: if o.media_type.len == 0 {
                    None
                } else {
                    Some(input_string(o.media_type, "media_type")?)
                },
                schema_id: input_bytes(o.schema_id, "schema_id")?.to_vec(),
            },
            options: if boolean(o.has_ttl, "has_ttl")? {
                BlobPublishOptions::finite_ttl_ms(o.ttl_ms)?
            } else {
                BlobPublishOptions::durable()
            },
            total_len: o.total_len,
        };
        with_node(node, |n| {
            capacity(n.writers.len())?;
            let stream = n.wait(
                n.running()?
                    .selected_blobs()
                    .open_publish_stream(request.clone()),
            )??;
            let offset = stream.durable_offset();
            let id = new_handle()?;
            n.writers.insert(
                id,
                Writer {
                    request,
                    stream: Some(stream),
                    offset,
                    finished: None,
                },
            );
            *out = AsterBlobWriterInfo {
                writer: id,
                durable_offset: offset,
                ..Default::default()
            };
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_writer_write(
    node: u64,
    writer: u64,
    offset: u64,
    bytes: AsterBytes,
) -> u32 {
    boundary(|| {
        let bytes = input_bytes(bytes, "Blob bytes")?;
        let segment = aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        if bytes.len() as u64 > segment - offset % segment {
            return Err(FfiError::invalid(
                "Blob write crosses a 1 MiB segment boundary",
            ));
        }
        with_node(node, |n| {
            let w = n.writers.get_mut(&writer).ok_or_else(closed)?;
            if w.finished.is_some() || offset != w.offset {
                return Err(FfiError::invalid(
                    "writer is finished or offset is not its accepted offset",
                ));
            }
            let stream = w
                .stream
                .as_mut()
                .ok_or_else(|| FfiError::invalid("reopen writer after failed finish"))?;
            let progress = wait(
                n.runtime.as_ref().ok_or_else(closed)?,
                stream.write(offset, Zeroizing::new(bytes.to_vec())),
            )??;
            w.offset = progress.accepted_offset;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_writer_finish(
    node: u64,
    writer: u64,
    out: *mut AsterPublishReceipt,
) -> u32 {
    boundary(|| {
        let out = versioned_mut(out, "Blob receipt")?;
        with_node(node, |n| {
            let w = n.writers.get_mut(&writer).ok_or_else(closed)?;
            if let Some(receipt) = w.finished {
                *out = receipt;
                return Ok(());
            }
            if w.offset != w.request.total_len {
                return Err(FfiError::invalid("Blob source is incomplete"));
            }
            let stream = w
                .stream
                .take()
                .ok_or_else(|| FfiError::invalid("reopen writer after failed finish"))?;
            let result = wait(n.runtime.as_ref().ok_or_else(closed)?, stream.finish())??;
            let receipt = blob_receipt(&result);
            w.finished = Some(receipt);
            *out = receipt;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_writer_close(node: u64, out: *mut u64) -> u32 {
    boundary(|| {
        let id = take_handle(out, "writer")?;
        if id == 0 {
            return Ok(());
        }
        with_node(node, |n| {
            n.writers.remove(&id).ok_or_else(closed)?;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_blob_reader_open(
    node: u64,
    request: *const AsterBlobReadRequest,
    out: *mut u64,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "Blob read")?;
        empty_handle(out, "reader")?;
        let request = BlobReadRequest {
            id: BlobId::from_bytes(r.blob_id),
            topic: input_topic(r.topic, "topic")?,
            scope: input_scope(r.scope, "scope")?,
        };
        with_node(node, |n| {
            capacity(n.readers.len())?;
            // Authenticate existence before returning a handle. Each read repeats
            // selected-node authorization; no plaintext is cached in the FFI.
            n.wait(
                n.running()?
                    .selected_blobs()
                    .read_page(BlobReadPageRequest {
                        blob: request.clone(),
                        offset: 0,
                        max_bytes: 1,
                    }),
            )??;
            let id = new_handle()?;
            n.readers.insert(
                id,
                Reader {
                    request,
                    offset: 0,
                    complete: false,
                },
            );
            write_output(out, id, "reader")
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_reader_read(
    node: u64,
    reader: u64,
    max_bytes: u64,
    out: *mut AsterOwnedBuffer,
) -> u32 {
    boundary(|| {
        let out = versioned_mut(out, "Blob page")?;
        require_empty_buffer(out, "Blob page")?;
        let max_bytes = bounded(max_bytes, MAX_SELECTED_BLOB_PAGE_BYTES, "read length")?;
        with_node(node, |n| {
            let handle = n.running()?.selected_blobs();
            let r = n.readers.get_mut(&reader).ok_or_else(closed)?;
            if r.complete {
                return Ok(());
            }
            let page = wait(
                n.runtime.as_ref().ok_or_else(closed)?,
                handle.read_page(BlobReadPageRequest {
                    blob: r.request.clone(),
                    offset: r.offset,
                    max_bytes,
                }),
            )??;
            // Allocate before advancing the stream: a failed output allocation
            // must not silently skip caller data.
            *out = owned_buffer(page.as_bytes())?;
            r.offset += page.len() as u64;
            r.complete = page.complete;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_blob_reader_close(node: u64, out: *mut u64) -> u32 {
    boundary(|| {
        let id = take_handle(out, "reader")?;
        if id == 0 {
            return Ok(());
        }
        with_node(node, |n| {
            n.readers.remove(&id).ok_or_else(closed)?;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_result_info(node: u64, result: u64, out: *mut AsterResultInfo) -> u32 {
    boundary(|| {
        let out = versioned_mut(out, "result info")?;
        with_node(node, |n| {
            let p = n.results.get(&result).ok_or_else(closed)?;
            *out = AsterResultInfo {
                len: (p.entries.len() + p.receipts.len() + p.peers.len()) as u64,
                scanned_through: p.marker,
                has_more: u8::from(p.more),
                ..Default::default()
            };
            Ok(())
        })
    })
}
fn index(value: u64) -> Result<usize, FfiError> {
    usize::try_from(value).map_err(|_| FfiError::invalid("index too large"))
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_result_entry(
    node: u64,
    result: u64,
    entry: u64,
    out: *mut AsterEntry,
) -> u32 {
    boundary(|| {
        let out = versioned_mut(out, "entry")?;
        for b in [
            &out.topic,
            &out.scope,
            &out.logical_key,
            &out.sibling_ids,
            &out.token,
        ] {
            require_empty_buffer(b, "entry buffer")?;
        }
        with_node(node, |n| {
            let e = n
                .results
                .get(&result)
                .ok_or_else(closed)?
                .entries
                .get(index(entry)?)
                .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "entry index out of range"))?;
            let mut b = OutputBuffers(Vec::new());
            let value = AsterEntry {
                item_count: e.items.len() as u64,
                id: e.id,
                attempt: e.attempt,
                kind: e.kind,
                retirement_reason: e.retirement_reason,
                retirement_generation: e.retirement_generation,
                has_guard: u8::from(e.guard.is_some()),
                topic: b.add(e.topic.as_bytes())?,
                scope: b.add(e.scope.as_bytes())?,
                logical_key: b.add(&e.key)?,
                sibling_ids: b.add(&e.siblings)?,
                token: b.add(&e.token)?,
                ..Default::default()
            };
            *out = value;
            b.commit();
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_result_item(
    node: u64,
    result: u64,
    entry: u64,
    item: u64,
    out: *mut AsterItem,
) -> u32 {
    boundary(|| {
        let out = versioned_mut(out, "item")?;
        for b in [
            &out.topic,
            &out.scope,
            &out.logical_key,
            &out.payload,
            &out.media_type,
            &out.schema_id,
        ] {
            require_empty_buffer(b, "item buffer")?;
        }
        with_node(node, |n| {
            let i = n
                .results
                .get(&result)
                .ok_or_else(closed)?
                .entries
                .get(index(entry)?)
                .and_then(|e| e.items.get(usize::try_from(item).ok()?))
                .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "item index out of range"))?;
            let mut b = OutputBuffers(Vec::new());
            let value = AsterItem {
                id: i.id,
                blob_id: i.blob_id,
                publisher: i.publisher,
                publisher_counter: i.counter,
                data_class: i.class,
                priority: i.priority,
                disposition: i.disposition,
                event_sequence: i.sequence,
                acceptance_marker: i.marker,
                total_len: i.total_len,
                ttl_ms: i.ttl.unwrap_or(0),
                has_ttl: u8::from(i.ttl.is_some()),
                tombstone: u8::from(i.tombstone),
                topic: b.add(i.topic.as_bytes())?,
                scope: b.add(i.scope.as_bytes())?,
                logical_key: b.add(&i.key)?,
                payload: b.add(&i.payload)?,
                media_type: b.add(i.media.as_bytes())?,
                schema_id: b.add(&i.schema)?,
                ..Default::default()
            };
            *out = value;
            b.commit();
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_result_receipt(
    node: u64,
    result: u64,
    item: u64,
    out: *mut AsterPublishReceipt,
) -> u32 {
    boundary(|| {
        let out = versioned_mut(out, "receipt")?;
        with_node(node, |n| {
            *out = *n
                .results
                .get(&result)
                .ok_or_else(closed)?
                .receipts
                .get(index(item)?)
                .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "receipt index out of range"))?;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_result_peer(
    node: u64,
    result: u64,
    item: u64,
    out: *mut AsterPeerSnapshot,
) -> u32 {
    boundary(|| {
        let out = versioned_mut(out, "peer")?;
        with_node(node, |n| {
            *out = *n
                .results
                .get(&result)
                .ok_or_else(closed)?
                .peers
                .get(index(item)?)
                .ok_or_else(|| FfiError::new(STATUS_NOT_FOUND, "peer index out of range"))?;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_result_close(node: u64, out: *mut u64) -> u32 {
    boundary(|| {
        let id = take_handle(out, "result")?;
        if id == 0 {
            return Ok(());
        }
        with_node(node, |n| {
            n.results.remove(&id).ok_or_else(closed)?;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_item_free(out: *mut AsterItem) -> u32 {
    boundary_preserve_error(|| {
        let out = versioned_mut(out, "item")?;
        for b in [
            &mut out.topic,
            &mut out.scope,
            &mut out.logical_key,
            &mut out.payload,
            &mut out.media_type,
            &mut out.schema_id,
        ] {
            release_buffer(b)?;
        }
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_entry_free(out: *mut AsterEntry) -> u32 {
    boundary_preserve_error(|| {
        let out = versioned_mut(out, "entry")?;
        for b in [
            &mut out.topic,
            &mut out.scope,
            &mut out.logical_key,
            &mut out.sibling_ids,
            &mut out.token,
        ] {
            release_buffer(b)?;
        }
        Ok(())
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_set_emission(node: u64, threshold: u32) -> u32 {
    boundary(|| {
        with_node(node, |n| {
            n.running()?
                .set_event_emission_policy(emission(threshold)?)?;
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_get_emission(node: u64, out: *mut u32) -> u32 {
    boundary(|| {
        check_mut_pointer(out, "emission")?;
        with_node(node, |n| {
            let policy = n.running()?.event_emission_policy()?.0;
            write_output(
                out,
                match policy {
                    EventEmissionPolicy::Normal => 0,
                    EventEmissionPolicy::AtLeast(p) => p as u32,
                    EventEmissionPolicy::ReceiveOnly => 4,
                },
                "emission",
            )
        })
    })
}
fn peer(p: &AuthenticatedPeerStatus) -> AsterPeerSnapshot {
    AsterPeerSnapshot {
        peer: p.peer,
        contacts: p.contacts,
        authorization: match p.authorization {
            PeerAuthorization::Active => 0,
            PeerAuthorization::Revoked => 1,
        },
        last_contact: match p.last_contact {
            ContactSyncStatus::CompleteForLastNegotiatedContact => 0,
            ContactSyncStatus::WorkRemained => 1,
            ContactSyncStatus::PolicyChangedSinceContact => 2,
        },
        ..Default::default()
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_peers(node: u64, out: *mut u64) -> u32 {
    boundary(|| {
        empty_handle(out, "peers")?;
        with_node(node, |n| {
            capacity(n.results.len())?;
            let status = n.wait(n.running()?.selected_events().status())??;
            let id = n.insert(Snapshot {
                peers: status.peers.into_iter().map(|p| peer(&p)).collect(),
                ..Default::default()
            })?;
            write_output(out, id, "peers")
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_peer_status(
    node: u64,
    request: *const AsterPeerRequest,
    out: *mut AsterPeerSnapshot,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "peer request")?;
        let out = versioned_mut(out, "peer")?;
        with_node(node, |n| {
            let status = n.wait(n.running()?.selected_events().status())??;
            *out = peer(
                &status
                    .peers
                    .into_iter()
                    .find(|p| p.peer == r.peer)
                    .ok_or_else(|| {
                        FfiError::new(STATUS_NOT_FOUND, "no authenticated contact for peer")
                    })?,
            );
            Ok(())
        })
    })
}
#[unsafe(no_mangle)]
pub extern "C" fn aster_node_rekey_scope(
    node: u64,
    request: *const AsterRekeyRequest,
    out: *mut AsterControlReceipt,
) -> u32 {
    boundary(|| {
        let r = versioned(request, "rekey")?;
        let out = versioned_mut(out, "control receipt")?;
        let mut recipients = Vec::new();
        for recipient in input_array(
            r.recipients,
            r.recipient_count,
            MAX_SELECTED_REKEY_RECIPIENTS,
            "recipients",
        )? {
            let topics = input_array(
                recipient.topics,
                recipient.topic_count,
                MAX_SELECTED_REKEY_TOPIC_GRANTS,
                "topics",
            )?
            .iter()
            .map(|t| input_topic(*t, "topic"))
            .collect::<Result<Vec<_>, _>>()?;
            recipients.push(if topics.is_empty() {
                aster_mesh::ScopeRekeyRecipient::route_only(recipient.node_id)
            } else {
                aster_mesh::ScopeRekeyRecipient::member(recipient.node_id, topics)
                    .map_err(|_| FfiError::invalid("invalid rekey topics"))?
            });
        }
        let request = ScopeRekeyRequest::new(
            input_bytes(r.signed_public_registry, "signed registry")?.to_vec(),
            RegistryGenerationWitness::try_from(r.minimum_registry_generation)?,
            input_scope(r.scope, "scope")?,
            std::num::NonZeroU64::new(r.epoch)
                .ok_or_else(|| FfiError::invalid("epoch must be positive"))?,
            recipients,
        )?;
        with_node(node, |n| {
            let v = n.wait(
                n.running()?
                    .selected_controls()
                    .publish_scope_rekey(request),
            )??;
            *out = AsterControlReceipt {
                transfer_id: *v.transfer_id.as_bytes(),
                sequence: v.sequence,
                activated: v.activated as u64,
                emitted: u8::from(v.emitted),
                ..Default::default()
            };
            Ok(())
        })
    })
}
