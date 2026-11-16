//! Receipt-free Blob carrier turns. Durable prefixes remain the only recovery authority.
#[cfg(test)]
#[path = "blob_ranges_stream_codec_tests.rs"]
mod codec_tests;
use super::*;
use crate::event_pages::TransferProfileId;
use sha2::{Digest, Sha256};

pub(super) const MAX_RANGES: usize = 64;
const REQUEST_PREFIX: &[u8] = b"ABRS\x01";
const DATA_PREFIX: &[u8] = b"ABRD\x01";
const END_PREFIX: &[u8] = b"ABRE\x01";
const ENVELOPE_BYTES: usize = 5 + 32 + 2;
const RANGE_FRAME_BYTES: usize = BLOB_RANGE_FETCH_PLAINTEXT_BYTES;
const MAX_REQUEST_BYTES: usize = 7 + MAX_RANGES * RANGE_FRAME_BYTES;
const MAX_DATA_BYTES: usize = ENVELOPE_BYTES + BLOB_RANGE_PLAINTEXT_MAX_BYTES;

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_schedule(input: &[u8]) -> bool {
    for direction in [
        EventDirection::ToSessionResponder,
        EventDirection::ToSessionInitiator,
    ] {
        if let Ok(ranges) = decode_schedule(input, direction, SEMANTIC_PROTOCOL_V7) {
            assert_eq!(
                encode_schedule(&ranges, direction, SEMANTIC_PROTOCOL_V7).unwrap(),
                input
            );
            return true;
        }
    }
    false
}

fn invalid(message: &str) -> NodeError {
    NodeError::Protocol(format!("Blob range stream: {message}"))
}

struct Context<'a> {
    store: &'a Store,
    guard: &'a EventLaneGuard,
    direction: EventDirection,
    semantic_version: u16,
    blob_contact_mode: BlobContactMode,
    digest: [u8; 32],
    reserve: ContactReserve,
}

impl<'a> Context<'a> {
    fn new(
        store: &'a Store,
        guard: &'a EventLaneGuard,
        blob_contact_mode: BlobContactMode,
        direction: EventDirection,
        receipt: &PeerReceipt,
    ) -> Result<Self, NodeError> {
        let compatible = matches!(
            (receipt.semantic_version, blob_contact_mode),
            (SEMANTIC_PROTOCOL_V7, BlobContactMode::DurableOnly)
                | (SEMANTIC_PROTOCOL_V8, BlobContactMode::CustodyV1)
        );
        if !compatible
            || !receipt
                .negotiated_transfer_profiles
                .is_some_and(|profiles| profiles[3] == TransferProfileId::BlobRangesStreamV1 as u16)
        {
            return Err(invalid(
                "Blob transfer requires BlobRangesStreamV1; legacy Blob transfer is unsupported",
            ));
        }
        let (exchanges, bytes) = future_blob_carrier_lane_reserve(direction);
        Ok(Self {
            store,
            guard,
            direction,
            semantic_version: receipt.semantic_version,
            blob_contact_mode,
            digest: receipt
                .transfer_profile_digest
                .ok_or_else(|| invalid("missing profile digest"))?,
            reserve: ContactReserve {
                items: EVENT_BRIDGE_CONTACT_RESERVE_ITEMS,
                protected_frames: exchanges * EXCHANGE_FRAMES + EVENT_BRIDGE_CONTACT_RESERVE_FRAMES,
                protected_bytes: bytes + EVENT_BRIDGE_CONTACT_RESERVE_BYTES,
            },
        })
    }

    fn check(&self) -> Result<(), NodeError> {
        self.guard.check(self.store)?;
        require_contact_policy_current()?;
        Ok(())
    }

    async fn write(
        &self,
        turn: &mut SendUniTurn,
        mission: &mut HybridMissionSession,
        plaintext: &[u8],
        receipt: &mut PeerReceipt,
    ) -> Result<(), NodeError> {
        self.check()?;
        require_contact_frame_initiation()?;
        let digest = self.digest;
        #[cfg(test)]
        let digest = blob_ranges_stream_test::write_digest(self.store, plaintext, digest);
        let protected = mission.seal_profiled_application_frame(
            digest,
            LaneId::Blob,
            TransferProfileId::BlobRangesStreamV1,
            self.direction,
            plaintext,
        )?;
        #[cfg(test)]
        let protected = blob_ranges_stream_test::write_ciphertext(self.store, plaintext, protected);
        check_protected_frame_with_reserve(receipt, protected.len(), self.reserve)?;
        turn.write_frame_checked(&protected, || {
            self.check()?;
            require_contact_frame_initiation()?;
            check_protected_frame_with_reserve(receipt, protected.len(), self.reserve)
        })
        .await?;
        account_outbound_protected_frame(receipt, protected.len())
    }

    async fn read(
        &self,
        turn: &mut ReceiveUniTurn,
        mission: &mut HybridMissionSession,
        limit: usize,
        receipt: &mut PeerReceipt,
    ) -> Result<Vec<u8>, NodeError> {
        let protected = turn
            .read_frame()
            .await?
            .ok_or_else(|| invalid("truncated turn"))?;
        if protected.len() > limit + REFERENCE_SESSION_FRAME_OVERHEAD_BYTES {
            return Err(invalid("oversized frame"));
        }
        self.check()?;
        check_protected_frame_with_reserve(receipt, protected.len(), self.reserve)?;
        let plaintext = mission.open_profiled_application_frame(
            self.digest,
            LaneId::Blob,
            TransferProfileId::BlobRangesStreamV1,
            self.direction,
            &protected,
        )?;
        account_inbound_protected_frame(receipt, protected.len())?;
        Ok(plaintext)
    }
}

fn request_frame(
    candidate: &BlobRangeCandidate,
    direction: EventDirection,
    semantic_version: u16,
) -> Result<Vec<u8>, NodeError> {
    Frame::BlobRangeFetch {
        direction,
        source_id: candidate.source,
        object_id: frame_blob_object_id(candidate.object)?,
        total_len: candidate.total_len,
        offset: candidate.offset,
        requested_len: candidate.requested_len,
        content_proof: candidate.proof,
    }
    .encode_for_semantic_version(semantic_version)
}

fn encode_schedule(
    ranges: &[BlobRangeCandidate],
    direction: EventDirection,
    semantic_version: u16,
) -> Result<Vec<u8>, NodeError> {
    if ranges.len() > MAX_RANGES {
        return Err(invalid("too many ranges"));
    }
    let mut bytes = REQUEST_PREFIX.to_vec();
    bytes.extend_from_slice(&(ranges.len() as u16).to_be_bytes());
    for candidate in ranges {
        bytes.extend_from_slice(&request_frame(candidate, direction, semantic_version)?);
    }
    Ok(bytes)
}

fn decode_schedule(
    bytes: &[u8],
    direction: EventDirection,
    semantic_version: u16,
) -> Result<Vec<BlobRangeCandidate>, NodeError> {
    if bytes.len() < 7 || bytes.len() > MAX_REQUEST_BYTES || &bytes[..5] != REQUEST_PREFIX {
        return Err(invalid("invalid schedule header"));
    }
    let count = usize::from(u16::from_be_bytes([bytes[5], bytes[6]]));
    if count > MAX_RANGES || bytes.len() != 7 + count * RANGE_FRAME_BYTES {
        return Err(invalid("invalid schedule length"));
    }
    let mut ranges: Vec<BlobRangeCandidate> = Vec::with_capacity(count);
    for encoded in bytes[7..].chunks_exact(RANGE_FRAME_BYTES) {
        let Frame::BlobRangeFetch {
            direction: actual,
            source_id,
            object_id,
            total_len,
            offset,
            requested_len,
            content_proof,
        } = Frame::decode_for_semantic_version(encoded, semantic_version)?
        else {
            return Err(invalid("schedule entry is not a range"));
        };
        if actual != direction || !canonical_blob_network_range(total_len, offset, requested_len) {
            return Err(invalid("noncanonical requested range"));
        }
        let object = store_blob_object_id(object_id)?;
        if let Some(previous) = ranges.last()
            && (source_id != previous.source
                || content_proof != previous.proof
                || object < previous.object
                || (object == previous.object
                    && (total_len != previous.total_len
                        || offset != previous.offset + u64::from(previous.requested_len))))
        {
            return Err(invalid("schedule order or tuple conflict"));
        }
        ranges.push(BlobRangeCandidate {
            source: source_id,
            object,
            total_len,
            offset,
            requested_len,
            proof: content_proof,
        });
    }
    Ok(ranges)
}

fn decode_range_response(
    payload: &[u8],
    direction: EventDirection,
    candidate: &BlobRangeCandidate,
    semantic_version: u16,
) -> Result<(BlobRangeDisposition, Vec<u8>), NodeError> {
    let Frame::BlobRange {
        direction: actual,
        source_id,
        object_id,
        total_len,
        offset,
        requested_len,
        disposition,
        bytes,
    } = Frame::decode_for_semantic_version(payload, semantic_version)?
    else {
        return Err(invalid("expected range data"));
    };
    if actual != direction
        || source_id != candidate.source
        || store_blob_object_id(object_id)? != candidate.object
        || total_len != candidate.total_len
        || offset != candidate.offset
        || requested_len != candidate.requested_len
    {
        return Err(invalid("response differs from exact requested tuple"));
    }
    Ok((disposition, bytes))
}

fn schedule_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"ASTER/blob-ranges-stream/schedule/v1\0");
    hash.update(bytes);
    hash.finalize().into()
}

fn envelope(prefix: &[u8], digest: [u8; 32], index: usize) -> Vec<u8> {
    let mut bytes = prefix.to_vec();
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&(index as u16).to_be_bytes());
    bytes
}

fn check_envelope<'a>(
    bytes: &'a [u8],
    prefix: &[u8],
    digest: [u8; 32],
    index: usize,
) -> Result<&'a [u8], NodeError> {
    if bytes.len() < ENVELOPE_BYTES || bytes[..ENVELOPE_BYTES] != envelope(prefix, digest, index) {
        return Err(invalid("wrong frame order or schedule binding"));
    }
    Ok(&bytes[ENVELOPE_BYTES..])
}

// Both endpoints compute admission before any stream opens. No legacy reserve changes.
fn capacity(receipt: &PeerReceipt, reserve: ContactReserve) -> Result<usize, NodeError> {
    let bytes = event_turn_wire_budget(receipt, reserve)?;
    let frames = MAX_CONTACT_FRAMES
        .checked_sub(receipt.handshake_frames + receipt.protected_frames + reserve.protected_frames)
        .ok_or_else(|| invalid("frame budget exhausted"))?;
    let fixed = 7 + 32 + ENVELOPE_BYTES + 3 * (REFERENCE_SESSION_FRAME_OVERHEAD_BYTES + 4) + 16;
    let per_range = RANGE_FRAME_BYTES + MAX_DATA_BYTES + REFERENCE_SESSION_FRAME_OVERHEAD_BYTES + 4;
    if bytes < fixed || frames < 3 {
        return Err(invalid("terminal reserve exhausted"));
    }
    Ok(MAX_RANGES.min(frames - 3).min((bytes - fixed) / per_range))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn receive(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut HybridMissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    blob_contact_mode: BlobContactMode,
    direction: EventDirection,
    interest: &BlobInterest,
    receipt: &mut PeerReceipt,
) -> Result<(), NodeError> {
    let context = Context::new(store, guard, blob_contact_mode, direction, receipt)?;
    context.check()?;
    if direction == EventDirection::ToSessionResponder {
        connection.begin_additional_uni_pair()?;
    }
    let limit = capacity(receipt, context.reserve)?;
    let peer = mission.peer_observation().mission_id();
    let cursor = store.blob_carrier_fetch_cursor(peer)?;
    let mut work = selected_pending_blob_contact_work(
        store,
        guard,
        verifier,
        interest,
        cursor.map(|cursor| cursor.source()),
        blob_contact_mode,
    )?;
    let mut ranges = Vec::new();
    if let Some(work) = work.as_mut() {
        let retained = blob_source_projection_for_contact(
            store,
            work.projection.transfer_id,
            blob_contact_mode,
        )?;
        if retained.as_ref().is_none_or(|retained| {
            retained.retention != BlobSourceRetention::Pending || retained.source != work.projection
        }) {
            return Err(invalid(
                "selected Blob source lost exact contact eligibility",
            ));
        }
        // Complete prefixes are deliberately left staged until this stream's
        // authenticated terminal arrives. A lost/bad terminal may retain byte
        // progress, but it cannot commit, promote, or rotate object work.
        work.carriers.sort_by_key(|status| status.object());
        for status in &work.carriers {
            let mut offset = status.prefix_len();
            while offset < status.total_len() && ranges.len() < limit {
                let requested_len =
                    (status.total_len() - offset).min(MAX_BLOB_NETWORK_RANGE_BYTES as u64) as u32;
                ranges.push(BlobRangeCandidate {
                    source: work.source,
                    object: status.object(),
                    total_len: status.total_len(),
                    offset,
                    requested_len,
                    proof: work.proof,
                });
                offset += u64::from(requested_len);
            }
            if ranges.len() == limit {
                break;
            }
        }
    }
    let schedule = encode_schedule(&ranges, direction, context.semantic_version)?;
    let digest = schedule_hash(&schedule);
    let deadline = tokio::time::Instant::now() + CONTACT_DEADLINE;
    let protected = mission.seal_profiled_application_frame(
        context.digest,
        LaneId::Blob,
        TransferProfileId::BlobRangesStreamV1,
        direction,
        &schedule,
    )?;
    let (response, ()) = connection
        .request_with_total_limit_checked(
            &protected,
            event_turn_wire_budget(receipt, context.reserve)?,
            || {
                context.check()?;
                require_contact_frame_initiation()?;
                Ok::<(), NodeError>(())
            },
        )
        .await?;
    let accepted = mission.open_profiled_application_frame(
        context.digest,
        LaneId::Blob,
        TransferProfileId::BlobRangesStreamV1,
        direction,
        &response,
    )?;
    if accepted != digest {
        return Err(invalid("schedule acceptance mismatch"));
    }
    account(receipt, protected.len(), response.len())?;
    let mut turn = connection
        .accept_uni(deadline, event_turn_wire_budget(receipt, context.reserve)?)
        .await?;
    // Once a requested prefix cannot advance, consume/authenticate the bounded
    // remainder but do not append across the gap. No storage receipt is emitted.
    let mut discard_remaining = false;
    let mut terminal_range_cursor_eligible = !ranges.is_empty();
    let mut terminal_source_rotation = false;
    for (index, candidate) in ranges.iter().enumerate() {
        let bytes = context
            .read(&mut turn, mission, MAX_DATA_BYTES, receipt)
            .await?;
        let payload = check_envelope(&bytes, DATA_PREFIX, digest, index)?;
        let (disposition, bytes) =
            decode_range_response(payload, direction, candidate, context.semantic_version)?;
        if disposition == BlobRangeDisposition::Unavailable {
            discard_remaining = true;
            terminal_range_cursor_eligible = false;
            terminal_source_rotation = false;
        }
        if discard_remaining {
            continue;
        }
        let work = work
            .as_mut()
            .ok_or_else(|| invalid("missing selected work"))?;
        context.check()?;
        ensure_mutable_active(
            store,
            work.blob.publisher(),
            work.blob.scope(),
            work.blob.key_epoch(),
        )?;
        verifier.verify_current_blob_lineage(&work.blob)?;
        #[cfg(test)]
        interrupt_receiver(store, connection, index, true).await?;
        #[cfg(test)]
        if fire_test_blob_contact_fault(TestBlobContactFault::AppendCoherence) {
            return Err(NodeError::FatalBlobCoherence(
                "injected Blob carrier append coherence failure".into(),
            ));
        }
        let append = || {
            append_blob_carrier_prefix_for_contact(
                store,
                guard.policy(),
                candidate.source,
                candidate.object,
                candidate.total_len,
                candidate.offset,
                &bytes,
                context.blob_contact_mode,
            )
        };
        #[cfg(test)]
        {
            let cache = contact_mutable_route_cache(verifier)?;
            cache.record_blob_carrier_append_attempt();
            cache.record_blob_admission_trace(TestBlobAdmissionTrace::Append {
                source: candidate.source,
                object: candidate.object,
                total_len: candidate.total_len,
                offset: candidate.offset,
                bytes_sha256: Sha256::digest(&bytes).into(),
            });
        }
        #[cfg(test)]
        let append_result = blob_ranges_stream_test::append_boundary(store, index, bytes.len())
            .and_then(|()| append());
        #[cfg(not(test))]
        let append_result = append();
        let appended = match append_result {
            Ok(outcome) => outcome,
            Err(error) if blob_apply_capacity_error(&error) => {
                receipt.blob_deferred = receipt.blob_deferred.saturating_add(1);
                discard_remaining = true;
                terminal_range_cursor_eligible = false;
                terminal_source_rotation = true;
                continue;
            }
            Err(error) if blob_lifetime_unavailable_error(&error) => {
                let transition = settle_pending_blob_lifetime_unavailability_for_contact(
                    store,
                    verifier,
                    work.source,
                    context.blob_contact_mode,
                )?;
                if transition == PendingBlobLifetimeTransition::Missing {
                    return Err(error.into());
                }
                discard_remaining = true;
                terminal_range_cursor_eligible = false;
                terminal_source_rotation = false;
                continue;
            }
            Err(error) if blob_contact_policy_transition_error(&error) => {
                return Err(error.into());
            }
            Err(error @ StoreError::Blob(BlobStoreError::PendingSourceMissing)) => {
                return Err(error.into());
            }
            Err(error @ StoreError::Blob(BlobStoreError::CarrierPrefixConflict)) => {
                store
                    .abort_blob_carrier_prefix(candidate.source, candidate.object)
                    .map_err(|abort| {
                        fatal_blob_coherence(
                            "conflicting Blob carrier prefix cleanup",
                            abort.into(),
                        )
                    })?;
                return Err(error.into());
            }
            Err(error) => {
                return Err(fatal_blob_coherence(
                    "authenticated streamed Blob prefix append",
                    error.into(),
                ));
            }
        };
        #[cfg(test)]
        interrupt_receiver(store, connection, index, false).await?;
        let status = match appended {
            BlobCarrierAppendOutcome::Duplicate(status) => {
                receipt.duplicates = receipt.duplicates.saturating_add(1);
                status
            }
            BlobCarrierAppendOutcome::Appended(status) => {
                receipt.blob_bytes_fetched += bytes.len();
                status
            }
        };
        #[cfg(test)]
        blob_progress_test::record(verifier.identity(), &work.blob, status);
        receipt.blob_ranges_fetched += 1;
        let retained = work
            .carriers
            .iter_mut()
            .find(|status| status.object() == candidate.object)
            .ok_or_else(|| invalid("carrier left selected work"))?;
        *retained = status;
    }
    #[cfg(test)]
    if let Some(fault) = blob_ranges_stream_test::get(store)
        && fault.boundary == blob_ranges_stream_test::Boundary::LostTerminal
        && !ranges.is_empty()
    {
        fault.receiver_paused.notify_one();
        fault.release_receiver.notified().await;
        connection.close();
        return Err(invalid("injected lost terminal after complete prefix"));
    }
    let terminal = context
        .read(&mut turn, mission, ENVELOPE_BYTES, receipt)
        .await?;
    if !check_envelope(&terminal, END_PREFIX, digest, ranges.len())?.is_empty() {
        return Err(invalid("terminal contains trailing bytes"));
    }
    if turn.read_frame().await?.is_some() {
        return Err(invalid("trailing frame after terminal"));
    }

    // Commit complete prefixes and promote only after the schedule-bound
    // terminal is authenticated. The recovery helper receives no scheduler
    // authority: this function performs the turn's sole cursor decision below.
    if !discard_remaining && let Some(work) = work.as_mut() {
        match recover_and_finalize_pending_blob(
            store,
            guard,
            verifier,
            work.source,
            &work.blob,
            &work.manifest_bytes,
            &work.plan,
            &mut work.carriers,
            context.blob_contact_mode,
        ) {
            Ok(Some(
                PendingBlobRecoveryDisposition::DeferredLease
                | PendingBlobRecoveryDisposition::Apply(MutableApplyDisposition::DeferredCapacity),
            )) => {
                receipt.blob_deferred = receipt.blob_deferred.saturating_add(1);
                terminal_range_cursor_eligible = false;
                terminal_source_rotation = true;
            }
            Ok(Some(PendingBlobRecoveryDisposition::Apply(_))) if ranges.is_empty() => {
                // A reconnect can authenticate an empty schedule for prefixes
                // that were already complete before this turn.
                terminal_range_cursor_eligible = false;
                terminal_source_rotation = true;
            }
            Ok(_) => {}
            Err(error) if node_blob_lifetime_unavailable_error(&error) => {
                let transition = settle_pending_blob_lifetime_unavailability_for_contact(
                    store,
                    verifier,
                    work.source,
                    context.blob_contact_mode,
                )?;
                if transition == PendingBlobLifetimeTransition::Missing {
                    return Err(error);
                }
                terminal_range_cursor_eligible = false;
                terminal_source_rotation = false;
            }
            Err(error) => return Err(error),
        }
    }

    if terminal_source_rotation {
        if let Some(work) = work.as_ref() {
            advance_terminal_blob_source_cursor(
                store,
                &work.plan,
                work.source,
                Some((peer, cursor)),
            )?;
        }
    } else if terminal_range_cursor_eligible && let Some(last) = ranges.last() {
        store.compare_and_advance_blob_carrier_fetch_cursor(
            peer,
            cursor,
            BlobCarrierFetchCursor::new(last.source, last.object),
        )?;
    }
    let remaining = blob_carrier_remaining(store, guard, context.blob_contact_mode)?;
    receipt.blob_remaining += remaining;
    add_unscheduled_mutable(receipt, remaining)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut HybridMissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    blob_contact_mode: BlobContactMode,
    direction: EventDirection,
    interest: &BlobInterest,
    receipt: &mut PeerReceipt,
) -> Result<(), NodeError> {
    let context = Context::new(store, guard, blob_contact_mode, direction, receipt)?;
    if direction == EventDirection::ToSessionResponder {
        connection.begin_additional_uni_pair()?;
    }
    let limit = capacity(receipt, context.reserve)?;
    let deadline = tokio::time::Instant::now() + CONTACT_DEADLINE;
    let mut schedule = None;
    let mut application_error = None;
    let result = connection
        .respond_once_with_total_limit(
            event_turn_wire_budget(receipt, context.reserve)?,
            |protected| {
                let handled = (|| -> Result<Vec<u8>, NodeError> {
                    context.check()?;
                    if protected.len() > MAX_REQUEST_BYTES + REFERENCE_SESSION_FRAME_OVERHEAD_BYTES
                    {
                        return Err(invalid("oversized request"));
                    }
                    let bytes = mission.open_profiled_application_frame(
                        context.digest,
                        LaneId::Blob,
                        TransferProfileId::BlobRangesStreamV1,
                        direction,
                        protected,
                    )?;
                    let ranges = decode_schedule(&bytes, direction, context.semantic_version)?;
                    if ranges.len() > limit {
                        return Err(invalid("schedule exceeds directional budget"));
                    }
                    let response = mission.seal_profiled_application_frame(
                        context.digest,
                        LaneId::Blob,
                        TransferProfileId::BlobRangesStreamV1,
                        direction,
                        &schedule_hash(&bytes),
                    )?;
                    account(receipt, protected.len(), response.len())?;
                    schedule = Some(bytes);
                    Ok(response)
                })();
                match handled {
                    Ok(response) => Ok((response, true)),
                    Err(error) => {
                        application_error = Some(error);
                        Err(CarrierError::Transport("Blob schedule rejected".into()))
                    }
                }
            },
        )
        .await;
    if let Some(error) = application_error {
        return Err(error);
    }
    result?;
    let schedule = schedule.ok_or_else(|| invalid("missing schedule"))?;
    let ranges = decode_schedule(&schedule, direction, context.semantic_version)?;
    #[cfg(test)]
    blob_ranges_stream_test::record_sender_schedule(store, ranges.len());
    let digest = schedule_hash(&schedule);
    let peer = mission.peer_observation().mission_id();
    let commitments = mission.peer_route_grant_commitments().to_vec();
    let mut turn = connection
        .open_send_uni(deadline, event_turn_wire_budget(receipt, context.reserve)?)
        .await?;
    let mut unavailable_remaining = false;
    let mut authenticated = None;
    for (index, candidate) in ranges.iter().enumerate() {
        context.check()?;
        let bytes = if unavailable_remaining {
            None
        } else {
            #[cfg(test)]
            blob_ranges_stream_test::record_sender_service_attempt(store);
            serve_verified_blob_range_in_schedule(
                store,
                guard,
                verifier,
                peer,
                &commitments,
                interest,
                candidate.source,
                candidate.object,
                candidate.total_len,
                candidate.offset,
                candidate.requested_len,
                &candidate.proof,
                context.blob_contact_mode,
                &mut authenticated,
            )?
        };
        #[cfg(test)]
        let bytes = blob_ranges_stream_test::range_bytes(store, index, bytes);
        unavailable_remaining |= bytes.is_none();
        let disposition = if bytes.is_some() {
            BlobRangeDisposition::Data
        } else {
            BlobRangeDisposition::Unavailable
        };
        let frame = Frame::BlobRange {
            direction,
            source_id: candidate.source,
            object_id: frame_blob_object_id(candidate.object)?,
            total_len: candidate.total_len,
            offset: candidate.offset,
            requested_len: candidate.requested_len,
            disposition,
            bytes: bytes.unwrap_or_default(),
        };
        let mut plaintext = envelope(DATA_PREFIX, digest, index);
        plaintext.extend_from_slice(&frame.encode_for_semantic_version(context.semantic_version)?);
        context
            .write(&mut turn, mission, &plaintext, receipt)
            .await?;
        #[cfg(test)]
        if let Some(fault) = blob_ranges_stream_test::get(store)
            && if matches!(
                fault.boundary,
                blob_ranges_stream_test::Boundary::LostTerminal
                    | blob_ranges_stream_test::Boundary::AppendCapacityLostTerminal
            ) {
                index + 1 == ranges.len()
            } else {
                index == 0
            }
        {
            fault.sender_paused.notify_one();
            fault.release_sender.notified().await;
            if matches!(
                fault.boundary,
                blob_ranges_stream_test::Boundary::Original
                    | blob_ranges_stream_test::Boundary::LostTerminal
                    | blob_ranges_stream_test::Boundary::AppendCapacityLostTerminal
            ) {
                fault.fired.store(true, Ordering::Release);
                connection.close();
                return Err(invalid("injected interruption before stream terminal"));
            }
        }
    }
    // One selected source turn, as in the legacy path, not one source item per
    // range. Range work has its own MAX_RANGES bound and wire admission. This
    // preserves the historical source-item reserve without changing Event's
    // allocator or treating a send attempt as remote persistence.
    if !ranges.is_empty() {
        receipt.offered = receipt.offered.saturating_add(1);
    }
    context
        .write(
            &mut turn,
            mission,
            &envelope(END_PREFIX, digest, ranges.len()),
            receipt,
        )
        .await?;
    turn.finish().await?;
    Ok(())
}

#[cfg(test)]
async fn interrupt_receiver(
    store: &Store,
    connection: &aster_iroh::Connection,
    index: usize,
    before_append: bool,
) -> Result<(), NodeError> {
    if index == 0
        && let Some(fault) = blob_ranges_stream_test::get(store)
        && fault.before_append == before_append
        && fault.boundary != blob_ranges_stream_test::Boundary::LostTerminal
    {
        fault.receiver_paused.notify_one();
        fault.release_receiver.notified().await;
        if fault.boundary == blob_ranges_stream_test::Boundary::Original {
            connection.close();
            return Err(invalid("injected interruption at append boundary"));
        }
        if fault.boundary == blob_ranges_stream_test::Boundary::Revocation {
            fault.fired.store(true, Ordering::Release);
        }
    }
    Ok(())
}
