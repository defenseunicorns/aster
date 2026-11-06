package org.defenseunicorns.aster.btlering1

sealed interface ValidationState {
    data object Ready : ValidationState
    data object Connecting : ValidationState
    data object CarrierConnected : ValidationState
    data object Authenticating : ValidationState
    data object Reconciling : ValidationState
    data class Complete(val summary: String) : ValidationState
    data class Failed(val category: String, val message: String) : ValidationState
}

sealed interface ValidationEvent {
    data object ConnectRequested : ValidationEvent
    data class Phase(val value: String) : ValidationEvent
    data class Complete(val receiptJson: String) : ValidationEvent
    data class Error(val category: String, val message: String) : ValidationEvent
}

fun reduce(state: ValidationState, event: ValidationEvent): ValidationState {
    if (state is ValidationState.Complete || state is ValidationState.Failed) return state
    return when (event) {
        ValidationEvent.ConnectRequested -> {
            if (state == ValidationState.Ready) ValidationState.Connecting else invalidTransition()
        }
        is ValidationEvent.Phase -> reducePhase(state, event.value)
        is ValidationEvent.Complete -> {
            if (state == ValidationState.Reconciling) {
                ReceiptSummary.parse(event.receiptJson)?.let {
                    ValidationState.Complete(it.render())
                } ?: ValidationState.Failed("internal", "invalid validator receipt")
            } else {
                invalidTransition()
            }
        }
        is ValidationEvent.Error -> ValidationState.Failed(
            category = sanitizeCategory(event.category),
            message = event.message.take(160).ifBlank { "validator failed" },
        )
    }
}

fun ValidationState.render(): String = when (this) {
    ValidationState.Ready -> "ready"
    ValidationState.Connecting -> "connecting"
    ValidationState.CarrierConnected -> "carrier connected"
    ValidationState.Authenticating -> "authenticating"
    ValidationState.Reconciling -> "reconciling"
    is ValidationState.Complete -> "complete\n$summary"
    is ValidationState.Failed -> "failed [$category]: $message"
}

private fun reducePhase(state: ValidationState, phase: String): ValidationState = when {
    state == ValidationState.Connecting && phase == "carrier_connected" ->
        ValidationState.CarrierConnected
    state == ValidationState.CarrierConnected && phase == "authenticating" ->
        ValidationState.Authenticating
    state == ValidationState.Authenticating && phase == "reconciling" ->
        ValidationState.Reconciling
    else -> invalidTransition()
}

private fun invalidTransition() =
    ValidationState.Failed("internal", "invalid validator phase transition")

private fun sanitizeCategory(value: String): String {
    val allowed = setOf(
        "permission", "configuration", "bounds", "unavailable", "timeout",
        "authentication", "protocol", "storage", "internal",
    )
    return value.takeIf(allowed::contains) ?: "internal"
}

private data class ReceiptSummary(
    val semantic: Long,
    val profiles: String,
    val digest: String,
    val sendPacketBytes: Long,
    val receivePacketBytes: Long,
    val eventEntries: Long,
    val eventBytes: Long,
    val eventInserts: Long,
    val peerMatch: Boolean,
    val digestMatch: Boolean,
    val eventLarger: Boolean,
    val noBlob: Boolean,
) {
    fun render(): String = buildString {
        append("semantic=").append(semantic)
        append(" profiles=").append(profiles)
        append(" digest=").append(digest)
        append("\npeer_match=").append(peerMatch)
        append(" digest_match=").append(digestMatch)
        append(" no_blob=").append(noBlob)
        append("\npackets tx=").append(sendPacketBytes)
        append(" rx=").append(receivePacketBytes)
        append("\nEvent entries=").append(eventEntries)
        append(" bytes=").append(eventBytes)
        append(" inserts=").append(eventInserts)
        append(" larger_than_rx=").append(eventLarger)
    }

    companion object {
        private fun number(json: String, name: String): Long? =
            Regex("\\\"$name\\\":([0-9]+)").find(json)?.groupValues?.get(1)?.toLongOrNull()

        private fun bool(json: String, name: String): Boolean? =
            Regex("\\\"$name\\\":(true|false)").find(json)?.groupValues?.get(1)?.toBooleanStrictOrNull()

        private fun string(json: String, name: String): String? =
            Regex("\\\"$name\\\":\\\"([^\\\"]*)\\\"").find(json)?.groupValues?.get(1)

        fun parse(json: String): ReceiptSummary? {
            if (json.length !in 2..4096) return null
            val profiles = Regex(
                "\\\"negotiated_transfer_profiles\\\":\\[([0-9]+(?:,[0-9]+){4})]",
            ).find(json)?.groupValues?.get(1) ?: return null
            val digest = string(json, "transfer_profile_digest") ?: return null
            if (!Regex("^[0-9a-f]{64}$").matches(digest)) return null
            return ReceiptSummary(
                semantic = number(json, "semantic_version") ?: return null,
                profiles = profiles,
                digest = digest,
                sendPacketBytes = number(json, "send_packet_bytes") ?: return null,
                receivePacketBytes = number(json, "receive_packet_bytes") ?: return null,
                eventEntries = number(json, "event_page_entries_received") ?: return null,
                eventBytes = number(json, "event_page_bytes_received") ?: return null,
                eventInserts = number(json, "event_page_inserts") ?: return null,
                peerMatch = bool(json, "mission_peer_match") ?: return null,
                digestMatch = bool(json, "profile_digest_match") ?: return null,
                eventLarger = bool(json, "event_larger_than_receive_packet") ?: return null,
                noBlob = bool(json, "no_blob_attempt") ?: return null,
            )
        }
    }
}
