package org.defenseunicorns.aster.btlering1

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ValidationStateTest {
    @Test
    fun acceptsOnlyOrderedPhasesAndIgnoresDuplicateTerminalCallbacks() {
        var state: ValidationState = ValidationState.Ready
        state = reduce(state, ValidationEvent.ConnectRequested)
        state = reduce(state, ValidationEvent.Phase("carrier_connected"))
        state = reduce(state, ValidationEvent.Phase("authenticating"))
        state = reduce(state, ValidationEvent.Phase("reconciling"))
        state = reduce(state, ValidationEvent.Complete(receipt()))
        val complete = state
        state = reduce(state, ValidationEvent.Error("internal", "late"))

        assertEquals(complete, state)
        assertTrue(state is ValidationState.Complete)
        assertTrue(state.render().contains("Event entries=1 bytes=513 inserts=1"))
        assertTrue(state.render().contains("published=${"42".repeat(32)}"))
        assertTrue(state.render().contains("payload_sha256=${"43".repeat(32)}"))
        assertTrue(state.render().contains("sent entries=1 bytes=128"))
    }

    @Test
    fun rejectsOutOfOrderPhaseAndSanitizesErrors() {
        val invalid = reduce(
            ValidationState.Connecting,
            ValidationEvent.Phase("authenticating"),
        )
        assertEquals(
            ValidationState.Failed("internal", "invalid validator phase transition"),
            invalid,
        )

        val message = "x".repeat(300)
        val failed = reduce(ValidationState.Connecting, ValidationEvent.Error("raw-peer", message))
        assertEquals("internal", (failed as ValidationState.Failed).category)
        assertEquals(160, failed.message.length)
    }

    @Test
    fun cancellationRequestedBeforeSocketPublicationIsRetained() {
        val cancellation = PendingCancellation()
        cancellation.reset()
        cancellation.request()

        assertTrue(cancellation.isRequested())
        cancellation.reset()
        assertEquals(false, cancellation.isRequested())
    }

    private fun receipt(): String = """{"semantic_version":9,"negotiated_transfer_profiles":[2,1,1,5,1],"transfer_profile_digest":"${"ac".repeat(32)}","mission_peer_match":true,"profile_digest_match":true,"send_packet_bytes":512,"receive_packet_bytes":256,"published_event_id":"${"42".repeat(32)}","published_payload_sha256":"${"43".repeat(32)}","event_page_entries_sent":1,"event_page_bytes_sent":128,"event_page_entries_received":1,"event_page_bytes_received":513,"event_page_inserts":1,"event_larger_than_receive_packet":true,"no_blob_attempt":true}"""
}
