package org.defenseunicorns.aster.btlering1

import org.junit.Assert.assertEquals
import org.junit.Test

class PumpExitTest {
    @Test
    fun bluetoothEofSignalsNativeInsteadOfRacingItsTerminalCallback() {
        assertEquals(
            PumpExitAction.SIGNAL_NATIVE_EOF,
            pumpExitAction(PumpDirection.BLUETOOTH_TO_NATIVE, failed = false),
        )
    }

    @Test
    fun nativeEofWaitsForItsTerminalCallback() {
        assertEquals(
            PumpExitAction.AWAIT_NATIVE_TERMINAL,
            pumpExitAction(PumpDirection.NATIVE_TO_BLUETOOTH, failed = false),
        )
    }

    @Test
    fun ioFailureStillFailsTheBridge() {
        for (direction in PumpDirection.entries) {
            assertEquals(
                PumpExitAction.FAIL_BRIDGE,
                pumpExitAction(direction, failed = true),
            )
        }
    }
}
