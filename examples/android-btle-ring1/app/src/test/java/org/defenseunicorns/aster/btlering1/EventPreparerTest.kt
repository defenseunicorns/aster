package org.defenseunicorns.aster.btlering1

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EventPreparerTest {
    @Test
    fun completesLocalPreparationBeforeContinuingToTransport() {
        val backend = RecordingPreparationBackend()
        val preparer = EventPreparer(backend)
        val continued = CountDownLatch(1)

        preparer.prepare(config(), RecordingCallback()) { continued.countDown() }

        assertTrue(continued.await(2, TimeUnit.SECONDS))
        assertTrue(backend.preparedJson.contains("\"event_text\":\"hello from Android\""))
        assertTrue(backend.preparationId.get() > 0)
        preparer.close()
    }

    @Test
    fun cancellationInterruptsActiveNativePreparationAndSuppressesContinuation() {
        val backend = BlockingPreparationBackend()
        val preparer = EventPreparer(backend)
        val continued = CountDownLatch(1)

        preparer.prepare(config(), RecordingCallback()) { continued.countDown() }
        assertTrue(backend.started.await(2, TimeUnit.SECONDS))
        preparer.cancel()

        assertTrue(backend.cancelled.await(2, TimeUnit.SECONDS))
        assertFalse(continued.await(100, TimeUnit.MILLISECONDS))
        preparer.close()
    }

    @Test
    fun cancellationBeforeWorkerStartPreventsNativePreparation() {
        val executor = Executors.newSingleThreadExecutor()
        val blockerStarted = CountDownLatch(1)
        val releaseBlocker = CountDownLatch(1)
        executor.execute {
            blockerStarted.countDown()
            releaseBlocker.await(2, TimeUnit.SECONDS)
        }
        assertTrue(blockerStarted.await(2, TimeUnit.SECONDS))
        val backend = RecordingPreparationBackend()
        val preparer = EventPreparer(backend, executor)
        val continued = CountDownLatch(1)

        preparer.prepare(config(), RecordingCallback()) { continued.countDown() }
        preparer.cancel()
        releaseBlocker.countDown()

        assertFalse(continued.await(100, TimeUnit.MILLISECONDS))
        assertFalse(backend.called.await(100, TimeUnit.MILLISECONDS))
        preparer.close()
    }

    private fun config(): ValidatorConfig {
        val root = Files.createTempDirectory("aster-event-preparer").toFile()
        val mission = File(root, "mission.bundle").apply { writeText("mission") }
        return ValidatorConfig.parse(
            address = "7C:FA:80:72:3B:7A",
            psm = "128",
            missionPeer = "11".repeat(32),
            missionBundle = mission,
            statePath = File(root, "state"),
            eventText = "hello from Android",
            sendPacketBytes = 1,
            receivePacketBytes = 1,
        )
    }

    private class RecordingPreparationBackend : PreparationBackend {
        lateinit var preparedJson: String
        val preparationId = AtomicLong()
        val called = CountDownLatch(1)

        override fun prepare(
            configJson: String,
            preparationId: Long,
            callback: NativeValidator.Callback,
        ): Boolean {
            called.countDown()
            preparedJson = configJson
            this.preparationId.set(preparationId)
            return true
        }

        override fun cancel(preparationId: Long) = Unit
    }

    private class BlockingPreparationBackend : PreparationBackend {
        val started = CountDownLatch(1)
        val cancelled = CountDownLatch(1)

        override fun prepare(
            configJson: String,
            preparationId: Long,
            callback: NativeValidator.Callback,
        ): Boolean {
            started.countDown()
            return cancelled.await(2, TimeUnit.SECONDS)
        }

        override fun cancel(preparationId: Long) {
            cancelled.countDown()
        }
    }

    private class RecordingCallback : NativeValidator.Callback {
        override fun onPhase(phase: String) = Unit
        override fun onComplete(receiptJson: String) = Unit
        override fun onError(category: String, message: String) = Unit
    }
}
