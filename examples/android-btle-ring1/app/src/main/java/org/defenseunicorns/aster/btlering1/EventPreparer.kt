package org.defenseunicorns.aster.btlering1

import java.io.Closeable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

internal interface PreparationBackend {
    fun prepare(
        configJson: String,
        preparationId: Long,
        callback: NativeValidator.Callback,
    ): Boolean

    fun cancel(preparationId: Long)
}

private object NativePreparationBackend : PreparationBackend {
    override fun prepare(
        configJson: String,
        preparationId: Long,
        callback: NativeValidator.Callback,
    ): Boolean = NativeValidator.nativePrepare(configJson, preparationId, callback)

    override fun cancel(preparationId: Long) =
        NativeValidator.nativeCancelPrepare(preparationId)
}

internal class EventPreparer(
    private val backend: PreparationBackend = NativePreparationBackend,
    private val executor: ExecutorService = Executors.newSingleThreadExecutor(),
    private val watchdog: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor(),
) : Closeable {
    private val activeId = AtomicLong(0)
    private val activeTask = AtomicReference<Future<*>?>(null)
    private val closed = AtomicBoolean(false)

    fun prepare(
        config: ValidatorConfig,
        callback: NativeValidator.Callback,
        onPrepared: () -> Unit,
    ) {
        check(!closed.get()) { "Event preparer is closed" }
        val id = NEXT_ID.getAndIncrement()
        check(id > 0 && activeId.compareAndSet(0, id)) {
            "Event preparation is already active"
        }
        val guarded = object : NativeValidator.Callback {
            override fun onPhase(phase: String) = Unit
            override fun onComplete(receiptJson: String) = Unit
            override fun onError(category: String, message: String) {
                fail(id, callback, category, message)
            }
        }
        val timeout = watchdog.schedule(
            {
                finish(id) {
                    backend.cancel(id)
                    callback.onError("timeout", "local Event preparation timed out")
                }
            },
            PREPARATION_TIMEOUT_SECONDS,
            TimeUnit.SECONDS,
        )
        try {
            val task = executor.submit {
                if (activeId.get() != id) return@submit
                try {
                    val prepared = backend.prepare(config.toJson(), id, guarded)
                    timeout.cancel(false)
                    if (prepared) {
                        finish(id, onPrepared)
                    } else {
                        fail(id, callback, "internal", "local Event preparation failed")
                    }
                } catch (_: Throwable) {
                    timeout.cancel(false)
                    fail(id, callback, "internal", "local Event preparation failed")
                }
            }
            if (!activeTask.compareAndSet(null, task)) {
                task.cancel(false)
                timeout.cancel(false)
                fail(id, callback, "internal", "local Event preparation failed")
            } else if (activeId.get() != id && activeTask.compareAndSet(task, null)) {
                task.cancel(false)
            }
        } catch (_: Throwable) {
            timeout.cancel(false)
            fail(id, callback, "internal", "local Event preparation failed")
        }
    }

    private fun fail(
        id: Long,
        callback: NativeValidator.Callback,
        category: String,
        message: String,
    ) = finish(id) { callback.onError(category, message) }

    private fun finish(id: Long, terminal: () -> Unit) {
        if (activeId.compareAndSet(id, 0)) {
            activeTask.set(null)
            terminal()
        }
    }

    fun cancel() {
        val id = activeId.getAndSet(0)
        if (id > 0) {
            activeTask.getAndSet(null)?.cancel(false)
            backend.cancel(id)
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        cancel()
        executor.shutdownNow()
        watchdog.shutdownNow()
    }

    companion object {
        private val NEXT_ID = AtomicLong(1)
        private const val PREPARATION_TIMEOUT_SECONDS = 30L
    }
}
