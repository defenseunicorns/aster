package org.defenseunicorns.aster.btlering1

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothSocket
import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class BluetoothBridge(private val adapter: BluetoothAdapter) : Closeable {
    private val lock = Any()
    private val connector = Executors.newSingleThreadExecutor()
    private val watchdog = Executors.newSingleThreadScheduledExecutor()
    private val pendingCancellation = PendingCancellation()
    private var active: Active? = null
    private var connecting = false
    private var closed = false

    @SuppressLint("MissingPermission")
    fun connect(config: ValidatorConfig, callback: NativeValidator.Callback) {
        synchronized(lock) {
            check(!closed) { "Bluetooth bridge is closed" }
            check(active == null && !connecting) { "validator already has an active run" }
            connecting = true
            pendingCancellation.reset()
        }
        connector.execute {
            var attempt: Active? = null
            try {
                check(adapter.isEnabled) { "Bluetooth is disabled" }
                val device = adapter.getRemoteDevice(config.bluetoothAddress)
                val socket = device.createInsecureL2capChannel(config.psm)
                val current = Active(socket, callback)
                attempt = current
                synchronized(lock) {
                    check(!closed && !pendingCancellation.isRequested() && active == null) {
                        "validator was cancelled"
                    }
                    active = current
                    connecting = false
                }
                val connectTimeout = watchdog.schedule(
                    { fail(current, "timeout", "Bluetooth LE connect timed out") },
                    CONNECT_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS,
                )
                try {
                    socket.connect()
                } finally {
                    connectTimeout.cancel(false)
                }
                check(!pendingCancellation.isRequested() && !current.terminal.get()) {
                    "validator was cancelled"
                }
                val sendPacketBytes = socket.maxTransmitPacketSize
                val receivePacketBytes = socket.maxReceivePacketSize
                check(sendPacketBytes in 1..0xffff && receivePacketBytes in 1..0xffff) {
                    "Bluetooth LE packet size is invalid"
                }
                val connectedConfig = config.copy(
                    sendPacketBytes = sendPacketBytes,
                    receivePacketBytes = receivePacketBytes,
                )
                val pair = ParcelFileDescriptor.createSocketPair()
                current.installPair(pair)
                val configJson = connectedConfig.toJson()
                current.startPumps(sendPacketBytes, receivePacketBytes)
                val runId = current.startNative(configJson)
                current.bindRun(runId)
                if (runId == 0L && !current.terminal.get()) {
                    fail(current, "internal", "validator native boundary did not start")
                }
            } catch (_: SecurityException) {
                attempt?.let { fail(it, "permission", "Bluetooth connect permission is required") }
                    ?: callback.onError("permission", "Bluetooth connect permission is required")
            } catch (_: Throwable) {
                attempt?.let { fail(it, "unavailable", "Bluetooth LE contact failed") }
                    ?: callback.onError("unavailable", "Bluetooth LE contact failed")
            } finally {
                synchronized(lock) {
                    if (active == null) connecting = false
                }
            }
        }
    }

    fun cancel() {
        val attempt = synchronized(lock) {
            pendingCancellation.request()
            active
        }
        if (attempt != null) {
            fail(attempt, "unavailable", "validator was cancelled")
        }
    }

    override fun close() {
        val attempt = synchronized(lock) {
            closed = true
            pendingCancellation.request()
            active
        }
        attempt?.let { terminate(it, cancelNative = true, terminal = null) }
        connector.shutdownNow()
        watchdog.shutdownNow()
    }

    private fun fail(attempt: Active, category: String, message: String) {
        terminate(attempt, cancelNative = true) {
            attempt.downstream.onError(category, message)
        }
    }

    private fun terminate(
        attempt: Active,
        cancelNative: Boolean,
        terminal: (() -> Unit)?,
    ) {
        if (!attempt.terminal.compareAndSet(false, true)) return
        val runId = attempt.runId.get()
        if (cancelNative && runId > 0) {
            NativeValidator.nativeCancel(runId)
        }
        attempt.closeResources()
        synchronized(lock) {
            if (active === attempt) active = null
        }
        terminal?.invoke()
    }

    private inner class Active(
        val socket: BluetoothSocket,
        val downstream: NativeValidator.Callback,
    ) {
        val terminal = AtomicBoolean(false)
        val runId = AtomicLong(0)
        private val handoffLock = Any()
        private val pumps: ExecutorService = Executors.newFixedThreadPool(2)
        private var nativeEndpoint: ParcelFileDescriptor? = null
        private var localReadEndpoint: ParcelFileDescriptor? = null
        private var localWriteEndpoint: ParcelFileDescriptor? = null
        private var localInput: InputStream? = null
        private var localOutput: OutputStream? = null

        val nativeCallback = object : NativeValidator.Callback {
            override fun onPhase(phase: String) {
                if (!terminal.get()) downstream.onPhase(phase)
            }

            override fun onComplete(receiptJson: String) {
                terminate(this@Active, cancelNative = false) {
                    downstream.onComplete(receiptJson)
                }
            }

            override fun onError(category: String, message: String) {
                terminate(this@Active, cancelNative = false) {
                    downstream.onError(category, message)
                }
            }
        }

        fun installPair(pair: Array<ParcelFileDescriptor>) {
            require(pair.size == 2) { "local socket pair is invalid" }
            synchronized(handoffLock) {
                val native = pair[0]
                val read = pair[1]
                if (terminal.get()) {
                    runCatching { native.close() }
                    runCatching { read.close() }
                    error("validator was cancelled")
                }
                nativeEndpoint = native
                localReadEndpoint = read
                val write = ParcelFileDescriptor.dup(read.fileDescriptor)
                localWriteEndpoint = write
                localInput = ParcelFileDescriptor.AutoCloseInputStream(read)
                localOutput = ParcelFileDescriptor.AutoCloseOutputStream(write)
            }
        }

        fun bindRun(id: Long) {
            runId.set(id)
            if (terminal.get() && id > 0) NativeValidator.nativeCancel(id)
        }

        fun startNative(configJson: String): Long = synchronized(handoffLock) {
            check(!terminal.get()) { "validator was cancelled" }
            val transferredFd = checkNotNull(nativeEndpoint).detachFd()
            try {
                NativeValidator.nativeStart(configJson, transferredFd, nativeCallback)
            } catch (error: LinkageError) {
                // The JVM did not enter nativeStart, so ownership never reached Rust.
                runCatching { ParcelFileDescriptor.adoptFd(transferredFd).close() }
                throw error
            }
        }

        fun startPumps(sendPacketBytes: Int, receivePacketBytes: Int) {
            val fromNative = checkNotNull(localInput)
            val toNative = checkNotNull(localOutput)
            val bluetoothOutput = socket.outputStream
            val bluetoothInput = socket.inputStream
            pumps.execute {
                pump(
                    from = fromNative,
                    to = bluetoothOutput,
                    bufferBytes = sendPacketBytes,
                )
            }
            pumps.execute {
                pump(
                    from = bluetoothInput,
                    to = toNative,
                    bufferBytes = receivePacketBytes,
                )
            }
        }

        private fun pump(from: InputStream, to: OutputStream, bufferBytes: Int) {
            try {
                val buffer = ByteArray(bufferBytes.coerceIn(1, 0xffff))
                while (!terminal.get()) {
                    val count = from.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    to.write(buffer, 0, count)
                    to.flush()
                }
            } catch (_: Throwable) {
                // The common close path below maps all carrier failures to one bounded error.
            } finally {
                if (!terminal.get()) {
                    fail(this, "unavailable", "Bluetooth LE stream ended")
                }
            }
        }

        fun closeResources() {
            synchronized(handoffLock) {
                runCatching { socket.close() }
                runCatching { localInput?.close() }
                runCatching { localOutput?.close() }
                runCatching { nativeEndpoint?.close() }
                runCatching { localReadEndpoint?.close() }
                runCatching { localWriteEndpoint?.close() }
            }
            pumps.shutdownNow()
        }
    }

    companion object {
        private const val CONNECT_TIMEOUT_SECONDS = 30L
    }
}

internal class PendingCancellation {
    private val requested = AtomicBoolean(false)

    fun reset() = requested.set(false)
    fun request() = requested.set(true)
    fun isRequested(): Boolean = requested.get()
}
