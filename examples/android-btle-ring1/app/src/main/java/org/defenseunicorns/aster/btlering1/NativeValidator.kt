package org.defenseunicorns.aster.btlering1

object NativeValidator {
    init {
        System.loadLibrary("aster_ble_android")
    }

    interface Callback {
        fun onPhase(phase: String)
        fun onComplete(receiptJson: String)
        fun onError(category: String, message: String)
    }

    @JvmStatic
    external fun nativePrepare(
        configJson: String,
        preparationId: Long,
        callback: Callback,
    ): Boolean

    @JvmStatic
    external fun nativeCancelPrepare(preparationId: Long)

    @JvmStatic
    external fun nativeStart(configJson: String, transferredFd: Int, callback: Callback): Long

    @JvmStatic
    external fun nativeCancel(runId: Long)
}
