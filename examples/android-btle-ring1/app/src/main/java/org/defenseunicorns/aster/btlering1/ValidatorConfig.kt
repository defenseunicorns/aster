package org.defenseunicorns.aster.btlering1

import java.io.File
import java.util.Locale

data class ValidatorConfig(
    val statePath: File,
    val missionBundle: File,
    val missionPeer: String,
    val bluetoothAddress: String,
    val psm: Int,
    val eventText: String,
    val sendPacketBytes: Int,
    val receivePacketBytes: Int,
) {
    fun toJson(): String = buildString {
        append('{')
        append("\"state_path\":\"").append(jsonEscape(statePath.absolutePath)).append("\",")
        append("\"mission_bundle_path\":\"")
            .append(jsonEscape(missionBundle.absolutePath)).append("\",")
        append("\"mission_peer\":\"").append(missionPeer).append("\",")
        append("\"bluetooth_address\":\"").append(bluetoothAddress).append("\",")
        append("\"psm\":").append(psm).append(',')
        append("\"event_text\":\"").append(jsonEscape(eventText)).append("\",")
        append("\"send_packet_bytes\":").append(sendPacketBytes).append(',')
        append("\"receive_packet_bytes\":").append(receivePacketBytes).append(',')
        append("\"require_event_larger_than_mtu\":true")
        append('}')
    }

    companion object {
        const val MAX_MISSION_BUNDLE_BYTES = 125_877L
        const val MAX_EVENT_TEXT_BYTES = 1_024
        private val ADDRESS = Regex("^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
        private val NODE_ID = Regex("^[0-9A-Fa-f]{64}$")

        fun parse(
            address: String,
            psm: String,
            missionPeer: String,
            missionBundle: File?,
            statePath: File,
            eventText: String,
            sendPacketBytes: Int,
            receivePacketBytes: Int,
        ): ValidatorConfig {
            val normalizedAddress = address.trim().uppercase(Locale.US)
            require(ADDRESS.matches(normalizedAddress)) { "Bluetooth address is invalid" }
            val parsedPsm = psm.trim().toIntOrNull()
            require(parsedPsm != null && parsedPsm in 0x80..0xff) {
                "LE PSM must be between 128 and 255"
            }
            val normalizedPeer = missionPeer.trim().lowercase(Locale.US)
            require(NODE_ID.matches(normalizedPeer)) { "mission node ID must be 64 hex characters" }
            require(missionBundle != null && missionBundle.isFile) { "select a mission bundle" }
            require(missionBundle.length() in 1..MAX_MISSION_BUNDLE_BYTES) {
                "mission bundle exceeds the Aster bound"
            }
            require(statePath.absolutePath != missionBundle.absolutePath) {
                "state and mission paths must be distinct"
            }
            require(eventText.isNotEmpty()) { "message must not be empty" }
            require(eventText.toByteArray(Charsets.UTF_8).size <= MAX_EVENT_TEXT_BYTES) {
                "message must not exceed $MAX_EVENT_TEXT_BYTES UTF-8 bytes"
            }
            require(sendPacketBytes in 1..0xffff && receivePacketBytes in 1..0xffff) {
                "Bluetooth packet size is invalid"
            }
            return ValidatorConfig(
                statePath = statePath,
                missionBundle = missionBundle,
                missionPeer = normalizedPeer,
                bluetoothAddress = normalizedAddress,
                psm = parsedPsm,
                eventText = eventText,
                sendPacketBytes = sendPacketBytes,
                receivePacketBytes = receivePacketBytes,
            )
        }

        private fun jsonEscape(value: String): String = buildString(value.length) {
            value.forEach { character ->
                when (character) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\b' -> append("\\b")
                    '\u000c' -> append("\\f")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> {
                        if (character.code < 0x20) {
                            append("\\u").append(character.code.toString(16).padStart(4, '0'))
                        } else {
                            append(character)
                        }
                    }
                }
            }
        }
    }
}

internal fun needsBluetoothConnectPermission(sdkInt: Int, permissionGranted: Boolean): Boolean =
    sdkInt >= 31 && !permissionGranted
