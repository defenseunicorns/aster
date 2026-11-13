package org.defenseunicorns.aster.btlering1

import java.io.File
import java.nio.file.Files
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ValidatorConfigTest {
    @Test
    fun parsesManualAddressPsmNodeAndMissionCopy() {
        val root = Files.createTempDirectory("aster-android-config").toFile()
        val mission = File(root, "mission.bundle").apply { writeText("mission") }

        val config = ValidatorConfig.parse(
            address = "7c:fa:80:72:3b:7a",
            psm = "128",
            missionPeer = "AB".repeat(32),
            missionBundle = mission,
            statePath = File(root, "state"),
            eventText = "hello from Android",
            sendPacketBytes = 512,
            receivePacketBytes = 256,
        )

        assertEquals("7C:FA:80:72:3B:7A", config.bluetoothAddress)
        assertEquals("ab".repeat(32), config.missionPeer)
        assertEquals(128, config.psm)
        assertTrue(config.toJson().contains("\"require_event_larger_than_mtu\":true"))
        root.deleteRecursively()
    }

    @Test
    fun rejectsMalformedFieldsAndMissingMissionCopy() {
        val root = Files.createTempDirectory("aster-android-invalid").toFile()
        val missing = File(root, "missing.bundle")
        val mission = File(root, "mission.bundle").apply { writeText("mission") }

        assertThrows(IllegalArgumentException::class.java) {
            valid("bad", "128", "11".repeat(32), mission, root)
        }
        assertThrows(IllegalArgumentException::class.java) {
            valid("7C:FA:80:72:3B:7A", "127", "11".repeat(32), mission, root)
        }
        assertThrows(IllegalArgumentException::class.java) {
            valid("7C:FA:80:72:3B:7A", "128", "11", mission, root)
        }
        assertThrows(IllegalArgumentException::class.java) {
            valid("7C:FA:80:72:3B:7A", "128", "11".repeat(32), missing, root)
        }
        root.deleteRecursively()
    }

    @Test
    fun requestsConnectPermissionOnlyOnAndroidTwelveAndLater() {
        assertEquals(false, needsBluetoothConnectPermission(30, false))
        assertEquals(true, needsBluetoothConnectPermission(31, false))
        assertEquals(false, needsBluetoothConnectPermission(31, true))
    }

    @Test
    fun preservesBoundedUnicodeAndControlTextInJson() {
        val root = Files.createTempDirectory("aster-android-text").toFile()
        val mission = File(root, "mission.bundle").apply { writeText("mission") }
        val text = "Snowman ☃\n\"quoted\"\u0000"

        val config = ValidatorConfig.parse(
            address = "7C:FA:80:72:3B:7A",
            psm = "128",
            missionPeer = "11".repeat(32),
            missionBundle = mission,
            statePath = File(root, "state"),
            eventText = text,
            sendPacketBytes = 512,
            receivePacketBytes = 256,
        )

        assertEquals(text, config.eventText)
        assertTrue(config.toJson().contains("\"event_text\":\"Snowman ☃\\n\\\"quoted\\\"\\u0000\""))
        root.deleteRecursively()
    }

    @Test
    fun rejectsEmptyOrOversizedUtf8Text() {
        val root = Files.createTempDirectory("aster-android-text-bound").toFile()
        val mission = File(root, "mission.bundle").apply { writeText("mission") }

        assertThrows(IllegalArgumentException::class.java) {
            valid("7C:FA:80:72:3B:7A", "128", "11".repeat(32), mission, root, "")
        }
        assertThrows(IllegalArgumentException::class.java) {
            valid(
                "7C:FA:80:72:3B:7A",
                "128",
                "11".repeat(32),
                mission,
                root,
                "x".repeat(1_025),
            )
        }
        assertEquals(
            1_024,
            valid(
                "7C:FA:80:72:3B:7A",
                "128",
                "11".repeat(32),
                mission,
                root,
                "é".repeat(512),
            ).eventText.toByteArray(Charsets.UTF_8).size,
        )
        root.deleteRecursively()
    }

    private fun valid(
        address: String,
        psm: String,
        peer: String,
        mission: File,
        root: File,
        eventText: String = "hello from Android",
    ) = ValidatorConfig.parse(
        address,
        psm,
        peer,
        mission,
        File(root, "state"),
        eventText,
        512,
        256,
    )
}
