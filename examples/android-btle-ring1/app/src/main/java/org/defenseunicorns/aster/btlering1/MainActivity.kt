package org.defenseunicorns.aster.btlering1

import android.Manifest
import android.app.Activity
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private lateinit var address: EditText
    private lateinit var psm: EditText
    private lateinit var missionPeer: EditText
    private lateinit var eventText: EditText
    private lateinit var selectMission: Button
    private lateinit var connect: Button
    private lateinit var cancel: Button
    private lateinit var missionStatus: TextView
    private lateinit var status: TextView

    private val fileExecutor = Executors.newSingleThreadExecutor()
    private val eventPreparer = EventPreparer()
    private var missionBundle: File? = null
    private var missionCopying = false
    private var bridge: BluetoothBridge? = null
    private var pendingPermissionConfig: ValidatorConfig? = null
    private var state: ValidationState = ValidationState.Ready

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        address = findViewById(R.id.address)
        psm = findViewById(R.id.psm)
        missionPeer = findViewById(R.id.missionPeer)
        eventText = findViewById(R.id.eventText)
        selectMission = findViewById(R.id.selectMission)
        connect = findViewById(R.id.connect)
        cancel = findViewById(R.id.cancel)
        missionStatus = findViewById(R.id.missionStatus)
        status = findViewById(R.id.status)

        psm.setText("128")
        selectMission.setOnClickListener { selectMissionBundle() }
        connect.setOnClickListener { validateAndConnect() }
        cancel.setOnClickListener { cancelValidation() }
        render()
    }

    private fun selectMissionBundle() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/octet-stream"
        }
        startActivityForResult(intent, REQUEST_MISSION)
    }

    @Deprecated("Activity result API is sufficient for this dependency-free validator")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_MISSION && resultCode == RESULT_OK) {
            data?.data?.let(::copyMissionBundle)
        }
    }

    private fun copyMissionBundle(uri: Uri) {
        missionBundle = null
        missionCopying = true
        missionStatus.text = "copying mission bundle"
        render()
        fileExecutor.execute {
            val destination = File(filesDir, "ring1-mission.bundle")
            val temporary = File(filesDir, "ring1-mission.bundle.tmp")
            val result = runCatching {
                var total = 0L
                contentResolver.openInputStream(uri).use { input ->
                    requireNotNull(input) { "mission bundle is unavailable" }
                    FileOutputStream(temporary, false).use { output ->
                        val buffer = ByteArray(8 * 1024)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            require(total <= ValidatorConfig.MAX_MISSION_BUNDLE_BYTES) {
                                "mission bundle exceeds the Aster bound"
                            }
                            output.write(buffer, 0, count)
                        }
                        require(total > 0) { "mission bundle is empty" }
                        output.fd.sync()
                    }
                }
                Files.move(temporary.toPath(), destination.toPath(), REPLACE_EXISTING, ATOMIC_MOVE)
                destination
            }
            if (result.isFailure) temporary.delete()
            runOnUiThread {
                missionCopying = false
                result.onSuccess {
                    missionBundle = it
                    missionStatus.text = "mission bundle copied (${it.length()} bytes)"
                }.onFailure {
                    missionStatus.text = "mission bundle copy failed"
                }
                render()
            }
        }
    }

    private fun validateAndConnect() {
        val config = runCatching {
            ValidatorConfig.parse(
                address = address.text.toString(),
                psm = psm.text.toString(),
                missionPeer = missionPeer.text.toString(),
                missionBundle = missionBundle,
                statePath = File(filesDir, "aster-state"),
                eventText = eventText.text.toString(),
                sendPacketBytes = 1,
                receivePacketBytes = 1,
            )
        }.getOrElse {
            state = ValidationState.Failed("configuration", it.message?.take(160) ?: "invalid form")
            render()
            return
        }

        state = reduce(ValidationState.Ready, ValidationEvent.ConnectRequested)
        render()
        eventPreparer.prepare(
            config,
            validationCallback(),
        ) {
            runOnUiThread { continueWithTransport(config) }
        }
    }

    private fun continueWithTransport(config: ValidatorConfig) {
        if (state != ValidationState.Connecting) return
        val permissionGranted = Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
            checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) ==
            PackageManager.PERMISSION_GRANTED
        if (needsBluetoothConnectPermission(Build.VERSION.SDK_INT, permissionGranted)) {
            pendingPermissionConfig = config
            requestPermissions(arrayOf(Manifest.permission.BLUETOOTH_CONNECT), REQUEST_CONNECT)
            return
        }
        beginTransport(config)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQUEST_CONNECT) return
        val config = pendingPermissionConfig.also { pendingPermissionConfig = null }
        if (state != ValidationState.Connecting || config == null) return
        if (grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED) {
            beginTransport(config)
        } else {
            state = ValidationState.Failed("permission", "Bluetooth connect permission was denied")
            render()
        }
    }

    private fun beginTransport(config: ValidatorConfig) {
        val adapter = getSystemService(BluetoothManager::class.java)?.adapter
        if (adapter == null) {
            state = ValidationState.Failed("unavailable", "Bluetooth LE is unavailable")
            render()
            return
        }
        val currentBridge = BluetoothBridge(adapter)
        bridge = currentBridge
        currentBridge.connect(config, validationCallback())
    }

    private fun validationCallback(): NativeValidator.Callback =
        object : NativeValidator.Callback {
            override fun onPhase(phase: String) = dispatch(ValidationEvent.Phase(phase))
            override fun onComplete(receiptJson: String) =
                dispatch(ValidationEvent.Complete(receiptJson))
            override fun onError(category: String, message: String) =
                dispatch(ValidationEvent.Error(category, message))
        }

    private fun cancelValidation() {
        pendingPermissionConfig = null
        val currentBridge = bridge
        eventPreparer.cancel()
        currentBridge?.cancel()
        if (currentBridge == null && state == ValidationState.Connecting) {
            state = ValidationState.Failed("unavailable", "validator was cancelled")
            render()
        }
    }

    private fun dispatch(event: ValidationEvent) {
        runOnUiThread {
            state = reduce(state, event)
            render()
            if (state is ValidationState.Complete || state is ValidationState.Failed) {
                bridge?.close()
                bridge = null
            }
        }
    }

    private fun render() {
        status.text = state.render()
        val running = state in setOf(
            ValidationState.Connecting,
            ValidationState.CarrierConnected,
            ValidationState.Authenticating,
            ValidationState.Reconciling,
        )
        address.isEnabled = !running
        psm.isEnabled = !running
        missionPeer.isEnabled = !running
        eventText.isEnabled = !running
        selectMission.isEnabled = !running && !missionCopying
        connect.isEnabled = !running && !missionCopying
        cancel.isEnabled = running
    }

    override fun onDestroy() {
        bridge?.close()
        bridge = null
        eventPreparer.close()
        fileExecutor.shutdownNow()
        super.onDestroy()
    }

    companion object {
        private const val REQUEST_MISSION = 100
        private const val REQUEST_CONNECT = 101
    }
}
