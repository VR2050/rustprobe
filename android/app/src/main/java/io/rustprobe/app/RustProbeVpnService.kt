package io.rustprobe.app

import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlin.concurrent.thread

class RustProbeVpnService : VpnService() {
    private var tunInterface: ParcelFileDescriptor? = null
    @Volatile
    private var ownerPolling = false
    private val ownerResolver: ConnectionOwnerResolver by lazy {
        ConnectionOwnerResolver(
            getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager,
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i("RustProbeVpnService", "onStartCommand flags=$flags startId=$startId")
        if (tunInterface == null) {
            val builder = Builder()
                .setSession("RustProbe")
                .addAddress("10.10.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")

            applyAppSelection(builder)
            tunInterface = builder.establish()
            Log.i("RustProbeVpnService", "TUN establish result=${tunInterface != null}")
        }

        val fd = tunInterface?.fd
        if (fd == null) {
            Log.e("RustProbeVpnService", "TUN interface was not established")
            stopSelf()
            return START_NOT_STICKY
        }

        val outputDir = "${filesDir.absolutePath}/rustprobe-output"
        val outputDirSet = RustBridge.nativeSetOutputDirectory(outputDir)
        Log.i(
            "RustProbeVpnService",
            "Configured Rust output dir=$outputDir applied=$outputDirSet",
        )

        val started = RustBridge.nativeStartCapture(fd)
        Log.i(
            "RustProbeVpnService",
            "Requested Rust capture start. started=$started running=${RustBridge.nativeIsCaptureRunning()}",
        )

        startOwnerResolutionLoop()

        // Future work:
        // 1. protect relay sockets
        // 2. hand tun fd to async Rust runtime instead of plain thread
        // 3. move polling owner resolution loop to structured coroutine/service worker
        return START_STICKY
    }

    override fun onDestroy() {
        ownerPolling = false
        RustBridge.nativeStopCapture()
        tunInterface?.close()
        tunInterface = null
        super.onDestroy()
    }

    private fun applyAppSelection(builder: Builder) {
        when (val selection = MonitoringPreferences.selection) {
            MonitoringSelection.Global -> Unit
            is MonitoringSelection.Single -> {
                runCatching { builder.addAllowedApplication(selection.packageName) }
                    .onFailure {
                        Log.w(
                            "RustProbeVpnService",
                            "Failed to allow single app ${selection.packageName}",
                            it,
                        )
                    }
            }
            is MonitoringSelection.Multiple -> {
                selection.packageNames.forEach { packageName ->
                    runCatching { builder.addAllowedApplication(packageName) }
                        .onFailure {
                            Log.w(
                                "RustProbeVpnService",
                                "Failed to allow monitored app $packageName",
                                it,
                            )
                        }
                }
            }
        }
    }

    private fun startOwnerResolutionLoop() {
        if (ownerPolling) return
        ownerPolling = true
        Log.i("RustProbeVpnService", "Starting owner resolution loop")

        thread(name = "rustprobe-owner-resolution", isDaemon = true) {
            while (ownerPolling) {
                runCatching {
                    val queries = RustBridge.takePendingOwnerQueries(limit = 32)
                    queries.forEach { query ->
                        val uid = ownerResolver.resolveOwnerUid(query)
                        if (uid >= 0) {
                            RustBridge.registerOwnerResolution(
                                protocol = query.protocol,
                                srcAddr = query.srcAddr,
                                srcPort = query.srcPort,
                                dstAddr = query.dstAddr,
                                dstPort = query.dstPort,
                                uid = uid,
                            )
                        }
                    }
                }.onFailure {
                    Log.w("RustProbeVpnService", "Owner resolution loop failed", it)
                }

                Thread.sleep(1000)
            }
        }
    }
}
