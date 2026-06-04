package io.rustprobe.app

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import kotlin.concurrent.thread

class RustProbeVpnService : VpnService() {
    companion object {
        private const val STATUS_LOG_INTERVAL_MS = 5_000L
        private const val LOCAL_SOCKS_PORT = 1080

        init {
            System.loadLibrary("hev-socks5-tunnel")
        }
    }

    private external fun TProxyStartService(configPath: String, fd: Int)
    private external fun TProxyStopService()
    private external fun TProxyGetStats(): LongArray

    private var tunInterface: ParcelFileDescriptor? = null
    @Volatile
    private var ownerPolling = false
    @Volatile
    private var forwardingStatusPolling = false
    @Volatile
    private var ownerQueryCount = 0L
    @Volatile
    private var ownerResolutionHitCount = 0L
    @Volatile
    private var ownerResolutionMissCount = 0L
    private val ownerResolver: ConnectionOwnerResolver by lazy {
        ConnectionOwnerResolver(
            getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager,
        )
    }
    private val forwardingEnabled: Boolean
        get() = MonitoringPreferences.forwardingEnabled

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i("RustProbeVpnService", "onStartCommand flags=$flags startId=$startId")
        return if (forwardingEnabled) {
            startForwardingVpn()
        } else {
            startCaptureVpn()
        }
    }

    override fun onRevoke() {
        stopSelf()
        super.onRevoke()
    }

    private fun startCaptureVpn(): Int {
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
        logRuntimeStatus("capture started")

        return START_STICKY
    }

    private fun startForwardingVpn(): Int {
        RustBridge.nativeStopCapture()
        ownerPolling = false
        startLocalSocksProxy()

        if (tunInterface == null) {
            val builder = Builder()
                .setSession("RustProbe Forwarding")
                .setBlocking(false)
                .setMtu(1500)
                .addAddress("10.10.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")

            applyAppSelection(builder)
            tunInterface = builder.establish()
            Log.i("RustProbeVpnService", "forwarding TUN establish result=${tunInterface != null}")
        }

        val fd = tunInterface?.fd
        if (fd == null) {
            Log.e("RustProbeVpnService", "forwarding TUN interface was not established")
            stopLocalSocksProxy()
            stopSelf()
            return START_NOT_STICKY
        }

        val configFile = File(cacheDir, "rustprobe-tproxy.yml")
        FileOutputStream(configFile, false).use { output ->
            output.write(
                buildString {
                    appendLine("misc:")
                    appendLine("  task-stack-size: 24576")
                    appendLine("  tcp-buffer-size: 4096")
                    appendLine("  log-file: stderr")
                    appendLine("  log-level: info")
                    appendLine("tunnel:")
                    appendLine("  mtu: 1500")
                    appendLine("socks5:")
                    appendLine("  address: '127.0.0.1'")
                    appendLine("  port: $LOCAL_SOCKS_PORT")
                    appendLine("  udp: 'udp'")
                }.toByteArray(),
            )
        }

        TProxyStartService(configFile.absolutePath, fd)
        val stats = runCatching { TProxyGetStats() }.getOrNull()
        Log.i(
            "RustProbeVpnService",
            "forwarding started localSocks=127.0.0.1:$LOCAL_SOCKS_PORT stats=${stats?.contentToString() ?: "unavailable"}",
        )
        startForwardingStatusLoop()
        return START_STICKY
    }

    override fun onDestroy() {
        ownerPolling = false
        forwardingStatusPolling = false
        if (forwardingEnabled) {
            val stats = runCatching { TProxyGetStats() }.getOrNull()
            Log.i(
                "RustProbeVpnService",
                "forwarding stopping stats=${stats?.contentToString() ?: "unavailable"}",
            )
            runCatching { TProxyStopService() }
                .onFailure { Log.w("RustProbeVpnService", "Failed to stop tunnel proxy", it) }
            stopLocalSocksProxy()
        } else {
            logRuntimeStatus("service stopping")
            RustBridge.nativeStopCapture()
        }
        tunInterface?.close()
        tunInterface = null
        super.onDestroy()
    }

    private fun startForwardingStatusLoop() {
        if (forwardingStatusPolling) return
        forwardingStatusPolling = true

        thread(name = "rustprobe-forwarding-status", isDaemon = true) {
            while (forwardingStatusPolling) {
                val stats = runCatching { TProxyGetStats() }.getOrNull()
                Log.i(
                    "RustProbeVpnService",
                    "forwarding status txPackets=${stats?.getOrNull(0) ?: -1} txBytes=${stats?.getOrNull(1) ?: -1} rxPackets=${stats?.getOrNull(2) ?: -1} rxBytes=${stats?.getOrNull(3) ?: -1}",
                )
                Thread.sleep(STATUS_LOG_INTERVAL_MS)
            }
        }
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

        runCatching { builder.addDisallowedApplication(packageName) }
            .onFailure {
                Log.w(
                    "RustProbeVpnService",
                    "Failed to disallow self package $packageName from VPN",
                    it,
                )
            }
    }

    private fun startOwnerResolutionLoop() {
        if (ownerPolling) return
        ownerPolling = true
        Log.i("RustProbeVpnService", "Starting owner resolution loop")

        thread(name = "rustprobe-owner-resolution", isDaemon = true) {
            var lastStatusAt = 0L
            while (ownerPolling) {
                runCatching {
                    val queries = RustBridge.takePendingOwnerQueries(limit = 32)
                    ownerQueryCount += queries.size
                    queries.forEach { query ->
                        val resolution = ownerResolver.resolveOwnerUid(query)
                        if (resolution != null) {
                            ownerResolutionHitCount += 1
                            val ownerApp = AppInventory.findAppByUid(this@RustProbeVpnService, resolution.uid)
                            if (ownerApp != null) {
                                val upserted = RustBridge.upsertApp(ownerApp)
                                Log.i(
                                    "RustProbeVpnService",
                                    "owner app synced uid=${ownerApp.uid} package=${ownerApp.packageName} label=${ownerApp.appLabel} upserted=$upserted",
                                )
                            } else {
                                Log.w(
                                    "RustProbeVpnService",
                                    "owner app lookup failed for uid=${resolution.uid}",
                                )
                            }
                            RustBridge.registerOwnerResolution(
                                protocol = query.protocol,
                                srcAddr = query.srcAddr,
                                srcPort = query.srcPort,
                                dstAddr = query.dstAddr,
                                dstPort = query.dstPort,
                                uid = resolution.uid,
                            )
                            Log.i(
                                "RustProbeVpnService",
                                "owner resolved protocol=${query.protocol} ${query.srcAddr}:${query.srcPort} -> ${query.dstAddr}:${query.dstPort} uid=${resolution.uid} direction=${resolution.matchedDirection} attempted=${resolution.attemptedDirections}",
                            )
                        } else {
                            ownerResolutionMissCount += 1
                            Log.i(
                                "RustProbeVpnService",
                                "owner unresolved protocol=${query.protocol} ${query.srcAddr}:${query.srcPort} -> ${query.dstAddr}:${query.dstPort}",
                            )
                        }
                    }
                }.onFailure {
                    Log.w("RustProbeVpnService", "Owner resolution loop failed", it)
                }

                val now = SystemClock.elapsedRealtime()
                if (now - lastStatusAt >= STATUS_LOG_INTERVAL_MS) {
                    logRuntimeStatus("periodic status")
                    lastStatusAt = now
                }

                Thread.sleep(1000)
            }
        }
    }

    private fun logRuntimeStatus(reason: String) {
        val captureRunning = runCatching { RustBridge.nativeIsCaptureRunning() }
            .getOrDefault(false)
        val packetsSeen = runCatching { RustBridge.nativePacketsSeen() }
            .getOrDefault(-1)
        val stats = runCatching { RustBridge.attributionStats() }
            .getOrNull()

        Log.i(
            "RustProbeVpnService",
            buildString {
                append(reason)
                append(": captureRunning=")
                append(captureRunning)
                append(" packetsSeen=")
                append(packetsSeen)
                append(" ownerQueryCount=")
                append(ownerQueryCount)
                append(" ownerResolutionHitCount=")
                append(ownerResolutionHitCount)
                append(" ownerResolutionMissCount=")
                append(ownerResolutionMissCount)
                if (stats != null) {
                    append(" pendingOwnerQueries=")
                    append(stats.pendingOwnerQueries)
                    append(" cachedFlowOwners=")
                    append(stats.cachedFlowOwners)
                    append(" ownerQueriesEnqueued=")
                    append(stats.totalOwnerQueriesEnqueued)
                    append(" ownerQueriesDrained=")
                    append(stats.totalOwnerQueriesDrained)
                    append(" ownerQueriesSkipped=")
                    append(stats.totalOwnerQueriesSkipped)
                    append(" ownerResolutions=")
                    append(stats.totalOwnerResolutions)
                }
            },
        )
    }

    private fun startLocalSocksProxy() {
        startService(
            Intent(this, LocalSocks5Service::class.java).apply {
                action = LocalSocks5Service.ACTION_START
            },
        )
    }

    private fun stopLocalSocksProxy() {
        startService(
            Intent(this, LocalSocks5Service::class.java).apply {
                action = LocalSocks5Service.ACTION_STOP
            },
        )
    }
}
