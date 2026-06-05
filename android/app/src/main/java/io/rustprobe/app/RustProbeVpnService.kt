package io.rustprobe.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.util.concurrent.ConcurrentHashMap
import kotlin.concurrent.thread

class RustProbeVpnService : VpnService() {
    private enum class ActiveSessionMode {
        Capture,
        Forward,
    }

    private enum class RustPipelineIngress {
        TunCapture,
        ForwardBridge,
    }

    companion object {
        private const val TAG = "RustProbeVpnService"
        private const val STATUS_LOG_INTERVAL_MS = 5_000L
        private const val LOCAL_SOCKS_PORT = 1080
        private const val FORWARDING_TCP_BUFFER_SIZE = 65_536
        private const val NOTIFICATION_CHANNEL_ID = "rustprobe_vpn"
        private const val NOTIFICATION_ID = 1001

        init {
            runCatching {
                System.loadLibrary("hev-socks5-tunnel")
                Log.i(TAG, "Loaded hev-socks5-tunnel successfully")
            }.onFailure {
                Log.e(TAG, "Failed to load hev-socks5-tunnel", it)
                throw it
            }
        }
    }

    private external fun TProxyStartService(configPath: String, fd: Int)
    private external fun TProxyStopService()
    private external fun TProxyGetStats(): LongArray

    private var tunInterface: ParcelFileDescriptor? = null
    private var activeSessionMode: ActiveSessionMode? = null
    private var activeSelection: MonitoringSelection? = null
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
    private val syncedOwnerUids = ConcurrentHashMap.newKeySet<Int>()
    private var forwardingRecorder: ForwardingObservationRecorder? = null
    private val ownerResolver: ConnectionOwnerResolver by lazy {
        ConnectionOwnerResolver(
            getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager,
        )
    }
    private val monitoringMode: MonitoringMode
        get() = MonitoringPreferences.mode

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand flags=$flags startId=$startId mode=$monitoringMode")
        return runCatching {
            ensureForegroundNotification()
            restartSessionIfNeeded()
            if (monitoringMode == MonitoringMode.Forward) {
                startForwardingVpn()
            } else {
                startCaptureVpn()
            }
        }.getOrElse { error ->
            Log.e(TAG, "VPN service start failed", error)
            teardownCurrentSession("startup failure")
            stopSelf()
            START_NOT_STICKY
        }
    }

    override fun onRevoke() {
        stopSelf()
        super.onRevoke()
    }

    private fun startCaptureVpn(): Int {
        Log.i(TAG, "Starting capture VPN session")
        resetRuntimeCounters()
        resetOutputSessionFiles(clearForwarding = true, clearCapture = true)
        val fd = establishTunInterface(forwarding = false)
        if (fd == null) {
            Log.e(TAG, "TUN interface was not established")
            stopSelf()
            return START_NOT_STICKY
        }

        startSharedRustPipeline(
            ingress = RustPipelineIngress.TunCapture,
            fd = fd,
        )

        startOwnerResolutionLoop()
        activeSessionMode = ActiveSessionMode.Capture
        activeSelection = MonitoringPreferences.selection
        logRuntimeStatus("capture shared pipeline started")

        return START_STICKY
    }

    private fun startForwardingVpn(): Int {
        Log.i(TAG, "Starting forwarding VPN session")
        resetRuntimeCounters()
        resetOutputSessionFiles(clearForwarding = false, clearCapture = true)
        forwardingRecorder = ForwardingObservationRecorder(this, MonitoringPreferences.selection)
        Log.i(TAG, "Forwarding recorder initialized selection=${MonitoringPreferences.selection}")
        startLocalSocksProxy()

        val fd = establishTunInterface(forwarding = true)
        if (fd == null) {
            Log.e(TAG, "forwarding TUN interface was not established")
            stopLocalSocksProxy()
            stopSelf()
            return START_NOT_STICKY
        }

        val configFile = File(cacheDir, "rustprobe-tproxy.yml")
        val tproxyLogPath = forwardingRecorder?.tproxyLogPath() ?: File(filesDir, "rustprobe-output/forwarding-tproxy.log").absolutePath
        FileOutputStream(configFile, false).use { output ->
            output.write(
                buildString {
                    appendLine("misc:")
                    appendLine("  task-stack-size: 24576")
                    appendLine("  tcp-buffer-size: $FORWARDING_TCP_BUFFER_SIZE")
                    appendLine("  log-file: '$tproxyLogPath'")
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

        startSharedRustPipeline(
            ingress = RustPipelineIngress.ForwardBridge,
            fd = fd,
        )

        Log.i(TAG, "Starting tunnel proxy config=${configFile.absolutePath} fd=$fd")
        TProxyStartService(configFile.absolutePath, fd)
        val stats = runCatching { TProxyGetStats() }.getOrNull()
        Log.i(
            TAG,
            "forwarding started localSocks=127.0.0.1:$LOCAL_SOCKS_PORT stats=${stats?.contentToString() ?: "unavailable"}",
        )
        activeSessionMode = ActiveSessionMode.Forward
        activeSelection = MonitoringPreferences.selection
        startOwnerResolutionLoop()
        startForwardingStatusLoop()
        logRuntimeStatus("forwarding shared pipeline started")
        return START_STICKY
    }

    private fun establishTunInterface(forwarding: Boolean): Int? {
        if (tunInterface == null) {
            val builder = Builder()
                .setSession(if (forwarding) "RustProbe Forwarding" else "RustProbe")
                .addAddress("10.10.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")

            if (forwarding) {
                builder.setBlocking(false)
                builder.setMtu(1500)
            }

            applyAppSelection(builder)
            tunInterface = builder.establish()
            Log.i(
                TAG,
                "${if (forwarding) "forwarding" else "capture"} TUN establish result=${tunInterface != null}",
            )
        }

        return tunInterface?.fd
    }

    private fun startSharedRustPipeline(ingress: RustPipelineIngress, fd: Int): Boolean {
        val outputDir = "${filesDir.absolutePath}/rustprobe-output"
        val outputDirSet = RustBridge.nativeSetOutputDirectory(outputDir)
        Log.i(
            TAG,
            "Configured shared Rust output dir=$outputDir applied=$outputDirSet ingress=$ingress",
        )

        val started = when (ingress) {
            RustPipelineIngress.TunCapture -> RustBridge.nativeStartCapture(fd)
            RustPipelineIngress.ForwardBridge -> RustBridge.nativeStartMirroredCapture()
        }
        Log.i(
            TAG,
            "Requested shared Rust pipeline start ingress=$ingress started=$started running=${RustBridge.nativeIsCaptureRunning()}",
        )
        return started
    }

    override fun onDestroy() {
        teardownCurrentSession("service stopping")
        runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        super.onDestroy()
    }

    private fun restartSessionIfNeeded() {
        val requestedMode = if (monitoringMode == MonitoringMode.Forward) {
            ActiveSessionMode.Forward
        } else {
            ActiveSessionMode.Capture
        }
        val requestedSelection = MonitoringPreferences.selection
        val captureRunning = RustBridge.nativeIsCaptureRunning()
        val sessionHealthy = when (requestedMode) {
            ActiveSessionMode.Forward -> tunInterface != null && captureRunning
            ActiveSessionMode.Capture -> tunInterface != null && captureRunning
        }

        if (
            activeSessionMode == requestedMode &&
            activeSelection == requestedSelection &&
            sessionHealthy
        ) {
            Log.i(
                TAG,
                "Restart check requestedMode=$requestedMode activeSessionMode=$activeSessionMode requestedSelection=$requestedSelection activeSelection=$activeSelection tunReady=${tunInterface != null} captureRunning=$captureRunning",
            )
            Log.i(
                TAG,
                "Skipping restart; requested session already active mode=$requestedMode selection=$requestedSelection",
            )
            return
        }

        if (activeSessionMode != null || tunInterface != null || captureRunning) {
            Log.i(TAG, "Restarting existing session mode=$activeSessionMode captureRunning=$captureRunning")
            teardownCurrentSession("restarting session")
        }
    }

    private fun teardownCurrentSession(reason: String) {
        ownerPolling = false
        forwardingStatusPolling = false
        when (activeSessionMode) {
            ActiveSessionMode.Forward -> {
                val stats = runCatching { TProxyGetStats() }.getOrNull()
                Log.i(
                    TAG,
                    "$reason forwarding stats=${stats?.contentToString() ?: "unavailable"}",
                )
                runCatching { TProxyStopService() }
                    .onFailure { Log.w(TAG, "Failed to stop tunnel proxy", it) }
                stopLocalSocksProxy()
                logRuntimeStatus(reason)
                RustBridge.nativeStopCapture()
            }
            ActiveSessionMode.Capture -> {
                logRuntimeStatus(reason)
                RustBridge.nativeStopCapture()
            }
            null -> {
                if (RustBridge.nativeIsCaptureRunning()) {
                    logRuntimeStatus(reason)
                    RustBridge.nativeStopCapture()
                }
            }
        }
        forwardingRecorder = null
        tunInterface?.close()
        tunInterface = null
        activeSessionMode = null
        activeSelection = null
    }

    private fun resetRuntimeCounters() {
        ownerQueryCount = 0L
        ownerResolutionHitCount = 0L
        ownerResolutionMissCount = 0L
        syncedOwnerUids.clear()
    }

    private fun resetOutputSessionFiles(clearForwarding: Boolean, clearCapture: Boolean) {
        val outputDir = File(filesDir, "rustprobe-output").apply { mkdirs() }
        val captureFiles = listOf("flows.jsonl", "objects.jsonl")
        val forwardingFiles = listOf(
            "forwarding-events.jsonl",
            "forwarding-socks5.log",
            "forwarding-tproxy.log",
        )

        if (clearCapture) {
            captureFiles.forEach { name ->
                File(outputDir, name).writeText("")
            }
        }
        if (clearForwarding) {
            forwardingFiles.forEach { name ->
                File(outputDir, name).writeText("")
            }
        }
    }

    private fun startForwardingStatusLoop() {
        if (forwardingStatusPolling) return
        forwardingStatusPolling = true

        thread(name = "rustprobe-forwarding-status", isDaemon = true) {
            while (forwardingStatusPolling) {
                val stats = runCatching { TProxyGetStats() }.getOrNull()
                runCatching { forwardingRecorder?.poll() }
                    .onFailure { Log.w(TAG, "Failed to poll forwarding recorder", it) }
                Log.i(
                    TAG,
                    "forwarding status txPackets=${stats?.getOrNull(0) ?: -1} txBytes=${stats?.getOrNull(1) ?: -1} rxPackets=${stats?.getOrNull(2) ?: -1} rxBytes=${stats?.getOrNull(3) ?: -1}",
                )
                Thread.sleep(STATUS_LOG_INTERVAL_MS)
            }
        }
    }

    private fun applyAppSelection(builder: Builder) {
        var usesAllowedApplications = false
        when (val selection = MonitoringPreferences.selection) {
            MonitoringSelection.Global -> Unit
            is MonitoringSelection.Single -> {
                usesAllowedApplications = true
                runCatching { builder.addAllowedApplication(selection.packageName) }
                    .onFailure {
                        Log.w(
                            TAG,
                            "Failed to allow single app ${selection.packageName}",
                            it,
                        )
                    }
            }
            is MonitoringSelection.Multiple -> {
                usesAllowedApplications = true
                selection.packageNames.forEach { packageName ->
                    runCatching { builder.addAllowedApplication(packageName) }
                        .onFailure {
                            Log.w(
                                TAG,
                                "Failed to allow monitored app $packageName",
                                it,
                            )
                        }
                }
            }
        }

        if (!usesAllowedApplications) {
            runCatching { builder.addDisallowedApplication(packageName) }
                .onFailure {
                    Log.w(
                        TAG,
                        "Failed to disallow self package $packageName from VPN",
                        it,
                    )
                }
        } else {
            Log.i(TAG, "Skipping self disallow because allowed-application mode is active")
        }
    }

    private fun startOwnerResolutionLoop() {
        if (ownerPolling) return
        ownerPolling = true
        Log.i(TAG, "Starting owner resolution loop")

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
                            if (syncedOwnerUids.add(resolution.uid)) {
                                val ownerApp = AppInventory.findAppByUid(this@RustProbeVpnService, resolution.uid)
                                if (ownerApp != null) {
                                    val upserted = RustBridge.upsertApp(ownerApp)
                                    Log.i(
                                        TAG,
                                        "owner app synced uid=${ownerApp.uid} package=${ownerApp.packageName} label=${ownerApp.appLabel} upserted=$upserted",
                                    )
                                } else {
                                    Log.w(
                                        TAG,
                                        "owner app lookup failed for uid=${resolution.uid}",
                                    )
                                }
                            }
                            RustBridge.registerOwnerResolution(
                                protocol = query.protocol,
                                srcAddr = query.srcAddr,
                                srcPort = query.srcPort,
                                dstAddr = query.dstAddr,
                                dstPort = query.dstPort,
                                uid = resolution.uid,
                            )
                            if (ownerResolutionHitCount <= 8L || ownerResolutionHitCount % 32L == 0L) {
                                Log.i(
                                    TAG,
                                    "owner resolved protocol=${query.protocol} ${query.srcAddr}:${query.srcPort} -> ${query.dstAddr}:${query.dstPort} uid=${resolution.uid} direction=${resolution.matchedDirection} attempted=${resolution.attemptedDirections}",
                                )
                            }
                        } else {
                            ownerResolutionMissCount += 1
                            if (ownerResolutionMissCount <= 4L || ownerResolutionMissCount % 32L == 0L) {
                                Log.i(
                                    TAG,
                                    "owner unresolved protocol=${query.protocol} ${query.srcAddr}:${query.srcPort} -> ${query.dstAddr}:${query.dstPort}",
                                )
                            }
                        }
                    }
                }.onFailure {
                    Log.w(TAG, "Owner resolution loop failed", it)
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
            TAG,
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
        Log.i(TAG, "Requesting LocalSocks5Service start")
        val intent = Intent(this, LocalSocks5Service::class.java).apply {
            action = LocalSocks5Service.ACTION_START
        }
        startService(intent)
    }

    private fun stopLocalSocksProxy() {
        Log.i(TAG, "Requesting LocalSocks5Service stop")
        val intent = Intent(this, LocalSocks5Service::class.java).apply {
            action = LocalSocks5Service.ACTION_STOP
        }
        startService(intent)
    }

    private fun ensureForegroundNotification() {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                "RustProbe VPN",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "RustProbe VPN capture and forwarding state"
            }
            manager.createNotificationChannel(channel)
        }

        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val modeLabel = if (monitoringMode == MonitoringMode.Forward) "Forward" else "Capture"
        val notification = Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("RustProbe 正在监听")
            .setContentText("模式：$modeLabel")
            .setOngoing(true)
            .setContentIntent(contentIntent)
            .build()

        Log.i(TAG, "Promoting VPN service to foreground modeLabel=$modeLabel")
        startForeground(NOTIFICATION_ID, notification)
    }
}
