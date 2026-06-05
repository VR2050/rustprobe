package io.rustprobe.app

import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.io.File
import java.io.FileOutputStream
import android.util.Log

class LocalSocks5Service : Service() {
    companion object {
        private const val TAG = "LocalSocks5Service"
        const val ACTION_START = "io.rustprobe.app.LOCAL_SOCKS5_START"
        const val ACTION_STOP = "io.rustprobe.app.LOCAL_SOCKS5_STOP"

        init {
            runCatching {
                System.loadLibrary("hev-socks5-server")
                Log.i(TAG, "Loaded hev-socks5-server successfully")
            }.onFailure {
                Log.e(TAG, "Failed to load hev-socks5-server", it)
                throw it
            }
        }
    }

    private external fun Socks5StartService(configPath: String)
    private external fun Socks5StopService()

    private var started = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action} flags=$flags startId=$startId started=$started")
        return runCatching {
            if (intent?.action == ACTION_STOP) {
                stopProxy()
                val stopped = stopSelfResult(startId)
                Log.i(TAG, "Processed stop request startId=$startId stopSelfResult=$stopped")
                START_NOT_STICKY
            } else {
                startProxy()
                START_STICKY
            }
        }.getOrElse { error ->
            Log.e(TAG, "onStartCommand failed", error)
            stopSelf()
            START_NOT_STICKY
        }
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    fun startProxy() {
        if (started) return

        Log.i(TAG, "Preparing local socks5 proxy config")
        val configFile = File(cacheDir, "rustprobe-socks5.conf")
        val outputDir = File(filesDir, "rustprobe-output").apply { mkdirs() }
        val logFile = File(outputDir, "forwarding-socks5.log")
        FileOutputStream(configFile, false).use { output ->
            output.write(
                buildString {
                    appendLine("main:")
                    appendLine("  workers: 4")
                    appendLine("  port: 1080")
                    appendLine("  listen-address: '127.0.0.1'")
                    appendLine("  udp-port: 1080")
                    appendLine("  udp-listen-address: '127.0.0.1'")
                    appendLine("  listen-ipv6-only: false")
                    appendLine("  bind-address-v4: ''")
                    appendLine("  bind-address-v6: ''")
                    appendLine("  bind-interface: ''")
                    appendLine("misc:")
                    appendLine("  task-stack-size: 24576")
                    appendLine("  log-file: '${logFile.absolutePath}'")
                    appendLine("  log-level: info")
                }.toByteArray(),
            )
        }

        Log.i(TAG, "Starting local socks5 proxy with config=${configFile.absolutePath}")
        Socks5StartService(configFile.absolutePath)
        started = true
        Log.i(TAG, "local socks5 proxy started on 127.0.0.1:1080")
    }

    fun stopProxy() {
        if (!started) return
        Log.i(TAG, "Stopping local socks5 proxy")
        Socks5StopService()
        Log.i(TAG, "local socks5 proxy stopped")
        started = false
    }
}
