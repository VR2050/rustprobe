package io.rustprobe.app

import android.app.Service
import android.content.Intent
import android.os.IBinder
import java.io.File
import java.io.FileOutputStream
import android.util.Log

class LocalSocks5Service : Service() {
    companion object {
        const val ACTION_START = "io.rustprobe.app.LOCAL_SOCKS5_START"
        const val ACTION_STOP = "io.rustprobe.app.LOCAL_SOCKS5_STOP"

        init {
            System.loadLibrary("hev-socks5-server")
        }
    }

    private external fun Socks5StartService(configPath: String)
    private external fun Socks5StopService()

    private var started = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopProxy()
            stopSelf()
            return START_NOT_STICKY
        }
        startProxy()
        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    fun startProxy() {
        if (started) return

        val configFile = File(cacheDir, "rustprobe-socks5.conf")
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
                    appendLine("  log-file: stderr")
                    appendLine("  log-level: info")
                }.toByteArray(),
            )
        }

        Socks5StartService(configFile.absolutePath)
        started = true
        Log.i("LocalSocks5Service", "local socks5 proxy started on 127.0.0.1:1080")
    }

    fun stopProxy() {
        if (!started) return
        Socks5StopService()
        Log.i("LocalSocks5Service", "local socks5 proxy stopped")
        started = false
    }
}
