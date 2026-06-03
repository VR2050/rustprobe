package io.rustprobe.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.ComponentActivity

class MainActivity : ComponentActivity() {
    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        Log.i("RustProbeMainActivity", "VPN permission result=${result.resultCode}")
        startService(Intent(this, RustProbeVpnService::class.java))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val rustLoaded = runCatching { RustBridge.nativeIsCaptureRunning() }
            .onFailure { Log.e("RustProbeMainActivity", "Rust bridge check failed", it) }
            .getOrDefault(false)
        val installedApps = AppInventory.listInstalledApps(this)
        val monitoredApps = installedApps
            .filterNot { it.isSystemApp }
            .take(3)
            .map { it.packageName }

        MonitoringPreferences.selection = when {
            monitoredApps.isEmpty() -> MonitoringSelection.Global
            monitoredApps.size == 1 && monitoredApps.first() == packageName ->
                MonitoringSelection.Global
            monitoredApps.size == 1 -> MonitoringSelection.Single(monitoredApps.first())
            else -> MonitoringSelection.Multiple(monitoredApps)
        }

        val syncedApps = RustBridge.syncInstalledApps(installedApps)
        val syncedSelection = RustBridge.setMonitoringSelection(MonitoringPreferences.selection)
        Log.i(
            "RustProbeMainActivity",
            "rustLoaded=$rustLoaded installedApps=${installedApps.size} monitoring=${MonitoringPreferences.selection} syncedApps=$syncedApps syncedSelection=$syncedSelection",
        )

        val view = TextView(this).apply {
            text = buildString {
                append("RustProbe Android shell placeholder\n")
                append("Installed apps discovered: ${installedApps.size}\n")
                append("Current monitoring mode: ${MonitoringPreferences.selection}\n")
                append("Rust app sync: $syncedApps, selection sync: $syncedSelection\n")
                append("Rust selection summary: ${RustBridge.nativeSelectionSummary()}\n")
                append("Request VPN permission to continue.")
            }
            textSize = 18f
            setPadding(32, 64, 32, 32)
        }
        setContentView(view)

        val intent = VpnService.prepare(this)
        if (intent != null) {
            Log.i("RustProbeMainActivity", "Requesting VPN permission")
            vpnPermissionLauncher.launch(intent)
        } else {
            Log.i("RustProbeMainActivity", "VPN permission already granted, starting service")
            startService(Intent(this, RustProbeVpnService::class.java))
        }
    }
}
