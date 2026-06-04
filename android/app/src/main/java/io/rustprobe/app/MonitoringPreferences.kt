package io.rustprobe.app

object MonitoringPreferences {
    @Volatile
    var selection: MonitoringSelection = MonitoringSelection.Global

    @Volatile
    var forwardingEnabled: Boolean = true
}
