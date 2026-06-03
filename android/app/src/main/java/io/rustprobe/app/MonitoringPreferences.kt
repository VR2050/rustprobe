package io.rustprobe.app

object MonitoringPreferences {
    @Volatile
    var selection: MonitoringSelection = MonitoringSelection.Global
}
