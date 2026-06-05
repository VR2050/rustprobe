package io.rustprobe.app

enum class MonitoringMode {
    Forward,
    Capture,
}

object MonitoringPreferences {
    @Volatile
    var selection: MonitoringSelection = MonitoringSelection.Global

    @Volatile
    var mode: MonitoringMode = MonitoringMode.Forward
}
