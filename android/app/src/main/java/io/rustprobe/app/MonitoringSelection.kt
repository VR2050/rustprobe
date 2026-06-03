package io.rustprobe.app

sealed class MonitoringSelection {
    data object Global : MonitoringSelection()
    data class Single(val packageName: String) : MonitoringSelection()
    data class Multiple(val packageNames: List<String>) : MonitoringSelection()
}
