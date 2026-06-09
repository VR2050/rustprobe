package io.rustprobe.app

data class CaptureStats(
    val captureRunning: Boolean,
    val packetsSeen: Long,
    val mirroredPacketsReceived: Long,
    val mirroredPacketsAccepted: Long,
    val mirroredPacketsDropped: Long,
    val mirroredDropRatio: Double,
    val mirroredIngestQueueCapacity: Int,
)
