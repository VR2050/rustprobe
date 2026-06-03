package io.rustprobe.app

data class PendingOwnerQuery(
    val protocol: String,
    val srcAddr: String,
    val dstAddr: String,
    val srcPort: Int,
    val dstPort: Int,
)
