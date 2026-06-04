package io.rustprobe.app

data class OwnerResolutionTrace(
    val uid: Int,
    val matchedDirection: String,
    val attemptedDirections: List<String>,
)
