package io.rustprobe.app

data class AttributionStats(
    val trackedApps: Int,
    val cachedFlowOwners: Int,
    val pendingOwnerQueries: Int,
    val totalOwnerQueriesEnqueued: Long,
    val totalOwnerQueriesDrained: Long,
    val totalOwnerQueriesSkipped: Long,
    val totalOwnerResolutions: Long,
)
