package io.rustprobe.app

import android.util.Log
import org.json.JSONArray
import org.json.JSONObject

object RustBridge {
    init {
        runCatching {
            System.loadLibrary("rustprobe_ffi")
            Log.i("RustBridge", "Loaded rustprobe_ffi successfully")
        }.onFailure {
            Log.e("RustBridge", "failed to load rustprobe_ffi", it)
        }
    }

    external fun nativeStartCapture(fd: Int): Boolean
    external fun nativeStartMirroredCapture(): Boolean
    external fun nativeStopCapture()
    external fun nativeIsCaptureRunning(): Boolean
    external fun nativePacketsSeen(): Int
    external fun nativeSyncInstalledApps(appsJson: String): Boolean
    external fun nativeUpsertApp(appJson: String): Boolean
    external fun nativeSetMonitoringSelection(selectionJson: String): Boolean
    external fun nativeSetOutputDirectory(path: String): Boolean
    external fun nativeRegisterOwnerResolution(resolutionJson: String): Boolean
    external fun nativeTakePendingOwnerQueries(limit: Int): String
    external fun nativeQueueOwnerQuery(queryJson: String): Boolean
    external fun nativeSelectionSummary(): String
    external fun nativeAttributionStats(): String

    fun syncInstalledApps(apps: List<InstalledAppInfo>): Boolean {
        val json = JSONArray().apply {
            apps.forEach { app ->
                put(app.toRustJson())
            }
        }.toString()

        return nativeSyncInstalledApps(json)
    }

    fun upsertApp(app: InstalledAppInfo): Boolean {
        return nativeUpsertApp(app.toRustJson().toString())
    }

    fun setMonitoringSelection(selection: MonitoringSelection): Boolean {
        val json = when (selection) {
            MonitoringSelection.Global -> "\"Global\""
            is MonitoringSelection.Single -> JSONObject()
                .put("Single", selection.packageName)
                .toString()
            is MonitoringSelection.Multiple -> JSONObject()
                .put("Multiple", JSONArray(selection.packageNames))
                .toString()
        }

        return nativeSetMonitoringSelection(json)
    }

    fun registerOwnerResolution(
        protocol: String,
        srcAddr: String,
        srcPort: Int,
        dstAddr: String,
        dstPort: Int,
        uid: Int,
    ): Boolean {
        val json = JSONObject().apply {
            put(
                "key",
                JSONObject().apply {
                    put("src_addr", srcAddr)
                    put("dst_addr", dstAddr)
                    put("src_port", srcPort)
                    put("dst_port", dstPort)
                    put("protocol", protocol)
                },
            )
            put("uid", uid)
        }.toString()

        return nativeRegisterOwnerResolution(json)
    }

    fun takePendingOwnerQueries(limit: Int): List<PendingOwnerQuery> {
        val raw = nativeTakePendingOwnerQueries(limit)
        val array = JSONArray(raw)
        return buildList {
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                val key = item.getJSONObject("key")
                add(
                    PendingOwnerQuery(
                        protocol = key.getString("protocol"),
                        srcAddr = key.getString("src_addr"),
                        dstAddr = key.getString("dst_addr"),
                        srcPort = key.getInt("src_port"),
                        dstPort = key.getInt("dst_port"),
                    ),
                )
            }
        }
    }

    fun attributionStats(): AttributionStats {
        val json = JSONObject(nativeAttributionStats())
        return AttributionStats(
            trackedApps = json.optInt("tracked_apps"),
            cachedFlowOwners = json.optInt("cached_flow_owners"),
            pendingOwnerQueries = json.optInt("pending_owner_queries"),
            totalOwnerQueriesEnqueued = json.optLong("total_owner_queries_enqueued"),
            totalOwnerQueriesDrained = json.optLong("total_owner_queries_drained"),
            totalOwnerQueriesSkipped = json.optLong("total_owner_queries_skipped"),
            totalOwnerResolutions = json.optLong("total_owner_resolutions"),
        )
    }
}
