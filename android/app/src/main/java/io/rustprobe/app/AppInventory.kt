package io.rustprobe.app

import android.content.Context
import android.content.pm.ApplicationInfo

object AppInventory {
    fun listInstalledApps(context: Context): List<InstalledAppInfo> {
        val pm = context.packageManager
        return pm.getInstalledApplications(0)
            .map { info ->
                InstalledAppInfo(
                    uid = info.uid,
                    packageName = info.packageName,
                    appLabel = pm.getApplicationLabel(info).toString(),
                    isSystemApp = info.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                )
            }
            .sortedBy { it.appLabel.lowercase() }
    }
}
