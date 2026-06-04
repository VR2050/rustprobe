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

    fun findAppByUid(context: Context, uid: Int): InstalledAppInfo? {
        val pm = context.packageManager
        val packageName = pm.getPackagesForUid(uid)?.firstOrNull() ?: return null
        val info = runCatching { pm.getApplicationInfo(packageName, 0) }.getOrNull() ?: return null
        return InstalledAppInfo(
            uid = uid,
            packageName = packageName,
            appLabel = pm.getApplicationLabel(info).toString(),
            isSystemApp = info.flags and ApplicationInfo.FLAG_SYSTEM != 0,
        )
    }
}
