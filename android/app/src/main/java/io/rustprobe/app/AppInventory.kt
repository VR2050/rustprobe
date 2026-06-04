package io.rustprobe.app

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.LauncherApps
import android.content.pm.PackageManager
import android.os.Process

object AppInventory {
    fun listInstalledApps(context: Context): List<InstalledAppInfo> {
        val pm = context.packageManager
        val launcherApps = context.getSystemService(LauncherApps::class.java)
        val launcherEntries = runCatching {
            launcherApps?.getActivityList(null, Process.myUserHandle()).orEmpty()
        }.getOrDefault(emptyList())

        val apps = launcherEntries
            .mapNotNull { activityInfo ->
                val packageName = activityInfo.applicationInfo.packageName
                val info = runCatching { pm.getApplicationInfo(packageName, 0) }.getOrNull()
                    ?: activityInfo.applicationInfo
                InstalledAppInfo(
                    uid = info.uid,
                    packageName = packageName,
                    appLabel = activityInfo.label?.toString()
                        ?.takeIf { it.isNotBlank() }
                        ?: pm.getApplicationLabel(info).toString(),
                    isSystemApp = info.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                )
            }
            .distinctBy { it.packageName }
            .sortedBy { it.appLabel.lowercase() }

        if (apps.isNotEmpty()) {
            android.util.Log.i(
                "RustProbeAppInventory",
                "listed launcher apps via LauncherApps count=${apps.size} sample=${apps.take(8).joinToString { "${it.appLabel}(${it.packageName})" }}",
            )
            return apps
        }

        val launcherIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
        }
        val resolveFlags = PackageManager.ResolveInfoFlags.of(0)
        val fallbackApps = pm.queryIntentActivities(launcherIntent, resolveFlags)
            .mapNotNull { resolveInfo ->
                val packageName = resolveInfo.activityInfo?.packageName ?: return@mapNotNull null
                val info = runCatching { pm.getApplicationInfo(packageName, 0) }.getOrNull()
                    ?: return@mapNotNull null
                InstalledAppInfo(
                    uid = info.uid,
                    packageName = packageName,
                    appLabel = resolveInfo.loadLabel(pm)?.toString()
                        ?.takeIf { it.isNotBlank() }
                        ?: pm.getApplicationLabel(info).toString(),
                    isSystemApp = info.flags and ApplicationInfo.FLAG_SYSTEM != 0,
                )
            }
            .distinctBy { it.packageName }
            .sortedBy { it.appLabel.lowercase() }
        android.util.Log.i(
            "RustProbeAppInventory",
            "listed launcher apps via queryIntentActivities count=${fallbackApps.size} sample=${fallbackApps.take(8).joinToString { "${it.appLabel}(${it.packageName})" }}",
        )
        return fallbackApps
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

    fun findAppByPackage(context: Context, packageName: String): InstalledAppInfo? {
        val pm = context.packageManager
        val info = runCatching { pm.getApplicationInfo(packageName, 0) }.getOrNull() ?: return null
        return InstalledAppInfo(
            uid = info.uid,
            packageName = packageName,
            appLabel = pm.getApplicationLabel(info).toString(),
            isSystemApp = info.flags and ApplicationInfo.FLAG_SYSTEM != 0,
        )
    }
}
