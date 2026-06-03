package io.rustprobe.app

data class InstalledAppInfo(
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    val isSystemApp: Boolean,
)
