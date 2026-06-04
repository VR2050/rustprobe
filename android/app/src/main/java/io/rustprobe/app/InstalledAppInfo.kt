package io.rustprobe.app

import org.json.JSONObject

data class InstalledAppInfo(
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    val isSystemApp: Boolean,
) {
    fun toRustJson(): JSONObject {
        return JSONObject().apply {
            put("uid", uid)
            put("package_name", packageName)
            put("app_label", appLabel)
        }
    }
}
