package io.rustprobe.app

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile

class ForwardingObservationRecorder(
    context: Context,
    private val selection: MonitoringSelection,
) {
    private val outputDir = File(context.filesDir, "rustprobe-output").apply { mkdirs() }
    private val eventsFile = File(outputDir, "forwarding-events.jsonl")
    private val socksLogFile = File(outputDir, "forwarding-socks5.log")
    private val tproxyLogFile = File(outputDir, "forwarding-tproxy.log")
    private val singleAppInfo = when (selection) {
        is MonitoringSelection.Single -> AppInventory.findAppByPackage(context, selection.packageName)
        else -> null
    }
    private var socksOffset = 0L
    private var tproxyOffset = 0L

    fun socksLogPath(): String = socksLogFile.absolutePath

    fun tproxyLogPath(): String = tproxyLogFile.absolutePath

    fun poll() {
        val newEvents = parseSocks5Log() + parseTproxyLog()
        if (newEvents > 0) {
            Log.i("ForwardingRecorder", "recorded forwarding events count=$newEvents file=${eventsFile.absolutePath}")
        }
    }

    private fun parseSocks5Log(): Int {
        val linePattern = Regex(""".*\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})].*\[I] .*socks5 server (tcp|udp) \[([^\]]+)]:(\d+)""")
        val (lines, nextOffset) = readNewLines(socksLogFile, socksOffset)
        socksOffset = nextOffset

        return appendEvents(
            lines.mapNotNull { line ->
                val match = linePattern.matchEntire(line) ?: return@mapNotNull null
                val timestamp = match.groupValues[1]
                val transport = match.groupValues[2].uppercase()
                val host = match.groupValues[3]
                val port = match.groupValues[4].toIntOrNull() ?: return@mapNotNull null
                if (host == "0.0.0.0" && port == 0) return@mapNotNull null
                buildEvent(
                    timestamp = timestamp,
                    source = "forwarding-socks5",
                    transport = transport,
                    host = host,
                    port = port,
                )
            },
        )
    }

    private fun parseTproxyLog(): Int {
        val linePattern = Regex(""".*\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})].*\[I] .*socks5 client tcp -> \[([^\]]+)]:(\d+)""")
        val (lines, nextOffset) = readNewLines(tproxyLogFile, tproxyOffset)
        tproxyOffset = nextOffset

        return appendEvents(
            lines.mapNotNull { line ->
                val match = linePattern.matchEntire(line) ?: return@mapNotNull null
                val timestamp = match.groupValues[1]
                val host = match.groupValues[2]
                val port = match.groupValues[3].toIntOrNull() ?: return@mapNotNull null
                buildEvent(
                    timestamp = timestamp,
                    source = "forwarding-tproxy",
                    transport = "TCP",
                    host = host,
                    port = port,
                )
            },
        )
    }

    private fun appendEvents(events: List<JSONObject>): Int {
        if (events.isEmpty()) return 0
        eventsFile.parentFile?.mkdirs()
        eventsFile.appendText(
            buildString {
                events.forEach { event ->
                    append(event.toString())
                    append('\n')
                }
            },
        )
        return events.size
    }

    private fun buildEvent(
        timestamp: String,
        source: String,
        transport: String,
        host: String,
        port: Int,
    ): JSONObject {
        return JSONObject().apply {
            put("timestamp", timestamp)
            put("source", source)
            put("transport", transport)
            put("host", host)
            put("port", port)
            put("object_kind", if (host.contains(Regex("""[A-Za-z]"""))) "Domain" else "Ip")
            put("selection_mode", selectionSummary())
            singleAppInfo?.let { app ->
                put("app_uid", app.uid)
                put("app_package", app.packageName)
                put("app_label", app.appLabel)
            }
            if (selection is MonitoringSelection.Multiple) {
                put("monitored_packages", JSONArray(selection.packageNames))
            }
        }
    }

    private fun readNewLines(file: File, offset: Long): Pair<List<String>, Long> {
        if (!file.exists()) return emptyList<String>() to offset
        RandomAccessFile(file, "r").use { raf ->
            val safeOffset = offset.coerceAtMost(raf.length())
            raf.seek(safeOffset)
            val lines = mutableListOf<String>()
            while (true) {
                val line = raf.readLine() ?: break
                lines += line
            }
            return lines to raf.filePointer
        }
    }

    private fun selectionSummary(): String {
        return when (selection) {
            MonitoringSelection.Global -> "Global"
            is MonitoringSelection.Single -> "Single(${selection.packageName})"
            is MonitoringSelection.Multiple -> "Multiple(${selection.packageNames.joinToString(",")})"
        }
    }
}
