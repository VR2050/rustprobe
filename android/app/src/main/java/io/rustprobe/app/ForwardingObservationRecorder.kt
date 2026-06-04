package io.rustprobe.app

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.util.LinkedHashSet

class ForwardingObservationRecorder(
    context: Context,
    private val selection: MonitoringSelection,
) {
    companion object {
        private const val MAX_RECENT_EVENT_KEYS = 4096
    }

    private val outputDir = File(context.filesDir, "rustprobe-output").apply { mkdirs() }
    private val eventsFile = File(outputDir, "forwarding-events.jsonl")
    private val socksLogFile = File(outputDir, "forwarding-socks5.log")
    private val tproxyLogFile = File(outputDir, "forwarding-tproxy.log")
    private val sessionStartedAtEpochMs = System.currentTimeMillis()
    private val sessionId = "forwarding-$sessionStartedAtEpochMs"
    private val singleAppInfo = when (selection) {
        is MonitoringSelection.Single -> AppInventory.findAppByPackage(context, selection.packageName)
        else -> null
    }
    private val monitoredPackages = when (selection) {
        MonitoringSelection.Global -> emptyList()
        is MonitoringSelection.Single -> listOf(selection.packageName)
        is MonitoringSelection.Multiple -> selection.packageNames
    }
    private var socksOffset = 0L
    private var tproxyOffset = 0L
    private var socksRemainder = ""
    private var tproxyRemainder = ""
    private val recentEventKeys = LinkedHashSet<String>()
    private var eventSequence = 0L

    init {
        resetSessionFiles()
    }

    fun socksLogPath(): String = socksLogFile.absolutePath

    fun tproxyLogPath(): String = tproxyLogFile.absolutePath

    fun poll() {
        val socksResult = parseSocks5Log()
        val tproxyResult = parseTproxyLog()
        val newEvents = socksResult.recordedCount + tproxyResult.recordedCount
        val duplicateEvents = socksResult.duplicateCount + tproxyResult.duplicateCount
        if (newEvents > 0 || duplicateEvents > 0) {
            Log.i(
                "ForwardingRecorder",
                "poll session=$sessionId newEvents=$newEvents duplicates=$duplicateEvents file=${eventsFile.absolutePath}",
            )
        }
    }

    private fun parseSocks5Log(): AppendResult {
        val linePattern = Regex(""".*\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})].*\[I] .*socks5 server (tcp|udp) \[([^\]]+)]:(\d+)""")
        val (lines, nextOffset, remainder) = readNewLines(socksLogFile, socksOffset, socksRemainder)
        socksOffset = nextOffset
        socksRemainder = remainder

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
                    rawLine = line,
                )
            },
        )
    }

    private fun parseTproxyLog(): AppendResult {
        val linePattern = Regex(""".*\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})].*\[I] .*socks5 client tcp -> \[([^\]]+)]:(\d+)""")
        val (lines, nextOffset, remainder) = readNewLines(tproxyLogFile, tproxyOffset, tproxyRemainder)
        tproxyOffset = nextOffset
        tproxyRemainder = remainder

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
                    rawLine = line,
                )
            },
        )
    }

    private fun appendEvents(events: List<JSONObject>): AppendResult {
        if (events.isEmpty()) return AppendResult(0, 0)
        val freshEvents = mutableListOf<JSONObject>()
        var duplicateCount = 0
        events.forEach { event ->
            val key = event.getString("dedupe_key")
            if (recentEventKeys.add(key)) {
                trimRecentEventKeys()
                freshEvents += event
            } else {
                duplicateCount += 1
            }
        }
        if (freshEvents.isEmpty()) return AppendResult(0, duplicateCount)

        eventsFile.parentFile?.mkdirs()
        eventsFile.appendText(
            buildString {
                freshEvents.forEach { event ->
                    val serialized = JSONObject(event.toString()).apply {
                        remove("dedupe_key")
                    }
                    append(serialized.toString())
                    append('\n')
                }
            },
        )
        return AppendResult(freshEvents.size, duplicateCount)
    }

    private fun buildEvent(
        timestamp: String,
        source: String,
        transport: String,
        host: String,
        port: Int,
        rawLine: String,
    ): JSONObject {
        val objectKind = classifyObjectKind(host)
        val normalizedHost = if (objectKind == "Domain") host.lowercase() else host
        val eventKey = "$sessionId|$source|$timestamp|$transport|$normalizedHost|$port"
        return JSONObject().apply {
            put("event_seq", ++eventSequence)
            put("session_id", sessionId)
            put("session_started_at_ms", sessionStartedAtEpochMs)
            put("observed_at_ms", System.currentTimeMillis())
            put("timestamp", timestamp)
            put("source", source)
            put("transport", transport)
            put("host", normalizedHost)
            put("port", port)
            put("object_kind", objectKind)
            put("selection_mode", selectionSummary())
            put("monitored_packages", JSONArray(monitoredPackages))
            put("raw_line", rawLine)
            put("dedupe_key", eventKey)
            singleAppInfo?.let { app ->
                put("app_uid", app.uid)
                put("app_package", app.packageName)
                put("app_label", app.appLabel)
            }
        }
    }

    private fun readNewLines(file: File, offset: Long, remainder: String): Triple<List<String>, Long, String> {
        if (!file.exists()) return Triple(emptyList(), offset, remainder)
        RandomAccessFile(file, "r").use { raf ->
            val safeOffset = offset.coerceAtMost(raf.length())
            raf.seek(safeOffset)
            val bytes = ByteArray((raf.length() - safeOffset).toInt())
            raf.readFully(bytes)

            val chunk = remainder + String(bytes, StandardCharsets.UTF_8)
            if (chunk.isEmpty()) {
                return Triple(emptyList(), raf.filePointer, "")
            }

            val lines = chunk.split('\n')
            val completeLines = lines.dropLast(1).map { it.trimEnd('\r') }.filter { it.isNotEmpty() }
            val nextRemainder = lines.last()
            return Triple(completeLines, raf.filePointer, nextRemainder)
        }
    }

    private fun selectionSummary(): String {
        return when (selection) {
            MonitoringSelection.Global -> "Global"
            is MonitoringSelection.Single -> "Single(${selection.packageName})"
            is MonitoringSelection.Multiple -> "Multiple(${selection.packageNames.joinToString(",")})"
        }
    }

    private fun resetSessionFiles() {
        socksOffset = 0L
        tproxyOffset = 0L
        socksRemainder = ""
        tproxyRemainder = ""
        eventSequence = 0L
        recentEventKeys.clear()
        listOf(eventsFile, socksLogFile, tproxyLogFile).forEach { file ->
            file.parentFile?.mkdirs()
            file.writeText("")
        }
        Log.i("ForwardingRecorder", "reset forwarding session files session=$sessionId dir=${outputDir.absolutePath}")
    }

    private fun trimRecentEventKeys() {
        while (recentEventKeys.size > MAX_RECENT_EVENT_KEYS) {
            val iterator = recentEventKeys.iterator()
            if (!iterator.hasNext()) return
            iterator.next()
            iterator.remove()
        }
    }

    private fun classifyObjectKind(host: String): String {
        return if (host.any { it.isLetter() }) "Domain" else "Ip"
    }

    private data class AppendResult(
        val recordedCount: Int,
        val duplicateCount: Int,
    )
}
