package io.rustprobe.app

import android.app.Activity
import android.app.ActivityManager
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private var autoRefreshEnabled = false
    private var manuallyStopped = false
    private val refreshTicker = object : Runnable {
        override fun run() {
            refreshDashboard()
            if (autoRefreshEnabled) {
                handler.postDelayed(this, REFRESH_INTERVAL_MS)
            }
        }
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        Log.i("RustProbeMainActivity", "VPN permission result=${result.resultCode}")
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            statusTextView?.text = "VPN 权限被拒绝，无法启动监听。"
        }
    }

    private lateinit var installedApps: List<InstalledAppInfo>
    private val appCheckBoxes = linkedMapOf<String, CheckBox>()
    private val selectedPackages = linkedSetOf<String>()
    private val trafficRefreshVersion = AtomicInteger(0)
    private var appSelectionMode = UiSelectionMode.Global

    private var forwardingRadio: RadioButton? = null
    private var captureRadio: RadioButton? = null
    private var globalSelectionRadio: RadioButton? = null
    private var singleSelectionRadio: RadioButton? = null
    private var multipleSelectionRadio: RadioButton? = null
    private var filterEditText: EditText? = null
    private var appListContainer: LinearLayout? = null
    private var selectedAppsTextView: TextView? = null
    private var appListEmptyTextView: TextView? = null
    private var statusTextView: TextView? = null
    private var summaryTextView: TextView? = null
    private var eventsTextView: TextView? = null
    private var domainsTextView: TextView? = null
    private var flowModeHintTextView: TextView? = null
    private var statusChipTextView: TextView? = null
    private var summaryPanel: View? = null
    private var eventsPanel: View? = null
    private var domainsPanel: View? = null
    private var summaryTabButton: Button? = null
    private var eventsTabButton: Button? = null
    private var domainsTabButton: Button? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val rustLoaded = runCatching { RustBridge.nativeIsCaptureRunning() }
            .onFailure { Log.e("RustProbeMainActivity", "Rust bridge check failed", it) }
            .getOrDefault(false)

        installedApps = AppInventory.listInstalledApps(this)
            .filterNot { it.packageName == packageName }
        syncAppsIntoRust(installedApps)

        restoreStateFromPreferences()
        setContentView(buildContentView())
        refreshDashboard()

        statusTextView?.text = if (rustLoaded) {
            "Rust 后端已加载。请选择应用并启动监听。"
        } else {
            "Rust 后端暂未完全就绪，但你仍然可以启动 VPN 并查看转发事件。"
        }
    }

    override fun onResume() {
        super.onResume()
        evaluateAutoRefresh()
    }

    override fun onPause() {
        stopAutoRefresh()
        super.onPause()
    }

    private fun buildContentView(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#F3F1EA"))
            setPadding(dp(14), dp(14), dp(14), dp(14))
        }

        val controlsScroll = ScrollView(this).apply {
            isFillViewport = true
            overScrollMode = View.OVER_SCROLL_IF_CONTENT_SCROLLS
        }
        val controlsColumn = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        controlsScroll.addView(
            controlsColumn,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        val headerCard = cardLayout().apply {
            addView(titleView("RustProbe 控制台"))
            addView(
                bodyView(
                    "上半部分负责配置，下半部分固定显示结果。刷新后不需要再往下找内容。",
                ),
            )
            statusChipTextView = chipView("等待状态...")
            addView(statusChipTextView)
            statusTextView = bodyView("等待刷新运行状态...")
            addView(statusTextView)
        }
        controlsColumn.addView(headerCard, cardParams(bottom = 12))

        val configCard = cardLayout().apply {
            addView(sectionTitle("监听模式"))
            val modeGroup = RadioGroup(this@MainActivity).apply {
                orientation = RadioGroup.HORIZONTAL
            }
            forwardingRadio = RadioButton(this@MainActivity).apply {
                text = "Forward"
                id = View.generateViewId()
                isChecked = MonitoringPreferences.forwardingEnabled
            }
            captureRadio = RadioButton(this@MainActivity).apply {
                text = "Capture"
                id = View.generateViewId()
                isChecked = !MonitoringPreferences.forwardingEnabled
            }
            modeGroup.addView(forwardingRadio)
            modeGroup.addView(captureRadio)
            addView(modeGroup)

            flowModeHintTextView = bodyView("")
            addView(flowModeHintTextView)

            addView(sectionTitle("应用选择"))
            val selectionModeGroup = RadioGroup(this@MainActivity).apply {
                orientation = RadioGroup.HORIZONTAL
                setOnCheckedChangeListener { _, checkedId ->
                    val mode = when (checkedId) {
                        globalSelectionRadio?.id -> UiSelectionMode.Global
                        singleSelectionRadio?.id -> UiSelectionMode.Single
                        else -> UiSelectionMode.Multiple
                    }
                    setSelectionMode(mode)
                }
            }
            globalSelectionRadio = RadioButton(this@MainActivity).apply {
                text = "全部应用"
                id = View.generateViewId()
                isChecked = appSelectionMode == UiSelectionMode.Global
            }
            singleSelectionRadio = RadioButton(this@MainActivity).apply {
                text = "单个应用"
                id = View.generateViewId()
                isChecked = appSelectionMode == UiSelectionMode.Single
            }
            multipleSelectionRadio = RadioButton(this@MainActivity).apply {
                text = "多个应用"
                id = View.generateViewId()
                isChecked = appSelectionMode == UiSelectionMode.Multiple
            }
            selectionModeGroup.addView(globalSelectionRadio)
            selectionModeGroup.addView(singleSelectionRadio)
            selectionModeGroup.addView(multipleSelectionRadio)
            addView(selectionModeGroup)

            selectedAppsTextView = bodyView("")
            addView(selectedAppsTextView)
            addView(
                actionButton("选择应用") {
                    openAppPickerDialog()
                }.apply {
                    layoutParams = marginParams(bottom = 8)
                },
            )

            addView(sectionTitle("操作"))
            addView(buttonRow())
        }
        controlsColumn.addView(configCard)
        root.addView(
            controlsScroll,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f,
            ).apply {
                bottomMargin = dp(12)
            },
        )

        val contentCard = cardLayout().apply {
            addView(sectionTitle("实时观察"))

            val tabRow = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
            }
            summaryTabButton = tabButton("摘要") { showPanel("summary") }
            eventsTabButton = tabButton("流量") { showPanel("events") }
            domainsTabButton = tabButton("聚合") { showPanel("domains") }
            tabRow.addView(summaryTabButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            tabRow.addView(eventsTabButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            tabRow.addView(domainsTabButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            addView(tabRow, marginParams(bottom = 10))

            val panelHost = FrameLayout(this@MainActivity).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    0,
                    1f,
                )
                minimumHeight = dp(260)
            }

            summaryTextView = monoBlock("正在生成运行摘要...")
            summaryPanel = panelScroll(summaryTextView!!)
            eventsTextView = monoBlock("等待最近流量数据...")
            eventsPanel = panelScroll(eventsTextView!!)
            domainsTextView = monoBlock("等待域名 / IP / 端口聚合...")
            domainsPanel = panelScroll(domainsTextView!!)

            panelHost.addView(summaryPanel, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            panelHost.addView(eventsPanel, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            panelHost.addView(domainsPanel, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            addView(panelHost)
        }
        root.addView(
            contentCard,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1.15f,
            ),
        )

        showPanel("summary")
        return root
    }

    private fun cardLayout(): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            background = roundedDrawable("#FFFDF8", "#DED8CC")
        }
    }

    private fun buttonRow(): View {
        return HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
            addView(
                LinearLayout(this@MainActivity).apply {
                    orientation = LinearLayout.HORIZONTAL
                    addView(actionButton("应用配置") {
                        applyCurrentSelection()
                        refreshDashboard()
                    })
                    addView(actionButton("启动/重启监听") {
                        applyCurrentSelection()
                        requestVpnAndStart()
                    })
                    addView(actionButton("停止监听") {
                        manuallyStopped = true
                        stopService(Intent(this@MainActivity, RustProbeVpnService::class.java))
                        stopAutoRefresh()
                        statusTextView?.text = "已请求停止 VPN 监听服务。"
                        refreshDashboard()
                    })
                    addView(actionButton("刷新") {
                        refreshDashboard()
                    })
                },
            )
        }
    }

    private fun actionButton(label: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
            minHeight = dp(44)
            background = roundedDrawable("#222222", "#222222")
            setTextColor(Color.WHITE)
            setOnClickListener { onClick() }
            layoutParams = marginParams(end = 8)
        }
    }

    private fun tabButton(label: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
            minHeight = dp(42)
            setOnClickListener { onClick() }
        }
    }

    private fun panelScroll(content: TextView): View {
        return ScrollView(this).apply {
            background = roundedDrawable("#FBFAF5", "#E2DDD2")
            setPadding(0, 0, 0, 0)
            addView(
                content,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
    }

    private fun showPanel(panel: String) {
        summaryPanel?.visibility = if (panel == "summary") View.VISIBLE else View.GONE
        eventsPanel?.visibility = if (panel == "events") View.VISIBLE else View.GONE
        domainsPanel?.visibility = if (panel == "domains") View.VISIBLE else View.GONE
        styleTab(summaryTabButton, panel == "summary")
        styleTab(eventsTabButton, panel == "events")
        styleTab(domainsTabButton, panel == "domains")
    }

    private fun styleTab(button: Button?, selected: Boolean) {
        button ?: return
        if (selected) {
            button.setTextColor(Color.WHITE)
            button.background = roundedDrawable("#2B4C7E", "#2B4C7E")
        } else {
            button.setTextColor(Color.parseColor("#2B2B2B"))
            button.background = roundedDrawable("#EEE9DE", "#D8D2C6")
        }
    }

    private fun restoreStateFromPreferences() {
        selectedPackages.clear()
        when (val selection = MonitoringPreferences.selection) {
            MonitoringSelection.Global -> {
                appSelectionMode = UiSelectionMode.Global
            }
            is MonitoringSelection.Single -> {
                appSelectionMode = UiSelectionMode.Single
                selectedPackages += selection.packageName
            }
            is MonitoringSelection.Multiple -> {
                appSelectionMode = UiSelectionMode.Multiple
                selectedPackages += selection.packageNames
            }
        }
    }

    private fun rebuildAppList() {
        updateAppListEnabledState()
        updateSelectedAppsSummary()
    }

    private fun syncSingleSelectionUi(selectedPackage: String) {
        appCheckBoxes.forEach { (packageName, checkBox) ->
            val shouldCheck = packageName == selectedPackage
            if (checkBox.isChecked != shouldCheck) {
                checkBox.setOnCheckedChangeListener(null)
                checkBox.isChecked = shouldCheck
                bindAppSelectionListener(checkBox, packageName)
            }
        }
    }

    private fun bindAppSelectionListener(checkBox: CheckBox, packageName: String) {
        checkBox.setOnCheckedChangeListener { _, isChecked ->
            when (appSelectionMode) {
                UiSelectionMode.Global -> {
                    if (isChecked) {
                        setSelectionMode(UiSelectionMode.Single, rebuild = false)
                        selectedPackages.clear()
                        selectedPackages += packageName
                        syncSingleSelectionUi(packageName)
                    }
                }
                UiSelectionMode.Single -> {
                    if (isChecked) {
                        selectedPackages.clear()
                        selectedPackages += packageName
                        syncSingleSelectionUi(packageName)
                    } else if (selectedPackages.contains(packageName)) {
                        selectedPackages.remove(packageName)
                    }
                }
                UiSelectionMode.Multiple -> {
                    if (isChecked) {
                        selectedPackages += packageName
                    } else {
                        selectedPackages -= packageName
                    }
                }
            }
            updateSelectedAppsSummary()
        }
    }

    private fun openAppPickerDialog() {
        if (appSelectionMode == UiSelectionMode.Global) {
            setSelectionMode(UiSelectionMode.Single, rebuild = false)
        }

        val dialogRoot = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(10), dp(18), dp(6))
        }
        val searchInput = EditText(this).apply {
            hint = "搜索应用名或包名，比如 夸克 / quark"
            inputType = InputType.TYPE_CLASS_TEXT
            setPadding(dp(12), dp(10), dp(12), dp(10))
            background = roundedDrawable("#FFFDF8", "#D7D2C5")
        }
        val hintView = bodyView("").apply {
            setPadding(0, dp(8), 0, dp(8))
        }
        val listScroll = ScrollView(this).apply {
            background = roundedDrawable("#FBFAF5", "#E2DDD2")
        }
        val listContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(8), dp(8), dp(8), dp(8))
        }
        listScroll.addView(
            listContainer,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        dialogRoot.addView(searchInput, marginParams(bottom = 8))
        dialogRoot.addView(hintView)
        dialogRoot.addView(
            listScroll,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(420),
            ),
        )

        fun rebuildDialogList(query: String) {
            listContainer.removeAllViews()
            val visibleApps = installedApps
                .filter { app ->
                    query.isBlank() ||
                        app.appLabel.lowercase().contains(query) ||
                        app.packageName.lowercase().contains(query)
                }
            Log.i(
                "RustProbeMainActivity",
                "picker query='$query' mode=$appSelectionMode visible=${visibleApps.size} matches=${visibleApps.take(6).joinToString { "${it.appLabel}(${it.packageName})" }}",
            )
            hintView.text = when {
                visibleApps.isEmpty() -> "没有找到匹配 \"$query\" 的应用"
                appSelectionMode == UiSelectionMode.Single -> "单个应用模式：点选一个 app 即可"
                else -> "多个应用模式：可勾选多个 app"
            }

            visibleApps.forEach { app ->
                val checkBox = CheckBox(this).apply {
                    text = if (app.isSystemApp) "${app.appLabel} [系统]" else app.appLabel
                    isChecked = selectedPackages.contains(app.packageName)
                    textSize = 14f
                    setTextColor(Color.parseColor("#222222"))
                    setPadding(dp(6), dp(6), dp(6), dp(6))
                    setOnCheckedChangeListener { _, isChecked ->
                        when (appSelectionMode) {
                            UiSelectionMode.Single -> {
                                if (isChecked) {
                                    selectedPackages.clear()
                                    selectedPackages += app.packageName
                                    rebuildDialogList(query)
                                } else if (selectedPackages.contains(app.packageName)) {
                                    selectedPackages.remove(app.packageName)
                                }
                            }
                            UiSelectionMode.Multiple -> {
                                if (isChecked) selectedPackages += app.packageName else selectedPackages -= app.packageName
                            }
                            UiSelectionMode.Global -> Unit
                        }
                    }
                }
                listContainer.addView(checkBox)
                listContainer.addView(
                    bodyView(app.packageName).apply {
                        textSize = 12f
                        setTextColor(Color.parseColor("#737373"))
                        setPadding(dp(34), 0, 0, dp(6))
                    },
                )
            }
        }

        searchInput.addTextChangedListener(
            object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = Unit
                override fun afterTextChanged(s: Editable?) {
                    rebuildDialogList(s?.toString()?.trim()?.lowercase().orEmpty())
                }
            },
        )

        rebuildDialogList("")

        AlertDialog.Builder(this)
            .setTitle("选择监听应用")
            .setView(dialogRoot)
            .setPositiveButton("确定") { _, _ ->
                updateSelectedAppsSummary()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun setSelectionMode(mode: UiSelectionMode, rebuild: Boolean = true) {
        if (appSelectionMode == mode) return
        appSelectionMode = mode
        if (mode == UiSelectionMode.Single && selectedPackages.size > 1) {
            val first = selectedPackages.firstOrNull()
            selectedPackages.clear()
            if (first != null) {
                selectedPackages += first
            }
        }
        globalSelectionRadio?.isChecked = mode == UiSelectionMode.Global
        singleSelectionRadio?.isChecked = mode == UiSelectionMode.Single
        multipleSelectionRadio?.isChecked = mode == UiSelectionMode.Multiple
        if (rebuild) {
            rebuildAppList()
        } else {
            updateAppListEnabledState()
            updateSelectedAppsSummary()
        }
    }

    private fun applyCurrentSelection() {
        val forwardingEnabled = forwardingRadio?.isChecked == true
        val selection = buildSelectionFromUi()
        MonitoringPreferences.forwardingEnabled = forwardingEnabled
        MonitoringPreferences.selection = selection
        val syncedApps = syncAppsIntoRust(installedApps)
        val syncedSelection = RustBridge.setMonitoringSelection(selection)

        statusTextView?.text = buildString {
            append("已应用配置：模式=")
            append(if (forwardingEnabled) "Forward" else "Capture")
            append("，选择=")
            append(selectionSummary(selection))
            append("，syncInstalledApps=")
            append(syncedApps)
            append("，syncSelection=")
            append(syncedSelection)
            append("。如果 VPN 已经在运行，请点“启动/重启监听”让新配置生效。")
        }
        updateStatusChip(if (forwardingEnabled) "Forward 已配置" else "Capture 已配置", false)
    }

    private fun requestVpnAndStart() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnPermissionLauncher.launch(intent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        manuallyStopped = false
        startService(Intent(this, RustProbeVpnService::class.java))
        statusTextView?.text = "已请求启动 VPN 监听服务。"
        updateStatusChip("监听启动中", false)
        startAutoRefresh()
        refreshDashboard()
    }

    private fun refreshDashboard() {
        flowModeHintTextView?.text = if (forwardingRadio?.isChecked == true) {
            "Forward：优先保证不断网，同时输出轻量 forwarding 事件；当前还不是完整 Rust 分析链路。"
        } else {
            "Capture：让 Rust 直接读取 TUN，能拿到更完整的 flow、DNS、SNI 和归因；当前版本下可能影响联网。"
        }

        updateSelectedAppsSummary()
        refreshSummary()
        refreshTrafficSectionsAsync()
        evaluateAutoRefresh()
    }

    private fun refreshSummary() {
        val packetsSeen = runCatching { RustBridge.nativePacketsSeen() }.getOrDefault(-1)
        val captureRunning = runCatching { RustBridge.nativeIsCaptureRunning() }.getOrDefault(false)
        val selectionSummary = runCatching { RustBridge.nativeSelectionSummary() }.getOrDefault("unavailable")
        val attribution = runCatching { RustBridge.attributionStats() }.getOrNull()
        val outputDir = File(filesDir, "rustprobe-output")
        val flowCoverage = computeFlowCoverageStats(
            readLastJsonObjects(File(outputDir, "flows.jsonl"), limit = 240),
        )

        summaryTextView?.text = buildString {
            appendLine("模式: ${if (MonitoringPreferences.forwardingEnabled) "Forward" else "Capture"}")
            appendLine(
                if (MonitoringPreferences.forwardingEnabled) {
                    "抓包线程运行中: $captureRunning（当前是 Forward，这里显示 false 是正常的）"
                } else {
                    "抓包线程运行中: $captureRunning"
                },
            )
            appendLine("已见数据包数: $packetsSeen")
            appendLine("当前选择: $selectionSummary")
            appendLine("输出目录: ${outputDir.absolutePath}")
            appendLine("forwarding-events.jsonl: ${File(outputDir, "forwarding-events.jsonl").length()} bytes")
            appendLine("flows.jsonl: ${File(outputDir, "flows.jsonl").length()} bytes")
            appendLine("objects.jsonl: ${File(outputDir, "objects.jsonl").length()} bytes")
            if (attribution != null) {
                appendLine("已跟踪应用数: ${attribution.trackedApps}")
                appendLine(
                    if (MonitoringPreferences.forwardingEnabled) {
                        "缓存 flow owner 数: ${attribution.cachedFlowOwners}（Forward 下通常会偏低或为 0，因为 Rust 没有直接读完整 TUN flow）"
                    } else {
                        "缓存 flow owner 数: ${attribution.cachedFlowOwners}"
                    },
                )
                appendLine("待处理 owner 查询: ${attribution.pendingOwnerQueries}")
                appendLine("已入队 owner 查询: ${attribution.totalOwnerQueriesEnqueued}")
                appendLine("已取出 owner 查询: ${attribution.totalOwnerQueriesDrained}")
                appendLine("已跳过 owner 查询: ${attribution.totalOwnerQueriesSkipped}")
                appendLine("owner 解析成功数: ${attribution.totalOwnerResolutions}")
            } else {
                appendLine("归因统计: 暂不可用")
            }
            appendLine()
            appendLine("最近 flow 命中统计:")
            appendLine("唯一 flow 数: ${flowCoverage.uniqueFlows}")
            appendLine(
                "带域名 flow: ${flowCoverage.domainFlows}" +
                    formatRate(flowCoverage.domainFlows, flowCoverage.uniqueFlows),
            )
            appendLine(
                "已归因 flow: ${flowCoverage.attributedFlows}" +
                    formatRate(flowCoverage.attributedFlows, flowCoverage.uniqueFlows),
            )
            appendLine("协议分布: ${flowCoverage.protocolSummary()}")
            appendLine("域名来源: ${flowCoverage.domainSourceSummary()}")
            appendLine("候选命中: DNS=${flowCoverage.dnsCandidates} TLS=${flowCoverage.tlsCandidates} QUIC=${flowCoverage.quicCandidates} QUIC-Initial=${flowCoverage.quicInitialCandidates}")
            appendLine("高级识别: DoH=${flowCoverage.dohCandidates} DoT=${flowCoverage.dotCandidates} HTTP/3=${flowCoverage.http3Candidates}")
            if (flowCoverage.alpnSummary().isNotBlank()) {
                appendLine("ALPN Top: ${flowCoverage.alpnSummary()}")
            }
        }
        updateStatusChip(
            if (captureRunning) "监听活跃中" else if (MonitoringPreferences.forwardingEnabled) "Forward 运行中" else "等待 Capture 启动",
            captureRunning,
        )
    }

    private fun refreshTrafficSectionsAsync() {
        val refreshVersion = trafficRefreshVersion.incrementAndGet()
        val outputDir = File(filesDir, "rustprobe-output")
        eventsTextView?.text = "正在刷新最近流量..."
        domainsTextView?.text = "正在刷新域名 / IP / 端口聚合..."

        thread(name = "rustprobe-ui-traffic-refresh", isDaemon = true) {
            val forwardingEvents = readLastJsonObjects(File(outputDir, "forwarding-events.jsonl"), limit = 10)
            val flowEvents = readLastJsonObjects(File(outputDir, "flows.jsonl"), limit = 24)
            val objectEvents = readLastJsonObjects(File(outputDir, "objects.jsonl"), limit = 240)
            val aggregates = aggregateObjectEvents(objectEvents)

            val eventsText = buildString {
                if (forwardingEvents.isNotEmpty()) {
                    appendLine("最近 Forward 事件：")
                    forwardingEvents.forEach { event ->
                        appendLine(formatForwardingEvent(event))
                    }
                }

                if (flowEvents.isNotEmpty()) {
                    if (isNotEmpty()) appendLine()
                    appendLine("最近 Rust flow snapshot：")
                    flowEvents.takeLast(12).forEach { flow ->
                        appendLine(formatFlowEvent(flow))
                    }
                }

                if (isEmpty()) {
                    append("暂时还没有最近流量数据。请先启动监听，再触发一些网络活动。")
                }
            }

            val domainsText = buildString {
                if (aggregates.isEmpty()) {
                    appendLine("当前还没有可展示的聚合对象。")
                    appendLine("说明：")
                    appendLine("1. Forward 下目前主要是 forwarding 事件，不是完整 Rust 域名对象流。")
                    appendLine("2. Capture 下如果命中 DNS 或 TLS SNI，才会把域名写进 objects.jsonl。")
                    appendLine("3. 现在会按最新对象状态聚合展示域名、目的 IP 和目的端口。")
                    appendLine("4. URL 统计目前还没接进主链路。")
                } else {
                    appendLine("域名 Top：")
                    appendAggregateSection(this, aggregates.domains)
                    appendLine()
                    appendLine("目的 IP Top：")
                    appendAggregateSection(this, aggregates.ips)
                    appendLine()
                    appendLine("目的端口 Top：")
                    appendAggregateSection(this, aggregates.ports)
                }
            }

            runOnUiThread {
                if (trafficRefreshVersion.get() != refreshVersion) return@runOnUiThread
                eventsTextView?.text = eventsText
                domainsTextView?.text = domainsText
            }
        }
    }

    private fun updateAppListEnabledState() {
        filterEditText?.isEnabled = true
    }

    private fun updateSelectedAppsSummary() {
        val selected = selectedPackages.toList()
        selectedAppsTextView?.text = when (appSelectionMode) {
            UiSelectionMode.Global -> "当前选择：监听全部应用"
            UiSelectionMode.Single -> {
                val label = installedApps.firstOrNull { it.packageName in selected }?.appLabel
                if (label != null) {
                    "当前选择：单个应用 - $label"
                } else {
                    "当前选择：单个应用，请从下方点选一个 app"
                }
            }
            UiSelectionMode.Multiple -> buildString {
                append("已选应用数：")
                append(selected.size)
                if (selected.isEmpty()) {
                    append("，请从下方勾选多个 app")
                } else {
                    val labels = installedApps
                        .filter { selected.contains(it.packageName) }
                        .take(3)
                        .joinToString("、") { it.appLabel }
                    if (labels.isNotBlank()) {
                        append("，示例：")
                        append(labels)
                    }
                    if (selected.size > 3) {
                        append(" 等")
                    }
                }
            }
        }
    }

    private fun buildSelectionFromUi(): MonitoringSelection {
        val selected = selectedPackages.toList().sorted()
        return when (appSelectionMode) {
            UiSelectionMode.Global -> MonitoringSelection.Global
            UiSelectionMode.Single -> {
                val packageName = selected.firstOrNull()
                if (packageName != null) MonitoringSelection.Single(packageName) else MonitoringSelection.Global
            }
            UiSelectionMode.Multiple -> {
                when (selected.size) {
                    0 -> MonitoringSelection.Global
                    1 -> MonitoringSelection.Single(selected.first())
                    else -> MonitoringSelection.Multiple(selected)
                }
            }
        }
    }

    private fun syncAppsIntoRust(apps: List<InstalledAppInfo>): Boolean {
        return RustBridge.syncInstalledApps(apps)
    }

    private fun selectionSummary(selection: MonitoringSelection): String {
        return when (selection) {
            MonitoringSelection.Global -> "全局监听"
            is MonitoringSelection.Single -> "单应用(${selection.packageName})"
            is MonitoringSelection.Multiple -> "多应用(${selection.packageNames.size} 个)"
        }
    }

    private fun readLastJsonObjects(file: File, limit: Int): List<JSONObject> {
        if (!file.exists()) return emptyList()
        return runCatching {
            readLastLines(file, maxLines = limit * 6, maxBytes = TAIL_READ_BYTES)
                .asReversed()
                .asSequence()
                .filter { it.isNotBlank() }
                .take(limit)
                .map { JSONObject(it) }
                .toList()
                .asReversed()
        }.getOrElse { error ->
            Log.w("RustProbeMainActivity", "Failed to read ${file.name}", error)
            emptyList()
        }
    }

    private fun readLastLines(file: File, maxLines: Int, maxBytes: Int): List<String> {
        if (!file.exists()) return emptyList()
        RandomAccessFile(file, "r").use { raf ->
            val length = raf.length()
            if (length <= 0L) return emptyList()
            val start = (length - maxBytes).coerceAtLeast(0L)
            raf.seek(start)
            val bytes = ByteArray((length - start).toInt())
            raf.readFully(bytes)
            var text = String(bytes, StandardCharsets.UTF_8)
            if (start > 0L) {
                val firstNewline = text.indexOf('\n')
                if (firstNewline >= 0) {
                    text = text.substring(firstNewline + 1)
                }
            }
            val lines = text
                .lineSequence()
                .filter { it.isNotBlank() }
                .toList()
            return if (lines.size <= maxLines) lines else lines.takeLast(maxLines)
        }
    }

    private fun formatForwardingEvent(event: JSONObject): String {
        val ts = event.optString("timestamp", "-")
        val source = event.optString("source", "-")
        val transport = event.optString("transport", "-")
        val host = event.optString("host", "-")
        val port = event.optInt("port", -1)
        val appPackage = event.optString("app_package", "")
        val appSuffix = if (appPackage.isNotBlank()) " app=$appPackage" else ""
        return "$ts $source $transport $host:$port$appSuffix"
    }

    private fun formatFlowEvent(event: JSONObject): String {
        val key = event.optJSONObject("key")
        val app = event.optJSONObject("app")
        val protocol = event.optString("protocol_hint")
            .takeIf { it.isNotBlank() }
            ?: key?.optString("protocol", "-")
            ?: "-"
        val srcAddr = key?.optString("src_addr", "-") ?: "-"
        val srcPort = key?.optInt("src_port", 0) ?: 0
        val dstAddr = key?.optString("dst_addr", "-") ?: "-"
        val dstPort = key?.optInt("dst_port", 0) ?: 0
        val packets = event.optLong("packets", 0)
        val bytes = event.optLong("payload_bytes", 0)
        val domain = event.optString("domain", "")
        val domainSource = event.optString("domain_source", "")
        val sni = event.optString("tls_server_name", "")
        val quicSni = event.optString("quic_server_name", "")
        val httpHost = event.optString("http_host", "")
        val dohCandidate = event.optBoolean("doh_candidate", false)
        val dotCandidate = event.optBoolean("dot_candidate", false)
        val http3Candidate = event.optBoolean("http3_candidate", false)
        val dnsCandidate = event.optBoolean("dns_candidate", false)
        val tlsCandidate = event.optBoolean("tls_candidate", false)
        val quicCandidate = event.optBoolean("quic_candidate", false)
        val quicInitialCandidate = event.optBoolean("quic_initial_candidate", false)
        val alpn = event.optJSONArray("application_protocols")
            ?.let { array ->
                buildList {
                    for (index in 0 until array.length()) {
                        val value = array.optString(index)
                        if (value.isNotBlank()) add(value)
                    }
                }
            }
            .orEmpty()
        val appName = app?.optString("package_name", "unattributed") ?: "unattributed"

        return buildString {
            append("$protocol $srcAddr:$srcPort -> $dstAddr:$dstPort")
            append(" packets=$packets bytes=$bytes")
            append(" app=$appName")
            if (domain.isNotBlank()) append(" domain=$domain")
            if (domainSource.isNotBlank()) append(" source=$domainSource")
            if (sni.isNotBlank()) append(" sni=$sni")
            if (quicSni.isNotBlank()) append(" quic-sni=$quicSni")
            if (httpHost.isNotBlank()) append(" host=$httpHost")
            if (alpn.isNotEmpty()) append(" alpn=${alpn.joinToString(",")}")
            if (dnsCandidate) append(" dns?")
            if (tlsCandidate) append(" tls?")
            if (quicCandidate) append(" quic?")
            if (quicInitialCandidate) append(" quic-initial?")
            if (dohCandidate) append(" doh?")
            if (dotCandidate) append(" dot?")
            if (http3Candidate) append(" h3?")
        }
    }

    private fun computeFlowCoverageStats(events: List<JSONObject>): FlowCoverageStats {
        if (events.isEmpty()) return FlowCoverageStats.EMPTY

        val latestByFlow = linkedMapOf<String, JSONObject>()
        events.forEach { event ->
            val key = event.optJSONObject("key") ?: return@forEach
            val flowId = listOf(
                key.optString("src_addr"),
                key.optInt("src_port"),
                key.optString("dst_addr"),
                key.optInt("dst_port"),
                key.optString("protocol"),
            ).joinToString("|")
            val lastSeen = event.optLong("last_seen_unix_ms", 0)
            val existing = latestByFlow[flowId]
            if (existing == null || lastSeen >= existing.optLong("last_seen_unix_ms", 0)) {
                latestByFlow[flowId] = event
            }
        }

        val protocolCounts = linkedMapOf<String, Int>()
        val domainSourceCounts = linkedMapOf<String, Int>()
        val alpnCounts = linkedMapOf<String, Int>()
        var attributedFlows = 0
        var domainFlows = 0
        var dnsCandidates = 0
        var tlsCandidates = 0
        var quicCandidates = 0
        var quicInitialCandidates = 0
        var dohCandidates = 0
        var dotCandidates = 0
        var http3Candidates = 0

        latestByFlow.values.forEach { event ->
            val protocol = event.optString("protocol_hint").ifBlank {
                event.optJSONObject("key")?.optString("protocol", "Unknown") ?: "Unknown"
            }
            protocolCounts[protocol] = (protocolCounts[protocol] ?: 0) + 1
            if (event.optJSONObject("app") != null) attributedFlows += 1
            if (event.optString("domain").isNotBlank()) domainFlows += 1
            val domainSource = event.optString("domain_source")
            if (domainSource.isNotBlank()) {
                domainSourceCounts[domainSource] = (domainSourceCounts[domainSource] ?: 0) + 1
            }
            if (event.optBoolean("dns_candidate", false)) dnsCandidates += 1
            if (event.optBoolean("tls_candidate", false)) tlsCandidates += 1
            if (event.optBoolean("quic_candidate", false)) quicCandidates += 1
            if (event.optBoolean("quic_initial_candidate", false)) quicInitialCandidates += 1
            if (event.optBoolean("doh_candidate", false)) dohCandidates += 1
            if (event.optBoolean("dot_candidate", false)) dotCandidates += 1
            if (event.optBoolean("http3_candidate", false)) http3Candidates += 1
            val protocols = event.optJSONArray("application_protocols")
            if (protocols != null) {
                for (index in 0 until protocols.length()) {
                    val value = protocols.optString(index)
                    if (value.isNotBlank()) {
                        alpnCounts[value] = (alpnCounts[value] ?: 0) + 1
                    }
                }
            }
        }

        return FlowCoverageStats(
            uniqueFlows = latestByFlow.size,
            attributedFlows = attributedFlows,
            domainFlows = domainFlows,
            dnsCandidates = dnsCandidates,
            tlsCandidates = tlsCandidates,
            quicCandidates = quicCandidates,
            quicInitialCandidates = quicInitialCandidates,
            dohCandidates = dohCandidates,
            dotCandidates = dotCandidates,
            http3Candidates = http3Candidates,
            protocolCounts = protocolCounts,
            domainSourceCounts = domainSourceCounts,
            alpnCounts = alpnCounts,
        )
    }

    private fun formatRate(part: Int, total: Int): String {
        if (total <= 0) return ""
        val ratio = (part * 100.0) / total.toDouble()
        return " (${String.format("%.1f", ratio)}%)"
    }

    private fun aggregateObjectEvents(events: List<JSONObject>): AggregatedObjects {
        val latestByObject = linkedMapOf<String, AggregateEntry>()
        events.forEach { event ->
            val key = event.optJSONObject("key") ?: return@forEach
            val kind = key.optString("kind")
            val value = key.optString("value")
            if (kind.isBlank() || value.isBlank()) return@forEach
            val hits = event.optLong("hits", 0)
            val bytes = event.optLong("bytes", 0)
            val lastSeen = event.optLong("last_seen_unix_ms", 0)
            val mapKey = "$kind::$value"
            val existing = latestByObject[mapKey]
            if (existing == null || lastSeen >= existing.lastSeenUnixMs) {
                latestByObject[mapKey] = AggregateEntry(
                    label = value,
                    hits = hits,
                    bytes = bytes,
                    lastSeenUnixMs = lastSeen,
                )
            }
        }

        fun topFor(kind: String): List<AggregateEntry> {
            return latestByObject
                .asSequence()
                .filter { (key, _) -> key.startsWith("$kind::") }
                .map { it.value }
                .sortedWith(
                    compareByDescending<AggregateEntry> { it.hits }
                        .thenByDescending { it.bytes }
                        .thenByDescending { it.lastSeenUnixMs },
                )
                .take(8)
                .toList()
        }

        return AggregatedObjects(
            domains = topFor("Domain"),
            ips = topFor("Ip"),
            ports = topFor("Port"),
        )
    }

    private fun appendAggregateSection(builder: StringBuilder, entries: List<AggregateEntry>) {
        if (entries.isEmpty()) {
            builder.appendLine("暂无数据")
            return
        }
        entries.forEach { entry ->
            builder.appendLine("${entry.label}  hits=${entry.hits} bytes=${entry.bytes}")
        }
    }

    private fun titleView(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 22f
            setTextColor(Color.parseColor("#171717"))
        }
    }

    private fun sectionTitle(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 16f
            setTextColor(Color.parseColor("#2C2C2C"))
            setPadding(0, dp(8), 0, dp(8))
        }
    }

    private fun bodyView(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 14f
            setTextColor(Color.parseColor("#4A4A4A"))
            setPadding(0, 0, 0, dp(8))
        }
    }

    private fun monoBlock(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 13f
            typeface = android.graphics.Typeface.MONOSPACE
            setTextColor(Color.parseColor("#1F1F1F"))
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setTextIsSelectable(true)
        }
    }

    private fun chipView(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 13f
            setPadding(dp(12), dp(8), dp(12), dp(8))
            setTextColor(Color.WHITE)
            background = roundedDrawable("#5C6B73", "#5C6B73", radius = 18f)
        }
    }

    private fun updateStatusChip(text: String, active: Boolean) {
        statusChipTextView?.text = text
        statusChipTextView?.background = if (active) {
            roundedDrawable("#1F7A53", "#1F7A53", radius = 18f)
        } else {
            roundedDrawable("#7A5E2E", "#7A5E2E", radius = 18f)
        }
    }

    private fun evaluateAutoRefresh() {
        if (manuallyStopped) {
            stopAutoRefresh()
            return
        }
        if (isListeningActive()) {
            startAutoRefresh()
        } else {
            stopAutoRefresh()
        }
    }

    private fun startAutoRefresh() {
        if (autoRefreshEnabled) return
        autoRefreshEnabled = true
        handler.removeCallbacks(refreshTicker)
        handler.post(refreshTicker)
    }

    private fun stopAutoRefresh() {
        autoRefreshEnabled = false
        handler.removeCallbacks(refreshTicker)
    }

    private fun isListeningActive(): Boolean {
        val captureRunning = runCatching { RustBridge.nativeIsCaptureRunning() }.getOrDefault(false)
        if (captureRunning) return true

        val activityManager = getSystemService(ActivityManager::class.java) ?: return false
        @Suppress("DEPRECATION")
        return activityManager.getRunningServices(Int.MAX_VALUE)
            .any { it.service.className == RustProbeVpnService::class.java.name }
    }

    private fun roundedDrawable(fill: String, stroke: String, radius: Float = 16f): GradientDrawable {
        return GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = dp(radius.toInt()).toFloat()
            setColor(Color.parseColor(fill))
            setStroke(dp(1), Color.parseColor(stroke))
        }
    }

    private fun cardParams(bottom: Int = 0): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply {
            bottomMargin = dp(bottom)
        }
    }

    private fun marginParams(bottom: Int = 0, end: Int = 0): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        ).apply {
            bottomMargin = dp(bottom)
            marginEnd = dp(end)
        }
    }

    private fun dp(value: Int): Int {
        return (value * resources.displayMetrics.density).toInt()
    }

    companion object {
        private const val REFRESH_INTERVAL_MS = 3_000L
        private const val TAIL_READ_BYTES = 256 * 1024
    }

    private data class AggregatedObjects(
        val domains: List<AggregateEntry>,
        val ips: List<AggregateEntry>,
        val ports: List<AggregateEntry>,
    ) {
        fun isEmpty(): Boolean {
            return domains.isEmpty() && ips.isEmpty() && ports.isEmpty()
        }
    }

    private data class AggregateEntry(
        val label: String,
        val hits: Long,
        val bytes: Long,
        val lastSeenUnixMs: Long,
    )

    private data class FlowCoverageStats(
        val uniqueFlows: Int,
        val attributedFlows: Int,
        val domainFlows: Int,
        val dnsCandidates: Int,
        val tlsCandidates: Int,
        val quicCandidates: Int,
        val quicInitialCandidates: Int,
        val dohCandidates: Int,
        val dotCandidates: Int,
        val http3Candidates: Int,
        val protocolCounts: Map<String, Int>,
        val domainSourceCounts: Map<String, Int>,
        val alpnCounts: Map<String, Int>,
    ) {
        fun protocolSummary(): String {
            return summarize(protocolCounts)
        }

        fun domainSourceSummary(): String {
            return summarize(domainSourceCounts)
        }

        fun alpnSummary(): String {
            return summarize(alpnCounts, limit = 4)
        }

        private fun summarize(values: Map<String, Int>, limit: Int = 6): String {
            if (values.isEmpty()) return "暂无"
            return values.entries
                .sortedByDescending { it.value }
                .take(limit)
                .joinToString(" | ") { "${it.key}=${it.value}" }
        }

        companion object {
            val EMPTY = FlowCoverageStats(
                uniqueFlows = 0,
                attributedFlows = 0,
                domainFlows = 0,
                dnsCandidates = 0,
                tlsCandidates = 0,
                quicCandidates = 0,
                quicInitialCandidates = 0,
                dohCandidates = 0,
                dotCandidates = 0,
                http3Candidates = 0,
                protocolCounts = emptyMap(),
                domainSourceCounts = emptyMap(),
                alpnCounts = emptyMap(),
            )
        }
    }

    private enum class UiSelectionMode {
        Global,
        Single,
        Multiple,
    }
}
