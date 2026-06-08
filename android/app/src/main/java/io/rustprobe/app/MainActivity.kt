package io.rustprobe.app

import android.app.Activity
import android.app.ActivityManager
import android.app.AlertDialog
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.os.StatFs
import android.os.SystemClock
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.util.Log
import android.view.Gravity
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
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.math.max

class MainActivity : ComponentActivity() {
    private val handler = Handler(Looper.getMainLooper())
    private var autoRefreshEnabled = false
    private var manuallyStopped = false
    private var serviceStartInFlight = false
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
    private val summaryRefreshVersion = AtomicInteger(0)
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
    private var analysisSummaryTextView: TextView? = null
    private var eventsTextView: TextView? = null
    private var analysisEventsTextView: TextView? = null
    private var domainsTextView: TextView? = null
    private var appInsightsTextView: TextView? = null
    private var trafficChartView: MiniLineChartView? = null
    private var trafficPulseTextView: TextView? = null
    private var trafficBucketsTextView: TextView? = null
    private var protocolBarsContainer: LinearLayout? = null
    private var ipBarsContainer: LinearLayout? = null
    private var domainBarsContainer: LinearLayout? = null
    private var portBarsContainer: LinearLayout? = null
    private var appCardsContainer: LinearLayout? = null
    private var appDetailTitleTextView: TextView? = null
    private var appDetailSummaryTextView: TextView? = null
    private var appDetailChartView: MiniLineChartView? = null
    private var appDetailObjectsTextView: TextView? = null
    private var flowModeHintTextView: TextView? = null
    private var statusChipTextView: TextView? = null
    private var modeMetricValueTextView: TextView? = null
    private var packetsMetricValueTextView: TextView? = null
    private var flowsMetricValueTextView: TextView? = null
    private var appsMetricValueTextView: TextView? = null
    private var memoryMetricValueTextView: TextView? = null
    private var overviewMemoryGaugeView: GaugeView? = null
    private var overviewTemperatureGaugeView: GaugeView? = null
    private var overviewPowerGaugeView: GaugeView? = null
    private var overviewSpeedChartView: MiniLineChartView? = null
    private var overviewMemoryDetailTextView: TextView? = null
    private var overviewTemperatureDetailTextView: TextView? = null
    private var overviewSpeedDetailTextView: TextView? = null
    private var overviewPowerDetailTextView: TextView? = null
    private var overviewStorageDetailTextView: TextView? = null
    private var overviewNetworkDetailTextView: TextView? = null
    private var overviewSensorLogTextView: TextView? = null
    private var overviewScreen: View? = null
    private var monitorScreen: View? = null
    private var analysisScreen: View? = null
    private var overviewNavButton: Button? = null
    private var monitorNavButton: Button? = null
    private var analysisNavButton: Button? = null
    private var summaryPanel: View? = null
    private var eventsPanel: View? = null
    private var domainsPanel: View? = null
    private var appPanel: View? = null
    private var summaryTabButton: Button? = null
    private var eventsTabButton: Button? = null
    private var domainsTabButton: Button? = null
    private var appsTabButton: Button? = null
    private var latestAnalyticsSnapshot: JSONObject? = null
    private var selectedAnalyticsScope: String? = null
    private val sensorLogLines = ArrayDeque<String>()
    private val speedHistory = ArrayDeque<Long>()
    private val sensorLastLogAt = linkedMapOf<Int, Long>()
    private var sensorManager: SensorManager? = null
    private var sensorEventListener: SensorEventListener? = null
    private var trafficSampleAtMs: Long = 0L
    private var trafficSampleRxBytes: Long = 0L
    private var trafficSampleTxBytes: Long = 0L
    private var lastSmoothedSpeedBytesPerSecond: Double = 0.0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val rustLoaded = runCatching { RustBridge.nativeIsCaptureRunning() }
            .onFailure { Log.e("RustProbeMainActivity", "Rust bridge check failed", it) }
            .getOrDefault(false)

        installedApps = AppInventory.listInstalledApps(this)
            .filterNot { it.packageName == packageName }
        syncAppsIntoRust(installedApps)
        setupSensorMonitoring()

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
        registerSensorListeners()
        evaluateAutoRefresh()
    }

    override fun onPause() {
        unregisterSensorListeners()
        stopAutoRefresh()
        super.onPause()
    }

    private fun buildContentView(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#070B11"))
            setPadding(dp(12), dp(12), dp(12), dp(12))
        }

        val heroCard = cardLayout(fill = "#0B1017", stroke = "#203040").apply {
            addView(eyebrowView("RUSTPROBE / ANDROID"))
            addView(titleView("网络监听工作台"))
            addView(bodyView("把总览、监听和分析拆成三个界面。少滚动，少回想，直接进入当前任务。"))
            statusChipTextView = chipView("等待状态...")
            addView(statusChipTextView)
            statusTextView = bodyView("等待刷新运行状态...")
            addView(statusTextView)
        }
        root.addView(heroCard, cardParams(bottom = 12))

        val metricsColumn = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        val metricsRowTop = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        val metricsRowBottom = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        val modeMetric = metricCard("模式")
        modeMetricValueTextView = modeMetric.second
        val packetMetric = metricCard("数据包")
        packetsMetricValueTextView = packetMetric.second
        val flowMetric = metricCard("Flow")
        flowsMetricValueTextView = flowMetric.second
        val appMetric = metricCard("应用")
        appsMetricValueTextView = appMetric.second
        val memoryMetric = metricCard("内存")
        memoryMetricValueTextView = memoryMetric.second
        metricsRowTop.addView(modeMetric.first, weightedCardParams())
        metricsRowTop.addView(packetMetric.first, weightedCardParams(start = 8))
        metricsRowTop.addView(flowMetric.first, weightedCardParams(start = 8))
        metricsRowBottom.addView(appMetric.first, weightedCardParams())
        metricsRowBottom.addView(memoryMetric.first, weightedCardParams(start = 8))
        metricsColumn.addView(metricsRowTop)
        metricsColumn.addView(metricsRowBottom, cardParams(bottom = 0).apply { topMargin = dp(8) })
        root.addView(metricsColumn, cardParams(bottom = 12))

        val navBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = roundedDrawable("#0F151E", "#203040", radius = 22f)
            setPadding(dp(6), dp(6), dp(6), dp(6))
        }
        overviewNavButton = navButton("总览") { showScreen("overview") }
        monitorNavButton = navButton("监听") { showScreen("monitor") }
        analysisNavButton = navButton("分析") { showScreen("analysis") }
        navBar.addView(overviewNavButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        navBar.addView(monitorNavButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        navBar.addView(analysisNavButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(navBar, cardParams(bottom = 12))

        overviewScreen = buildOverviewScreen()
        monitorScreen = buildMonitorScreen()
        analysisScreen = buildAnalysisScreen()

        val screenHost = FrameLayout(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                0,
                1f,
            )
        }
        screenHost.addView(overviewScreen, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        screenHost.addView(monitorScreen, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        screenHost.addView(analysisScreen, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
        root.addView(screenHost)

        showScreen("overview")
        showPanel("summary")
        return root
    }

    private fun cardLayout(fill: String = "#FFFDF8", stroke: String = "#DED8CC"): LinearLayout {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(16), dp(16), dp(16), dp(16))
            background = roundedDrawable(fill, stroke)
        }
    }

    private fun buildOverviewScreen(): View {
        val scroll = ScrollView(this).apply { isFillViewport = true }
        val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(
            column,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        val dialRowTop = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val dialRowBottom = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val memoryGaugeCard = buildGaugeCard(
            title = "表盘一 / 内存占用率",
            accent = "#3DD9FF",
            thresholdPercent = 82f,
        )
        overviewMemoryGaugeView = memoryGaugeCard.gauge
        overviewMemoryDetailTextView = memoryGaugeCard.detail
        dialRowTop.addView(memoryGaugeCard.card, weightedCardParams())

        val temperatureGaugeCard = buildGaugeCard(
            title = "表盘二 / 当前热度",
            accent = "#FF8A3D",
            thresholdPercent = 84f,
        )
        overviewTemperatureGaugeView = temperatureGaugeCard.gauge
        overviewTemperatureDetailTextView = temperatureGaugeCard.detail
        dialRowTop.addView(temperatureGaugeCard.card, weightedCardParams(start = 8))

        val waveCard = buildWaveCard("表盘三 / 实时网速")
        overviewSpeedChartView = waveCard.chart
        overviewSpeedDetailTextView = waveCard.detail
        dialRowBottom.addView(waveCard.card, weightedCardParams())

        val powerGaugeCard = buildGaugeCard(
            title = "表盘四 / 动力输出",
            accent = "#2FE6C6",
            thresholdPercent = 78f,
        )
        overviewPowerGaugeView = powerGaugeCard.gauge
        overviewPowerDetailTextView = powerGaugeCard.detail
        dialRowBottom.addView(powerGaugeCard.card, weightedCardParams(start = 8))
        column.addView(dialRowTop, cardParams(bottom = 12))
        column.addView(dialRowBottom, cardParams(bottom = 12))

        val systemCard = cardLayout(fill = "#0F151E", stroke = "#223243").apply {
            addView(sectionTitleDark("系统态监控"))
            overviewStorageDetailTextView = bodyViewDark("正在采样存储占用...")
            addView(overviewStorageDetailTextView)
            overviewNetworkDetailTextView = bodyViewDark("正在采样网络质量与信号...")
            addView(overviewNetworkDetailTextView)
        }
        column.addView(systemCard, cardParams(bottom = 12))

        val overviewSummaryCard = cardLayout(fill = "#0F151E", stroke = "#223243").apply {
            addView(sectionTitleDark("运行总览"))
            summaryTextView = monoBlockDark("正在生成运行摘要...")
            addView(summaryTextView)
        }
        column.addView(overviewSummaryCard, cardParams(bottom = 12))

        val sensorCard = cardLayout(fill = "#101821", stroke = "#223243").apply {
            addView(sectionTitleDark("底部滚动日志 / 实时传感器"))
            addView(bodyViewDark("陀螺仪、气压、光强会持续滚动刷新。没有对应硬件时会明确标出来。"))
            overviewSensorLogTextView = monoBlockDark("等待传感器数据...")
            addView(panelScroll(overviewSensorLogTextView!!))
        }
        column.addView(sensorCard, cardParams(bottom = 12))

        val overviewGuideCard = cardLayout(fill = "#101821", stroke = "#223243").apply {
            addView(sectionTitleDark("导航提示"))
            addView(bodyViewDark("在“监听”中配置模式、筛选 app 和启停服务。"))
            addView(bodyViewDark("在“分析”中看趋势、协议分布、IP / 域名 / 端口排行。"))
        }
        column.addView(overviewGuideCard)
        return scroll
    }

    private fun buildGaugeCard(
        title: String,
        accent: String,
        thresholdPercent: Float,
    ): GaugeCardBinding {
        val detail = bodyViewDark("等待数据...")
        val gauge = GaugeView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(150),
            ).apply { bottomMargin = dp(10) }
            setAccentColor(accent)
            setThresholdPercent(thresholdPercent)
        }
        val card = cardLayout(fill = "#0F151E", stroke = "#223243").apply {
            addView(sectionTitleDark(title))
            addView(gauge)
            addView(detail)
        }
        return GaugeCardBinding(card, gauge, detail)
    }

    private fun buildWaveCard(title: String): WaveCardBinding {
        val detail = bodyViewDark("等待网速采样...")
        val chart = MiniLineChartView(this).apply {
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                dp(150),
            ).apply { bottomMargin = dp(10) }
        }
        val card = cardLayout(fill = "#0F151E", stroke = "#223243").apply {
            addView(sectionTitleDark(title))
            addView(chart)
            addView(detail)
        }
        return WaveCardBinding(card, chart, detail)
    }

    private fun setupSensorMonitoring() {
        sensorManager = getSystemService(SensorManager::class.java)
        sensorEventListener = object : SensorEventListener {
            override fun onSensorChanged(event: SensorEvent) {
                val sensor = event.sensor ?: return
                val now = SystemClock.elapsedRealtime()
                val last = sensorLastLogAt[sensor.type] ?: 0L
                if (now - last < 900L) return
                sensorLastLogAt[sensor.type] = now
                val line = when (sensor.type) {
                    Sensor.TYPE_GYROSCOPE -> {
                        "gyro ${formatClockTime(now)}  x=${event.values.getOrNull(0)?.let { String.format("%.2f", it) }}  y=${event.values.getOrNull(1)?.let { String.format("%.2f", it) }}  z=${event.values.getOrNull(2)?.let { String.format("%.2f", it) }}"
                    }
                    Sensor.TYPE_PRESSURE -> {
                        "baro ${formatClockTime(now)}  ${event.values.getOrNull(0)?.let { String.format("%.1f hPa", it) }}"
                    }
                    Sensor.TYPE_LIGHT -> {
                        "light ${formatClockTime(now)}  ${event.values.getOrNull(0)?.let { String.format("%.1f lx", it) }}"
                    }
                    else -> return
                }
                appendSensorLog(line)
            }

            override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) = Unit
        }

        appendSensorLog(
            buildString {
                append("sensors armed  ")
                append(sensorAvailability("gyro", Sensor.TYPE_GYROSCOPE))
                append("  ")
                append(sensorAvailability("baro", Sensor.TYPE_PRESSURE))
                append("  ")
                append(sensorAvailability("light", Sensor.TYPE_LIGHT))
            },
        )
    }

    private fun registerSensorListeners() {
        val manager = sensorManager ?: return
        val listener = sensorEventListener ?: return
        listOf(
            Sensor.TYPE_GYROSCOPE,
            Sensor.TYPE_PRESSURE,
            Sensor.TYPE_LIGHT,
        ).forEach { type ->
            manager.getDefaultSensor(type)?.let { sensor ->
                manager.registerListener(listener, sensor, SensorManager.SENSOR_DELAY_NORMAL)
            }
        }
    }

    private fun unregisterSensorListeners() {
        val manager = sensorManager ?: return
        val listener = sensorEventListener ?: return
        manager.unregisterListener(listener)
    }

    private fun appendSensorLog(line: String) {
        if (sensorLogLines.size >= 24) {
            sensorLogLines.removeFirst()
        }
        sensorLogLines.addLast(line)
        overviewSensorLogTextView?.text = sensorLogLines.joinToString("\n")
    }

    private fun sensorAvailability(label: String, type: Int): String {
        return if (sensorManager?.getDefaultSensor(type) != null) {
            "$label=online"
        } else {
            "$label=na"
        }
    }

    private fun buildMonitorScreen(): View {
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            overScrollMode = View.OVER_SCROLL_IF_CONTENT_SCROLLS
        }
        val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(
            column,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        val configCard = cardLayout(fill = "#0F151E", stroke = "#223243").apply {
            addView(sectionTitleDark("监听模式"))
            val modeGroup = RadioGroup(this@MainActivity).apply {
                orientation = RadioGroup.HORIZONTAL
            }
            forwardingRadio = RadioButton(this@MainActivity).apply {
                text = "Forward"
                id = View.generateViewId()
                isChecked = MonitoringPreferences.mode == MonitoringMode.Forward
                setTextColor(Color.parseColor("#DDEEFF"))
            }
            captureRadio = RadioButton(this@MainActivity).apply {
                text = "Capture"
                id = View.generateViewId()
                isChecked = MonitoringPreferences.mode == MonitoringMode.Capture
                setTextColor(Color.parseColor("#DDEEFF"))
            }
            modeGroup.addView(forwardingRadio)
            modeGroup.addView(captureRadio)
            addView(modeGroup)

            flowModeHintTextView = bodyViewDark("")
            addView(flowModeHintTextView)

            addView(sectionTitleDark("应用选择"))
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
                setTextColor(Color.parseColor("#DDEEFF"))
            }
            singleSelectionRadio = RadioButton(this@MainActivity).apply {
                text = "单个应用"
                id = View.generateViewId()
                isChecked = appSelectionMode == UiSelectionMode.Single
                setTextColor(Color.parseColor("#DDEEFF"))
            }
            multipleSelectionRadio = RadioButton(this@MainActivity).apply {
                text = "多个应用"
                id = View.generateViewId()
                isChecked = appSelectionMode == UiSelectionMode.Multiple
                setTextColor(Color.parseColor("#DDEEFF"))
            }
            selectionModeGroup.addView(globalSelectionRadio)
            selectionModeGroup.addView(singleSelectionRadio)
            selectionModeGroup.addView(multipleSelectionRadio)
            addView(selectionModeGroup)

            selectedAppsTextView = bodyViewDark("")
            addView(selectedAppsTextView)
            addView(
                actionButton("选择应用") {
                    openAppPickerDialog()
                }.apply {
                    layoutParams = marginParams(bottom = 8)
                },
            )

            addView(sectionTitleDark("操作"))
            addView(buttonRow())
        }
        column.addView(configCard, cardParams(bottom = 12))

        val eventCard = cardLayout(fill = "#101821", stroke = "#223243").apply {
            addView(sectionTitleDark("最近流量"))
            addView(bodyViewDark("这里优先用于排查链路是否工作，能快速看到 Forward 事件和 Rust flow 快照。"))
            eventsTextView = monoBlockDark("等待最近流量数据...")
            addView(panelScroll(eventsTextView!!))
        }
        column.addView(eventCard)
        return scroll
    }

    private fun buildAnalysisScreen(): View {
        val scroll = ScrollView(this).apply { isFillViewport = true }
        val column = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(
            column,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        val contentCard = cardLayout(fill = "#0F151E", stroke = "#223243").apply {
            addView(sectionTitleDark("分析工作台"))
            addView(bodyViewDark("把应用走势、协议分布和对象排行聚在一起，减少上下跳读。"))

            val tabRow = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
            }
            summaryTabButton = tabButton("概览") { showPanel("summary") }
            eventsTabButton = tabButton("流量") { showPanel("events") }
            domainsTabButton = tabButton("对象") { showPanel("domains") }
            appsTabButton = tabButton("应用") { showPanel("apps") }
            tabRow.addView(summaryTabButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            tabRow.addView(eventsTabButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(6) })
            tabRow.addView(domainsTabButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(6) })
            tabRow.addView(appsTabButton, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply { marginStart = dp(6) })
            addView(tabRow, marginParams(bottom = 10))

            val panelHost = FrameLayout(this@MainActivity).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    0,
                    1f,
                )
                minimumHeight = dp(340)
            }

            analysisSummaryTextView = monoBlockDark("正在生成应用分析概览...")
            summaryPanel = panelScroll(analysisSummaryTextView!!)
            eventsPanel = buildTrafficPanel()
            domainsPanel = buildObjectsPanel()
            appPanel = buildAppsPanel()

            panelHost.addView(summaryPanel, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            panelHost.addView(eventsPanel, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            panelHost.addView(domainsPanel, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            panelHost.addView(appPanel, FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.MATCH_PARENT))
            addView(panelHost)
        }
        column.addView(
            contentCard,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )
        return scroll
    }

    private fun buildTrafficPanel(): View {
        val scroll = ScrollView(this)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(4), dp(4), dp(4), dp(4))
        }
        scroll.addView(
            column,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        val chartCard = cardLayout(fill = "#0F1218", stroke = "#2A3442").apply {
            addView(sectionTitleDark("流量走势"))
            trafficPulseTextView = bodyViewDark("等待流量 pulse...")
            addView(trafficPulseTextView)
            trafficChartView = MiniLineChartView(this@MainActivity).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    dp(180),
                ).apply { bottomMargin = dp(10) }
            }
            addView(trafficChartView)
            trafficBucketsTextView = monoBlockDark("等待时间桶明细...")
            addView(trafficBucketsTextView)
        }
        column.addView(chartCard, cardParams(bottom = 12))

        val flowCard = cardLayout(fill = "#121720", stroke = "#273240").apply {
            addView(sectionTitleDark("最近流量"))
            analysisEventsTextView = monoBlockDark("等待按应用的最近流量...")
            addView(analysisEventsTextView)
        }
        column.addView(flowCard)
        return scroll
    }

    private fun buildObjectsPanel(): View {
        val scroll = ScrollView(this)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(4), dp(4), dp(4), dp(4))
        }
        scroll.addView(
            column,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        val overviewCard = cardLayout(fill = "#0F1218", stroke = "#2A3442").apply {
            addView(sectionTitleDark("对象分析"))
            domainsTextView = bodyViewDark("等待对象总览...")
            addView(domainsTextView)
        }
        column.addView(overviewCard, cardParams(bottom = 12))

        protocolBarsContainer = rankSectionCard(column, "协议分布")
        ipBarsContainer = rankSectionCard(column, "IP 访问排行")
        domainBarsContainer = rankSectionCard(column, "域名访问排行")
        portBarsContainer = rankSectionCard(column, "端口访问排行")
        return scroll
    }

    private fun buildAppsPanel(): View {
        val scroll = ScrollView(this)
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(4), dp(4), dp(4), dp(4))
        }
        scroll.addView(
            column,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        val listCard = cardLayout(fill = "#0F1218", stroke = "#2A3442").apply {
            addView(sectionTitleDark("应用列表"))
            addView(bodyViewDark("点击某个应用卡片，查看它的流量体量、趋势和对象摘要。"))
            appCardsContainer = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.VERTICAL
            }
            addView(appCardsContainer)
        }
        column.addView(listCard, cardParams(bottom = 12))

        val detailCard = cardLayout(fill = "#121720", stroke = "#273240").apply {
            appDetailTitleTextView = titleViewDark("应用详情")
            addView(appDetailTitleTextView)
            appDetailSummaryTextView = bodyViewDark("等待应用详情...")
            addView(appDetailSummaryTextView)
            appDetailChartView = MiniLineChartView(this@MainActivity).apply {
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    dp(160),
                ).apply { bottomMargin = dp(10) }
            }
            addView(appDetailChartView)
            appDetailObjectsTextView = monoBlockDark("等待协议 / 对象摘要...")
            addView(appDetailObjectsTextView)
        }
        column.addView(detailCard)
        return scroll
    }

    private fun rankSectionCard(parent: LinearLayout, title: String): LinearLayout {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }
        val card = cardLayout(fill = "#121720", stroke = "#273240").apply {
            addView(sectionTitleDark(title))
            addView(container)
        }
        parent.addView(card, cardParams(bottom = 12))
        return container
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
                        if (serviceStartInFlight) return@actionButton
                        applyCurrentSelection()
                        requestVpnAndStart()
                    })
                    addView(actionButton("停止监听") {
                        serviceStartInFlight = false
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
            background = roundedDrawable("#132334", "#2FE6C6")
            setTextColor(Color.parseColor("#DFFFF8"))
            setOnClickListener { onClick() }
            layoutParams = marginParams(end = 8)
        }
    }

    private fun navButton(label: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            text = label
            isAllCaps = false
            minHeight = dp(42)
            setOnClickListener { onClick() }
            setTextColor(Color.parseColor("#86A5BC"))
            background = roundedDrawable("#00000000", "#00000000", radius = 18f)
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
            background = roundedDrawable("#0B1118", "#223243")
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

    private fun metricCard(label: String): Pair<View, TextView> {
        val valueView = TextView(this).apply {
            text = "--"
            textSize = 18f
            setTextColor(Color.parseColor("#E7F8FF"))
            typeface = Typeface.create("monospace", Typeface.BOLD)
        }
        val card = cardLayout(fill = "#101821", stroke = "#223243").apply {
            minimumHeight = dp(86)
            addView(
                TextView(this@MainActivity).apply {
                    text = label
                    textSize = 12f
                    setTextColor(Color.parseColor("#6F8BA0"))
                },
            )
            addView(valueView)
        }
        return card to valueView
    }

    private fun showPanel(panel: String) {
        summaryPanel?.visibility = if (panel == "summary") View.VISIBLE else View.GONE
        eventsPanel?.visibility = if (panel == "events") View.VISIBLE else View.GONE
        domainsPanel?.visibility = if (panel == "domains") View.VISIBLE else View.GONE
        appPanel?.visibility = if (panel == "apps") View.VISIBLE else View.GONE
        styleTab(summaryTabButton, panel == "summary")
        styleTab(eventsTabButton, panel == "events")
        styleTab(domainsTabButton, panel == "domains")
        styleTab(appsTabButton, panel == "apps")
    }

    private fun showScreen(screen: String) {
        overviewScreen?.visibility = if (screen == "overview") View.VISIBLE else View.GONE
        monitorScreen?.visibility = if (screen == "monitor") View.VISIBLE else View.GONE
        analysisScreen?.visibility = if (screen == "analysis") View.VISIBLE else View.GONE
        styleNavButton(overviewNavButton, screen == "overview")
        styleNavButton(monitorNavButton, screen == "monitor")
        styleNavButton(analysisNavButton, screen == "analysis")
    }

    private fun styleTab(button: Button?, selected: Boolean) {
        button ?: return
        if (selected) {
            button.setTextColor(Color.parseColor("#071016"))
            button.background = roundedDrawable("#2FE6C6", "#2FE6C6")
        } else {
            button.setTextColor(Color.parseColor("#88A6BB"))
            button.background = roundedDrawable("#101821", "#223243")
        }
    }

    private fun styleNavButton(button: Button?, selected: Boolean) {
        button ?: return
        if (selected) {
            button.setTextColor(Color.parseColor("#061015"))
            button.background = roundedDrawable("#3DD9FF", "#3DD9FF", radius = 18f)
        } else {
            button.setTextColor(Color.parseColor("#86A5BC"))
            button.background = roundedDrawable("#00000000", "#00000000", radius = 18f)
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
            setBackgroundColor(Color.parseColor("#0A0F15"))
        }
        val searchInput = EditText(this).apply {
            hint = "搜索应用名或包名，比如 夸克 / quark"
            inputType = InputType.TYPE_CLASS_TEXT
            setPadding(dp(12), dp(10), dp(12), dp(10))
            setTextColor(Color.parseColor("#E7F8FF"))
            setHintTextColor(Color.parseColor("#6F8BA0"))
            background = roundedDrawable("#121A23", "#223243")
        }
        val hintView = bodyViewDark("").apply {
            setPadding(0, dp(8), 0, dp(8))
        }
        val listScroll = ScrollView(this).apply {
            background = roundedDrawable("#0F151E", "#223243")
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
                    setTextColor(Color.parseColor("#E7F8FF"))
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
                checkBox.buttonTintList = android.content.res.ColorStateList.valueOf(Color.parseColor("#2FE6C6"))
                listContainer.addView(checkBox)
                listContainer.addView(
                    bodyViewDark(app.packageName).apply {
                        textSize = 12f
                        setTextColor(Color.parseColor("#6F8BA0"))
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
        val monitoringMode = if (forwardingRadio?.isChecked == true) {
            MonitoringMode.Forward
        } else {
            MonitoringMode.Capture
        }
        val selection = buildSelectionFromUi()
        MonitoringPreferences.mode = monitoringMode
        MonitoringPreferences.selection = selection
        val syncedApps = syncAppsIntoRust(installedApps)
        val syncedSelection = RustBridge.setMonitoringSelection(selection)

        statusTextView?.text = buildString {
            append("已应用配置：模式=")
            append(monitoringMode.name)
            append("，选择=")
            append(selectionSummary(selection))
            append("，syncInstalledApps=")
            append(syncedApps)
            append("，syncSelection=")
            append(syncedSelection)
            append("。如果 VPN 已经在运行，请点“启动/重启监听”让新配置生效。")
        }
        updateStatusChip("${monitoringMode.name} 已配置", false)
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
        if (serviceStartInFlight) return
        serviceStartInFlight = true
        manuallyStopped = false
        runCatching {
            val intent = Intent(this, RustProbeVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        }.onSuccess {
            statusTextView?.text = "已请求启动 VPN 监听服务。正在等待运行态刷新..."
            updateStatusChip("监听启动中", false)
            startAutoRefresh()
            handler.postDelayed(
                {
                    serviceStartInFlight = false
                    refreshDashboard()
                },
                800L,
            )
        }.onFailure { error ->
            serviceStartInFlight = false
            statusTextView?.text = "启动 VPN 监听失败：${error.message}"
            updateStatusChip("启动失败", false)
            Log.e("RustProbeMainActivity", "Failed to start VPN service", error)
        }
    }

    private fun refreshDashboard() {
        flowModeHintTextView?.text = when {
            forwardingRadio?.isChecked == true ->
                "Forward：走共享 Rust 解析链，默认动作是捕获全部并继续转发。"
            else ->
                "Capture：也走共享 Rust 解析链，默认偏向抓取，后面可以扩成自定义转发策略。"
        }

        updateSelectedAppsSummary()
        refreshSummary()
        refreshTrafficSectionsAsync()
        evaluateAutoRefresh()
    }

    private fun refreshSummary() {
        val refreshVersion = summaryRefreshVersion.incrementAndGet()
        summaryTextView?.text = "正在刷新摘要统计..."

        thread(name = "rustprobe-ui-summary-refresh", isDaemon = true) {
            val packetsSeen = runCatching { RustBridge.nativePacketsSeen() }.getOrDefault(-1)
            val captureRunning = runCatching { RustBridge.nativeIsCaptureRunning() }.getOrDefault(false)
            val selectionSummary = runCatching { RustBridge.nativeSelectionSummary() }.getOrDefault("unavailable")
            val attribution = runCatching { RustBridge.attributionStats() }.getOrNull()
            val systemMemory = captureSystemMemorySnapshot()
            val systemDashboard = captureSystemDashboardSnapshot(systemMemory)
            val outputDir = File(filesDir, "rustprobe-output")
            val flowCoverage = computeFlowCoverageStats(
                readLastJsonObjects(File(outputDir, "flows.jsonl"), limit = 160),
            )
            val analyticsSnapshot = readLastJsonObjects(File(outputDir, "analytics.jsonl"), limit = 1)
                .lastOrNull()

            val summaryText = buildString {
                appendLine("模式: ${MonitoringPreferences.mode.name}")
                appendLine(
                    if (MonitoringPreferences.mode == MonitoringMode.Forward) {
                        "共享解析链运行中（Forward 默认转发）: $captureRunning"
                    } else {
                        "共享解析链运行中（Capture 默认抓取）: $captureRunning"
                    },
                )
                appendLine("系统内存占用: ${systemMemory.summaryLine()}")
                appendLine("系统内存详情: used=${formatBytes(systemMemory.usedBytes)} / total=${formatBytes(systemMemory.totalBytes)} / avail=${formatBytes(systemMemory.availableBytes)}")
                appendLine("系统内存阈值: ${formatBytes(systemMemory.thresholdBytes)}  lowMemory=${if (systemMemory.lowMemory) "yes" else "no"}")
                appendLine("电池热度: ${systemDashboard.temperatureSummary}")
                appendLine("动力输出: ${systemDashboard.powerSummary}")
                appendLine("实时网速: ${systemDashboard.speedSummary}")
                appendLine("存储占用: ${systemDashboard.storageSummary}")
                appendLine("网络质量: ${systemDashboard.networkSummary}")
                appendLine("已见数据包数: $packetsSeen")
                appendLine("当前选择: $selectionSummary")
                appendLine("输出目录: ${outputDir.absolutePath}")
                appendLine("forwarding-events.jsonl: ${File(outputDir, "forwarding-events.jsonl").length()} bytes")
                appendLine("flows.jsonl: ${File(outputDir, "flows.jsonl").length()} bytes")
                appendLine("objects.jsonl: ${File(outputDir, "objects.jsonl").length()} bytes")
                appendLine("analytics.jsonl: ${File(outputDir, "analytics.jsonl").length()} bytes")
                if (attribution != null) {
                    appendLine("已跟踪应用数: ${attribution.trackedApps}")
                    appendLine("缓存 flow owner 数: ${attribution.cachedFlowOwners}")
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
                appendLine()
                append(buildAnalyticsSummary(analyticsSnapshot))
            }

            runOnUiThread {
                if (summaryRefreshVersion.get() != refreshVersion) return@runOnUiThread
                summaryTextView?.text = summaryText
                analysisSummaryTextView?.text = buildAnalyticsSummary(analyticsSnapshot)
                modeMetricValueTextView?.text = MonitoringPreferences.mode.name
                packetsMetricValueTextView?.text = compactCount(packetsSeen.toLong())
                flowsMetricValueTextView?.text = compactCount(flowCoverage.uniqueFlows.toLong())
                appsMetricValueTextView?.text = compactCount((attribution?.trackedApps ?: 0).toLong())
                memoryMetricValueTextView?.text = systemMemory.metricLabel()
                updateOverviewDashboard(systemDashboard)
                updateStatusChip(
                    if (captureRunning) "监听活跃中"
                    else if (MonitoringPreferences.mode == MonitoringMode.Forward) "Forward 运行中"
                    else "等待 Capture 启动",
                    captureRunning,
                )
            }
        }
    }

    private fun refreshTrafficSectionsAsync() {
        val refreshVersion = trafficRefreshVersion.incrementAndGet()
        val outputDir = File(filesDir, "rustprobe-output")
        eventsTextView?.text = "正在刷新最近流量..."
        analysisEventsTextView?.text = "正在刷新流量图表..."
        domainsTextView?.text = "正在刷新对象聚合..."
        trafficPulseTextView?.text = "正在刷新流量 pulse..."
        trafficBucketsTextView?.text = "正在刷新时间桶..."

        thread(name = "rustprobe-ui-traffic-refresh", isDaemon = true) {
            val forwardingEvents = readLastJsonObjects(File(outputDir, "forwarding-events.jsonl"), limit = 10)
            val flowEvents = readLastJsonObjects(File(outputDir, "flows.jsonl"), limit = 24)
            val objectEvents = readLastJsonObjects(File(outputDir, "objects.jsonl"), limit = 240)
            val analyticsSnapshot = readLastJsonObjects(File(outputDir, "analytics.jsonl"), limit = 1)
                .lastOrNull()
            val aggregates = aggregateObjectEvents(objectEvents)

            val eventsText = buildString {
                append(buildTrafficWorkbench(analyticsSnapshot))
                appendLine()
                appendLine()
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
                append(buildObjectWorkbench(analyticsSnapshot))
                appendLine()
                appendLine()
                if (aggregates.isEmpty()) {
                    appendLine("当前还没有可展示的聚合对象。")
                    appendLine("说明：")
                    appendLine("1. 只有镜像解析真正收到包后，才会把域名对象写进 objects.jsonl。")
                    appendLine("2. 如果命中 DNS、TLS SNI、QUIC Initial SNI 或 HTTP Host，就会逐步看到域名聚合。")
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

            val appText = buildAppWorkbench(analyticsSnapshot)

            runOnUiThread {
                if (trafficRefreshVersion.get() != refreshVersion) return@runOnUiThread
                latestAnalyticsSnapshot = analyticsSnapshot
                eventsTextView?.text = eventsText
                analysisEventsTextView?.text = eventsText
                domainsTextView?.text = domainsText
                appInsightsTextView?.text = appText
                updateTrafficPanel(analyticsSnapshot)
                updateObjectsPanel(analyticsSnapshot, aggregates)
                updateAppsPanel(analyticsSnapshot)
            }
        }
    }

    private fun updateTrafficPanel(snapshot: JSONObject?) {
        if (snapshot == null) {
            trafficChartView?.submit(emptyList())
            trafficPulseTextView?.text = "等待 analytics.jsonl..."
            trafficBucketsTextView?.text = "暂无时间桶数据"
            return
        }
        val target = selectedScopeSnapshot(snapshot)
        val series = extractSeries(target.optJSONArray("traffic_series"))
        trafficChartView?.submit(series.map { it.bytes })
        trafficPulseTextView?.text = buildString {
            append(target.optString("scope", "All Monitored Apps"))
            append("  ")
            append(renderTrafficSeriesSummary(target.optJSONArray("traffic_series")))
        }
        trafficBucketsTextView?.text = renderTrafficSeriesTable(target.optJSONArray("traffic_series"))
    }

    private fun updateObjectsPanel(snapshot: JSONObject?, aggregates: AggregatedObjects) {
        if (snapshot == null) {
            domainsTextView?.text = "等待对象分析数据..."
            populateRankBars(protocolBarsContainer, null, "#3DD9FF", "暂无协议分布")
            populateRankBars(ipBarsContainer, null, "#1EF2A6", "暂无 IP 排行")
            populateRankBars(domainBarsContainer, null, "#FF8A3D", "暂无域名排行")
            populateRankBars(portBarsContainer, null, "#FFD54A", "暂无端口排行")
            return
        }

        val target = selectedScopeSnapshot(snapshot)
        domainsTextView?.text = buildString {
            append(target.optString("scope", "All Monitored Apps"))
            append("  ")
            append(formatBytesDetailed(target.optLong("total_bytes", 0)))
            append("  packets=")
            append(compactCount(target.optLong("total_packets", 0)))
            append("  flows=")
            append(target.optInt("active_flows", 0))
            if (!aggregates.isEmpty()) {
                append("\n最近对象镜像已同步，可和 app 聚合交叉查看。")
            }
        }
        populateRankBars(protocolBarsContainer, target.optJSONArray("protocol_distribution"), "#3DD9FF", "暂无协议分布")
        populateRankBars(ipBarsContainer, target.optJSONArray("top_ips"), "#1EF2A6", "暂无 IP 排行")
        populateRankBars(domainBarsContainer, target.optJSONArray("top_domains"), "#FF8A3D", "暂无域名排行")
        populateRankBars(portBarsContainer, target.optJSONArray("top_ports"), "#FFD54A", "暂无端口排行")
    }

    private fun updateAppsPanel(snapshot: JSONObject?) {
        val container = appCardsContainer ?: return
        container.removeAllViews()
        if (snapshot == null) {
            container.addView(emptyStateText("等待按应用分析数据..."))
            renderAppDetail(null)
            return
        }

        val apps = snapshot.optJSONArray("apps")
        if (apps == null || apps.length() == 0) {
            container.addView(emptyStateText("当前还没有可点击的应用卡片。"))
            renderAppDetail(null)
            return
        }

        if (selectedAnalyticsScope.isNullOrBlank()) {
            selectedAnalyticsScope = apps.optJSONObject(0)?.optString("scope")
        }

        val totalBytes = snapshot.optJSONObject("overall")?.optLong("total_bytes", 0) ?: 0L
        for (index in 0 until apps.length()) {
            val item = apps.optJSONObject(index) ?: continue
            val scope = item.optString("scope", "Unknown App")
            val selected = scope == selectedAnalyticsScope
            container.addView(appCardView(item, totalBytes, selected))
        }

        renderAppDetail(findScopeSnapshot(snapshot, selectedAnalyticsScope) ?: apps.optJSONObject(0))
    }

    private fun appCardView(item: JSONObject, totalBytes: Long, selected: Boolean): View {
        val scope = item.optString("scope", "Unknown App")
        val card = cardLayout(
            fill = if (selected) "#132334" else "#0D141C",
            stroke = if (selected) "#2FE6C6" else "#223243",
        ).apply {
            val header = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            header.addView(
                TextView(this@MainActivity).apply {
                    text = scope
                    textSize = 16f
                    typeface = Typeface.create("monospace", Typeface.BOLD)
                    setTextColor(Color.parseColor("#E7F8FF"))
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                },
            )
            header.addView(
                chipView(if (selected) "已选中" else "点击查看").apply {
                    background = roundedDrawable(
                        if (selected) "#2FE6C6" else "#16212B",
                        if (selected) "#2FE6C6" else "#223243",
                        radius = 18f,
                    )
                    setTextColor(Color.parseColor(if (selected) "#061015" else "#8EC9D8"))
                },
            )
            addView(header, marginParams(bottom = 6))
            addView(bodyViewDark("流量 ${formatBytes(item.optLong("total_bytes", 0))}    packets ${compactCount(item.optLong("total_packets", 0))}    flows ${item.optInt("active_flows", 0)}"))
            addView(barRow(scope, item.optLong("total_bytes", 0), max(totalBytes, 1L), "#2FE6C6"))
            addView(bodyViewDark("协议 ${renderRankedMetricsInline(item.optJSONArray("protocol_distribution"), 3)}"))
        }
        card.setOnClickListener {
            selectedAnalyticsScope = scope
            updateAppsPanel(latestAnalyticsSnapshot)
            updateTrafficPanel(latestAnalyticsSnapshot)
            updateObjectsPanel(latestAnalyticsSnapshot, AggregatedObjects(emptyList(), emptyList(), emptyList()))
        }
        return card.apply {
            layoutParams = cardParams(bottom = 10)
        }
    }

    private fun renderAppDetail(item: JSONObject?) {
        if (item == null) {
            appDetailTitleTextView?.text = "应用详情"
            appDetailSummaryTextView?.text = "请选择一个应用卡片查看详情。"
            appDetailChartView?.submit(emptyList())
            appDetailObjectsTextView?.text = "暂无协议 / 对象摘要"
            return
        }

        val topDomain = item.optJSONArray("top_domains")?.optJSONObject(0)?.optString("label").orEmpty()
        val topIp = item.optJSONArray("top_ips")?.optJSONObject(0)?.optString("label").orEmpty()
        val topPort = item.optJSONArray("top_ports")?.optJSONObject(0)?.optString("label").orEmpty()
        appDetailTitleTextView?.text = item.optString("scope", "应用详情")
        appDetailSummaryTextView?.text = buildString {
            append("总量 ")
            append(formatBytesDetailed(item.optLong("total_bytes", 0)))
            append("    packets ")
            append(compactCount(item.optLong("total_packets", 0)))
            append("    flows ")
            append(item.optInt("active_flows", 0))
        }
        appDetailChartView?.submit(extractSeries(item.optJSONArray("traffic_series")).map { it.bytes })
        appDetailObjectsTextView?.text = buildString {
            appendLine("协议   ${renderRankedMetricsInline(item.optJSONArray("protocol_distribution"), 4)}")
            appendLine("域名   ${if (topDomain.isBlank()) "暂无" else topDomain}")
            appendLine("IP     ${if (topIp.isBlank()) "暂无" else topIp}")
            append("端口   ${if (topPort.isBlank()) "暂无" else topPort}")
        }
    }

    private fun populateRankBars(
        container: LinearLayout?,
        array: org.json.JSONArray?,
        accentColor: String,
        emptyText: String,
    ) {
        container ?: return
        container.removeAllViews()
        if (array == null || array.length() == 0) {
            container.addView(emptyStateText(emptyText))
            return
        }

        val items = buildList {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                add(
                    RankedMetric(
                        label = item.optString("label", "-"),
                        bytes = item.optLong("bytes", 0),
                        hits = item.optLong("hits", 0),
                    ),
                )
            }
        }
        val maxBytes = items.maxOfOrNull { it.bytes }?.coerceAtLeast(1L) ?: 1L
        items.forEachIndexed { index, item ->
            container.addView(rankRowView(index + 1, item, maxBytes, accentColor))
        }
    }

    private fun rankRowView(rank: Int, item: RankedMetric, maxBytes: Long, accentColor: String): View {
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = roundedDrawable("#0B1118", "#1B2834")
            setPadding(dp(12), dp(10), dp(12), dp(10))

            val header = LinearLayout(this@MainActivity).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            header.addView(
                TextView(this@MainActivity).apply {
                    text = String.format("%02d", rank)
                    textSize = 12f
                    typeface = Typeface.create("monospace", Typeface.BOLD)
                    setTextColor(Color.parseColor("#6F8BA0"))
                    layoutParams = LinearLayout.LayoutParams(dp(28), LinearLayout.LayoutParams.WRAP_CONTENT)
                },
            )
            header.addView(
                TextView(this@MainActivity).apply {
                    text = item.label
                    textSize = 14f
                    maxLines = 1
                    setTextColor(Color.parseColor("#E7F8FF"))
                    layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                },
            )
            header.addView(
                TextView(this@MainActivity).apply {
                    text = formatBytes(item.bytes)
                    textSize = 12f
                    setTextColor(Color.parseColor("#8EC9D8"))
                },
            )
            addView(header)
            addView(barRow(item.label, item.bytes, maxBytes, accentColor))
            addView(
                TextView(this@MainActivity).apply {
                    text = "hits ${compactCount(item.hits)}    ${formatBytesDetailed(item.bytes)}"
                    textSize = 12f
                    typeface = Typeface.MONOSPACE
                    setTextColor(Color.parseColor("#6F8BA0"))
                    setPadding(0, dp(6), 0, 0)
                },
            )
            layoutParams = cardParams(bottom = 10)
        }
    }

    private fun barRow(label: String, value: Long, maxValue: Long, accentColor: String): View {
        val ratio = (value.toFloat() / maxValue.coerceAtLeast(1L).toFloat()).coerceIn(0.06f, 1f)
        return LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dp(8), 0, 0)
            addView(
                View(this@MainActivity).apply {
                    background = roundedDrawable(accentColor, accentColor, radius = 10f)
                    layoutParams = LinearLayout.LayoutParams(0, dp(8), ratio)
                },
            )
            addView(
                View(this@MainActivity).apply {
                    background = roundedDrawable("#17222D", "#17222D", radius = 10f)
                    layoutParams = LinearLayout.LayoutParams(0, dp(8), 1f - ratio).apply {
                        marginStart = dp(4)
                    }
                },
            )
        }.apply {
            contentDescription = "$label ${formatBytes(value)}"
        }
    }

    private fun emptyStateText(text: String): TextView {
        return bodyViewDark(text).apply {
            setPadding(dp(4), dp(4), dp(4), dp(4))
        }
    }

    private fun selectedScopeSnapshot(snapshot: JSONObject): JSONObject {
        return findScopeSnapshot(snapshot, selectedAnalyticsScope) ?: selectAnalyticsScope(snapshot)
    }

    private fun findScopeSnapshot(snapshot: JSONObject, scope: String?): JSONObject? {
        if (scope.isNullOrBlank()) return null
        val apps = snapshot.optJSONArray("apps") ?: return null
        for (index in 0 until apps.length()) {
            val item = apps.optJSONObject(index) ?: continue
            if (item.optString("scope") == scope) {
                return item
            }
        }
        return null
    }

    private fun extractSeries(series: org.json.JSONArray?): List<TrafficPoint> {
        if (series == null || series.length() == 0) return emptyList()
        return buildList {
            for (index in 0 until series.length()) {
                val item = series.optJSONObject(index) ?: continue
                add(
                    TrafficPoint(
                        bucketStartUnixMs = item.optLong("bucket_start_unix_ms", 0),
                        bytes = item.optLong("bytes", 0),
                        packets = item.optLong("packets", 0),
                    ),
                )
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
            val skippedLines = mutableListOf<String>()
            val parsed = readLastLines(file, maxLines = limit * 8, maxBytes = TAIL_READ_BYTES)
                .asReversed()
                .asSequence()
                .filter { it.isNotBlank() }
                .mapNotNull { line ->
                    runCatching { JSONObject(line) }
                        .onFailure {
                            if (skippedLines.size < 3) {
                                skippedLines += line.take(220)
                            }
                        }
                        .getOrNull()
                }
                .take(limit)
                .toList()
                .asReversed()
            if (skippedLines.isNotEmpty()) {
                Log.w(
                    "RustProbeMainActivity",
                    "Skipped ${skippedLines.size} malformed json lines from ${file.name}: ${skippedLines.joinToString(" || ")}",
                )
            }
            parsed
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

    private fun buildAnalyticsSummary(snapshot: JSONObject?): String {
        if (snapshot == null) {
            return "应用分析: 暂无 analytics.jsonl 数据。启动监听并产生真实流量后，这里会显示按应用的总量、走势和协议分布。"
        }

        val overall = snapshot.optJSONObject("overall")
        val apps = snapshot.optJSONArray("apps")
        val bucketSizeMs = snapshot.optLong("bucket_size_ms", 0)
        val bucketCount = snapshot.optInt("bucket_count", 0)
        val totalBytes = overall?.optLong("total_bytes", 0L) ?: 0L
        val totalPackets = overall?.optLong("total_packets", 0L) ?: 0L

        return buildString {
            appendLine("应用分析窗口")
            appendLine("window  ${bucketCount} x ${bucketSizeMs / 1000}s")
            appendLine("traffic ${formatBytesDetailed(totalBytes)}")
            appendLine("packets $totalPackets")
            appendLine("trend   ${renderTrafficSeries(overall?.optJSONArray("traffic_series"))}")
            appendLine("pulse   ${renderTrafficSeriesSummary(overall?.optJSONArray("traffic_series"))}")
            appendLine("proto   ${renderRankedMetricsInline(overall?.optJSONArray("protocol_distribution"), 5)}")
            appendLine()
            appendLine("Top App")
            if (apps == null || apps.length() == 0) {
                appendLine("暂无按应用统计")
            } else {
                val max = minOf(4, apps.length())
                for (index in 0 until max) {
                    val item = apps.optJSONObject(index) ?: continue
                    appendLine(
                        "${index + 1}. ${item.optString("scope", "-")}  ${miniBar(item.optLong("total_bytes", 0), totalBytes)}  ${formatBytes(item.optLong("total_bytes", 0))}  flow=${item.optInt("active_flows", 0)}",
                    )
                }
            }
        }.trimEnd()
    }

    private fun buildObjectWorkbench(snapshot: JSONObject?): String {
        if (snapshot == null) {
            return "应用分析详情: 暂无数据。"
        }

        val target = selectAnalyticsScope(snapshot)
        return buildString {
            appendLine("对象分析 / ${target.optString("scope", "All Monitored Apps")}")
            appendLine("traffic  ${formatBytesDetailed(target.optLong("total_bytes", 0))}")
            appendLine("packets  ${target.optLong("total_packets", 0)}")
            appendLine("flows    ${target.optInt("active_flows", 0)}")
            appendLine()
            appendLine("协议分布")
            appendLine(renderRankedMetricsBlock(target.optJSONArray("protocol_distribution")))
            appendLine()
            appendLine("IP 访问排行")
            appendLine(renderRankedMetricsBlock(target.optJSONArray("top_ips")))
            appendLine()
            appendLine("域名访问排行")
            appendLine(renderRankedMetricsBlock(target.optJSONArray("top_domains")))
            appendLine()
            appendLine("端口访问排行")
            appendLine(renderRankedMetricsBlock(target.optJSONArray("top_ports")))
        }.trimEnd()
    }

    private fun buildTrafficWorkbench(snapshot: JSONObject?): String {
        if (snapshot == null) return "流量视图: 暂无 analytics.jsonl 数据。"
        val target = selectAnalyticsScope(snapshot)
        return buildString {
            appendLine("流量视图 / ${target.optString("scope", "All Monitored Apps")}")
            appendLine("走势  ${renderTrafficSeries(target.optJSONArray("traffic_series"))}")
            appendLine("概况  ${renderTrafficSeriesSummary(target.optJSONArray("traffic_series"))}")
            appendLine("明细")
            appendLine(renderTrafficSeriesTable(target.optJSONArray("traffic_series")))
        }.trimEnd()
    }

    private fun buildAppWorkbench(snapshot: JSONObject?): String {
        if (snapshot == null) return "应用视图: 暂无 analytics.jsonl 数据。"
        val apps = snapshot.optJSONArray("apps")
        val overall = snapshot.optJSONObject("overall")
        val totalBytes = overall?.optLong("total_bytes", 0) ?: 0L
        return buildString {
            appendLine("应用排行")
            if (apps == null || apps.length() == 0) {
                appendLine("暂无按应用统计")
            } else {
                val max = minOf(8, apps.length())
                for (index in 0 until max) {
                    val item = apps.optJSONObject(index) ?: continue
                    appendLine(
                        "${index + 1}. ${item.optString("scope", "-")}",
                    )
                    appendLine("   traffic ${miniBar(item.optLong("total_bytes", 0), totalBytes)} ${formatBytesDetailed(item.optLong("total_bytes", 0))}")
                    appendLine("   packets ${compactCount(item.optLong("total_packets", 0))}   flows ${item.optInt("active_flows", 0)}")
                    appendLine("   proto   ${renderRankedMetricsInline(item.optJSONArray("protocol_distribution"), 3)}")
                    val topDomain = item.optJSONArray("top_domains")?.optJSONObject(0)?.optString("label").orEmpty()
                    if (topDomain.isNotBlank()) {
                        appendLine("   domain  $topDomain")
                    }
                }
            }
        }.trimEnd()
    }

    private fun selectAnalyticsScope(snapshot: JSONObject): JSONObject {
        val overall = snapshot.optJSONObject("overall") ?: JSONObject()
        val apps = snapshot.optJSONArray("apps") ?: return overall
        val selection = MonitoringPreferences.selection
        if (selection is MonitoringSelection.Single) {
            for (index in 0 until apps.length()) {
                val item = apps.optJSONObject(index) ?: continue
                val app = item.optJSONObject("app") ?: continue
                if (app.optString("package_name") == selection.packageName) {
                    return item
                }
            }
        }
        return overall
    }

    private fun renderTrafficSeries(series: org.json.JSONArray?): String {
        if (series == null || series.length() == 0) return "暂无"
        val values = buildList {
            for (index in 0 until series.length()) {
                val item = series.optJSONObject(index) ?: continue
                add(item.optLong("bytes", 0))
            }
        }
        if (values.isEmpty()) return "暂无"

        val max = values.maxOrNull()?.coerceAtLeast(1L) ?: 1L
        return values.takeLast(18).joinToString("") { value ->
            when {
                value <= 0L -> "·"
                value * 8 >= max * 7 -> "█"
                value * 8 >= max * 6 -> "▇"
                value * 8 >= max * 5 -> "▆"
                value * 8 >= max * 4 -> "▅"
                value * 8 >= max * 3 -> "▄"
                value * 8 >= max * 2 -> "▃"
                value * 8 >= max -> "▂"
                else -> "▁"
            }
        }
    }

    private fun renderTrafficSeriesSummary(series: org.json.JSONArray?): String {
        if (series == null || series.length() == 0) return "暂无"
        val values = buildList {
            for (index in 0 until series.length()) {
                val item = series.optJSONObject(index) ?: continue
                add(item.optLong("bytes", 0))
            }
        }
        if (values.isEmpty()) return "暂无"
        val latest = values.lastOrNull() ?: 0L
        val peak = values.maxOrNull() ?: 0L
        val total = values.sum()
        return "latest=${formatBytesDetailed(latest)} peak=${formatBytesDetailed(peak)} bucketsTotal=${formatBytesDetailed(total)}"
    }

    private fun renderTrafficSeriesTable(series: org.json.JSONArray?): String {
        if (series == null || series.length() == 0) return "暂无"
        val rows = buildList {
            val start = (series.length() - 8).coerceAtLeast(0)
            for (index in start until series.length()) {
                val item = series.optJSONObject(index) ?: continue
                val bucketStart = item.optLong("bucket_start_unix_ms", 0)
                val bytes = item.optLong("bytes", 0)
                val packets = item.optLong("packets", 0)
                add("${formatBucketTime(bucketStart)}  ${formatBytesDetailed(bytes)}  packets=$packets")
            }
        }
        return if (rows.isEmpty()) "暂无" else rows.joinToString("\n")
    }

    private fun renderRankedMetricsInline(array: org.json.JSONArray?, limit: Int): String {
        if (array == null || array.length() == 0) return "暂无"
        return buildList {
            val max = minOf(limit, array.length())
            for (index in 0 until max) {
                val item = array.optJSONObject(index) ?: continue
                add("${item.optString("label", "-")}=${formatBytesDetailed(item.optLong("bytes", 0))}")
            }
        }.joinToString(" | ")
    }

    private fun renderRankedMetricsBlock(array: org.json.JSONArray?): String {
        if (array == null || array.length() == 0) return "暂无"
        val maxBytes = buildList {
            for (index in 0 until array.length()) {
                add(array.optJSONObject(index)?.optLong("bytes", 0) ?: 0L)
            }
        }.maxOrNull()?.coerceAtLeast(1L) ?: 1L

        return buildString {
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val bytes = item.optLong("bytes", 0)
                val rank = index + 1
                append(rank)
                append(". ")
                append(item.optString("label", "-"))
                append('\n')
                append("   ")
                append(miniBar(bytes, maxBytes))
                append("  ")
                append(formatBytesDetailed(bytes))
                append("  hits=")
                append(item.optLong("hits", 0))
                append('\n')
            }
        }.trimEnd()
    }

    private fun miniBar(value: Long, max: Long): String {
        val safeMax = max.coerceAtLeast(1L)
        val width = ((value * 10) / safeMax).toInt().coerceIn(1, 10)
        return "█".repeat(width) + "░".repeat((10 - width).coerceAtLeast(0))
    }

    private fun formatBytes(bytes: Long): String {
        val value = bytes.toDouble()
        return when {
            value >= 1024 * 1024 * 1024 -> String.format("%.2f GB", value / (1024 * 1024 * 1024))
            value >= 1024 * 1024 -> String.format("%.2f MB", value / (1024 * 1024))
            value >= 1024 -> String.format("%.2f KB", value / 1024)
            else -> "$bytes B"
        }
    }

    private fun formatBytesDetailed(bytes: Long): String {
        val kb = bytes / 1024.0
        val mb = bytes / (1024.0 * 1024.0)
        val gb = bytes / (1024.0 * 1024.0 * 1024.0)
        return buildString {
            append(formatBytes(bytes))
            append(" (")
            append(String.format("%.3f MB", mb))
            append(", ")
            append(String.format("%.5f GB", gb))
            append(", ")
            append(bytes)
            append(" B)")
        }
    }

    private fun captureSystemMemorySnapshot(): SystemMemorySnapshot {
        val activityManager = getSystemService(ActivityManager::class.java)
        val memoryInfo = ActivityManager.MemoryInfo()
        activityManager?.getMemoryInfo(memoryInfo)
        val totalBytes = memoryInfo.totalMem.coerceAtLeast(0L)
        val availableBytes = memoryInfo.availMem.coerceAtLeast(0L)
        val usedBytes = (totalBytes - availableBytes).coerceAtLeast(0L)
        val usedPercent = if (totalBytes > 0L) {
            (usedBytes * 100.0) / totalBytes.toDouble()
        } else {
            0.0
        }
        return SystemMemorySnapshot(
            totalBytes = totalBytes,
            availableBytes = availableBytes,
            usedBytes = usedBytes,
            thresholdBytes = memoryInfo.threshold.coerceAtLeast(0L),
            lowMemory = memoryInfo.lowMemory,
            usedPercent = usedPercent,
        )
    }

    private fun captureSystemDashboardSnapshot(memory: SystemMemorySnapshot): SystemDashboardSnapshot {
        val batteryIntent = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val batteryManager = getSystemService(BatteryManager::class.java)
        val rawTemp = batteryIntent?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE) ?: Int.MIN_VALUE
        val temperatureC = if (rawTemp != Int.MIN_VALUE) rawTemp / 10f else null
        val rawLevel = batteryIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val rawScale = batteryIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val batteryLevelPercent = if (rawLevel >= 0 && rawScale > 0) {
            (rawLevel * 100f) / rawScale.toFloat()
        } else {
            null
        }
        val batteryStatus = batteryIntent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val batteryPlugged = batteryIntent?.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) ?: -1
        val batteryHealth = batteryIntent?.getIntExtra(BatteryManager.EXTRA_HEALTH, -1) ?: -1
        val currentUa = batteryManager?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW)
            ?.takeIf { it != Int.MIN_VALUE }
        val statFs = StatFs(Environment.getDataDirectory().absolutePath)
        val storageTotal = statFs.totalBytes.coerceAtLeast(0L)
        val storageAvailable = statFs.availableBytes.coerceAtLeast(0L)
        val storageUsed = (storageTotal - storageAvailable).coerceAtLeast(0L)
        val storageUsedPercent = if (storageTotal > 0L) {
            (storageUsed * 100.0) / storageTotal.toDouble()
        } else {
            0.0
        }

        val now = SystemClock.elapsedRealtime()
        val rx = TrafficStats.getTotalRxBytes().coerceAtLeast(0L)
        val tx = TrafficStats.getTotalTxBytes().coerceAtLeast(0L)
        val elapsedMs = (now - trafficSampleAtMs).coerceAtLeast(1L)
        val rxBps = if (trafficSampleAtMs > 0L && now > trafficSampleAtMs) {
            (((rx - trafficSampleRxBytes).coerceAtLeast(0L)) * 1000.0 / elapsedMs.toDouble()).toLong()
        } else {
            0L
        }
        val txBps = if (trafficSampleAtMs > 0L && now > trafficSampleAtMs) {
            (((tx - trafficSampleTxBytes).coerceAtLeast(0L)) * 1000.0 / elapsedMs.toDouble()).toLong()
        } else {
            0L
        }
        val instantTotalBps = rxBps + txBps
        val smoothedTotalBps = if (trafficSampleAtMs > 0L) {
            ((lastSmoothedSpeedBytesPerSecond * 0.62) + (instantTotalBps * 0.38)).toLong()
        } else {
            instantTotalBps
        }
        lastSmoothedSpeedBytesPerSecond = smoothedTotalBps.toDouble()
        trafficSampleAtMs = now
        trafficSampleRxBytes = rx
        trafficSampleTxBytes = tx
        if (speedHistory.size >= 24) {
            speedHistory.removeFirst()
        }
        speedHistory.addLast(smoothedTotalBps)

        val connectivityManager = getSystemService(ConnectivityManager::class.java)
        val capabilities = connectivityManager?.getNetworkCapabilities(connectivityManager.activeNetwork)
        val wifiManager = applicationContext.getSystemService(WifiManager::class.java)
        val powerManager = getSystemService(PowerManager::class.java)
        val transportLabel = when {
            capabilities == null -> "offline"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "Other"
        }
        val signalSummary = if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
            @Suppress("DEPRECATION")
            val rssi = runCatching { wifiManager?.connectionInfo?.rssi }.getOrNull()
            if (rssi != null && rssi > -127) {
                val level = wifiSignalLevel(rssi)
                "RSSI ${rssi}dBm  L$level/5"
            } else {
                "Wi-Fi signal unavailable"
            }
        } else {
            val down = capabilities?.linkDownstreamBandwidthKbps ?: 0
            val up = capabilities?.linkUpstreamBandwidthKbps ?: 0
            if (down > 0 || up > 0) "bw ${down}↓/${up}↑ kbps" else "signal unavailable"
        }
        val currentAverageUa = batteryManager?.getIntProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_AVERAGE)
            ?.takeIf { it != Int.MIN_VALUE }
        val signedCurrentMa = (currentAverageUa ?: currentUa)?.let { it / 1000f }
        val isDischarging = signedCurrentMa?.let { it < 0f }
        val thermalStatus = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            powerManager?.currentThermalStatus ?: PowerManager.THERMAL_STATUS_NONE
        } else {
            PowerManager.THERMAL_STATUS_NONE
        }
        val networkFlags = buildList {
            if (capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true) add("validated")
            if (capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == true) add("unmetered")
            if (capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED) == true) add("not-congested")
        }
        val validated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val wifiSignalLevel = if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) {
            @Suppress("DEPRECATION")
            runCatching { wifiManager?.connectionInfo?.rssi }.getOrNull()?.takeIf { it > -127 }?.let { wifiSignalLevel(it) }
        } else {
            null
        }
        val qualityLabel = determineNetworkQuality(
            smoothedTotalBps = smoothedTotalBps,
            validated = validated,
            wifiLevel = wifiSignalLevel,
            capabilities = capabilities,
        )

        return SystemDashboardSnapshot(
            memory = memory,
            batteryLevelPercent = batteryLevelPercent,
            temperatureC = temperatureC,
            currentMa = signedCurrentMa?.let { kotlin.math.abs(it) },
            isDischarging = isDischarging,
            batteryStatus = batteryStatusLabel(batteryStatus, batteryPlugged),
            batteryHealth = batteryHealthLabel(batteryHealth),
            thermalStatus = thermalStatusLabel(thermalStatus),
            storageUsedBytes = storageUsed,
            storageTotalBytes = storageTotal,
            storageUsedPercent = storageUsedPercent,
            totalBytesPerSecond = smoothedTotalBps,
            instantaneousBytesPerSecond = instantTotalBps,
            rxBytesPerSecond = rxBps,
            txBytesPerSecond = txBps,
            trafficHistory = speedHistory.toList(),
            transportLabel = transportLabel,
            signalSummary = listOf(signalSummary, networkFlags.joinToString(" ")).filter { it.isNotBlank() }.joinToString("  "),
            qualityLabel = qualityLabel,
        )
    }

    private fun updateOverviewDashboard(snapshot: SystemDashboardSnapshot) {
        overviewMemoryGaugeView?.submit(snapshot.memory.usedPercent.toFloat(), snapshot.memory.metricLabel(), "RAM")
        overviewMemoryDetailTextView?.text = "used ${formatBytes(snapshot.memory.usedBytes)} / total ${formatBytes(snapshot.memory.totalBytes)}"

        val tempPercent = ((snapshot.temperatureC ?: 0f) / 50f * 100f).coerceIn(0f, 100f)
        overviewTemperatureGaugeView?.submit(
            tempPercent,
            snapshot.temperatureC?.let { String.format("%.1fC", it) } ?: "--",
            "TEMP",
        )
        overviewTemperatureDetailTextView?.text = snapshot.temperatureSummary

        overviewSpeedChartView?.submit(snapshot.trafficHistory)
        overviewSpeedDetailTextView?.text = snapshot.speedSummary

        val currentPercent = (((snapshot.currentMa ?: 0f) / 2500f) * 100f).coerceIn(0f, 100f)
        overviewPowerGaugeView?.submit(
            currentPercent,
            snapshot.currentMa?.let { String.format("%.0fmA", it) } ?: "--",
            "PWR",
        )
        overviewPowerDetailTextView?.text = snapshot.powerSummary

        overviewStorageDetailTextView?.text = snapshot.storageSummary
        overviewNetworkDetailTextView?.text = snapshot.networkSummary
    }

    private fun compactCount(value: Long): String {
        return when {
            value >= 1_000_000L -> String.format("%.1fM", value / 1_000_000.0)
            value >= 1_000L -> String.format("%.1fK", value / 1_000.0)
            else -> value.toString()
        }
    }

    private fun formatBucketTime(bucketStartUnixMs: Long): String {
        val totalSeconds = bucketStartUnixMs / 1000L
        val hours = (totalSeconds / 3600L) % 24L
        val minutes = (totalSeconds / 60L) % 60L
        val seconds = totalSeconds % 60L
        return String.format("%02d:%02d:%02d", hours, minutes, seconds)
    }

    private fun formatClockTime(elapsedRealtimeMs: Long): String {
        val totalSeconds = elapsedRealtimeMs / 1000L
        val minutes = (totalSeconds / 60L) % 60L
        val seconds = totalSeconds % 60L
        return String.format("%02d:%02d", minutes, seconds)
    }

    private fun wifiSignalLevel(rssi: Int): Int {
        return when {
            rssi >= -55 -> 5
            rssi >= -62 -> 4
            rssi >= -69 -> 3
            rssi >= -76 -> 2
            else -> 1
        }
    }

    private fun determineNetworkQuality(
        smoothedTotalBps: Long,
        validated: Boolean,
        wifiLevel: Int?,
        capabilities: NetworkCapabilities?,
    ): String {
        val throughputTier = when {
            smoothedTotalBps >= 8L * 1024 * 1024 -> 4
            smoothedTotalBps >= 2L * 1024 * 1024 -> 3
            smoothedTotalBps >= 512L * 1024 -> 2
            smoothedTotalBps > 0L -> 1
            else -> 0
        }
        val signalTier = when {
            wifiLevel != null -> wifiLevel - 1
            capabilities?.linkDownstreamBandwidthKbps ?: 0 >= 20_000 -> 4
            capabilities?.linkDownstreamBandwidthKbps ?: 0 >= 5_000 -> 3
            capabilities?.linkDownstreamBandwidthKbps ?: 0 >= 1_000 -> 2
            capabilities?.linkDownstreamBandwidthKbps ?: 0 > 0 -> 1
            else -> 0
        }
        val effectiveTier = if (wifiLevel != null || (capabilities?.linkDownstreamBandwidthKbps ?: 0) > 0) {
            minOf(throughputTier, signalTier)
        } else {
            throughputTier
        }
        return when {
            !validated && effectiveTier <= 1 -> "unstable"
            effectiveTier >= 4 && validated -> "excellent"
            effectiveTier >= 3 && validated -> "strong"
            effectiveTier >= 2 -> "steady"
            effectiveTier >= 1 -> "light"
            else -> "idle"
        }
    }

    private fun batteryStatusLabel(status: Int, plugged: Int): String {
        val base = when (status) {
            BatteryManager.BATTERY_STATUS_CHARGING -> "charging"
            BatteryManager.BATTERY_STATUS_DISCHARGING -> "discharging"
            BatteryManager.BATTERY_STATUS_FULL -> "full"
            BatteryManager.BATTERY_STATUS_NOT_CHARGING -> "idle"
            else -> "unknown"
        }
        val source = when (plugged) {
            BatteryManager.BATTERY_PLUGGED_USB -> "usb"
            BatteryManager.BATTERY_PLUGGED_AC -> "ac"
            BatteryManager.BATTERY_PLUGGED_WIRELESS -> "wireless"
            BatteryManager.BATTERY_PLUGGED_DOCK -> "dock"
            else -> ""
        }
        return listOf(base, source).filter { it.isNotBlank() }.joinToString(" ")
    }

    private fun batteryHealthLabel(health: Int): String {
        return when (health) {
            BatteryManager.BATTERY_HEALTH_GOOD -> "good"
            BatteryManager.BATTERY_HEALTH_OVERHEAT -> "overheat"
            BatteryManager.BATTERY_HEALTH_DEAD -> "dead"
            BatteryManager.BATTERY_HEALTH_OVER_VOLTAGE -> "over-voltage"
            BatteryManager.BATTERY_HEALTH_UNSPECIFIED_FAILURE -> "failure"
            BatteryManager.BATTERY_HEALTH_COLD -> "cold"
            else -> "unknown"
        }
    }

    private fun thermalStatusLabel(status: Int): String {
        return when (status) {
            PowerManager.THERMAL_STATUS_NONE -> "nominal"
            PowerManager.THERMAL_STATUS_LIGHT -> "light"
            PowerManager.THERMAL_STATUS_MODERATE -> "moderate"
            PowerManager.THERMAL_STATUS_SEVERE -> "severe"
            PowerManager.THERMAL_STATUS_CRITICAL -> "critical"
            PowerManager.THERMAL_STATUS_EMERGENCY -> "emergency"
            PowerManager.THERMAL_STATUS_SHUTDOWN -> "shutdown-risk"
            else -> "unknown"
        }
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
            textSize = 24f
            setTextColor(Color.parseColor("#17110C"))
        }
    }

    private fun eyebrowView(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 11f
            letterSpacing = 0.12f
            setTextColor(Color.parseColor("#8A5A34"))
            setPadding(0, 0, 0, dp(6))
        }
    }

    private fun sectionTitle(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 16f
            setTextColor(Color.parseColor("#2A211A"))
            typeface = Typeface.create("monospace", Typeface.BOLD)
            setPadding(0, dp(8), 0, dp(8))
        }
    }

    private fun bodyView(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 14f
            setTextColor(Color.parseColor("#5A4B3E"))
            setPadding(0, 0, 0, dp(8))
        }
    }

    private fun monoBlock(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#1F1F1F"))
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setTextIsSelectable(true)
        }
    }

    private fun titleViewDark(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 23f
            typeface = Typeface.create("monospace", Typeface.BOLD)
            setTextColor(Color.parseColor("#E7F8FF"))
            setPadding(0, 0, 0, dp(8))
        }
    }

    private fun sectionTitleDark(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 16f
            typeface = Typeface.create("monospace", Typeface.BOLD)
            setTextColor(Color.parseColor("#CFEFFF"))
            setPadding(0, dp(8), 0, dp(8))
        }
    }

    private fun bodyViewDark(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 14f
            setTextColor(Color.parseColor("#88A6BB"))
            setPadding(0, 0, 0, dp(8))
        }
    }

    private fun monoBlockDark(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(Color.parseColor("#DFF4FF"))
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setTextIsSelectable(true)
            background = roundedDrawable("#0A1016", "#1B2834")
        }
    }

    private fun chipView(text: String): TextView {
        return TextView(this).apply {
            this.text = text
            textSize = 13f
            setPadding(dp(12), dp(8), dp(12), dp(8))
            setTextColor(Color.parseColor("#DFF4FF"))
            typeface = Typeface.create("monospace", Typeface.BOLD)
            background = roundedDrawable("#132334", "#223243", radius = 18f)
        }
    }

    private fun weightedCardParams(start: Int = 0): LinearLayout.LayoutParams {
        return LinearLayout.LayoutParams(
            0,
            LinearLayout.LayoutParams.WRAP_CONTENT,
            1f,
        ).apply {
            marginStart = dp(start)
        }
    }

    private fun updateStatusChip(text: String, active: Boolean) {
        statusChipTextView?.text = text
        statusChipTextView?.background = if (active) {
            roundedDrawable("#1EF2A6", "#1EF2A6", radius = 18f)
        } else {
            roundedDrawable("#132334", "#223243", radius = 18f)
        }
        statusChipTextView?.setTextColor(
            Color.parseColor(
                if (active) "#061015" else "#DFF4FF",
            ),
        )
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

    private data class TrafficPoint(
        val bucketStartUnixMs: Long,
        val bytes: Long,
        val packets: Long,
    )

    private data class GaugeCardBinding(
        val card: View,
        val gauge: GaugeView,
        val detail: TextView,
    )

    private data class WaveCardBinding(
        val card: View,
        val chart: MiniLineChartView,
        val detail: TextView,
    )

    private data class SystemMemorySnapshot(
        val totalBytes: Long,
        val availableBytes: Long,
        val usedBytes: Long,
        val thresholdBytes: Long,
        val lowMemory: Boolean,
        val usedPercent: Double,
    ) {
        fun metricLabel(): String {
            return "${String.format("%.0f", usedPercent)}%"
        }

        fun summaryLine(): String {
            return "${formatStaticBytes(usedBytes)} / ${formatStaticBytes(totalBytes)} (${String.format("%.1f", usedPercent)}%)"
        }
    }

    private data class SystemDashboardSnapshot(
        val memory: SystemMemorySnapshot,
        val batteryLevelPercent: Float?,
        val temperatureC: Float?,
        val currentMa: Float?,
        val isDischarging: Boolean?,
        val batteryStatus: String,
        val batteryHealth: String,
        val thermalStatus: String,
        val storageUsedBytes: Long,
        val storageTotalBytes: Long,
        val storageUsedPercent: Double,
        val totalBytesPerSecond: Long,
        val instantaneousBytesPerSecond: Long,
        val rxBytesPerSecond: Long,
        val txBytesPerSecond: Long,
        val trafficHistory: List<Long>,
        val transportLabel: String,
        val signalSummary: String,
        val qualityLabel: String,
    ) {
        val temperatureSummary: String
            get() = buildString {
                append(
                    temperatureC?.let { String.format("%.1f C", it) } ?: "temperature unavailable",
                )
                batteryLevelPercent?.let {
                    append("  battery ")
                    append(String.format("%.0f%%", it))
                }
                append("  thermal ")
                append(thermalStatus)
                if ((temperatureC ?: 0f) >= 42f) {
                    append("  warning>42C")
                }
            }

        val powerSummary: String
            get() = currentMa?.let {
                buildString {
                    append(String.format("%.0f mA", it))
                    append("  ")
                    append(
                        when (isDischarging) {
                            true -> "discharging"
                            false -> "charging"
                            null -> batteryStatus
                        },
                    )
                    append("  health=")
                    append(batteryHealth)
                }
            }
                ?: "current unavailable  status=$batteryStatus  health=$batteryHealth"

        val speedSummary: String
            get() = "${formatStaticBytes(totalBytesPerSecond)}/s  rx=${formatStaticBytes(rxBytesPerSecond)}/s  tx=${formatStaticBytes(txBytesPerSecond)}/s  instant=${formatStaticBytes(instantaneousBytesPerSecond)}/s  quality=$qualityLabel"

        val storageSummary: String
            get() = "storage ${formatStaticBytes(storageUsedBytes)} / ${formatStaticBytes(storageTotalBytes)} (${String.format("%.1f", storageUsedPercent)}%)"

        val networkSummary: String
            get() = "$transportLabel  $signalSummary"
    }

    private data class RankedMetric(
        val label: String,
        val bytes: Long,
        val hits: Long,
    )

    companion object {
        private const val REFRESH_INTERVAL_MS = 3_000L
        private const val TAIL_READ_BYTES = 96 * 1024
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

private class MiniLineChartView(context: android.content.Context) : View(context) {
    private val gridPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#1D2B37")
        strokeWidth = 2f
        style = Paint.Style.STROKE
    }
    private val linePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#3DD9FF")
        strokeWidth = 5f
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val glowPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#2FE6C6")
        strokeWidth = 10f
        alpha = 48
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#143447")
        alpha = 120
        style = Paint.Style.FILL
    }
    private val pointPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#E7F8FF")
        style = Paint.Style.FILL
    }

    private var points: List<Long> = emptyList()

    fun submit(values: List<Long>) {
        points = values.takeLast(24)
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val chartWidth = width.toFloat()
        val chartHeight = height.toFloat()
        if (chartWidth <= 0f || chartHeight <= 0f) return

        val left = paddingLeft.toFloat() + 8f
        val right = chartWidth - paddingRight.toFloat() - 8f
        val top = paddingTop.toFloat() + 8f
        val bottom = chartHeight - paddingBottom.toFloat() - 8f
        val innerHeight = bottom - top
        val innerWidth = right - left

        for (i in 0..3) {
            val y = top + innerHeight * (i / 3f)
            canvas.drawLine(left, y, right, y, gridPaint)
        }

        if (points.isEmpty()) return
        if (points.size == 1) {
            canvas.drawCircle(left + innerWidth / 2f, bottom, 6f, pointPaint)
            return
        }

        val maxValue = (points.maxOrNull() ?: 0L).coerceAtLeast(1L).toFloat()
        val stepX = if (points.size == 1) 0f else innerWidth / (points.size - 1).toFloat()
        val linePath = Path()
        val fillPath = Path()

        points.forEachIndexed { index, value ->
            val x = left + (stepX * index)
            val normalized = value.toFloat() / maxValue
            val y = bottom - (normalized * innerHeight)
            if (index == 0) {
                linePath.moveTo(x, y)
                fillPath.moveTo(x, bottom)
                fillPath.lineTo(x, y)
            } else {
                linePath.lineTo(x, y)
                fillPath.lineTo(x, y)
            }
        }
        fillPath.lineTo(right, bottom)
        fillPath.close()

        canvas.drawPath(fillPath, fillPaint)
        canvas.drawPath(linePath, glowPaint)
        canvas.drawPath(linePath, linePaint)

        val lastX = left + (stepX * (points.size - 1))
        val lastY = bottom - ((points.last().toFloat() / maxValue) * innerHeight)
        canvas.drawCircle(lastX, lastY, 7f, pointPaint)
    }
}

private class GaugeView(context: android.content.Context) : View(context) {
    private val trackPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#18232E")
        style = Paint.Style.STROKE
        strokeWidth = 18f
        strokeCap = Paint.Cap.ROUND
    }
    private val valuePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#3DD9FF")
        style = Paint.Style.STROKE
        strokeWidth = 20f
        strokeCap = Paint.Cap.ROUND
    }
    private val thresholdPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#FF5E5E")
        style = Paint.Style.STROKE
        strokeWidth = 6f
        strokeCap = Paint.Cap.ROUND
    }
    private val labelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#E7F8FF")
        textAlign = Paint.Align.CENTER
        textSize = 42f
        typeface = Typeface.create("monospace", Typeface.BOLD)
    }
    private val subLabelPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#88A6BB")
        textAlign = Paint.Align.CENTER
        textSize = 26f
        typeface = Typeface.MONOSPACE
    }

    private var percent: Float = 0f
    private var valueText: String = "--"
    private var label: String = "--"
    private var thresholdPercent: Float = 80f

    fun submit(percent: Float, valueText: String, label: String) {
        this.percent = percent.coerceIn(0f, 100f)
        this.valueText = valueText
        this.label = label
        invalidate()
    }

    fun setAccentColor(color: String) {
        valuePaint.color = Color.parseColor(color)
    }

    fun setThresholdPercent(percent: Float) {
        thresholdPercent = percent.coerceIn(0f, 100f)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val w = width.toFloat()
        val h = height.toFloat()
        if (w <= 0f || h <= 0f) return

        val pad = 28f
        val arcLeft = pad
        val arcTop = pad
        val arcRight = w - pad
        val arcBottom = h - pad
        val startAngle = 150f
        val sweepAngle = 240f
        canvas.drawArc(arcLeft, arcTop, arcRight, arcBottom, startAngle, sweepAngle, false, trackPaint)
        canvas.drawArc(arcLeft, arcTop, arcRight, arcBottom, startAngle, sweepAngle * (percent / 100f), false, valuePaint)

        val thresholdAngle = Math.toRadians((startAngle + sweepAngle * (thresholdPercent / 100f)).toDouble())
        val cx = w / 2f
        val cy = h / 2f + 10f
        val radius = (w.coerceAtMost(h) / 2f) - 28f
        val x1 = cx + kotlin.math.cos(thresholdAngle).toFloat() * (radius - 18f)
        val y1 = cy + kotlin.math.sin(thresholdAngle).toFloat() * (radius - 18f)
        val x2 = cx + kotlin.math.cos(thresholdAngle).toFloat() * (radius + 4f)
        val y2 = cy + kotlin.math.sin(thresholdAngle).toFloat() * (radius + 4f)
        canvas.drawLine(x1, y1, x2, y2, thresholdPaint)

        canvas.drawText(valueText, cx, h * 0.58f, labelPaint)
        canvas.drawText(label, cx, h * 0.75f, subLabelPaint)
    }
}

private fun formatStaticBytes(bytes: Long): String {
    val value = bytes.toDouble()
    return when {
        value >= 1024 * 1024 * 1024 -> String.format("%.2f GB", value / (1024 * 1024 * 1024))
        value >= 1024 * 1024 -> String.format("%.2f MB", value / (1024 * 1024))
        value >= 1024 -> String.format("%.2f KB", value / 1024)
        else -> "$bytes B"
    }
}
