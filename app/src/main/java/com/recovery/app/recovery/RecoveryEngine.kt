package com.recovery.app.recovery

import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoverableRecord
import com.recovery.app.model.RecoveryType
import com.recovery.app.model.ScanSettings
import com.recovery.app.model.ScanState
import com.recovery.app.model.ScanPhase
import com.recovery.app.model.LogEntry
import com.recovery.app.model.LogLevel
import com.recovery.app.util.RootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 恢复引擎
 *
 * 核心改进：
 *  - 实时流式更新 ScanState（进度条 + 中间结果）
 *  - 支持扫描设置（快速/完整模式、大小过滤、置信度过滤）
 *  - 文件类与数据库类结果合并到同一个状态流
 *  - 实时日志流（环形缓冲，最多 300 条）
 */
class RecoveryEngine {

    private val fileCarver = FileCarver()
    private val sqliteRecovery = SQLiteRecovery()

    private val systemDbPaths = mapOf(
        RecoveryType.CALL_LOG to "/data/data/com.android.providers.contacts/databases/calllog.db",
        RecoveryType.SMS to "/data/data/com.android.providers.telephony/databases/mmssms.db",
        RecoveryType.CONTACT to "/data/data/com.android.providers.contacts/databases/contacts2.db",
        RecoveryType.WHATSAPP to "/data/data/com.whatsapp/databases/msgstore.db"
    )

    private val _scanState = MutableStateFlow(ScanState())
    val scanState: StateFlow<ScanState> = _scanState.asStateFlow()

    // 日志环形缓冲（最多 300 条）
    private val maxLogs = 300
    private val _logs = MutableStateFlow<List<LogEntry>>(emptyList())
    val logs: StateFlow<List<LogEntry>> = _logs.asStateFlow()

    private fun log(level: LogLevel, message: String) {
        val entry = LogEntry(System.currentTimeMillis(), level, message)
        val current = _logs.value
        val updated = if (current.size >= maxLogs) {
            current.drop(current.size - maxLogs + 1) + entry
        } else {
            current + entry
        }
        _logs.value = updated
    }

    private fun logInfo(msg: String) = log(LogLevel.INFO, msg)
    private fun logWarn(msg: String) = log(LogLevel.WARN, msg)
    private fun logError(msg: String) = log(LogLevel.ERROR, msg)
    private fun logSuccess(msg: String) = log(LogLevel.SUCCESS, msg)

    /**
     * 执行完整恢复扫描，结果通过 scanState 实时更新
     */
    suspend fun recover(types: Set<RecoveryType>, settings: ScanSettings = ScanSettings()) {
        withContext(Dispatchers.IO) {
            val startTime = System.currentTimeMillis()
            val files = mutableListOf<RecoverableFile>()
            val records = mutableListOf<RecoverableRecord>()

            logInfo("开始恢复扫描，类型: ${types.joinToString { it.name }}")
            _scanState.value = ScanState(
                phase = ScanPhase.LOCATING_PARTITION,
                isScanning = true,
                currentPhaseText = "正在定位存储分区..."
            )

            val fileTypes = types.filter {
                it in setOf(
                    RecoveryType.IMAGE, RecoveryType.VIDEO,
                    RecoveryType.AUDIO, RecoveryType.DOCUMENT, RecoveryType.ARCHIVE
                )
            }.toSet()

            // ===== 文件类恢复 =====
            if (fileTypes.isNotEmpty()) {
                val partition = RootShell.getUserdataPartition()
                if (partition != null) {
                    logInfo("定位到分区: $partition")
                    _scanState.value = _scanState.value.copy(
                        phase = ScanPhase.SCANNING_FILES,
                        currentPhaseText = "正在扫描分区: $partition"
                    )

                    var lastEmitTime = System.currentTimeMillis()

                    fileCarver.scanPartition(partition, fileTypes, settings) { logMsg ->
                        logInfo(logMsg)
                    }.collect { event ->
                        when (event) {
                            is FileCarver.ScanEvent.FileFound -> {
                                files.add(event.file)
                                val now = System.currentTimeMillis()
                                if (now - lastEmitTime > 100 || files.size % 10 == 0) {
                                    _scanState.value = _scanState.value.copy(
                                        files = files.toList(),
                                        filesFound = files.size
                                    )
                                    lastEmitTime = now
                                }
                            }
                            is FileCarver.ScanEvent.Progress -> {
                                _scanState.value = _scanState.value.copy(
                                    scannedBytes = event.scannedBytes,
                                    totalBytes = event.totalBytes,
                                    speedBytesPerSec = event.speedBytesPerSec,
                                    etaMs = event.etaMs,
                                    currentPhaseText = "已扫描 ${formatBytes(event.scannedBytes)} / ${formatBytes(event.totalBytes)} · 发现 ${files.size} 个文件"
                                )
                            }
                        }
                    }
                    logSuccess("文件扫描完成，共发现 ${files.size} 个文件")
                } else {
                    logError("无法定位 userdata 分区")
                    _scanState.value = _scanState.value.copy(
                        currentPhaseText = "无法定位 userdata 分区"
                    )
                }
            }

            // ===== 数据库类恢复 =====
            val dbTypes = types.filter { it in systemDbPaths.keys }.toSet()

            for (type in dbTypes) {
                val dbPath = systemDbPaths[type] ?: continue
                logInfo("正在恢复 ${typeText(type)} 数据库: $dbPath")
                _scanState.value = _scanState.value.copy(
                    phase = ScanPhase.SCANNING_DB,
                    currentPhaseText = "正在恢复 ${typeText(type)} 数据库..."
                )

                val tempDb = "/data/local/tmp/recovery_${type.name.lowercase()}.db"
                val copied = RootShell.copyProtectedFile(dbPath, tempDb)

                if (copied && File(tempDb).exists()) {
                    val recovered = sqliteRecovery.recoverDeletedRecords(tempDb, type)
                    records.addAll(recovered)
                    logSuccess("恢复 ${recovered.size} 条 ${typeText(type)} 记录")
                    _scanState.value = _scanState.value.copy(
                        records = records.toList(),
                        recordsFound = records.size,
                        currentPhaseText = "已恢复 ${records.size} 条 ${typeText(type)} 记录"
                    )
                    RootShell.execute("rm -f $tempDb")
                } else {
                    logWarn("无法读取 ${typeText(type)} 数据库（需要 root 或路径不存在）")
                    _scanState.value = _scanState.value.copy(
                        currentPhaseText = "无法读取 ${typeText(type)} 数据库（需要 root）"
                    )
                }
            }

            // 完成
            val duration = System.currentTimeMillis() - startTime
            _scanState.value = _scanState.value.copy(
                phase = ScanPhase.COMPLETED,
                isScanning = false,
                files = files.toList(),
                records = records.toList(),
                filesFound = files.size,
                recordsFound = records.size,
                scannedBytes = _scanState.value.totalBytes,
                durationMs = duration,
                currentPhaseText = "扫描完成：发现 ${files.size} 个文件，${records.size} 条记录（耗时 ${duration / 1000}s）"
            )
            logSuccess("全部扫描完成，耗时 ${duration / 1000}s")
        }
    }

    /**
     * 恢复单个文件到指定输出路径
     *
     * - 自动创建输出目录
     * - 文件名冲突时自动追加序号（recovered_1.jpg, recovered_1_2.jpg...）
     * - 返回实际保存的完整路径
     */
    suspend fun recoverFile(item: RecoverableFile, outputDir: String): String? {
        // 确保目录存在
        val dir = File(outputDir)
        if (!dir.exists()) dir.mkdirs()

        // 生成不冲突的文件名
        var outputPath = "$outputDir/recovered_${item.id}.${item.extension}"
        var counter = 2
        while (File(outputPath).exists()) {
            outputPath = "$outputDir/recovered_${item.id}_$counter.${item.extension}"
            counter++
        }

        return if (fileCarver.saveRecoveredFile(item, outputPath)) outputPath else null
    }

    /**
     * 批量恢复文件
     */
    suspend fun recoverFiles(items: List<RecoverableFile>, outputDir: String): List<String> {
        return items.mapNotNull { recoverFile(it, outputDir) }
    }

    /**
     * 导出记录为 JSON
     */
    fun exportRecordsJson(records: List<RecoverableRecord>): String {
        val sb = StringBuilder("[")
        records.forEachIndexed { i, r ->
            if (i > 0) sb.append(",")
            sb.append("{\"type\":\"${r.type.name}\",")
            sb.append("\"source\":\"${r.source}\",")
            sb.append("\"fields\":{")
            r.fields.entries.forEachIndexed { j, (k, v) ->
                if (j > 0) sb.append(",")
                val safeV = v.replace("\"", "\\\"").replace("\n", "\\n")
                sb.append("\"$k\":\"$safeV\"")
            }
            sb.append("}}")
        }
        sb.append("]")
        return sb.toString()
    }

    private fun typeText(type: RecoveryType): String = when (type) {
        RecoveryType.IMAGE -> "图片"
        RecoveryType.VIDEO -> "视频"
        RecoveryType.AUDIO -> "音频"
        RecoveryType.DOCUMENT -> "文档"
        RecoveryType.ARCHIVE -> "压缩包"
        RecoveryType.CALL_LOG -> "通话记录"
        RecoveryType.SMS -> "短信"
        RecoveryType.CONTACT -> "联系人"
        RecoveryType.WHATSAPP -> "WhatsApp"
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024L * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024))} MB"
        else -> "${"%.2f".format(bytes / (1024.0 * 1024 * 1024))} GB"
    }
}
