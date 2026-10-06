package com.recovery.app.recovery

import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoverableRecord
import com.recovery.app.model.RecoveryType
import com.recovery.app.model.ScanSettings
import com.recovery.app.model.ScanState
import com.recovery.app.model.ScanPhase
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

    /**
     * 执行完整恢复扫描，结果通过 scanState 实时更新
     */
    suspend fun recover(types: Set<RecoveryType>, settings: ScanSettings = ScanSettings()) {
        withContext(Dispatchers.IO) {
            val startTime = System.currentTimeMillis()
            val files = mutableListOf<RecoverableFile>()
            val records = mutableListOf<RecoverableRecord>()

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
                    _scanState.value = _scanState.value.copy(
                        phase = ScanPhase.SCANNING_FILES,
                        currentPhaseText = "正在扫描分区: $partition"
                    )

                    var lastEmitTime = System.currentTimeMillis()

                    fileCarver.scanPartition(partition, fileTypes, settings).collect { event ->
                        when (event) {
                            is FileCarver.ScanEvent.FileFound -> {
                                files.add(event.file)
                                // 限流：每 100ms 或每 10 个文件更新一次
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
                                    currentPhaseText = "已扫描 ${formatBytes(event.scannedBytes)} / ${formatBytes(event.totalBytes)} · 发现 ${files.size} 个文件"
                                )
                            }
                        }
                    }
                } else {
                    _scanState.value = _scanState.value.copy(
                        currentPhaseText = "无法定位 userdata 分区"
                    )
                }
            }

            // ===== 数据库类恢复 =====
            val dbTypes = types.filter { it in systemDbPaths.keys }.toSet()

            for (type in dbTypes) {
                val dbPath = systemDbPaths[type] ?: continue
                _scanState.value = _scanState.value.copy(
                    phase = ScanPhase.SCANNING_DB,
                    currentPhaseText = "正在恢复 ${typeText(type)} 数据库..."
                )

                val tempDb = "/data/local/tmp/recovery_${type.name.lowercase()}.db"
                val copied = RootShell.copyProtectedFile(dbPath, tempDb)

                if (copied && File(tempDb).exists()) {
                    val recovered = sqliteRecovery.recoverDeletedRecords(tempDb, type)
                    records.addAll(recovered)
                    _scanState.value = _scanState.value.copy(
                        records = records.toList(),
                        recordsFound = records.size,
                        currentPhaseText = "已恢复 ${records.size} 条 ${typeText(type)} 记录"
                    )
                    RootShell.execute("rm -f $tempDb")
                } else {
                    _scanState.value = _scanState.value.copy(
                        currentPhaseText = "无法读取 ${typeText(type)} 数据库（需要 root）"
                    )
                }
            }

            // 完成
            _scanState.value = _scanState.value.copy(
                phase = ScanPhase.COMPLETED,
                isScanning = false,
                files = files.toList(),
                records = records.toList(),
                filesFound = files.size,
                recordsFound = records.size,
                scannedBytes = _scanState.value.totalBytes,
                durationMs = System.currentTimeMillis() - startTime,
                currentPhaseText = "扫描完成：发现 ${files.size} 个文件，${records.size} 条记录"
            )
        }
    }

    /**
     * 恢复单个文件到指定输出路径
     */
    suspend fun recoverFile(item: RecoverableFile, outputDir: String): String? {
        val outputPath = "$outputDir/recovered_${item.id}.${item.extension}"
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
