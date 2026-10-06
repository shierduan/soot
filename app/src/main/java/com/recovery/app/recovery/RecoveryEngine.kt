package com.recovery.app.recovery

import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoverableRecord
import com.recovery.app.model.RecoveryResult
import com.recovery.app.model.RecoveryType
import com.recovery.app.util.RootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 恢复引擎
 *
 * 整合文件雕刻（FileCarver）和 SQLite 已删除记录恢复，
 * 提供统一的恢复接口。
 *
 * 恢复策略：
 *  1. 文件类（图片/视频/音频/文档）：通过 FileCarver 扫描原始分区
 *  2. 数据库类（通话/短信/联系人/WhatsApp）：通过 SQLiteRecovery 解析
 *     对应数据库的空闲页和未分配空间
 */
class RecoveryEngine {

    private val fileCarver = FileCarver()
    private val sqliteRecovery = SQLiteRecovery()

    // Android 系统数据库路径（需 root 读取）
    private val systemDbPaths = mapOf(
        RecoveryType.CALL_LOG to "/data/data/com.android.providers.contacts/databases/calllog.db",
        RecoveryType.SMS to "/data/data/com.android.providers.telephony/databases/mmssms.db",
        RecoveryType.CONTACT to "/data/data/com.android.providers.contacts/databases/contacts2.db",
        RecoveryType.WHATSAPP to "/data/data/com.whatsapp/databases/msgstore.db"
    )

    /**
     * 执行完整恢复扫描
     *
     * @param types 要恢复的数据类型集合
     * @param onProgress 进度回调 (已扫描类型, 总数)
     * @return 恢复结果
     */
    suspend fun recover(
        types: Set<RecoveryType>,
        onProgress: (String) -> Unit
    ): RecoveryResult = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        val files = mutableListOf<RecoverableFile>()
        val records = mutableListOf<RecoverableRecord>()
        var scannedBytes = 0L

        // ===== 文件类恢复：扫描存储分区 =====
        val fileTypes = types.filter {
            it in setOf(
                RecoveryType.IMAGE, RecoveryType.VIDEO,
                RecoveryType.AUDIO, RecoveryType.DOCUMENT, RecoveryType.ARCHIVE
            )
        }.toSet()

        if (fileTypes.isNotEmpty()) {
            onProgress("正在定位存储分区...")
            val partition = RootShell.getUserdataPartition()
            if (partition != null) {
                onProgress("正在扫描分区: $partition")
                fileCarver.scanPartition(partition, fileTypes).collect { file ->
                    files.add(file)
                    if (files.size % 50 == 0) {
                        onProgress("已发现 ${files.size} 个可恢复文件...")
                    }
                }
                scannedBytes = RootShell.execute("blockdev --getsize64 $partition").trim().toLongOrNull() ?: 0
            } else {
                onProgress("无法定位 userdata 分区")
            }
        }

        // ===== 数据库类恢复：解析 SQLite 已删除记录 =====
        val dbTypes = types.filter { it in systemDbPaths.keys }.toSet()

        for (type in dbTypes) {
            val dbPath = systemDbPaths[type] ?: continue
            onProgress("正在恢复 ${typeText(type)} 数据库...")

            // 复制受保护的数据库到临时文件
            val tempDb = "/data/local/tmp/recovery_${type.name.lowercase()}.db"
            val copied = RootShell.copyProtectedFile(dbPath, tempDb)

            if (copied && File(tempDb).exists()) {
                val recovered = sqliteRecovery.recoverDeletedRecords(tempDb, type)
                records.addAll(recovered)
                onProgress("已恢复 ${recovered.size} 条 ${typeText(type)} 记录")
                // 清理临时文件
                RootShell.execute("rm -f $tempDb")
            } else {
                onProgress("无法读取 ${typeText(type)} 数据库（需要 root）")
            }
        }

        RecoveryResult(
            files = files,
            records = records,
            scannedBytes = scannedBytes,
            durationMs = System.currentTimeMillis() - startTime
        )
    }

    /**
     * 恢复单个文件到指定输出路径
     */
    suspend fun recoverFile(item: RecoverableFile, outputDir: String): String? {
        val outputPath = "$outputDir/recovered_${item.id}.${item.extension}"
        return if (fileCarver.saveRecoveredFile(item, outputPath)) outputPath else null
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
}
