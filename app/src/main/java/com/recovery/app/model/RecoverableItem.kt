package com.recovery.app.model

/**
 * 可恢复的数据项类型
 */
enum class RecoveryType {
    IMAGE,      // 图片
    VIDEO,      // 视频
    AUDIO,      // 音频
    DOCUMENT,   // 文档
    ARCHIVE,    // 压缩包
    CALL_LOG,   // 通话记录
    SMS,        // 短信
    CONTACT,    // 联系人
    WHATSAPP    // WhatsApp 消息
}

/**
 * 置信度等级
 */
enum class Confidence {
    HIGH,    // 高：有 footer 或完整结构校验通过
    MEDIUM,  // 中：header + 部分结构校验通过
    LOW      // 低：仅 header 匹配
}

/**
 * 文件签名匹配到的可恢复文件
 */
data class RecoverableFile(
    val id: Long,
    val type: RecoveryType,
    val mimeType: String,
    val extension: String,
    val offset: Long,          // 在分区/镜像中的偏移量
    val estimatedSize: Long,   // 预估大小（基于 footer 或启发式）
    val headerBytes: ByteArray,  // 文件头字节（用于预览/校验）
    val source: String,        // 来源：分区路径或数据库名
    val confidence: Confidence = Confidence.LOW,
    val thumbnail: ByteArray? = null  // 解码后的缩略图字节（仅图片）
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RecoverableFile) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

/**
 * 从 SQLite 恢复的结构化记录（通话/短信/联系人等）
 */
data class RecoverableRecord(
    val id: Long,
    val type: RecoveryType,
    val fields: Map<String, String>,
    val source: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RecoverableRecord) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

/**
 * 恢复会话结果
 */
data class RecoveryResult(
    val files: List<RecoverableFile> = emptyList(),
    val records: List<RecoverableRecord> = emptyList(),
    val scannedBytes: Long = 0,
    val durationMs: Long = 0
)

// ========== 扫描状态 ==========

/**
 * 扫描阶段
 */
enum class ScanPhase {
    IDLE,              // 空闲
    LOCATING_PARTITION, // 定位分区
    SCANNING_FILES,     // 扫描文件类数据
    SCANNING_DB,        // 扫描数据库记录
    COMPLETED,          // 完成
    ERROR               // 出错
}

/**
 * 扫描实时状态（用于驱动 UI 进度条和结果列表）
 */
data class ScanState(
    val phase: ScanPhase = ScanPhase.IDLE,
    val isScanning: Boolean = false,
    val scannedBytes: Long = 0,
    val totalBytes: Long = 0,
    val currentPhaseText: String = "",
    val filesFound: Int = 0,
    val recordsFound: Int = 0,
    val files: List<RecoverableFile> = emptyList(),
    val records: List<RecoverableRecord> = emptyList(),
    val error: String? = null,
    val durationMs: Long = 0
) {
    /** 进度百分比 0.0 - 1.0 */
    val progress: Float
        get() = if (totalBytes > 0) (scannedBytes.toFloat() / totalBytes).coerceIn(0f, 1f) else 0f

    /** 是否已完成 */
    val isCompleted: Boolean
        get() = phase == ScanPhase.COMPLETED || phase == ScanPhase.ERROR
}

// ========== 扫描设置 ==========

/**
 * 扫描模式
 */
enum class ScanMode {
    QUICK,   // 快速：仅扫描前 N GB，适合快速定位
    FULL     // 完整：扫描整个分区
}

/**
 * 扫描设置
 */
data class ScanSettings(
    val mode: ScanMode = ScanMode.FULL,
    val quickScanLimitGb: Int = 5,        // 快速扫描上限（GB）
    val minFileSizeKb: Int = 1,           // 最小文件大小（KB）
    val maxFileSizeMb: Int = 2048,        // 最大文件大小（MB）
    val onlyHighConfidence: Boolean = false, // 仅显示高/中置信度
    val dedupeEnabled: Boolean = true     // 启用去重
)
