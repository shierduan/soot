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
    val source: String         // 来源：分区路径或数据库名
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
