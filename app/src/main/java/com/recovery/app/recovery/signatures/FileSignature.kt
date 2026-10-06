package com.recovery.app.recovery.signatures

import com.recovery.app.model.RecoveryType

/**
 * 文件签名定义
 *
 * 包含文件头（header）和可选的文件尾（footer）魔数，
 * 用于在原始存储中扫描并识别已删除的文件。
 */
data class FileSignature(
    val type: RecoveryType,
    val mimeType: String,
    val extension: String,
    val header: ByteArray,         // 文件头魔数
    val footer: ByteArray? = null, // 文件尾魔数（可选，用于精确确定文件大小）
    val headerOffset: Int = 0,     // header 在文件中的偏移
    val maxSize: Long = 512L * 1024 * 1024  // 单文件最大尺寸限制
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is FileSignature) return false
        return type == other.type && extension == other.extension
    }

    override fun hashCode(): Int = type.hashCode() * 31 + extension.hashCode()
}
