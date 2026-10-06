package com.recovery.app.preview

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoverableRecord
import com.recovery.app.model.RecoveryType
import com.recovery.app.util.RootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 预览管理器
 *
 * 在恢复或删除操作前，提供数据预览功能：
 *  - 图片：解码文件头生成缩略图
 *  - 视频：提取首帧或显示文件信息
 *  - 文本/记录：显示结构化字段
 *  - 文档：显示文件类型和大小信息
 */
class PreviewManager {

    /**
     * 预览信息
     */
    data class PreviewInfo(
        val type: RecoveryType,
        val title: String,
        val details: Map<String, String>,
        val thumbnail: Bitmap? = null,
        val previewText: String? = null
    )

    /**
     * 生成可恢复文件的预览
     */
    suspend fun previewFile(item: RecoverableFile): PreviewInfo = withContext(Dispatchers.IO) {
        val details = mutableMapOf(
            "文件类型" to item.mimeType,
            "扩展名" to item.extension,
            "预估大小" to formatSize(item.estimatedSize),
            "存储偏移" to "0x${item.offset.toString(16)}",
            "来源" to item.source
        )

        var thumbnail: Bitmap? = null
        var previewText: String? = null

        when (item.type) {
            RecoveryType.IMAGE -> {
                // 尝试从文件头解码缩略图
                thumbnail = decodeThumbnail(item.headerBytes)
                if (thumbnail != null) {
                    details["尺寸"] = "${thumbnail.width}x${thumbnail.height}"
                }
            }
            RecoveryType.VIDEO -> {
                details["说明"] = "视频文件，恢复后可播放预览"
                previewText = buildVideoInfo(item)
            }
            RecoveryType.AUDIO -> {
                details["说明"] = "音频文件，恢复后可播放预览"
            }
            RecoveryType.DOCUMENT -> {
                details["说明"] = "文档文件，恢复后可打开预览"
            }
            RecoveryType.ARCHIVE -> {
                details["说明"] = "压缩包，恢复后可解压预览内容"
            }
            else -> {}
        }

        PreviewInfo(
            type = item.type,
            title = "recovered_${item.id}.${item.extension}",
            details = details,
            thumbnail = thumbnail,
            previewText = previewText
        )
    }

    /**
     * 生成可恢复记录的预览
     */
    fun previewRecord(record: RecoverableRecord): PreviewInfo {
        return PreviewInfo(
            type = record.type,
            title = record.type.name,
            details = record.fields,
            previewText = record.fields.entries.joinToString("\n") { "${it.key}: ${it.value}" }
        )
    }

    /**
     * 生成待删除文件的预览
     */
    fun previewFileForDelete(path: String): PreviewInfo {
        val file = File(path)
        val ext = file.extension.lowercase()
        val type = when (ext) {
            "jpg", "jpeg", "png", "gif", "webp", "bmp" -> RecoveryType.IMAGE
            "mp4", "3gp", "mkv", "avi", "mov", "flv" -> RecoveryType.VIDEO
            "mp3", "wav", "aac", "amr", "ogg" -> RecoveryType.AUDIO
            "pdf", "doc", "docx", "txt", "xls", "xlsx", "ppt", "pptx" -> RecoveryType.DOCUMENT
            "zip", "rar", "7z", "tar", "gz" -> RecoveryType.ARCHIVE
            else -> RecoveryType.DOCUMENT
        }

        val details = mutableMapOf(
            "文件名" to file.name,
            "文件大小" to formatSize(file.length()),
            "最后修改" to java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                .format(java.util.Date(file.lastModified())),
            "路径" to file.absolutePath
        )

        return PreviewInfo(
            type = type,
            title = file.name,
            details = details,
            previewText = "此文件将被安全删除（覆写 $DEFAULT_PASSES 次后删除），删除后无法恢复。"
        )
    }

    /**
     * 从文件头字节解码图片缩略图
     */
    private fun decodeThumbnail(headerBytes: ByteArray): Bitmap? {
        return try {
            if (headerBytes.isEmpty()) return null
            val opts = BitmapFactory.Options().apply {
                inJustDecodeBounds = true
            }
            BitmapFactory.decodeByteArray(headerBytes, 0, headerBytes.size, opts)
            if (opts.outWidth > 0 && opts.outHeight > 0) {
                // 实际解码
                BitmapFactory.decodeByteArray(headerBytes, 0, headerBytes.size)
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun buildVideoInfo(item: RecoverableFile): String {
        return buildString {
            appendLine("视频文件信息：")
            appendLine("格式: ${item.extension.uppercase()}")
            appendLine("MIME: ${item.mimeType}")
            appendLine("预估大小: ${formatSize(item.estimatedSize)}")
            appendLine()
            appendLine("恢复后可使用系统播放器播放。")
        }
    }

    private fun formatSize(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024))} MB"
            else -> "${"%.2f".format(bytes / (1024.0 * 1024 * 1024))} GB"
        }
    }

    companion object {
        const val DEFAULT_PASSES = 3
    }
}
