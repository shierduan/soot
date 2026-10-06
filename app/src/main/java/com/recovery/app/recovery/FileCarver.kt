package com.recovery.app.recovery

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.recovery.app.model.Confidence
import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoveryType
import com.recovery.app.model.ScanSettings
import com.recovery.app.recovery.signatures.FileSignature
import com.recovery.app.recovery.signatures.SignatureRegistry
import com.recovery.app.util.RootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.io.File

/**
 * 文件雕刻引擎（File Carving Engine）
 *
 * 核心改进：
 *  - 快速读取：使用 dd bs=4096 大块读取（比 bs=1 快数千倍）
 *  - 去重：按偏移量去重，同一偏移只返回一次
 *  - 置信度：有 footer=HIGH，结构校验通过=MEDIUM，仅 header=LOW
 *  - 结构校验：JPEG 必须有 JFIF/EXIF，PNG 必须有 IHDR 等
 *  - 缩略图：图片即时解码缩略图用于列表渲染
 *  - 进度回调：实时上报已扫描字节 / 总字节
 */
class FileCarver {

    // 扫描缓冲区大小：16MB（更大缓冲区减少 I/O 次数）
    private val bufferSize = 16 * 1024 * 1024

    // 重叠区域大小：确保跨缓冲区边界的文件头不被遗漏
    private val overlapSize = 128 * 1024

    /**
     * 扫描事件：文件发现 / 进度更新
     */
    sealed class ScanEvent {
        data class FileFound(val file: RecoverableFile) : ScanEvent()
        data class Progress(val scannedBytes: Long, val totalBytes: Long) : ScanEvent()
    }

    /**
     * 扫描指定分区
     */
    fun scanPartition(
        device: String,
        types: Set<RecoveryType>,
        settings: ScanSettings = ScanSettings()
    ): Flow<ScanEvent> = flow {
        val targetSignatures = SignatureRegistry.signatures.filter { it.type in types }
        if (targetSignatures.isEmpty()) return@flow

        // 获取分区大小
        val partitionSize = getPartitionSize(device)
        if (partitionSize <= 0) return@flow

        // 快速扫描限制
        val scanLimit = if (settings.mode == com.recovery.app.model.ScanMode.QUICK) {
            (settings.quickScanLimitGb.toLong() * 1024 * 1024 * 1024).coerceAtMost(partitionSize)
        } else {
            partitionSize
        }

        val minBytes = settings.minFileSizeKb * 1024L
        val maxBytes = settings.maxFileSizeMb * 1024L * 1024L

        // 去重集合（偏移量）
        val seenOffsets = HashSet<Long>()
        var idCounter = 0L
        val overlap = ByteArray(overlapSize)
        var overlapLen = 0
        var offset = 0L

        while (offset < scanLimit) {
            val toRead = minOf(bufferSize.toLong(), scanLimit - offset).toInt()
            val buffer = ByteArray(toRead + overlapLen)

            // 复制上一次的重叠部分
            if (overlapLen > 0) {
                overlap.copyInto(buffer, 0, 0, overlapLen)
            }

            // 读取新数据（快速大块读取）
            val newBytes = RootShell.readBytes(device, offset, toRead)
            newBytes.copyInto(buffer, overlapLen)

            val actualLen = overlapLen + newBytes.size
            if (actualLen < 16) break

            val bufferBaseOffset = offset - overlapLen

            // 搜索文件签名
            val matches = SignatureRegistry.findMatches(buffer)

            for ((sig, bufIndex) in matches) {
                if (sig.type !in types) continue

                val absoluteOffset = bufferBaseOffset + bufIndex

                // 去重：同一偏移只处理一次
                if (settings.dedupeEnabled) {
                    if (!seenOffsets.add(absoluteOffset)) continue
                }

                // 结构校验（过滤明显误报）
                if (!validateStructure(sig, buffer, bufIndex, actualLen)) continue

                // 估算文件大小
                val estimatedSize = estimateFileSize(sig, buffer, bufIndex, actualLen)

                // 大小过滤
                if (estimatedSize < minBytes || estimatedSize > maxBytes) continue
                if (estimatedSize > sig.maxSize) continue

                // 计算置信度
                val confidence = computeConfidence(sig, buffer, bufIndex, actualLen)

                // 仅显示高/中置信度
                if (settings.onlyHighConfidence && confidence == Confidence.LOW) continue

                // 读取文件头（用于预览）
                val headerLen = minOf(512, estimatedSize.toInt())
                val headerBytes = if (bufIndex + headerLen <= actualLen) {
                    buffer.copyOfRange(bufIndex, minOf(bufIndex + headerLen, actualLen))
                } else ByteArray(0)

                // 图片：尝试解码缩略图
                val thumbnail = if (sig.type == RecoveryType.IMAGE) {
                    decodeThumbnail(buffer, bufIndex, actualLen)
                } else null

                emit(
                    ScanEvent.FileFound(
                        RecoverableFile(
                            id = ++idCounter,
                            type = sig.type,
                            mimeType = sig.mimeType,
                            extension = sig.extension,
                            offset = absoluteOffset,
                            estimatedSize = estimatedSize,
                            headerBytes = headerBytes,
                            source = device,
                            confidence = confidence,
                            thumbnail = thumbnail
                        )
                    )
                )
            }

            // 保存尾部重叠
            overlapLen = minOf(overlapSize, actualLen)
            buffer.copyInto(overlap, 0, actualLen - overlapLen, actualLen)

            offset += toRead

            // 上报进度
            emit(ScanEvent.Progress(offset.coerceAtMost(scanLimit), scanLimit))
        }
    }.flowOn(Dispatchers.IO)

    /**
     * 获取分区大小
     */
    private suspend fun getPartitionSize(device: String): Long {
        val sizeInfo = RootShell.execute("blockdev --getsize64 $device 2>/dev/null")
        return sizeInfo.trim().toLongOrNull() ?: run {
            val name = device.substringAfterLast("/")
            val parts = RootShell.execute("grep $name /proc/partitions").trim().split(Regex("\\s+"))
            if (parts.size >= 3) (parts[2].toLongOrNull() ?: 0L) * 1024 else 0L
        }
    }

    /**
     * 结构校验：过滤明显的误报
     */
    private fun validateStructure(sig: FileSignature, buffer: ByteArray, offset: Int, len: Int): Boolean {
        return when (sig.extension) {
            "jpg" -> {
                // JPEG: FF D8 FF 后必须是 E0 (JFIF)、E1 (EXIF)、E2 等 APP 标记
                if (offset + 4 > len) return false
                val marker = buffer[offset + 3].toInt() and 0xFF
                marker in 0xE0..0xEF || marker == 0xDB || marker == 0xC0 || marker == 0xFE
            }
            "png" -> {
                // PNG: 8 字节 header 后必须是 IHDR chunk (49 48 44 52)
                if (offset + 16 > len) return false
                buffer[offset + 12].toInt() and 0xFF == 0x49 && // I
                        buffer[offset + 13].toInt() and 0xFF == 0x48 && // H
                        buffer[offset + 14].toInt() and 0xFF == 0x44 && // D
                        buffer[offset + 15].toInt() and 0xFF == 0x52    // R
            }
            "gif" -> {
                // GIF: header 后是版本号 (87a/89a) 和逻辑屏幕描述符
                offset + 13 <= len
            }
            "bmp" -> {
                // BMP: BM 后 4 字节是文件大小（小端）
                if (offset + 6 > len) return false
                val size = (buffer[offset + 2].toLong() and 0xFF) or
                        ((buffer[offset + 3].toLong() and 0xFF) shl 8) or
                        ((buffer[offset + 4].toLong() and 0xFF) shl 16) or
                        ((buffer[offset + 5].toLong() and 0xFF) shl 24)
                size in 14..100L * 1024 * 1024
            }
            "mp4", "3gp", "heic", "mov" -> {
                // ISO Base Media: ftyp box 的 size 必须合理
                val boxStart = offset - sig.headerOffset
                if (boxStart < 0 || boxStart + 8 > len) return false
                val size = ((buffer[boxStart].toLong() and 0xFF) shl 24) or
                        ((buffer[boxStart + 1].toLong() and 0xFF) shl 16) or
                        ((buffer[boxStart + 2].toLong() and 0xFF) shl 8) or
                        (buffer[boxStart + 3].toLong() and 0xFF)
                size in 8..(4L * 1024 * 1024 * 1024)
            }
            "pdf" -> {
                // PDF: %PDF- 后跟版本号如 1.4
                if (offset + 8 > len) return false
                buffer[offset + 4].toInt() and 0xFF == 0x2D // '-'
            }
            "zip" -> {
                // ZIP: PK\x03\x04 后跟版本号
                if (offset + 6 > len) return false
                val version = (buffer[offset + 4].toInt() and 0xFF) or
                        ((buffer[offset + 5].toInt() and 0xFF) shl 8)
                version in 0..100
            }
            else -> true
        }
    }

    /**
     * 计算置信度
     */
    private fun computeConfidence(sig: FileSignature, buffer: ByteArray, offset: Int, len: Int): Confidence {
        // 有 footer 且能在合理范围内找到 → HIGH
        sig.footer?.let { footer ->
            val searchStart = offset + sig.header.size + sig.headerOffset
            val searchEnd = minOf(len, offset + sig.maxSize.toInt())
            if (searchEnd - searchStart > footer.size) {
                val found = indexOf(buffer, footer, searchStart, searchEnd)
                if (found > 0) return Confidence.HIGH
            }
        }
        // ISO Base Media 有正确的 box size → HIGH
        if (sig.mimeType.startsWith("video/") || sig.extension == "heic") {
            val size = parseIsoBoxSizeRaw(buffer, offset, sig)
            if (size > 0) return Confidence.HIGH
        }
        // RIFF 有正确的 size 字段 → HIGH
        if (sig.header.contentEquals(byteArrayOf(0x52, 0x49, 0x46, 0x46))) {
            if (offset + 8 <= len) {
                val riffSize = readUInt32LE(buffer, offset + 4)
                if (riffSize in 8..sig.maxSize) return Confidence.HIGH
            }
        }
        // 结构校验通过 → MEDIUM
        return if (validateStructure(sig, buffer, offset, len)) Confidence.MEDIUM else Confidence.LOW
    }

    /**
     * 估算文件大小
     */
    private fun estimateFileSize(sig: FileSignature, buffer: ByteArray, fileOffset: Int, bufferLen: Int): Long {
        // 1. 有 footer 时搜索
        sig.footer?.let { footer ->
            val searchStart = fileOffset + sig.header.size + sig.headerOffset
            val searchEnd = minOf(bufferLen, fileOffset + sig.maxSize.toInt())
            val idx = indexOf(buffer, footer, searchStart, searchEnd)
            if (idx > 0) return (idx - fileOffset + footer.size).toLong()
        }

        // 2. ISO Base Media (MP4/MOV/3GP/HEIC)
        if (sig.mimeType.startsWith("video/") || sig.extension == "heic") {
            return parseIsoBoxSize(buffer, fileOffset, sig)
        }

        // 3. RIFF 容器 (WebP/AVI/WAV)
        if (sig.header.contentEquals(byteArrayOf(0x52, 0x49, 0x46, 0x46))) {
            if (fileOffset + 8 <= bufferLen) {
                val riffSize = readUInt32LE(buffer, fileOffset + 4)
                if (riffSize in 0..sig.maxSize) return riffSize + 8
            }
        }

        // 4. PNG：从 IHDR 块估算
        if (sig.extension == "png") {
            if (fileOffset + 24 <= bufferLen) {
                val ihdrLen = readUInt32BE(buffer, fileOffset + 8)
                if (ihdrLen in 0..0x7FFFFFFF) {
                    return minOf(sig.maxSize, ihdrLen + 1024L)
                }
            }
        }

        // 5. 回退：默认估算值
        return defaultEstimate(sig)
    }

    private fun parseIsoBoxSize(buffer: ByteArray, fileOffset: Int, sig: FileSignature): Long {
        val boxStart = fileOffset - sig.headerOffset
        if (boxStart < 0 || boxStart + 8 > buffer.size) return defaultEstimate(sig)
        var size = readUInt32BE(buffer, boxStart).toLong()
        when {
            size == 0L -> return defaultEstimate(sig)
            size == 1L -> {
                if (boxStart + 16 <= buffer.size) size = readUInt64BE(buffer, boxStart + 8)
                else return defaultEstimate(sig)
            }
        }
        return if (size in 8..sig.maxSize) size else defaultEstimate(sig)
    }

    private fun parseIsoBoxSizeRaw(buffer: ByteArray, fileOffset: Int, sig: FileSignature): Long {
        val boxStart = fileOffset - sig.headerOffset
        if (boxStart < 0 || boxStart + 8 > buffer.size) return 0
        val size = readUInt32BE(buffer, boxStart).toLong()
        return if (size in 8..sig.maxSize) size else 0
    }

    private fun defaultEstimate(sig: FileSignature): Long = when (sig.type) {
        RecoveryType.IMAGE -> 3L * 1024 * 1024
        RecoveryType.VIDEO -> 100L * 1024 * 1024
        RecoveryType.AUDIO -> 5L * 1024 * 1024
        RecoveryType.DOCUMENT -> 2L * 1024 * 1024
        RecoveryType.ARCHIVE -> 50L * 1024 * 1024
        else -> 1L * 1024 * 1024
    }

    /**
     * 在缓冲区中搜索字节序列
     */
    private fun indexOf(buffer: ByteArray, target: ByteArray, from: Int, to: Int): Int {
        outer@ for (i in from until to - target.size) {
            for (j in target.indices) {
                if (buffer[i + j] != target[j]) continue@outer
            }
            return i
        }
        return -1
    }

    /**
     * 从缓冲区解码图片缩略图（缩放到最大 96px）
     */
    private fun decodeThumbnail(buffer: ByteArray, offset: Int, len: Int): ByteArray? {
        return try {
            val sampleLen = minOf(64 * 1024, len - offset)
            if (sampleLen <= 0) return null
            val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(buffer, offset, sampleLen, opts)
            if (opts.outWidth <= 0 || opts.outHeight <= 0) return null
            val scale = maxOf(1, maxOf(opts.outWidth, opts.outHeight) / 96)
            val decodeOpts = BitmapFactory.Options().apply { inSampleSize = scale }
            val bmp = BitmapFactory.decodeByteArray(buffer, offset, sampleLen, decodeOpts) ?: return null
            val stream = java.io.ByteArrayOutputStream()
            bmp.compress(Bitmap.CompressFormat.JPEG, 60, stream)
            bmp.recycle()
            stream.toByteArray()
        } catch (e: Exception) {
            null
        }
    }

    private fun readUInt32BE(buffer: ByteArray, offset: Int): Long {
        return ((buffer[offset].toLong() and 0xFF) shl 24) or
                ((buffer[offset + 1].toLong() and 0xFF) shl 16) or
                ((buffer[offset + 2].toLong() and 0xFF) shl 8) or
                (buffer[offset + 3].toLong() and 0xFF)
    }

    private fun readUInt32LE(buffer: ByteArray, offset: Int): Long {
        return (buffer[offset].toLong() and 0xFF) or
                ((buffer[offset + 1].toLong() and 0xFF) shl 8) or
                ((buffer[offset + 2].toLong() and 0xFF) shl 16) or
                ((buffer[offset + 3].toLong() and 0xFF) shl 24)
    }

    private fun readUInt64BE(buffer: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 8) value = (value shl 8) or (buffer[offset + i].toLong() and 0xFF)
        return value
    }

    /**
     * 将恢复的文件保存到指定路径（使用大块 dd）
     */
    suspend fun saveRecoveredFile(item: RecoverableFile, outputPath: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                // 使用 bs=4096 加速读取
                val bs = 4096
                val skip = item.offset / bs
                val skipRemainder = (item.offset % bs).toInt()
                val count = (item.estimatedSize + bs - 1) / bs

                val cmd = if (skipRemainder == 0) {
                    "dd if=${item.source} of=$outputPath bs=$bs skip=$skip count=$count 2>/dev/null"
                } else {
                    // 非对齐：先跳过余数再读
                    "dd if=${item.source} of=$outputPath bs=1 skip=${item.offset} count=${item.estimatedSize} 2>/dev/null"
                }
                RootShell.execute(cmd)
                val file = File(outputPath)
                file.exists() && file.length() > 0
            } catch (e: Exception) {
                false
            }
        }
}
