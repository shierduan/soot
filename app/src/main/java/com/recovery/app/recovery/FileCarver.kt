package com.recovery.app.recovery

import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoveryType
import com.recovery.app.recovery.signatures.FileSignature
import com.recovery.app.recovery.signatures.SignatureRegistry
import com.recovery.app.util.RootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import kotlin.math.max

/**
 * 文件雕刻引擎（File Carving Engine）
 *
 * 原理：当文件被删除时，文件系统仅删除文件索引（inode/dentry），
 * 但实际数据块可能仍然存在于存储介质上。本引擎通过直接读取
 * 原始块设备（需 root），扫描文件魔数（magic bytes）来识别
 * 并恢复已删除的文件。
 *
 * 支持类型：图片(JPEG/PNG/GIF/WebP/BMP/HEIC)、
 *           视频(MP4/3GP/MKV/AVI/FLV)、音频、文档、压缩包。
 */
class FileCarver {

    // 扫描缓冲区大小：8MB（平衡 I/O 与内存）
    private val bufferSize = 8 * 1024 * 1024

    // 重叠区域大小：确保跨缓冲区边界的文件头不被遗漏
    private val overlapSize = 64 * 1024

    /**
     * 扫描指定分区，返回恢复文件的 Flow
     *
     * @param device 块设备路径，如 /dev/block/mmcblk0p42
     * @param types 要恢复的文件类型
     * @return Flow 发射 RecoverableFile
     */
    fun scanPartition(device: String, types: Set<RecoveryType>): Flow<RecoverableFile> = flow {
        val targetSignatures = if (types.contains(RecoveryType.IMAGE) ||
            types.contains(RecoveryType.VIDEO)) {
            SignatureRegistry.signatures.filter { it.type in types }
        } else {
            SignatureRegistry.signatures.filter { it.type in types }
        }

        if (targetSignatures.isEmpty()) return@flow

        // 获取分区大小
        val sizeInfo = RootShell.execute("blockdev --getsize64 $device 2>/dev/null")
        val partitionSize = sizeInfo.trim().toLongOrNull() ?: run {
            // 备用：从 /proc/partitions 获取
            val name = device.substringAfterLast("/")
            val parts = RootShell.execute("grep $name /proc/partitions").trim().split(Regex("\\s+"))
            if (parts.size >= 3) (parts[2].toLongOrNull() ?: 0) * 1024 else 0L
        }

        if (partitionSize <= 0) return@flow

        var offset = 0L
        var idCounter = 0L
        val overlap = ByteArray(overlapSize)
        var overlapLen = 0

        while (offset < partitionSize) {
            val toRead = minOf(bufferSize.toLong(), partitionSize - offset).toInt()
            val buffer = ByteArray(toRead + overlapLen)

            // 复制上一次的重叠部分
            if (overlapLen > 0) {
                overlap.copyInto(buffer, 0, 0, overlapLen)
            }

            // 读取新数据
            val newBytes = RootShell.readBytes(device, offset, toRead)
            newBytes.copyInto(buffer, overlapLen)

            val actualLen = overlapLen + newBytes.size
            if (actualLen < 16) break

            // 缓冲区对应的分区起始偏移
            val bufferBaseOffset = offset - overlapLen

            // 在缓冲区中搜索文件签名
            val matches = SignatureRegistry.findMatches(buffer)

            for ((sig, bufIndex) in matches) {
                if (sig.type !in types) continue

                // 估算文件大小（基于缓冲区索引）
                val estimatedSize = estimateFileSize(
                    sig, buffer, bufIndex, actualLen
                )

                if (estimatedSize > 0 && estimatedSize <= sig.maxSize) {
                    // 读取文件头用于预览
                    val headerLen = minOf(512, estimatedSize.toInt())
                    val headerBytes = if (bufIndex + headerLen <= actualLen) {
                        buffer.copyOfRange(bufIndex, minOf(bufIndex + headerLen, actualLen))
                    } else {
                        ByteArray(0)
                    }

                    emit(
                        RecoverableFile(
                            id = ++idCounter,
                            type = sig.type,
                            mimeType = sig.mimeType,
                            extension = sig.extension,
                            offset = bufferBaseOffset + bufIndex,
                            estimatedSize = estimatedSize,
                            headerBytes = headerBytes,
                            source = device
                        )
                    )
                }
            }

            // 保存尾部重叠
            overlapLen = minOf(overlapSize, actualLen)
            buffer.copyInto(overlap, 0, actualLen - overlapLen, actualLen)

            offset += toRead
        }
    }.flowOn(Dispatchers.IO)

    /**
     * 估算文件大小
     * 策略：
     *  1. 如果有 footer，在缓冲区中向前搜索 footer
     *  2. 对于 ISO Base Media (MP4)，从 ftyp box 解析尺寸
     *  3. 对于 RIFF，从头部读取大小字段
     *  4. 回退到默认估算值
     */
    private fun estimateFileSize(
        sig: FileSignature,
        buffer: ByteArray,
        fileOffset: Int,
        bufferLen: Int
    ): Long {
        // 1. 有 footer 时搜索
        sig.footer?.let { footer ->
            val searchStart = fileOffset + sig.header.size + sig.headerOffset
            val searchEnd = minOf(bufferLen, fileOffset + sig.maxSize.toInt())
            for (i in searchStart until searchEnd - footer.size) {
                var match = true
                for (j in footer.indices) {
                    if (buffer[i + j] != footer[j]) {
                        match = false
                        break
                    }
                }
                if (match) {
                    return (i - fileOffset + footer.size).toLong()
                }
            }
        }

        // 2. ISO Base Media (MP4/MOV/3GP/HEIC)：解析 box size
        if (sig.mimeType.startsWith("video/") || sig.extension == "heic") {
            return parseIsoBoxSize(buffer, fileOffset, sig)
        }

        // 3. RIFF 容器 (WebP/AVI/WAV)：4字节大小在偏移4处
        if (sig.header.contentEquals(byteArrayOf(0x52, 0x49, 0x46, 0x46))) {
            if (fileOffset + 8 <= bufferLen) {
                val riffSize = readUInt32LE(buffer, fileOffset + 4)
                if (riffSize in 0..sig.maxSize) return riffSize + 8
            }
        }

        // 4. PNG：从 IHDR 块估算，默认用 maxSize 的小比例
        if (sig.extension == "png") {
            // PNG chunks: length(4) type(4) data length
            if (fileOffset + 24 <= bufferLen) {
                val ihdrLen = readUInt32BE(buffer, fileOffset + 8)
                if (ihdrLen in 0..0x7FFFFFFF) {
                    // 粗略估算：PNG 通常几 MB
                    return minOf(sig.maxSize, ihdrLen + 1024L)
                }
            }
        }

        // 5. 回退：使用合理的默认估算值
        return defaultEstimate(sig)
    }

    /**
     * 解析 ISO Base Media File Format (MP4/MOV/3GP/HEIC) 的文件大小
     *
     * MP4 文件结构：
     *  - 每个 box = [size(4字节BE)][type(4字节)][data]
     *  - 文件以 ftyp box 开头（type 在偏移4处）
     *  - size=0 表示到文件末尾，size=1 表示使用 64 位扩展大小
     */
    private fun parseIsoBoxSize(buffer: ByteArray, fileOffset: Int, sig: FileSignature): Long {
        // fileOffset 指向 header 的实际位置（可能有 headerOffset）
        val boxStart = fileOffset - sig.headerOffset
        if (boxStart < 0 || boxStart + 8 > buffer.size) return defaultEstimate(sig)

        var size = readUInt32BE(buffer, boxStart).toLong()
        when {
            size == 0L -> {
                // 到文件末尾，使用最大估算
                return defaultEstimate(sig)
            }
            size == 1L -> {
                // 64 位扩展大小，在偏移 8 处
                if (boxStart + 16 <= buffer.size) {
                    size = readUInt64BE(buffer, boxStart + 8)
                } else {
                    return defaultEstimate(sig)
                }
            }
        }

        if (size in 8..sig.maxSize) return size
        return defaultEstimate(sig)
    }

    /**
     * 默认文件大小估算（按类型经验值）
     */
    private fun defaultEstimate(sig: FileSignature): Long = when (sig.type) {
        RecoveryType.IMAGE -> 3L * 1024 * 1024      // 图片约 3MB
        RecoveryType.VIDEO -> 100L * 1024 * 1024     // 视频约 100MB
        RecoveryType.AUDIO -> 5L * 1024 * 1024       // 音频约 5MB
        RecoveryType.DOCUMENT -> 2L * 1024 * 1024    // 文档约 2MB
        RecoveryType.ARCHIVE -> 50L * 1024 * 1024    // 压缩包约 50MB
        else -> 1L * 1024 * 1024
    }

    /** 读取 32 位无符号大端整数 */
    private fun readUInt32BE(buffer: ByteArray, offset: Int): Long {
        return ((buffer[offset].toLong() and 0xFF) shl 24) or
                ((buffer[offset + 1].toLong() and 0xFF) shl 16) or
                ((buffer[offset + 2].toLong() and 0xFF) shl 8) or
                (buffer[offset + 3].toLong() and 0xFF)
    }

    /** 读取 32 位无符号小端整数 */
    private fun readUInt32LE(buffer: ByteArray, offset: Int): Long {
        return (buffer[offset].toLong() and 0xFF) or
                ((buffer[offset + 1].toLong() and 0xFF) shl 8) or
                ((buffer[offset + 2].toLong() and 0xFF) shl 16) or
                ((buffer[offset + 3].toLong() and 0xFF) shl 24)
    }

    /** 读取 64 位无符号大端整数 */
    private fun readUInt64BE(buffer: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 8) {
            value = (value shl 8) or (buffer[offset + i].toLong() and 0xFF)
        }
        return value
    }

    /**
     * 将恢复的文件保存到指定路径
     */
    suspend fun saveRecoveredFile(item: RecoverableFile, outputPath: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                // 通过 dd 从原始分区读取文件数据并写入输出文件
                val result = RootShell.execute(
                    "dd if=${item.source} of=$outputPath bs=1 skip=${item.offset} " +
                            "count=${item.estimatedSize} 2>/dev/null"
                )
                val file = File(outputPath)
                file.exists() && file.length() > 0
            } catch (e: Exception) {
                false
            }
        }
}
