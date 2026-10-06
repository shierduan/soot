package com.recovery.app.recovery

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import com.recovery.app.model.Confidence
import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoveryType
import com.recovery.app.model.ScanMode
import com.recovery.app.model.ScanSettings
import com.recovery.app.recovery.signatures.ExtensionResolver
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
        data class Progress(
            val scannedBytes: Long,
            val totalBytes: Long,
            val speedBytesPerSec: Long = 0,
            val etaMs: Long = 0
        ) : ScanEvent()
    }

    /**
     * 扫描指定分区
     *
     * 性能策略：
     *  - DEEP/RANGE：单个 su 进程流式 dd，持续读取 16MB 缓冲区，消除逐次 su 开销
     *  - QUICK：单 su 进程内 shell 循环稀疏采样，真正减少 I/O
     *
     * @param onLog 日志回调
     */
    fun scanPartition(
        device: String,
        types: Set<RecoveryType>,
        settings: ScanSettings = ScanSettings(),
        onLog: (String) -> Unit = {}
    ): Flow<ScanEvent> = flow {
        val targetSignatures = SignatureRegistry.signatures.filter { it.type in types }
        if (targetSignatures.isEmpty()) return@flow

        // 获取分区大小
        val partitionSize = getPartitionSize(device)
        if (partitionSize <= 0) {
            onLog("无法获取分区 $device 大小")
            return@flow
        }

        // 计算扫描范围 [startOffset, scanSize)
        val (startOffset, scanSize, modeDesc) = computeScanRange(partitionSize, settings)
        onLog("分区大小: ${formatBytes(partitionSize)}, 模式: $modeDesc, " +
                "范围: ${formatBytes(startOffset)} ~ ${formatBytes(startOffset + scanSize)}")

        val minBytes = settings.minFileSizeKb * 1024L
        val maxBytes = settings.maxFileSizeMb * 1024L * 1024L
        val seenOffsets = HashSet<Long>()
        var idCounter = 0L

        when (settings.mode) {
            ScanMode.DEEP, ScanMode.RANGE -> {
                // 顺序流式扫描
                val process = RootShell.openBlockStream(device, startOffset, scanSize)
                if (process == null) {
                    onLog("无法打开块设备流")
                    return@flow
                }
                onLog("已打开块设备流，开始顺序扫描...")
                try {
                    streamSequentialScan(
                        process, device, startOffset, scanSize, types, settings,
                        minBytes, maxBytes, seenOffsets, idCounter,
                        onLog
                    ) { evt -> emit(evt); if (evt is ScanEvent.FileFound) idCounter++ }
                } finally {
                    runCatching { process.destroy() }
                }
            }
            ScanMode.QUICK -> {
                // 稀疏采样扫描
                val process = RootShell.openSparseScanStream(
                    device, partitionSize, settings.sampleBytes, settings.gapBytes
                )
                if (process == null) {
                    onLog("无法打开稀疏扫描流")
                    return@flow
                }
                onLog("已打开稀疏扫描流（采样 ${formatBytes(settings.sampleBytes)} / 跳过 ${formatBytes(settings.gapBytes)}）")
                try {
                    streamSparseScan(
                        process, device, partitionSize, settings.sampleBytes, settings.gapBytes,
                        types, settings, minBytes, maxBytes, seenOffsets, idCounter,
                        onLog
                    ) { evt -> emit(evt); if (evt is ScanEvent.FileFound) idCounter++ }
                } finally {
                    runCatching { process.destroy() }
                }
            }
        }
        onLog("扫描完成")
    }.flowOn(Dispatchers.IO)

    /**
     * 计算扫描范围
     * @return Triple(startOffset, scanSize, 描述)
     */
    private fun computeScanRange(partitionSize: Long, settings: ScanSettings): Triple<Long, Long, String> {
        val bs = 4096L
        return when (settings.mode) {
            ScanMode.DEEP -> Triple(0L, partitionSize, "深度扫描")
            ScanMode.RANGE -> {
                val start = (partitionSize * settings.rangeStartPercent / 100).toLong()
                val end = (partitionSize * settings.rangeEndPercent / 100).toLong()
                val alignedStart = (start / bs) * bs
                val size = (end - alignedStart).coerceAtLeast(0)
                Triple(alignedStart, size,
                    "范围扫描 ${settings.rangeStartPercent.toInt()}%~${settings.rangeEndPercent.toInt()}%")
            }
            ScanMode.QUICK -> Triple(0L, partitionSize, "快速扫描(稀疏采样)")
        }
    }

    /**
     * 顺序流式扫描（DEEP / RANGE）
     */
    private suspend fun streamSequentialScan(
        process: Process,
        device: String,
        startOffset: Long,
        scanSize: Long,
        types: Set<RecoveryType>,
        settings: ScanSettings,
        minBytes: Long,
        maxBytes: Long,
        seenOffsets: HashSet<Long>,
        startId: Long,
        onLog: (String) -> Unit,
        emit: suspend (ScanEvent) -> Unit
    ) {
        val input = process.inputStream
        val readBuffer = ByteArray(bufferSize)
        val overlap = ByteArray(overlapSize)
        var overlapLen = 0
        var scanned = 0L
        var idCounter = startId
        var lastProgressEmit = 0L
        val rateTracker = RateTracker()

        while (scanned < scanSize) {
            val toRead = minOf(readBuffer.size, (scanSize - scanned).toInt())
            val n = input.read(readBuffer, 0, toRead)
            if (n <= 0) break

            // 合并 overlap + 新数据
            val combined = ByteArray(overlapLen + n)
            if (overlapLen > 0) overlap.copyInto(combined, 0, 0, overlapLen)
            readBuffer.copyInto(combined, overlapLen, 0, n)
            val actualLen = combined.size

            val bufferBaseOffset = startOffset + scanned - overlapLen
            processBuffer(
                combined, actualLen, bufferBaseOffset, device, types, settings,
                minBytes, maxBytes, seenOffsets
            ) { file ->
                emit(ScanEvent.FileFound(file.copy(id = ++idCounter)))
            }

            // 保存尾部 overlap
            overlapLen = minOf(overlapSize, actualLen)
            combined.copyInto(overlap, 0, actualLen - overlapLen, actualLen)

            scanned += n

            // 限流进度上报（每 1MB 或每 200ms）
            val now = System.currentTimeMillis()
            if (scanned - lastProgressEmit >= 1024 * 1024 || now - lastProgressEmit > 200) {
                val absScanned = startOffset + scanned
                val absTotal = startOffset + scanSize
                rateTracker.addSample(now, absScanned)
                emit(
                    ScanEvent.Progress(
                        scannedBytes = absScanned,
                        totalBytes = absTotal,
                        speedBytesPerSec = rateTracker.speedBytesPerSec(),
                        etaMs = rateTracker.etaMs(absScanned, absTotal)
                    )
                )
                lastProgressEmit = scanned
            }
        }
        val finalAbs = startOffset + scanSize
        emit(ScanEvent.Progress(finalAbs, finalAbs, 0, 0))
    }

    /**
     * 稀疏采样扫描（QUICK）
     * 每次读取 sampleBytes（对齐到 4096），对应分区偏移 = sampleIndex * (sample+gap)
     */
    private suspend fun streamSparseScan(
        process: Process,
        device: String,
        partitionSize: Long,
        sampleBytes: Long,
        gapBytes: Long,
        types: Set<RecoveryType>,
        settings: ScanSettings,
        minBytes: Long,
        maxBytes: Long,
        seenOffsets: HashSet<Long>,
        startId: Long,
        onLog: (String) -> Unit,
        emit: suspend (ScanEvent) -> Unit
    ) {
        val input = process.inputStream
        val step = sampleBytes + gapBytes
        val sampleAligned = ((sampleBytes + 4095) / 4096) * 4096
        val sampleBuf = ByteArray(sampleAligned.toInt())
        var sampleIndex = 0L
        var idCounter = startId
        var lastProgressEmit = 0L
        val rateTracker = RateTracker()
        var actualBytesRead = 0L  // 实际读取的字节数（用于速率计算）

        while (true) {
            val expectedOffset = sampleIndex * step
            if (expectedOffset >= partitionSize) break

            // 读取一个采样块
            var totalRead = 0
            while (totalRead < sampleBuf.size) {
                val n = input.read(sampleBuf, totalRead, sampleBuf.size - totalRead)
                if (n <= 0) break
                totalRead += n
            }
            if (totalRead <= 0) break

            actualBytesRead += totalRead

            val actualLen = totalRead
            processBuffer(
                sampleBuf, actualLen, expectedOffset, device, types, settings,
                minBytes, maxBytes, seenOffsets
            ) { file ->
                emit(ScanEvent.FileFound(file.copy(id = ++idCounter)))
            }

            sampleIndex++
            val scannedEstimate = sampleIndex * step
            val now = System.currentTimeMillis()
            if (now - lastProgressEmit > 300) {
                val absScanned = scannedEstimate.coerceAtMost(partitionSize)
                // 速率用实际读取字节计算
                rateTracker.addSample(now, actualBytesRead)
                val speed = rateTracker.speedBytesPerSec()
                // ETA 用实际剩余字节计算：剩余虚拟字节 * (sample/step) 即为待读实际字节
                val remainingVirtual = (partitionSize - absScanned).coerceAtLeast(0)
                val remainingActual = (remainingVirtual * sampleBytes / step).coerceAtLeast(0)
                val eta = if (speed > 0) remainingActual * 1000L / speed else 0L
                emit(
                    ScanEvent.Progress(
                        scannedBytes = absScanned,
                        totalBytes = partitionSize,
                        speedBytesPerSec = speed,
                        etaMs = eta
                    )
                )
                lastProgressEmit = now
            }
        }
        emit(ScanEvent.Progress(partitionSize, partitionSize, 0, 0))
    }

    /**
     * 在缓冲区中查找文件签名并发射
     *
     * 智能跳过策略：
     *  1. 先扫描所有签名（目标 + 非目标）
     *  2. 对非目标类型中结构有效且体积 > skipThreshold 的文件，
     *     记录其占用区间 [offset, offset+size] 为跳过区
     *  3. 目标类型签名若落在跳过区内则跳过（极可能是大文件内部的字节，非独立文件）
     *
     * 收益：减少误报 + 节省目标匹配的 CPU 开销（尤其只扫图片时跳过视频区间）
     */
    private suspend fun processBuffer(
        buffer: ByteArray,
        len: Int,
        bufferBaseOffset: Long,
        device: String,
        types: Set<RecoveryType>,
        settings: ScanSettings,
        minBytes: Long,
        maxBytes: Long,
        seenOffsets: HashSet<Long>,
        emit: suspend (RecoverableFile) -> Unit
    ) {
        if (len < 16) return
        val allMatches = SignatureRegistry.findMatches(buffer)
        if (allMatches.isEmpty()) return

        // 阈值：非目标文件超过此大小才建立跳过区间（过小文件跳过无意义）
        val skipThreshold = 256L * 1024 // 256KB

        // 第一阶段：收集非目标大文件的占用区间
        val skipRegions = ArrayList<Pair<Long, Long>>()
        for ((sig, bufIndex) in allMatches) {
            if (sig.type in types) continue
            if (!validateStructure(sig, buffer, bufIndex, len)) continue
            val est = estimateFileSize(sig, buffer, bufIndex, len)
            if (est < skipThreshold || est > sig.maxSize) continue
            val start = bufferBaseOffset + bufIndex
            skipRegions.add(start to (start + est))
        }

        // 判断偏移是否落在任一跳过区间内
        val inSkipRegion: (Long) -> Boolean = { offset ->
            skipRegions.any { (s, e) -> offset in s until e }
        }

        // 第二阶段：处理目标类型签名，跳过落在非目标大文件区间内的匹配
        for ((sig, bufIndex) in allMatches) {
            if (sig.type !in types) continue
            val absoluteOffset = bufferBaseOffset + bufIndex
            if (settings.dedupeEnabled && !seenOffsets.add(absoluteOffset)) continue
            if (inSkipRegion(absoluteOffset)) continue
            if (!validateStructure(sig, buffer, bufIndex, len)) continue

            val estimatedSize = estimateFileSize(sig, buffer, bufIndex, len)
            if (estimatedSize < minBytes || estimatedSize > maxBytes) continue
            if (estimatedSize > sig.maxSize) continue

            val confidence = computeConfidence(sig, buffer, bufIndex, len)
            if (settings.onlyHighConfidence && confidence == Confidence.LOW) continue

            val headerLen = minOf(512, estimatedSize.toInt())
            val headerBytes = if (bufIndex + headerLen <= len) {
                buffer.copyOfRange(bufIndex, minOf(bufIndex + headerLen, len))
            } else ByteArray(0)

            // 逆向还原精确扩展名（ZIP→docx/xlsx/pptx, RIFF→webp/avi/wav, ftyp→mp4/mov/3gp...）
            val (resolvedExt, resolvedMime) = if (headerBytes.size >= 8) {
                ExtensionResolver.resolve(headerBytes, sig)
            } else {
                sig.extension to sig.mimeType
            }

            val thumbnail = if (sig.type == RecoveryType.IMAGE) {
                decodeThumbnail(buffer, bufIndex, len)
            } else null

            emit(
                RecoverableFile(
                    id = 0, // id 在调用方赋值
                    type = sig.type,
                    mimeType = resolvedMime,
                    extension = resolvedExt,
                    offset = absoluteOffset,
                    estimatedSize = estimatedSize,
                    headerBytes = headerBytes,
                    source = device,
                    confidence = confidence,
                    thumbnail = thumbnail
                )
            )
        }
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024L * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024))} MB"
        else -> "${"%.2f".format(bytes / (1024.0 * 1024 * 1024))} GB"
    }

    /**
     * 滑动窗口速率计算器
     * 保留最近 windowMs 毫秒内的 (时间戳, 已扫描字节) 样本，
     * 计算平均速率并估算剩余时间。
     */
    private class RateTracker(private val windowMs: Long = 5000) {
        private val samples = ArrayDeque<Pair<Long, Long>>() // (timestamp, scannedBytes)

        fun addSample(timestamp: Long, scannedBytes: Long) {
            samples.addLast(timestamp to scannedBytes)
            val cutoff = timestamp - windowMs
            while (samples.isNotEmpty() && samples.first().first < cutoff) {
                samples.removeFirst()
            }
        }

        /** 平均速率（字节/秒），0 表示样本不足 */
        fun speedBytesPerSec(): Long {
            if (samples.size < 2) return 0
            val (t0, b0) = samples.first()
            val (t1, b1) = samples.last()
            val dt = t1 - t0
            if (dt <= 0) return 0
            return (b1 - b0) * 1000L / dt
        }

        /** 估算剩余时间（毫秒），0 表示无法估算 */
        fun etaMs(scannedBytes: Long, totalBytes: Long): Long {
            val speed = speedBytesPerSec()
            if (speed <= 0) return 0
            val remaining = (totalBytes - scannedBytes).coerceAtLeast(0)
            return remaining * 1000L / speed
        }
    }

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
