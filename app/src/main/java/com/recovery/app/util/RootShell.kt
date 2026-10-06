package com.recovery.app.util

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Root Shell 工具
 * 用于执行需要 root 权限的命令。
 *
 * 核心策略：
 *  - 通过 "su" 启动交互式 shell
 *  - 读取 /proc/partitions 和块设备节点获取存储分区
 *  - 使用 dd 读取原始分区数据
 *  - 读取受保护的 SQLite 数据库
 */
object RootShell {

    private var suProcess: Process? = null
    private var available: Boolean? = null

    /**
     * 检查设备是否已 root
     */
    suspend fun isRootAvailable(): Boolean {
        if (available != null) return available!!
        return withContext(Dispatchers.IO) {
            try {
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
                val output = BufferedReader(InputStreamReader(process.inputStream)).readText()
                val ok = output.contains("uid=0")
                process.waitFor()
                available = ok
                ok
            } catch (e: Exception) {
                available = false
                false
            }
        }
    }

    /**
     * 执行单条 root 命令并返回输出
     */
    suspend fun execute(command: String): String = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
            val output = BufferedReader(InputStreamReader(process.inputStream)).readText()
            val error = BufferedReader(InputStreamReader(process.errorStream)).readText()
            process.waitFor()
            if (process.exitValue() != 0) error else output
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * 获取所有存储分区设备路径
     */
    suspend fun getBlockDevices(): List<String> = withContext(Dispatchers.IO) {
        val output = execute("ls -la /dev/block/by-name/ 2>/dev/null || ls /dev/block/mmcblk0* 2>/dev/null")
        output.lines().mapNotNull { line ->
            val parts = line.trim().split(Regex("\\s+"))
            // 匹配 /dev/block/... 路径
            parts.firstOrNull { it.startsWith("/dev/") && !it.contains("by-name") }
        }.distinct().filter { it.isNotBlank() }
    }

    /**
     * 获取 userdata 分区路径（通常是最大的可写分区）
     */
    suspend fun getUserdataPartition(): String? = withContext(Dispatchers.IO) {
        // 优先按名称查找
        val byName = execute("ls -la /dev/block/by-name/userdata 2>/dev/null")
        val linkMatch = Regex("->\\s*(\\S+)").find(byName)
        if (linkMatch != null) {
            val target = linkMatch.groupValues[1]
            if (target.startsWith("/")) return@withContext target
            return@withContext "/dev/block/by-name/$target"
        }
        // 回退：查找最大的 mmc 分区
        val partitions = execute("cat /proc/partitions").lines()
        var best: String? = null
        var bestSize = 0L
        for (line in partitions) {
            val cols = line.trim().split(Regex("\\s+"))
            if (cols.size >= 4 && cols[3].startsWith("mmc")) {
                val size = cols[2].toLongOrNull() ?: continue
                val name = cols[3]
                // 过滤掉主设备（带 p 后缀的是分区）
                if (size > bestSize && name.contains("p")) {
                    bestSize = size
                    best = "/dev/block/$name"
                }
            }
        }
        best
    }

    /**
     * 从指定偏移读取原始字节（通过 dd）
     *
     * 优化：使用 bs=4096 大块读取，比 bs=1 快数千倍。
     * 对于非对齐偏移，先按块读取再截断。
     */
    suspend fun readBytes(device: String, offset: Long, size: Int): ByteArray = withContext(Dispatchers.IO) {
        try {
            val bs = 4096L
            val skipBlocks = offset / bs
            val skipRemainder = (offset % bs).toInt()
            val totalBytes = skipRemainder + size
            val countBlocks = (totalBytes + bs - 1) / bs

            val process = Runtime.getRuntime().exec(
                arrayOf(
                    "su", "-c",
                    "dd if=$device bs=$bs skip=$skipBlocks count=$countBlocks 2>/dev/null"
                )
            )
            val raw = process.inputStream.readBytes()
            process.waitFor()
            // 跳过前缀余数，返回所需长度
            if (raw.size > skipRemainder) {
                raw.copyOfRange(skipRemainder, minOf(skipRemainder + size, raw.size))
            } else {
                ByteArray(0)
            }
        } catch (e: Exception) {
            ByteArray(0)
        }
    }

    /**
     * 打开一个持续输出原始字节的进程流（用于顺序深度/范围扫描）
     *
     * 单个 su 进程执行 dd，从 startOffset 开始输出 size 字节，
     * 调用方持续读取其 inputStream，避免逐次 su 进程开销。
     *
     * @return Process（需调用方负责读取并销毁）
     */
    fun openBlockStream(device: String, startOffset: Long, size: Long): Process? {
        return try {
            val bs = 4096L
            val skipBlocks = startOffset / bs
            val countBlocks = (size + bs - 1) / bs
            Runtime.getRuntime().exec(
                arrayOf(
                    "su", "-c",
                    "dd if=$device bs=$bs skip=$skipBlocks count=$countBlocks 2>/dev/null"
                )
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 构建稀疏采样扫描的 shell 命令（用于 QUICK 模式）
     *
     * 在单个 su 进程内通过 shell while 循环，每隔 (sample+gap) 字节读取 sample 字节，
     * 真正减少 I/O（而非读后丢弃）。所有采样数据连续输出到 stdout。
     */
    fun buildSparseScanCommand(
        device: String,
        totalSize: Long,
        sampleBytes: Long,
        gapBytes: Long
    ): String {
        val bs = 4096
        val step = sampleBytes + gapBytes
        // bash while 循环：pos 从 0 到 totalSize，每次读 sample 字节
        return "pos=0; step=$step; sample=$sampleBytes; bs=$bs; " +
                "total=$totalSize; " +
                "while [ \$pos -lt \$total ]; do " +
                "dd if=$device bs=\$bs skip=\$((pos/bs)) count=\$(((sample+bs-1)/bs)) 2>/dev/null; " +
                "pos=\$((pos+step)); done"
    }

    /**
     * 执行稀疏采样命令并返回进程
     */
    fun openSparseScanStream(
        device: String,
        totalSize: Long,
        sampleBytes: Long,
        gapBytes: Long
    ): Process? {
        return try {
            val cmd = buildSparseScanCommand(device, totalSize, sampleBytes, gapBytes)
            Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 将受保护的数据库复制到临时可读路径
     */
    suspend fun copyProtectedFile(remotePath: String, tempPath: String): Boolean {
        val result = execute("cp $remotePath $tempPath && chmod 644 $tempPath")
        return result.isEmpty()
    }
}
