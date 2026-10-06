package com.recovery.app.secure

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile

/**
 * 安全删除工具
 *
 * 通过覆写文件内容为 0（或随机数据）后再删除，
 * 使已删除的数据无法通过数据雕刻（file carving）恢复。
 *
 * 安全删除流程：
 *  1. 验证锁屏密码（由 CredentialVerifier 完成）
 *  2. 以可写模式打开文件
 *  3. 分块覆写文件内容为 0x00
 *  4. 强制 flush + fsync，确保数据写入物理介质
 *  5. 截断文件为 0 长度
 *  6. 删除文件
 *
 * 注意：
 *  - 对于日志型文件系统（如 F2FS）和 SSD，覆写可能无法完全消除数据，
 *    因为磨损均衡可能将数据写入其他物理块。
 *  - 对于 ext4 等传统文件系统，覆写通常有效。
 *  - 建议多次覆写（DoD 5220.22-M 标准为 3 次）。
 */
object SecureDelete {

    /**
     * 安全删除单个文件
     *
     * @param path 文件路径
     * @param passes 覆写次数（默认 3 次，符合 DoD 标准）
     * @param useRandom 是否使用随机数据（true=随机，false=零填充）
     * @return 是否成功
     */
    suspend fun deleteFile(
        path: String,
        passes: Int = 3,
        useRandom: Boolean = false
    ): Boolean = withContext(Dispatchers.IO) {
        val file = File(path)
        if (!file.exists() || !file.isFile) return@withContext false

        try {
            val fileSize = file.length()

            // 多轮覆写
            for (pass in 1..passes) {
                overwriteFile(file, fileSize, useRandom, pass)
            }

            // 截断为 0
            RandomAccessFile(file, "rws").use { raf ->
                raf.setLength(0)
                raf.fd.sync()
            }

            // 删除文件
            file.delete()
            !file.exists()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 安全删除目录下所有文件
     */
    suspend fun deleteDirectory(
        dirPath: String,
        passes: Int = 3,
        useRandom: Boolean = false,
        onProgress: (String) -> Unit
    ): Int = withContext(Dispatchers.IO) {
        val dir = File(dirPath)
        if (!dir.exists() || !dir.isDirectory) return@withContext 0

        var deleted = 0
        dir.walkTopDown().filter { it.isFile }.forEach { file ->
            onProgress("正在安全删除: ${file.name}")
            if (deleteFile(file.absolutePath, passes, useRandom)) {
                deleted++
            }
        }
        deleted
    }

    /**
     * 覆写文件内容
     */
    private fun overwriteFile(file: File, fileSize: Long, useRandom: Boolean, pass: Int) {
        val bufferSize = 64 * 1024 // 64KB 缓冲区
        val buffer = ByteArray(bufferSize)

        // 填充缓冲区
        if (useRandom) {
            java.security.SecureRandom().nextBytes(buffer)
        } else {
            // 零填充：默认全 0
        }

        RandomAccessFile(file, "rws").use { raf ->
            raf.seek(0)
            var remaining = fileSize
            while (remaining > 0) {
                val toWrite = minOf(bufferSize.toLong(), remaining).toInt()
                raf.write(buffer, 0, toWrite)
                remaining -= toWrite
            }
            raf.fd.sync()
        }
    }

    /**
     * 检查文件是否可以被安全删除（存在且可写）
     */
    fun canDelete(path: String): Boolean {
        val file = File(path)
        return file.exists() && file.isFile && file.canWrite()
    }
}
