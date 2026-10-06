package com.recovery.app.recovery

import com.recovery.app.model.RecoverableRecord
import com.recovery.app.model.RecoveryType
import com.recovery.app.util.RootShell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * SQLite 已删除记录恢复引擎
 *
 * 原理：SQLite 将数据组织为固定大小的页（默认 4096 字节）。
 * 当记录被删除时，SQLite 并不会清零数据，而是：
 *  1. 将该页加入空闲页链表（freelist）
 *  2. 在页内将记录所占空间标记为 freeblock
 *  3. 修改页头的 cell 指针数组
 *
 * 因此，已删除的记录数据仍然残留在：
 *  - 空闲页（freelist trunk/leaf pages）
 *  - 页内的 freeblock 区域
 *  - 页内 cell 内容区末尾到页尾的未分配空间
 *
 * 本引擎直接解析 SQLite 文件格式，从这些区域中扫描并恢复已删除的记录。
 *
 * 参考：SQLite Database File Format (https://www.sqlite.org/fileformat.html)
 *       "Making the Invisible Visible - Recovering Deleted SQLite Data Records"
 */
class SQLiteRecovery {

    companion object {
        // SQLite 数据库头魔数
        private val SQLITE_HEADER = "SQLite format 3\u0000".toByteArray()

        // 页类型常量
        private const val PAGE_LEAF_TABLE = 0x0D
        private const val PAGE_LEAF_INDEX = 0x0A
        private const val PAGE_INTERIOR_TABLE = 0x05
        private const val PAGE_INTERIOR_INDEX = 0x02
    }

    /**
     * 恢复指定 SQLite 数据库中的已删除记录
     *
     * @param dbPath 数据库文件路径
     * @param type 记录类型（用于分类）
     * @return 恢复的记录列表
     */
    suspend fun recoverDeletedRecords(dbPath: String, type: RecoveryType): List<RecoverableRecord> =
        withContext(Dispatchers.IO) {
            // 检查是否为有效 SQLite 数据库
            val file = File(dbPath)
            if (!file.exists() || file.length() < 100) return@withContext emptyList()

            try {
                RandomAccessFile(file, "r").use { raf ->
                    val header = ByteArray(100)
                    raf.read(header)

                    // 验证 SQLite 魔数
                    if (!header.copyOfRange(0, 16).contentEquals(SQLITE_HEADER)) {
                        return@withContext emptyList()
                    }

                    // 解析数据库头
                    val pageSize = parsePageSize(header)
                    val reservedSize = header[20].toInt() and 0xFF
                    val firstFreeTrunkPage = readUInt32BE(header, 32)
                    val totalFreePages = readUInt32BE(header, 36)

                    val usablePageSize = pageSize - reservedSize
                    val records = mutableListOf<RecoverableRecord>()
                    val idCounter = java.util.concurrent.atomic.AtomicLong(0)

                    // 策略1：扫描空闲页链表
                    if (firstFreeTrunkPage > 0) {
                        scanFreePages(raf, pageSize, usablePageSize, firstFreeTrunkPage, type, records, idCounter)
                    }

                    // 策略2：扫描所有页的未分配空间和 freeblock
                    val totalPages = file.length() / pageSize
                    for (pageNum in 1..totalPages) {
                        scanPageUnallocated(raf, pageNum, pageSize, usablePageSize, type, records, idCounter)
                    }

                    records
                }
            } catch (e: Exception) {
                emptyList()
            }
        }

    /**
     * 解析页大小（偏移 16，2 字节大端；1 表示 65536）
     */
    private fun parsePageSize(header: ByteArray): Int {
        val size = ((header[16].toInt() and 0xFF) shl 8) or (header[17].toInt() and 0xFF)
        return if (size == 1) 65536 else size
    }

    /**
     * 扫描空闲页链表中的已删除记录
     *
     * 空闲页链表结构：
     *  - Trunk page: [nextTrunkPage(4)][leafCount(4)][leafPage1(4)][leafPage2(4)]...
     *  - Leaf page: 完全空闲，可能包含旧记录数据
     */
    private fun scanFreePages(
        raf: RandomAccessFile,
        pageSize: Int,
        usablePageSize: Int,
        firstTrunkPage: Long,
        type: RecoveryType,
        records: MutableList<RecoverableRecord>,
        idCounter: java.util.concurrent.atomic.AtomicLong
    ) {
        var currentTrunk = firstTrunkPage

        while (currentTrunk > 0) {
            val trunkData = readPage(raf, currentTrunk, pageSize) ?: break
            val nextTrunk = readUInt32BE(trunkData, 0)
            val leafCount = readUInt32BE(trunkData, 4).toInt()

            // 扫描 trunk page 本身的未使用区域（可能有旧记录碎片）
            scanForRecords(trunkData, 8, usablePageSize - 8, type, records, idCounter, "freelist_trunk")

            // 扫描每个 leaf page
            for (i in 0 until leafCount) {
                val leafPageNum = readUInt32BE(trunkData, 8 + i * 4)
                if (leafPageNum > 0) {
                    val leafData = readPage(raf, leafPageNum, pageSize) ?: continue
                    scanForRecords(leafData, 0, usablePageSize, type, records, idCounter, "freelist_leaf")
                }
            }

            currentTrunk = nextTrunk
        }
    }

    /**
     * 扫描单个页的未分配空间和 freeblock
     *
     * B-tree leaf page 结构：
     *  - 页头 (8 字节)
     *  - Cell pointer array (2 字节 * cellCount)
     *  - Freeblocks (链表)
     *  - Cell content area
     *  - 未分配空间 (cell content area start 到页尾)
     */
    private fun scanPageUnallocated(
        raf: RandomAccessFile,
        pageNum: Long,
        pageSize: Int,
        usablePageSize: Int,
        type: RecoveryType,
        records: MutableList<RecoverableRecord>,
        idCounter: java.util.concurrent.atomic.AtomicLong
    ) {
        val pageData = readPage(raf, pageNum, pageSize) ?: return
        if (pageData.isEmpty()) return

        val pageType = pageData[0].toInt() and 0xFF
        // 只处理表叶子页和索引叶子页
        if (pageType != PAGE_LEAF_TABLE && pageType != PAGE_LEAF_INDEX) return

        val cellCount = readUInt16BE(pageData, 3)
        val cellContentStart = readUInt16BE(pageData, 5)

        // 计算已使用的 cell 区域结束位置
        var cellAreaEnd = cellContentStart
        for (i in 0 until cellCount) {
            val cellOffset = readUInt16BE(pageData, 8 + i * 2)
            if (cellOffset in 1 until usablePageSize) {
                // 读取 cell 的 payload 长度
                val cellLen = parseCellLength(pageData, cellOffset)
                cellAreaEnd = maxOf(cellAreaEnd, cellOffset + cellLen)
            }
        }

        // 未分配空间：从 cellAreaEnd 到 usablePageSize
        if (cellAreaEnd < usablePageSize) {
            scanForRecords(
                pageData, cellAreaEnd, usablePageSize - cellAreaEnd,
                type, records, idCounter, "unallocated"
            )
        }

        // 扫描 freeblock 链表
        var freeblockOffset = readUInt16BE(pageData, 1)
        while (freeblockOffset in 1 until usablePageSize - 4) {
            val nextFreeblock = readUInt16BE(pageData, freeblockOffset)
            val freeblockSize = readUInt16BE(pageData, freeblockOffset + 2)
            if (freeblockSize > 4) {
                scanForRecords(
                    pageData, freeblockOffset + 4, freeblockSize - 4,
                    type, records, idCounter, "freeblock"
                )
            }
            freeblockOffset = nextFreeblock
        }
    }

    /**
     * 解析 cell 的总长度
     * 表叶子页 cell 格式: [payloadLength(varint)][rowid(varint)][payload]
     */
    private fun parseCellLength(pageData: ByteArray, cellOffset: Int): Int {
        try {
            var offset = cellOffset
            val (payloadLen, len1) = readVarint(pageData, offset)
            offset += len1
            if (pageData[0].toInt() and 0xFF == PAGE_LEAF_TABLE) {
                val (_, len2) = readVarint(pageData, offset)
                offset += len2
            }
            // 溢出处理：如果 payload > 大对象阈值，需要读取溢出页
            // 简化处理：返回 payloadLen + header
            return (payloadLen + (offset - cellOffset)).toInt()
        } catch (e: Exception) {
            return 0
        }
    }

    /**
     * 在指定字节区域内扫描可能的 SQLite 记录
     *
     * 策略：尝试将每个偏移处的数据解析为 SQLite 记录格式，
     * 验证其结构合理性（header length、serial type 有效性）。
     */
    private fun scanForRecords(
        data: ByteArray,
        startOffset: Int,
        length: Int,
        type: RecoveryType,
        records: MutableList<RecoverableRecord>,
        idCounter: java.util.concurrent.atomic.AtomicLong,
        source: String
    ) {
        if (length < 4) return

        var pos = startOffset
        val end = startOffset + length

        while (pos < end - 2) {
            // 尝试读取记录头长度（varint）
            val (headerLen, headerLenBytes) = tryReadVarint(data, pos)
            if (headerLen <= 0 || headerLen > length || headerLenBytes <= 0) {
                pos++
                continue
            }

            // 记录头长度应该合理（至少 1，且不超过区域长度）
            if (headerLen < 1 || headerLen > 2048) {
                pos++
                continue
            }

            // 解析记录头中的 serial type
            val headerEnd = pos + headerLen
            if (headerEnd >= end) {
                pos++
                continue
            }

            var headerPos = pos + headerLenBytes
            val serialTypes = mutableListOf<Long>()
            var valid = true

            while (headerPos < headerEnd) {
                val (serialType, stBytes) = tryReadVarint(data, headerPos)
                if (stBytes <= 0) {
                    valid = false
                    break
                }
                // 验证 serial type 有效性
                if (!isValidSerialType(serialType)) {
                    valid = false
                    break
                }
                serialTypes.add(serialType)
                headerPos += stBytes
            }

            if (!valid || serialTypes.isEmpty()) {
                pos++
                continue
            }

            // 计算 payload 长度
            val payloadLen = calculatePayloadLength(serialTypes)
            val totalLen = headerLen + payloadLen

            // 验证总长度合理
            if (totalLen <= 0 || totalLen > length) {
                pos++
                continue
            }

            // 尝试解析记录值
            val fields = parseRecordFields(data, pos, headerLen, serialTypes, type)
            if (fields.isNotEmpty()) {
                records.add(
                    RecoverableRecord(
                        id = idCounter.incrementAndGet(),
                        type = type,
                        fields = fields,
                        source = source
                    )
                )
                pos += totalLen.toInt()
                continue
            }

            pos++
        }
    }

    /**
     * 验证 SQLite serial type 是否有效
     * 0=NULL, 1=8bit, 2=16bit, 3=24bit, 4=32bit, 5=48bit, 6=64bit,
     * 7=float64, 8=0, 9=1, >=12 且为偶数=blob, >=13 且为奇数=text
     */
    private fun isValidSerialType(t: Long): Boolean {
        return when {
            t in 0..9 -> true
            t == 10L || t == 11L -> false  // 保留
            t >= 12 -> true
            else -> false
        }
    }

    /**
     * 根据 serial types 计算 payload 数据区长度
     */
    private fun calculatePayloadLength(serialTypes: List<Long>): Long {
        var len = 0L
        for (st in serialTypes) {
            len += when (st) {
                0L -> 0
                1L -> 1
                2L -> 2
                3L -> 3
                4L -> 4
                5L -> 6
                6L -> 8
                7L -> 8
                8L, 9L -> 0
                else -> if (st >= 12) (st - 12) / 2 else 0
            }
        }
        return len
    }

    /**
     * 解析记录的字段值
     */
    private fun parseRecordFields(
        data: ByteArray,
        recordStart: Int,
        headerLen: Long,
        serialTypes: List<Long>,
        type: RecoveryType
    ): Map<String, String> {
        return try {
            var dataPos = recordStart + headerLen.toInt()
            val values = mutableListOf<String>()

            for (st in serialTypes) {
                val value = when (st) {
                    0L -> "NULL"
                    1L -> readInt8(data, dataPos).toString()
                    2L -> readInt16BE(data, dataPos).toString()
                    3L -> readInt24BE(data, dataPos).toString()
                    4L -> readInt32BE(data, dataPos).toString()
                    5L -> readInt48BE(data, dataPos).toString()
                    6L -> readInt64BE(data, dataPos).toString()
                    7L -> readDoubleBE(data, dataPos).toString()
                    8L -> "0"
                    9L -> "1"
                    else -> {
                        if (st >= 12) {
                            val blobLen = ((st - 12) / 2).toInt()
                            if (dataPos + blobLen > data.size) return emptyMap()
                            val bytes = data.copyOfRange(dataPos, dataPos + blobLen)
                            if (st % 2 == 1L) {
                                // text
                                String(bytes, Charsets.UTF_8).replace("\u0000", "")
                            } else {
                                // blob - 转 hex 预览
                                bytes.take(16).joinToString("") { "%02X".format(it) } +
                                        if (blobLen > 16) "..." else ""
                            }
                        } else ""
                    }
                }
                values.add(value)
                dataPos += when (st) {
                    0L, 8L, 9L -> 0
                    1L -> 1
                    2L -> 2
                    3L -> 3
                    4L -> 4
                    5L -> 6
                    6L, 7L -> 8
                    else -> ((st - 12) / 2).toInt()
                }
            }

            // 根据类型映射字段名
            mapFieldsByType(values, type)
        } catch (e: Exception) {
            emptyMap()
        }
    }

    /**
     * 根据记录类型将值映射为有意义的字段名
     */
    private fun mapFieldsByType(values: List<String>, type: RecoveryType): Map<String, String> {
        return when (type) {
            RecoveryType.CALL_LOG -> mapOf(
                "号码" to (values.getOrNull(2) ?: ""),
                "日期" to (values.getOrNull(4)?.let { formatTimestamp(it) } ?: ""),
                "时长(秒)" to (values.getOrNull(5) ?: ""),
                "类型" to (values.getOrNull(3)?.let { callTypeText(it) } ?: "")
            )
            RecoveryType.SMS -> mapOf(
                "号码" to (values.getOrNull(2) ?: ""),
                "内容" to (values.getOrNull(5) ?: ""),
                "日期" to (values.getOrNull(4)?.let { formatTimestamp(it) } ?: ""),
                "类型" to (values.getOrNull(3)?.let { smsTypeText(it) } ?: "")
            )
            RecoveryType.CONTACT -> mapOf(
                "显示名" to (values.getOrNull(1) ?: ""),
                "数据" to (values.getOrNull(4) ?: "")
            )
            else -> values.mapIndexed { i, v -> "字段$i" to v }.toMap()
        }
    }

    private fun callTypeText(typeCode: String): String = when (typeCode) {
        "1" -> "来电"
        "2" -> "去电"
        "3" -> "未接"
        "4" -> "语音信箱"
        "5" -> "拒接"
        else -> "类型$typeCode"
    }

    private fun smsTypeText(typeCode: String): String = when (typeCode) {
        "1" -> "收件箱"
        "2" -> "已发送"
        "3" -> "草稿"
        "4" -> "发件箱"
        else -> "类型$typeCode"
    }

    private fun formatTimestamp(ts: String): String {
        return try {
            val t = ts.toLong()
            val ms = if (t > 1e12) t else t * 1000
            java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.getDefault())
                .format(java.util.Date(ms))
        } catch (e: Exception) {
            ts
        }
    }

    // ========== 字节读取工具 ==========

    private fun readPage(raf: RandomAccessFile, pageNum: Long, pageSize: Int): ByteArray? {
        return try {
            val offset = (pageNum - 1) * pageSize
            if (offset < 0 || offset >= raf.length()) return null
            raf.seek(offset)
            val data = ByteArray(pageSize)
            raf.read(data)
            data
        } catch (e: Exception) {
            null
        }
    }

    private fun readUInt32BE(data: ByteArray, offset: Int): Long {
        return ((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)
    }

    private fun readUInt16BE(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
    }

    private fun readInt8(data: ByteArray, offset: Int): Byte = data[offset]

    private fun readInt16BE(data: ByteArray, offset: Int): Short {
        return ((data[offset].toInt() shl 8) or (data[offset + 1].toInt() and 0xFF)).toShort()
    }

    private fun readInt24BE(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 16) or
                ((data[offset + 1].toInt() and 0xFF) shl 8) or
                (data[offset + 2].toInt() and 0xFF)
    }

    private fun readInt32BE(data: ByteArray, offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
                ((data[offset + 1].toInt() and 0xFF) shl 16) or
                ((data[offset + 2].toInt() and 0xFF) shl 8) or
                (data[offset + 3].toInt() and 0xFF)
    }

    private fun readInt48BE(data: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 6) {
            value = (value shl 8) or (data[offset + i].toLong() and 0xFF)
        }
        return value
    }

    private fun readInt64BE(data: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 8) {
            value = (value shl 8) or (data[offset + i].toLong() and 0xFF)
        }
        return value
    }

    private fun readDoubleBE(data: ByteArray, offset: Int): Double {
        val bits = readInt64BE(data, offset)
        return Double.fromBits(bits)
    }

    /**
     * 读取 SQLite varint（变长整数）
     * @return Pair(值, 占用字节数)
     */
    private fun readVarint(data: ByteArray, offset: Int): Pair<Long, Int> {
        var result = 0L
        var bytesRead = 0
        for (i in 0 until 9) {
            val b = data[offset + i].toInt() and 0xFF
            bytesRead++
            if (i < 8) {
                result = (result shl 7) or (b and 0x7F).toLong()
                if ((b and 0x80) == 0) break
            } else {
                result = (result shl 8) or b.toLong()
            }
        }
        return result to bytesRead
    }

    /**
     * 安全读取 varint，失败返回 (0, 0)
     */
    private fun tryReadVarint(data: ByteArray, offset: Int): Pair<Long, Int> {
        return try {
            readVarint(data, offset)
        } catch (e: Exception) {
            0L to 0
        }
    }
}
