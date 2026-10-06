package com.recovery.app.recovery.signatures

import com.recovery.app.model.RecoveryType

/**
 * 文件签名注册表
 *
 * 收录常见文件类型的魔数（magic bytes），用于在原始存储分区中
 * 进行文件雕刻（file carving），恢复已删除但数据仍残留在存储中的文件。
 *
 * 参考 DiskDigger、PhotoRec 等开源取证工具的签名库。
 */
object SignatureRegistry {

    /**
     * 所有已注册的文件签名
     */
    val signatures: List<FileSignature> = listOf(

        // ========== 图片格式 ==========

        // JPEG - header: FF D8 FF, footer: FF D9
        FileSignature(
            type = RecoveryType.IMAGE,
            mimeType = "image/jpeg",
            extension = "jpg",
            header = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte()),
            footer = byteArrayOf(0xFF.toByte(), 0xD9.toByte()),
            maxSize = 100L * 1024 * 1024
        ),

        // PNG - header: 89 50 4E 47 0D 0A 1A 0A, footer: 49 45 4E 44 AE 42 60 82
        FileSignature(
            type = RecoveryType.IMAGE,
            mimeType = "image/png",
            extension = "png",
            header = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A),
            footer = byteArrayOf(0x49, 0x45, 0x4E, 0x44, 0xAE.toByte(), 0x42, 0x60, 0x82.toByte()),
            maxSize = 100L * 1024 * 1024
        ),

        // GIF - header: 47 49 46 38 (GIF8)
        FileSignature(
            type = RecoveryType.IMAGE,
            mimeType = "image/gif",
            extension = "gif",
            header = byteArrayOf(0x47, 0x49, 0x46, 0x38),
            footer = byteArrayOf(0x00, 0x3B),
            maxSize = 50L * 1024 * 1024
        ),

        // WebP - RIFF....WEBP (RIFF header + WEBP at offset 8)
        FileSignature(
            type = RecoveryType.IMAGE,
            mimeType = "image/webp",
            extension = "webp",
            header = byteArrayOf(0x52, 0x49, 0x46, 0x46), // "RIFF"
            maxSize = 50L * 1024 * 1024
        ),

        // BMP - 42 4D (BM)
        FileSignature(
            type = RecoveryType.IMAGE,
            mimeType = "image/bmp",
            extension = "bmp",
            header = byteArrayOf(0x42, 0x4D),
            maxSize = 50L * 1024 * 1024
        ),

        // HEIC - ftyp box with heic brand (starts with size then ftyp)
        FileSignature(
            type = RecoveryType.IMAGE,
            mimeType = "image/heic",
            extension = "heic",
            header = byteArrayOf(0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70), // ftyp box
            maxSize = 100L * 1024 * 1024
        ),

        // ========== 视频格式 ==========

        // MP4/MOV - ISO Base Media File Format: [4-byte size][ftyp]
        // ftyp 在偏移 4 处
        FileSignature(
            type = RecoveryType.VIDEO,
            mimeType = "video/mp4",
            extension = "mp4",
            header = byteArrayOf(0x66, 0x74, 0x79, 0x70), // "ftyp" at offset 4
            headerOffset = 4,
            maxSize = 2L * 1024 * 1024 * 1024
        ),

        // 3GP - 3gp5 brand in ftyp
        FileSignature(
            type = RecoveryType.VIDEO,
            mimeType = "video/3gpp",
            extension = "3gp",
            header = byteArrayOf(0x66, 0x74, 0x79, 0x70), // ftyp
            headerOffset = 4,
            maxSize = 1L * 1024 * 1024 * 1024
        ),

        // MKV/WebM - EBML header: 1A 45 DF A3
        FileSignature(
            type = RecoveryType.VIDEO,
            mimeType = "video/x-matroska",
            extension = "mkv",
            header = byteArrayOf(0x1A, 0x45, 0xDF.toByte(), 0xA3.toByte()),
            maxSize = 5L * 1024 * 1024 * 1024
        ),

        // AVI - RIFF....AVI
        FileSignature(
            type = RecoveryType.VIDEO,
            mimeType = "video/x-msvideo",
            extension = "avi",
            header = byteArrayOf(0x52, 0x49, 0x46, 0x46), // RIFF, AVI at offset 8
            maxSize = 5L * 1024 * 1024 * 1024
        ),

        // FLV - 46 4C 56 01 (FLV\1)
        FileSignature(
            type = RecoveryType.VIDEO,
            mimeType = "video/x-flv",
            extension = "flv",
            header = byteArrayOf(0x46, 0x4C, 0x56, 0x01),
            maxSize = 2L * 1024 * 1024 * 1024
        ),

        // ========== 音频格式 ==========

        // MP3 - ID3 or FF FB
        FileSignature(
            type = RecoveryType.AUDIO,
            mimeType = "audio/mpeg",
            extension = "mp3",
            header = byteArrayOf(0x49, 0x44, 0x33), // "ID3"
            maxSize = 100L * 1024 * 1024
        ),

        // WAV - RIFF....WAVE
        FileSignature(
            type = RecoveryType.AUDIO,
            mimeType = "audio/wav",
            extension = "wav",
            header = byteArrayOf(0x52, 0x49, 0x46, 0x46),
            maxSize = 200L * 1024 * 1024
        ),

        // AMR - 23 21 41 4D 52 (#!AMR)
        FileSignature(
            type = RecoveryType.AUDIO,
            mimeType = "audio/amr",
            extension = "amr",
            header = byteArrayOf(0x23, 0x21, 0x41, 0x4D, 0x52),
            maxSize = 50L * 1024 * 1024
        ),

        // AAC - FF F1 or FFF9
        FileSignature(
            type = RecoveryType.AUDIO,
            mimeType = "audio/aac",
            extension = "aac",
            header = byteArrayOf(0xFF.toByte(), 0xF1.toByte()),
            maxSize = 100L * 1024 * 1024
        ),

        // ========== 文档格式 ==========

        // PDF - %PDF
        FileSignature(
            type = RecoveryType.DOCUMENT,
            mimeType = "application/pdf",
            extension = "pdf",
            header = byteArrayOf(0x25, 0x50, 0x44, 0x46),
            footer = byteArrayOf(0x25, 0x25, 0x45, 0x4F, 0x46), // %%EOF
            maxSize = 500L * 1024 * 1024
        ),

        // ZIP/DOCX/XLSX/PPTX - PK\x03\x04
        FileSignature(
            type = RecoveryType.ARCHIVE,
            mimeType = "application/zip",
            extension = "zip",
            header = byteArrayOf(0x50, 0x4B, 0x03, 0x04),
            footer = byteArrayOf(0x50, 0x4B, 0x05, 0x06), // End of central directory
            maxSize = 1L * 1024 * 1024 * 1024
        ),

        // RAR - Rar!\x1a\x07
        FileSignature(
            type = RecoveryType.ARCHIVE,
            mimeType = "application/x-rar",
            extension = "rar",
            header = byteArrayOf(0x52, 0x61, 0x72, 0x21, 0x1A, 0x07),
            maxSize = 1L * 1024 * 1024 * 1024
        ),

        // SQLite database - "SQLite format 3\000"
        FileSignature(
            type = RecoveryType.DOCUMENT,
            mimeType = "application/x-sqlite3",
            extension = "db",
            header = byteArrayOf(
                0x53, 0x51, 0x4C, 0x69, 0x74, 0x65, 0x20, 0x66,
                0x6F, 0x72, 0x6D, 0x61, 0x74, 0x20, 0x33, 0x00
            ),
            maxSize = 500L * 1024 * 1024
        )
    )

    /**
     * 按类型筛选签名
     */
    fun byType(type: RecoveryType): List<FileSignature> =
        signatures.filter { it.type == type }

    /**
     * 在给定字节缓冲区中搜索所有匹配的签名
     * @return 匹配列表，每项为 (签名, 在缓冲区中的索引)
     */
    fun findMatches(buffer: ByteArray): List<Pair<FileSignature, Int>> {
        val matches = mutableListOf<Pair<FileSignature, Int>>()
        for (sig in signatures) {
            val header = sig.header
            val startIdx = sig.headerOffset
            var i = 0
            while (i <= buffer.size - header.size - startIdx) {
                var matched = true
                for (j in header.indices) {
                    if (buffer[i + startIdx + j] != header[j]) {
                        matched = false
                        break
                    }
                }
                if (matched) {
                    // 对 RIFF 格式做二次校验（WEBP/AVI/WAV 的区分）
                    if (validateRiffVariant(buffer, i, sig)) {
                        matches.add(sig to i)
                    }
                }
                i++
            }
        }
        return matches
    }

    /**
     * 对 RIFF 容器格式做二次校验，区分 WEBP / AVI / WAV
     */
    private fun validateRiffVariant(buffer: ByteArray, offset: Int, sig: FileSignature): Boolean {
        return when (sig.extension) {
            "webp" -> offset + 12 <= buffer.size &&
                    buffer.copyOfRange(offset + 8, offset + 12)
                        .contentEquals(byteArrayOf(0x57, 0x45, 0x42, 0x50))
            "avi" -> offset + 11 <= buffer.size &&
                    buffer.copyOfRange(offset + 8, offset + 11)
                        .contentEquals(byteArrayOf(0x41, 0x56, 0x49))
            "wav" -> offset + 12 <= buffer.size &&
                    buffer.copyOfRange(offset + 8, offset + 12)
                        .contentEquals(byteArrayOf(0x57, 0x41, 0x56, 0x45))
            else -> true
        }
    }
}
