package com.recovery.app.recovery.signatures

import com.recovery.app.model.RecoverableFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 扩展名逆向还原器
 *
 * 文件雕刻仅靠魔数只能确定大类（如 ZIP/RIFF/ftyp），
 * 但同一魔数下可能对应多种具体格式：
 *  - ZIP 魔数(PK\x03\x04)：可能是 zip / docx / xlsx / pptx / apk / jar
 *  - RIFF 魔数：可能是 webp / avi / wav
 *  - ftyp(ISO Base Media)：可能是 mp4 / mov / 3gp / heic / m4a
 *
 * 本类通过解析文件内部结构，推断更精确的扩展名和 MIME 类型。
 */
object ExtensionResolver {

    /**
     * 推断精确扩展名
     *
     * @param headerBytes 文件头部字节（至少 512 字节，越准越多）
     * @param sig 当前匹配的签名
     * @return Pair(extension, mimeType)
     */
    fun resolve(headerBytes: ByteArray, sig: FileSignature): Pair<String, String> {
        if (headerBytes.size < 8) return sig.extension to sig.mimeType

        return when {
            // ZIP 系列：PK\x03\x04
            sig.header.contentEquals(byteArrayOf(0x50, 0x4B, 0x03, 0x04)) -> resolveZip(headerBytes, sig)

            // RIFF 系列
            sig.header.contentEquals(byteArrayOf(0x52, 0x49, 0x46, 0x46)) -> resolveRiff(headerBytes, sig)

            // ISO Base Media (ftyp) - header 在 offset 4
            sig.headerOffset == 4 && sig.header.contentEquals(byteArrayOf(0x66, 0x74, 0x79, 0x70)) ->
                resolveIsoBase(headerBytes, sig)

            // JPEG：区分 jpg/jpeg（默认 jpg）
            sig.extension == "jpg" -> "jpg" to "image/jpeg"

            else -> sig.extension to sig.mimeType
        }
    }

    /**
     * 解析 ZIP 系列
     * 通过读取 ZIP 中第一个文件的文件名判断具体类型：
     *  - 含 [Content_Types].xml + word/ → docx
     *  - 含 [Content_Types].xml + xl/ → xlsx
     *  - 含 [Content_Types].xml + ppt/ → pptx
     *  - 含 AndroidManifest.xml → apk
     *  - 含 META-INF/MANIFEST.MF → jar
     *  - 否则 → zip
     */
    private fun resolveZip(header: ByteArray, sig: FileSignature): Pair<String, String> {
        // ZIP local file header:
        // 0-3: PK\x03\x04
        // 4-5: version needed
        // 6-7: flags
        // 8-9: compression
        // 10-11: mod time
        // 12-13: mod date
        // 14-17: crc
        // 18-21: compressed size
        // 22-25: uncompressed size
        // 26-27: file name length
        // 28-29: extra field length
        // 30+: file name

        if (header.size < 32) return sig.extension to sig.mimeType
        val nameLen = ByteBuffer.wrap(header, 26, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
        val extraLen = ByteBuffer.wrap(header, 28, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt() and 0xFFFF
        val nameStart = 30
        val nameEnd = nameStart + nameLen
        if (nameEnd > header.size) return sig.extension to sig.mimeType

        val firstName = String(header, nameStart, nameLen, Charsets.UTF_8).lowercase()

        return when {
            firstName.contains("androidmanifest.xml") -> "apk" to "application/vnd.android.package-archive"
            firstName.contains("meta-inf/manifest.mf") -> "jar" to "application/java-archive"
            firstName.contains("[content_types].xml") || firstName.contains("word/") -> "docx" to "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            firstName.contains("xl/") -> "xlsx" to "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            firstName.contains("ppt/") -> "pptx" to "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            else -> "zip" to "application/zip"
        }
    }

    /**
     * 解析 RIFF 系列
     * offset 8-11 为格式标识：WEBP / AVI / WAVE
     */
    private fun resolveRiff(header: ByteArray, sig: FileSignature): Pair<String, String> {
        if (header.size < 12) return sig.extension to sig.mimeType
        val format = String(header, 8, 4, Charsets.US_ASCII)
        return when (format) {
            "WEBP" -> "webp" to "image/webp"
            "AVI " -> "avi" to "video/x-msvideo"
            "WAVE" -> "wav" to "audio/wav"
            else -> sig.extension to sig.mimeType
        }
    }

    /**
     * 解析 ISO Base Media File Format (ftyp)
     * offset 8-11 为 major brand：
     *  - isom/iso2/mp42/avc1/iso6 → mp4
     *  - qt  → mov
     *  - 3gp5/3gp6/3ge6/3ge7 → 3gp
     *  - heic/heix/mif1 → heic
     *  - M4A / f4v → m4a
     */
    private fun resolveIsoBase(header: ByteArray, sig: FileSignature): Pair<String, String> {
        if (header.size < 12) return sig.extension to sig.mimeType
        val brand = String(header, 8, 4, Charsets.US_ASCII).trim()
        val compatibleBrands = mutableListOf<String>()
        // 读取兼容 brand 列表（每 4 字节一个，从 offset 16 开始）
        var pos = 16
        while (pos + 4 <= header.size && pos < 64) {
            compatibleBrands.add(String(header, pos, 4, Charsets.US_ASCII).trim())
            pos += 4
        }
        val allBrands = listOf(brand) + compatibleBrands

        return when {
            allBrands.any { it in setOf("qt", "moov") } -> "mov" to "video/quicktime"
            allBrands.any { it in setOf("3gp5", "3gp6", "3ge6", "3ge7", "3g2a", "3g2b") } -> "3gp" to "video/3gpp"
            allBrands.any { it in setOf("heic", "heix", "hevc", "hevx", "mif1", "msf1") } -> "heic" to "image/heic"
            allBrands.any { it in setOf("M4A", "m4a", "f4v", "f4p", "f4a", "f4b") } -> "m4a" to "audio/mp4"
            allBrands.any { it in setOf("isom", "iso2", "mp42", "avc1", "iso6", "dash", "mp71") } -> "mp4" to "video/mp4"
            else -> sig.extension to sig.mimeType
        }
    }
}
