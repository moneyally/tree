package app.tree.shared.media

/**
 * Removes metadata from a JPEG file before it is sent: every APP1 to APP15
 * segment (EXIF with GPS position, camera and time; XMP; ICC profiles;
 * maker data) and every comment. The picture data is copied unchanged.
 * Plain Kotlin on bytes, the same on every platform.
 */
object JpegMeta {
    private const val SOI = 0xD8
    private const val SOS = 0xDA
    private const val EOI = 0xD9
    private const val COM = 0xFE

    fun isJpeg(b: ByteArray): Boolean = b.size >= 4 && b[0] == 0xFF.toByte() && b[1] == SOI.toByte()

    private fun dropped(marker: Int) = marker in 0xE1..0xEF || marker == COM

    /** The JPEG without metadata segments; `null` if it is not a well-formed JPEG. */
    fun strip(b: ByteArray): ByteArray? {
        if (!isJpeg(b)) return null
        val out = java.io.ByteArrayOutputStream(b.size)
        out.write(b, 0, 2)
        var i = 2
        while (i + 1 < b.size) {
            if (b[i] != 0xFF.toByte()) return null
            val marker = b[i + 1].toInt() and 0xff
            when {
                marker == 0xFF -> { i += 1; continue } // fill byte
                marker == EOI || marker in 0xD0..0xD7 || marker == 0x01 -> {
                    out.write(b, i, 2); i += 2; continue
                }
            }
            if (i + 3 >= b.size) return null
            val len = ((b[i + 2].toInt() and 0xff) shl 8) or (b[i + 3].toInt() and 0xff)
            if (len < 2 || i + 2 + len > b.size) return null
            if (marker == SOS) {
                // The scan and everything after it (entropy-coded data, more
                // scans of a progressive picture and their headers).
                return stripTail(b, i, out)
            }
            if (!dropped(marker)) out.write(b, i, 2 + len)
            i += 2 + len
        }
        return out.toByteArray()
    }

    /**
     * From a start-of-scan on: copies scan data as is, but still drops
     * metadata segments that appear between scans.
     */
    private fun stripTail(b: ByteArray, start: Int, out: java.io.ByteArrayOutputStream): ByteArray {
        var i = start
        while (i < b.size) {
            if (b[i] == 0xFF.toByte() && i + 3 < b.size) {
                val marker = b[i + 1].toInt() and 0xff
                if (dropped(marker)) {
                    val len = ((b[i + 2].toInt() and 0xff) shl 8) or (b[i + 3].toInt() and 0xff)
                    if (len >= 2 && i + 2 + len <= b.size) { i += 2 + len; continue }
                }
            }
            out.write(b[i].toInt()); i += 1
        }
        return out.toByteArray()
    }

    /** Markers of the metadata segments before the first scan (for checks). */
    fun metadataMarkers(b: ByteArray): List<Int> {
        if (!isJpeg(b)) return emptyList()
        val found = mutableListOf<Int>()
        var i = 2
        while (i + 3 < b.size && b[i] == 0xFF.toByte()) {
            val marker = b[i + 1].toInt() and 0xff
            if (marker == SOS || marker == EOI) break
            val len = ((b[i + 2].toInt() and 0xff) shl 8) or (b[i + 3].toInt() and 0xff)
            if (dropped(marker)) found += marker
            i += 2 + len
        }
        return found
    }
}
