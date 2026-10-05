package app.tree.shared.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.NotFoundException
import com.google.zxing.ChecksumException
import com.google.zxing.FormatException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.WriterException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.decoder.Mode
import com.google.zxing.qrcode.encoder.Encoder

/**
 * A QR code as a square of modules (true = dark), quiet zone included, so
 * the screens only draw squares. Drawn by the desktop and Android apps with
 * Compose; made and read with the ZXing core library (no platform service).
 */
class QrMatrix(val size: Int, private val modules: BooleanArray) {
    init { require(modules.size == size * size) }

    operator fun get(x: Int, y: Int): Boolean = modules[y * size + x]

    override fun equals(other: Any?) = other is QrMatrix && other.size == size && other.modules.contentEquals(modules)
    override fun hashCode() = 31 * size + modules.contentHashCode()
}

object QrCode {
    /** Quiet zone in modules on every side (ISO/IEC 18004 asks for 4). */
    const val QUIET = 4

    /** What the encoder chose, for tests: version, mode, error correction. */
    data class Info(val version: Int, val mode: Mode, val level: ErrorCorrectionLevel)

    private fun code(text: String) = Encoder.encode(
        text, ErrorCorrectionLevel.M,
        mapOf(EncodeHintType.CHARACTER_SET to "UTF-8", EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M),
    )

    /**
     * The QR code of [text] (exactly these bytes, error correction level M),
     * or null if it does not fit. Tree's link texts contain lower-case
     * letters, so the encoder always takes byte mode for them.
     */
    fun encode(text: String): QrMatrix? {
        val m = try { code(text).matrix } catch (_: WriterException) { return null }
        val n = m.width + 2 * QUIET
        val cells = BooleanArray(n * n)
        for (y in 0 until m.height) for (x in 0 until m.width) {
            if (m.get(x, y).toInt() == 1) cells[(y + QUIET) * n + x + QUIET] = true
        }
        return QrMatrix(n, cells)
    }

    fun info(text: String): Info = code(text).let { Info(it.version.versionNumber, it.mode, it.ecLevel) }

    /**
     * Reads a QR code from a camera frame's luminance (the Y plane of a YUV
     * image: one byte per pixel, `rowStride` bytes per row). Any rotation.
     * Null when no readable code is in the frame.
     */
    fun decode(y: ByteArray, width: Int, height: Int, rowStride: Int = width): String? {
        val source = PlanarYUVLuminanceSource(y, rowStride, height, 0, 0, width, height, false)
        val hints = mapOf(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.CHARACTER_SET to "UTF-8",
        )
        return try {
            QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
        } catch (_: NotFoundException) {
            null
        } catch (_: ChecksumException) {
            null
        } catch (_: FormatException) {
            null
        }
    }

    /** A grey picture of [m] (`scale` pixels per module), as a camera would see it; for tests. */
    fun luminance(m: QrMatrix, scale: Int): ByteArray {
        val w = m.size * scale
        val out = ByteArray(w * w) { 0xF0.toByte() }
        for (y in 0 until w) for (x in 0 until w) {
            if (m[x / scale, y / scale]) out[y * w + x] = 0x10
        }
        return out
    }
}
