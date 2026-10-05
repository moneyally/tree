package app.tree.android

import app.tree.shared.qr.CodeKind
import app.tree.shared.qr.QrCode
import app.tree.shared.qr.TreeCodes

/**
 * The scanner's decisions, without Android types so they run as JVM unit
 * tests: reading a camera frame's Y plane, and what to do with the text.
 */
object ScanFrames {
    /** What the scan screen does with a decoded text. */
    sealed interface Decision {
        /** A Tree code of the kind this screen expects: hand it to the model. */
        data class Use(val text: String) : Decision
        /** Anything else: show this message (a [app.tree.shared.Strings] key) and keep scanning. */
        data class Ignore(val messageKey: String) : Decision
    }

    /**
     * Only `tree://link/...` on the device-link scanner and `tree://u/...` on
     * the friend scanner are used; every other text is ignored and never
     * opened, whatever it is (web address, other app's link, plain text).
     */
    fun decide(text: String, want: CodeKind): Decision {
        val code = TreeCodes.parse(text)
        return when (code.kind) {
            want -> Decision.Use(code.text)
            CodeKind.NOT_TREE -> Decision.Ignore("qr_not_tree")
            else -> Decision.Ignore(when (want) { CodeKind.DEVICE_LINK -> "qr_wrong_device"; CodeKind.SAFETY -> "qr_wrong_safety"; else -> "qr_wrong_friend" })
        }
    }

    /**
     * The text of the QR code in a frame's Y plane (`rowStride` bytes per
     * row, one byte per pixel; the last row may be shorter, as the camera
     * hands it over), or null.
     */
    fun read(y: ByteArray, width: Int, height: Int, rowStride: Int): String? {
        if (width <= 0 || height <= 0 || rowStride < width) return null
        val need = rowStride * height
        val full = if (y.size >= need) y else y.copyOf(need)
        return QrCode.decode(full, width, height, rowStride)
    }
}
