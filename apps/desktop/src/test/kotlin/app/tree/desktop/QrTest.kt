package app.tree.desktop

import app.tree.shared.qr.CodeKind
import app.tree.shared.qr.QrCode
import app.tree.shared.qr.QrMatrix
import app.tree.shared.qr.TreeCodes
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.google.zxing.qrcode.decoder.Mode
import java.util.Base64
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** QR codes made and read in shared code, and what the scanner accepts (no server needed). */
class QrTest {
    private val b64u = Base64.getUrlEncoder().withoutPadding()
    private fun deviceLink(seed: Int) = "tree://link/" + b64u.encodeToString(Random(seed).nextBytes(145))
    private fun usernameLink(seed: Int) = "tree://u/" + b64u.encodeToString(Random(seed).nextBytes(16))

    private fun read(m: QrMatrix, scale: Int = 4): String? = QrCode.luminance(m, scale).let { QrCode.decode(it, m.size * scale, m.size * scale) }

    @Test
    fun deviceLinkIsByteModeLevelMAndReadsBack() {
        repeat(20) { seed ->
            val text = deviceLink(seed)
            assertEquals(206, text.length)
            val info = QrCode.info(text)
            assertEquals(Mode.BYTE, info.mode)
            assertEquals(ErrorCorrectionLevel.M, info.level)
            // 206 bytes: version 9 holds 180 at level M, version 10 holds 213.
            assertEquals(10, info.version)
            val m = assertNotNull(QrCode.encode(text))
            assertEquals(17 + 4 * 10 + 2 * QrCode.QUIET, m.size)
            assertEquals(text, read(m), "seed $seed")
        }
    }

    @Test
    fun usernameLinkReadsBack() {
        val text = usernameLink(7)
        val info = QrCode.info(text)
        assertEquals(Mode.BYTE, info.mode)
        assertEquals(3, info.version) // 31 bytes: version 2 holds 26 at level M, version 3 holds 42
        assertEquals(text, read(assertNotNull(QrCode.encode(text)), 3))
    }

    @Test
    fun quietZoneAndFinderPatterns() {
        val m = assertNotNull(QrCode.encode(usernameLink(1)))
        val q = QrCode.QUIET
        for (i in 0 until m.size) for (k in 0 until q) {
            assertFalse(m[i, k]); assertFalse(m[k, i]); assertFalse(m[i, m.size - 1 - k]); assertFalse(m[m.size - 1 - k, i])
        }
        // ISO/IEC 18004 finder pattern at the three corners: a dark 7x7 ring,
        // a light ring, a dark 3x3 centre; with its light separator.
        val n = m.size - 2 * q
        for ((ox, oy) in listOf(0 to 0, n - 7 to 0, 0 to n - 7)) {
            for (y in 0 until 7) for (x in 0 until 7) {
                val ring = maxOf(kotlin.math.abs(x - 3), kotlin.math.abs(y - 3))
                assertEquals(ring != 2, m[q + ox + x, q + oy + y], "finder at $ox,$oy cell $x,$y")
            }
        }
        // Timing pattern on row 6 between the finders: alternating, dark first.
        for (x in 8 until n - 8) assertEquals(x % 2 == 0, m[q + x, q + 6])
    }

    @Test
    fun cameraFramesWithPaddingAndRotationRead() {
        val text = deviceLink(42)
        val m = assertNotNull(QrCode.encode(text))
        val scale = 5
        val w = m.size * scale
        val pic = QrCode.luminance(m, scale)
        // A larger grey frame with a row stride wider than the picture, the
        // code turned by 90 degrees, as a phone camera hands it over.
        val frameW = w + 120
        val frameH = w + 80
        val stride = frameW + 32
        val frame = ByteArray(stride * frameH) { 0x80.toByte() }
        for (y in 0 until w) for (x in 0 until w) {
            frame[(40 + x) * stride + 60 + (w - 1 - y)] = pic[y * w + x]
        }
        assertEquals(text, QrCode.decode(frame, frameW, frameH, stride))
        // An empty frame has nothing to read.
        assertNull(QrCode.decode(ByteArray(stride * frameH) { 0x80.toByte() }, frameW, frameH, stride))
    }

    @Test
    fun tooLongTextHasNoCode() {
        assertNull(QrCode.encode("x".repeat(5000)))
    }

    @Test
    fun scannerAcceptsOnlyTreeLinks() {
        val dev = deviceLink(3)
        val user = usernameLink(3)
        assertEquals(CodeKind.DEVICE_LINK, TreeCodes.parse(dev).kind)
        assertEquals(CodeKind.DEVICE_LINK, TreeCodes.parse(" $dev\n").kind)
        assertEquals(dev, TreeCodes.parse(" $dev\n").text)
        assertEquals(CodeKind.USERNAME, TreeCodes.parse(user).kind)
        val bad = listOf(
            "", "tree://", "tree://u/", "tree://link/",
            "https://example.com/", "http://tree/u/AAAAAAAAAAAAAAAAAAAAAA", "javascript:alert(1)",
            "tree://join/" + "A".repeat(22), "tree://sticker/" + "A".repeat(22),
            "TREE://u/" + user.removePrefix("tree://u/"), "tree:/u/" + user.removePrefix("tree://u/"),
            user.dropLast(1), "$user" + "A", user.dropLast(1) + "=", user.dropLast(1) + "+", user.dropLast(1) + "/",
            dev.dropLast(1), dev + "A", user + "?x=1", user.replaceRange(12, 13, " "),
            "tree://u/" + "A".repeat(10) + "\n" + "A".repeat(11),
            "intent://u/AAAAAAAAAAAAAAAAAAAAAA#Intent;scheme=tree;end",
        )
        for (b in bad) assertEquals(CodeKind.NOT_TREE, TreeCodes.parse(b).kind, "accepted: $b")
    }
}
