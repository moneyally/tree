package app.tree.android

import app.tree.shared.qr.CodeKind
import app.tree.shared.qr.QrCode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.util.Base64
import kotlin.random.Random

/** The scanner's decisions and frame reading, on the JVM (no camera, no device). */
class ScanFramesTest {
    private val b64u = Base64.getUrlEncoder().withoutPadding()
    private val device = "tree://link/" + b64u.encodeToString(Random(1).nextBytes(145))
    private val friend = "tree://u/" + b64u.encodeToString(Random(2).nextBytes(16))

    @Test
    fun deviceScannerUsesOnlyDeviceLinks() {
        assertEquals(ScanFrames.Decision.Use(device), ScanFrames.decide(device, CodeKind.DEVICE_LINK))
        assertEquals(ScanFrames.Decision.Use(device), ScanFrames.decide("  $device\n", CodeKind.DEVICE_LINK))
        assertEquals(ScanFrames.Decision.Ignore("qr_wrong_device"), ScanFrames.decide(friend, CodeKind.DEVICE_LINK))
    }

    @Test
    fun friendScannerUsesOnlyUsernameLinks() {
        assertEquals(ScanFrames.Decision.Use(friend), ScanFrames.decide(friend, CodeKind.USERNAME))
        assertEquals(ScanFrames.Decision.Ignore("qr_wrong_friend"), ScanFrames.decide(device, CodeKind.USERNAME))
    }

    @Test
    fun everythingElseIsIgnored() {
        for (t in listOf("https://example.com", "tree://join/AAAAAAAAAAAAAAAAAAAAAA", "WIFI:S:x;;", "hello", "",
            friend + "x", device.dropLast(3), "market://details?id=x", "Tree://u/" + friend.removePrefix("tree://u/"))) {
            for (want in listOf(CodeKind.DEVICE_LINK, CodeKind.USERNAME)) {
                assertEquals(t, ScanFrames.Decision.Ignore("qr_not_tree"), ScanFrames.decide(t, want))
            }
        }
    }

    /** A Y plane as CameraX hands it over: wider rows than the picture, a short last row. */
    @Test
    fun readsAPaddedYPlane() {
        val m = QrCode.encode(device)!!
        val scale = 6
        val side = m.size * scale
        val pic = QrCode.luminance(m, scale)
        val width = side + 40
        val height = side + 20
        val stride = width + 64
        val y = ByteArray(stride * (height - 1) + width) { 0x90.toByte() }
        for (r in 0 until side) for (c in 0 until side) y[(10 + r) * stride + 20 + c] = pic[r * side + c]
        assertEquals(device, ScanFrames.read(y, width, height, stride))
        assertNull(ScanFrames.read(ByteArray(stride * height), width, height, stride))
        assertNull(ScanFrames.read(y, width, height, width - 1))
    }
}
