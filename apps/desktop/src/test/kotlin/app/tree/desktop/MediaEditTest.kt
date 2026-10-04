package app.tree.desktop

import app.tree.shared.AppModel
import app.tree.shared.media.Box
import app.tree.shared.media.EditOp
import app.tree.shared.media.JpegMeta
import app.tree.shared.media.MediaEdit
import app.tree.shared.media.Pt
import app.tree.shared.media.Raster
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import javax.imageio.ImageIO
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The media editor's operations (pure, shared) and the metadata strip. No server needed. */
class MediaEditTest {
    private val black = 0xFF000000.toInt()
    private val white = 0xFFFFFFFF.toInt()
    private val red = 0xFFFF0000.toInt()

    /** A picture whose every pixel says where it is: 0xFF00yyxx. */
    private fun numbered(w: Int, h: Int) = Raster(w, h, IntArray(w * h) { i -> 0xFF000000.toInt() or ((i / w) shl 8) or (i % w) })

    private fun checker(w: Int, h: Int, invert: Boolean = false) =
        Raster(w, h, IntArray(w * h) { i -> if (((i % w) + (i / w)) % 2 == 0 != invert) black else white })

    @Test
    fun cropKeepsExactlyTheBox() {
        val src = numbered(6, 5)
        val c = MediaEdit.crop(src, Box(1, 2, 3, 2))
        assertEquals(3 to 2, c.width to c.height)
        assertEquals(src[1, 2], c[0, 0])
        assertEquals(src[3, 3], c[2, 1])
        // A box reaching outside is clipped; a box dragged up-left works too.
        val edge = MediaEdit.crop(src, Box(4, 3, 10, 10))
        assertEquals(2 to 2, edge.width to edge.height)
        assertEquals(src[5, 4], edge[1, 1])
        assertEquals(Box(1, 1, 3, 2), Box.of(Pt(4f, 3f), Pt(1f, 1f)))
    }

    @Test
    fun rotateQuarterTurns() {
        val src = numbered(3, 2) // a b c / d e f
        val cw = MediaEdit.rotate(src, 1) // d a / e b / f c
        assertEquals(2 to 3, cw.width to cw.height)
        assertEquals(listOf(src[0, 1], src[0, 0], src[1, 1], src[1, 0], src[2, 1], src[2, 0]), cw.pixels.toList())
        val half = MediaEdit.rotate(src, 2)
        assertEquals(src[2, 1], half[0, 0])
        assertContentEquals(MediaEdit.rotate(src, 3).pixels, MediaEdit.rotate(src, -1).pixels)
        assertContentEquals(src.pixels, MediaEdit.rotate(MediaEdit.rotate(src, 1), 3).pixels)
        assertContentEquals(src.pixels, MediaEdit.rotate(src, 4).pixels)
    }

    @Test
    fun strokeDrawsAlongTheLineOnly() {
        val r = Raster.filled(20, 10, black)
        MediaEdit.stroke(r, EditOp.Stroke(listOf(Pt(2f, 5f), Pt(17f, 5f)), red, 3f))
        for (x in 3..16) assertEquals(red, r[x, 5], "x=$x")
        assertEquals(red, r[10, 4])
        assertEquals(black, r[10, 8])
        assertEquals(black, r[19, 5])
        // Half-transparent paint blends.
        val g = Raster.filled(4, 4, black)
        MediaEdit.stroke(g, EditOp.Stroke(listOf(Pt(2f, 2f)), 0x80FFFFFF.toInt(), 2f))
        assertEquals(0xFF808080.toInt(), g[2, 2])
    }

    /**
     * Blur: inside the box the detail is gone (two different pictures with
     * the same block averages come out the same), outside nothing changes.
     */
    @Test
    fun blurHidesTheRegionAndNothingElse() {
        val box = Box(8, 8, 16, 16)
        val a = MediaEdit.apply(checker(40, 40), listOf(EditOp.Blur(box, block = 8)))
        val b = MediaEdit.apply(checker(40, 40, invert = true), listOf(EditOp.Blur(box, block = 8)))
        for (y in 8 until 24) for (x in 8 until 24) {
            assertEquals(0xFF808080.toInt(), a[x, y], "($x,$y) is the block average")
            assertEquals(a[x, y], b[x, y])
        }
        val src = checker(40, 40)
        for (y in 0 until 40) for (x in 0 until 40) {
            if (x !in 8 until 24 || y !in 8 until 24) assertEquals(src[x, y], a[x, y], "($x,$y) outside")
        }
        // A face-sized region of a real gradient: changed, softened, and the original untouched.
        val grad = numbered(64, 64)
        val before = grad.pixels.copyOf()
        val out = MediaEdit.apply(grad, listOf(EditOp.Blur(Box(10, 10, 40, 40))))
        assertContentEquals(before, grad.pixels, "the original is not changed")
        assertNotEquals(grad[12, 12], out[12, 12])
        assertEquals(8, MediaEdit.blockSize(Box(0, 0, 40, 40), 0))
    }

    @Test
    fun opsApplyInOrderInTheCurrentPicture() {
        val src = numbered(8, 4)
        val out = MediaEdit.apply(src, listOf(EditOp.Crop(Box(2, 0, 4, 4)), EditOp.Rotate(1), EditOp.Crop(Box(0, 0, 2, 2))))
        assertEquals(2 to 2, out.width to out.height)
        assertEquals(src[2, 3], out[0, 0])
        // Text through the desktop painter changes pixels near where it is put.
        val t = MediaEdit.apply(Raster.filled(80, 40, black), listOf(EditOp.Text("Hi", 4, 4, 24f, white)), DesktopMedia.text)
        assertTrue(t.pixels.count { it == white } > 20)
        assertTrue((60 until 80).all { x -> t[x, 39] == black })
    }

    @Test
    fun thumbnailIsSmall() {
        val noise = java.util.Random(7)
        val big = Raster(1600, 1200, IntArray(1600 * 1200) { 0xFF000000.toInt() or noise.nextInt(0xFFFFFF) })
        val thumb = DesktopMedia.thumbnail(big)
        assertTrue(thumb.size <= 32 * 1024, "${thumb.size}")
        val img = assertNotNull(ImageIO.read(ByteArrayInputStream(thumb)))
        assertTrue(img.width <= 320 && img.height <= 240)
        assertEquals(320 to 240, MediaEdit.fit(1600, 1200, 320))
        assertEquals(100 to 50, MediaEdit.fit(100, 50, 320))
    }

    /** An EXIF segment with a GPS position (TIFF big-endian, GPS IFD with latitude). */
    private fun exifWithGps(): ByteArray {
        val tiff = ByteArrayOutputStream()
        fun u16(v: Int) { tiff.write(v shr 8); tiff.write(v and 0xff) }
        fun u32(v: Int) { u16(v ushr 16); u16(v and 0xffff) }
        tiff.write("MM".toByteArray()); u16(42); u32(8)
        // IFD0: one entry, GPSInfo -> offset 26.
        u16(1); u16(0x8825); u16(4); u32(1); u32(26); u32(0)
        // GPS IFD at 26: latitude ref "N", latitude 3 rationals at 56.
        u16(2)
        u16(1); u16(2); u32(2); tiff.write(byteArrayOf('N'.code.toByte(), 0, 0, 0))
        u16(2); u16(5); u32(3); u32(56)
        u32(0)
        for (v in listOf(37, 1, 33, 1, 59, 1)) u32(v) // 37° 33' 59"
        tiff.write("GPS-SECRET-PLACE".toByteArray())
        val body = "Exif\u0000\u0000".toByteArray() + tiff.toByteArray()
        val len = body.size + 2
        return byteArrayOf(0xFF.toByte(), 0xE1.toByte(), (len shr 8).toByte(), len.toByte()) + body
    }

    private fun withSegments(jpeg: ByteArray, vararg segments: ByteArray): ByteArray =
        jpeg.copyOfRange(0, 2) + segments.fold(ByteArray(0)) { a, s -> a + s } + jpeg.copyOfRange(2, jpeg.size)

    private fun contains(hay: ByteArray, needle: String): Boolean {
        val n = needle.toByteArray()
        return (0..hay.size - n.size).any { i -> n.indices.all { hay[i + it] == n[it] } }
    }

    /** A photo with a GPS position comes out of the editor without it. */
    @Test
    fun jpegWithGpsExifComesOutWithout() {
        val clean = DesktopMedia.jpeg(numbered(64, 48))
        assertEquals(emptyList(), JpegMeta.metadataMarkers(clean), "the encoder adds no metadata")
        val comment = "Pictures by me".toByteArray().let { c ->
            byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0, (c.size + 2).toByte()) + c
        }
        val photo = withSegments(clean, exifWithGps(), comment)
        assertEquals(listOf(0xE1, 0xFE), JpegMeta.metadataMarkers(photo))
        assertTrue(contains(photo, "GPS-SECRET-PLACE"))
        assertNotNull(ImageIO.read(ByteArrayInputStream(photo)), "still a valid JPEG")

        // The byte-level strip: same picture data, no metadata.
        val stripped = assertNotNull(JpegMeta.strip(photo))
        assertEquals(emptyList(), JpegMeta.metadataMarkers(stripped))
        assertFalse(contains(stripped, "Exif") || contains(stripped, "GPS-SECRET-PLACE") || contains(stripped, "Pictures by me"))
        assertContentEquals(clean, stripped)

        // The editor's path: load the file, edit, export.
        val file = Files.createTempFile("tree-gps", ".jpg").toFile()
        file.writeBytes(photo)
        val edited = DesktopMedia.load(file)!!.let { MediaEdit.apply(it, listOf(EditOp.Rotate(1), EditOp.Blur(Box(0, 0, 10, 10)))) }
        val out = DesktopMedia.jpeg(edited)
        assertEquals(emptyList(), JpegMeta.metadataMarkers(out))
        assertFalse(contains(out, "GPS-SECRET-PLACE"))
        assertEquals(48 to 64, ImageIO.read(ByteArrayInputStream(out)).let { it.width to it.height })
        val copy = assertNotNull(DesktopMedia.cleanCopy(file))
        assertFalse(contains(copy, "Exif"))
        assertEquals(null, JpegMeta.strip("not a jpeg".toByteArray()))
        file.delete()
    }

    @Test
    fun receivedNamesAreSafeOnDisk() {
        assertEquals("_.._etc_passwd", AppModel.safeName("../../etc/passwd").let { it })
        assertEquals("사진 1.jpg", AppModel.safeName("사진 1.jpg"))
        assertEquals("file", AppModel.safeName("..."))
        assertTrue(!AppModel.safeName("a/b\\c").contains('/') && !AppModel.safeName("a/b\\c").contains('\\'))
    }
}
