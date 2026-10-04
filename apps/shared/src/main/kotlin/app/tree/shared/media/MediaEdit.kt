package app.tree.shared.media

import kotlin.math.abs
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt
import kotlin.math.sqrt

/**
 * The media editor (Wave 1 item 6): crop, rotate, draw, text and blur on the
 * device, before sending. The original never leaves the device; only the
 * edited picture is exported (without metadata, see [JpegMeta]) and sent.
 *
 * Everything here is plain Kotlin on an ARGB pixel array, so the same list
 * of operations gives the same pixels on every platform. Each platform only
 * converts its bitmaps to and from [Raster] (desktop: `BufferedImage`,
 * Android: `Bitmap.getPixels`) and draws text through a [TextPainter].
 *
 * Coordinates of an operation are in the picture as it is when that
 * operation runs (after the operations before it).
 */
class Raster(val width: Int, val height: Int, val pixels: IntArray = IntArray(width * height)) {
    init {
        require(width > 0 && height > 0 && pixels.size == width * height) { "bad raster size" }
    }

    operator fun get(x: Int, y: Int): Int = pixels[y * width + x]

    operator fun set(x: Int, y: Int, argb: Int) {
        pixels[y * width + x] = argb
    }

    fun copy(): Raster = Raster(width, height, pixels.copyOf())

    companion object {
        fun filled(width: Int, height: Int, argb: Int) = Raster(width, height, IntArray(width * height) { argb })
    }
}

data class Pt(val x: Float, val y: Float)

/** A rectangle in pixels: left, top, width, height. */
data class Box(val x: Int, val y: Int, val w: Int, val h: Int) {
    /** The part inside a `width` x `height` picture (null if none). */
    fun clip(width: Int, height: Int): Box? {
        val l = max(0, min(x, x + w))
        val t = max(0, min(y, y + h))
        val r = min(width, max(x, x + w))
        val b = min(height, max(y, y + h))
        return if (r > l && b > t) Box(l, t, r - l, b - t) else null
    }

    companion object {
        fun of(a: Pt, b: Pt) = Box(
            floor(min(a.x, b.x)).toInt(), floor(min(a.y, b.y)).toInt(),
            ceil(abs(a.x - b.x)).toInt(), ceil(abs(a.y - b.y)).toInt(),
        )
    }
}

/** One editing step. */
sealed interface EditOp {
    /** Keep only this part of the picture. */
    data class Crop(val box: Box) : EditOp

    /** Turn by 90 degrees clockwise, `quarterTurns` times (negative: anticlockwise). */
    data class Rotate(val quarterTurns: Int) : EditOp

    /** A freehand line through `points`, `width` pixels thick. */
    data class Stroke(val points: List<Pt>, val argb: Int, val width: Float) : EditOp

    /** Text with its top-left corner at (`x`, `y`), `size` pixels high. */
    data class Text(val text: String, val x: Int, val y: Int, val size: Float, val argb: Int) : EditOp

    /**
     * Hides a region (faces, numbers): the region is cut into blocks and
     * every block becomes its average colour, then the blocks are softened.
     * The detail is gone, not just smudged: pictures that differ only
     * inside blocks come out the same. `block` 0 picks a size from the
     * region (at least 8 pixels, about a sixth of its shorter side).
     */
    data class Blur(val box: Box, val block: Int = 0) : EditOp
}

/** Draws [EditOp.Text]; supplied by the platform (fonts are not portable). */
fun interface TextPainter {
    fun paint(target: Raster, op: EditOp.Text)
}

object MediaEdit {
    /** Applies `ops` in order to a copy of `src` (the original is not changed). */
    fun apply(src: Raster, ops: List<EditOp>, text: TextPainter? = null): Raster {
        var r = src.copy()
        for (op in ops) {
            r = when (op) {
                is EditOp.Crop -> crop(r, op.box)
                is EditOp.Rotate -> rotate(r, op.quarterTurns)
                is EditOp.Stroke -> r.also { stroke(it, op) }
                is EditOp.Text -> r.also { text?.paint(it, op) }
                is EditOp.Blur -> r.also { blur(it, op) }
            }
        }
        return r
    }

    fun crop(r: Raster, box: Box): Raster {
        val b = box.clip(r.width, r.height) ?: return r
        val out = Raster(b.w, b.h)
        for (y in 0 until b.h) System.arraycopy(r.pixels, (b.y + y) * r.width + b.x, out.pixels, y * b.w, b.w)
        return out
    }

    fun rotate(r: Raster, quarterTurns: Int): Raster {
        return when (((quarterTurns % 4) + 4) % 4) {
            0 -> r
            1 -> Raster(r.height, r.width).also { o ->
                for (y in 0 until o.height) for (x in 0 until o.width) o[x, y] = r[y, r.height - 1 - x]
            }
            2 -> Raster(r.width, r.height).also { o ->
                for (y in 0 until o.height) for (x in 0 until o.width) o[x, y] = r[r.width - 1 - x, r.height - 1 - y]
            }
            else -> Raster(r.height, r.width).also { o ->
                for (y in 0 until o.height) for (x in 0 until o.width) o[x, y] = r[r.width - 1 - y, x]
            }
        }
    }

    /**
     * Covers the pixels within `width / 2` of the line with round dabs, then
     * paints each covered pixel once (so half-transparent paint does not
     * build up where dabs overlap).
     */
    fun stroke(r: Raster, op: EditOp.Stroke) {
        if (op.points.isEmpty() || op.width <= 0f) return
        val rad = op.width / 2f
        val covered = BooleanArray(r.width * r.height)
        val pts = if (op.points.size == 1) listOf(op.points[0], op.points[0]) else op.points
        for (i in 1 until pts.size) {
            val (a, b) = pts[i - 1] to pts[i]
            val len = sqrt((b.x - a.x) * (b.x - a.x) + (b.y - a.y) * (b.y - a.y))
            val steps = max(1, ceil(len * 2).toInt())
            for (s in 0..steps) {
                val t = s.toFloat() / steps
                dab(r, covered, a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t, rad)
            }
        }
        for (i in covered.indices) if (covered[i]) r.pixels[i] = blend(r.pixels[i], op.argb)
    }

    private fun dab(r: Raster, covered: BooleanArray, cx: Float, cy: Float, rad: Float) {
        val x0 = max(0, floor(cx - rad).toInt())
        val x1 = min(r.width - 1, ceil(cx + rad).toInt())
        val y0 = max(0, floor(cy - rad).toInt())
        val y1 = min(r.height - 1, ceil(cy + rad).toInt())
        for (y in y0..y1) for (x in x0..x1) {
            val dx = x + 0.5f - cx
            val dy = y + 0.5f - cy
            if (dx * dx + dy * dy <= rad * rad) covered[y * r.width + x] = true
        }
    }

    /** `top` over `under` (source-over). */
    fun blend(under: Int, top: Int): Int {
        val a = (top ushr 24) and 0xff
        if (a == 255) return top
        if (a == 0) return under
        val ua = (under ushr 24) and 0xff
        fun ch(shift: Int): Int {
            val t = (top ushr shift) and 0xff
            val u = (under ushr shift) and 0xff
            return (t * a + u * (255 - a) + 127) / 255
        }
        val outA = a + (ua * (255 - a) + 127) / 255
        return (outA shl 24) or (ch(16) shl 16) or (ch(8) shl 8) or ch(0)
    }

    fun blockSize(box: Box, block: Int): Int = if (block > 0) block else max(8, min(box.w, box.h) / 6)

    fun blur(r: Raster, op: EditOp.Blur) {
        val b = op.box.clip(r.width, r.height) ?: return
        val n = blockSize(b, op.block)
        // 1. Every block becomes its average (the detail is gone).
        var by = b.y
        while (by < b.y + b.h) {
            val bh = min(n, b.y + b.h - by)
            var bx = b.x
            while (bx < b.x + b.w) {
                val bw = min(n, b.x + b.w - bx)
                val sums = LongArray(4)
                for (y in by until by + bh) for (x in bx until bx + bw) {
                    val p = r[x, y]
                    for (c in 0..3) sums[c] += ((p ushr (c * 8)) and 0xff).toLong()
                }
                val cnt = (bw * bh).toLong()
                var avg = 0
                for (c in 0..3) avg = avg or (((sums[c] + cnt / 2) / cnt).toInt() shl (c * 8))
                for (y in by until by + bh) for (x in bx until bx + bw) r[x, y] = avg
                bx += n
            }
            by += n
        }
        // 2. Soften the block edges with a box blur that reads only the region.
        val rad = max(1, n / 2)
        boxBlur(r, b, rad, horizontal = true)
        boxBlur(r, b, rad, horizontal = false)
    }

    private fun boxBlur(r: Raster, b: Box, rad: Int, horizontal: Boolean) {
        val lines = if (horizontal) b.h else b.w
        val len = if (horizontal) b.w else b.h
        val line = IntArray(len)
        for (l in 0 until lines) {
            for (i in 0 until len) line[i] = if (horizontal) r[b.x + i, b.y + l] else r[b.x + l, b.y + i]
            for (i in 0 until len) {
                val lo = max(0, i - rad)
                val hi = min(len - 1, i + rad)
                val sums = LongArray(4)
                for (j in lo..hi) for (c in 0..3) sums[c] += ((line[j] ushr (c * 8)) and 0xff).toLong()
                val cnt = (hi - lo + 1).toLong()
                var v = 0
                for (c in 0..3) v = v or (((sums[c] + cnt / 2) / cnt).toInt() shl (c * 8))
                if (horizontal) r[b.x + i, b.y + l] = v else r[b.x + l, b.y + i] = v
            }
        }
    }

    /** Size of a picture scaled down to fit in `max` x `max` (never up). */
    fun fit(width: Int, height: Int, max: Int): Pair<Int, Int> {
        if (width <= max && height <= max) return width to height
        val s = max.toDouble() / maxOf(width, height)
        return maxOf(1, (width * s).roundToInt()) to maxOf(1, (height * s).roundToInt())
    }

    /** Scales down by averaging the source pixels under each target pixel. */
    fun scaleDown(r: Raster, w: Int, h: Int): Raster {
        if (w >= r.width && h >= r.height) return r.copy()
        val out = Raster(w, h)
        for (y in 0 until h) {
            val sy0 = y * r.height / h
            val sy1 = max(sy0 + 1, (y + 1) * r.height / h)
            for (x in 0 until w) {
                val sx0 = x * r.width / w
                val sx1 = max(sx0 + 1, (x + 1) * r.width / w)
                val sums = LongArray(4)
                for (sy in sy0 until sy1) for (sx in sx0 until sx1) {
                    val p = r[sx, sy]
                    for (c in 0..3) sums[c] += ((p ushr (c * 8)) and 0xff).toLong()
                }
                val cnt = ((sy1 - sy0) * (sx1 - sx0)).toLong()
                var v = 0
                for (c in 0..3) v = v or (((sums[c] + cnt / 2) / cnt).toInt() shl (c * 8))
                out[x, y] = v
            }
        }
        return out
    }
}
