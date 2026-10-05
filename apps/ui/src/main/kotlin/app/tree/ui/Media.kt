package app.tree.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.State
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawWithCache
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.random.Random

/**
 * Decoded pictures (stickers, previews, photos) shared by every screen.
 *
 * Bounded by an estimate of their pixel memory, least recently used out
 * first: scrolling a long chat full of stickers keeps memory flat, and a
 * picture that scrolls back in comes from here instead of being decoded
 * again. Evicted entries are only dropped from the map; nothing else holds
 * them once their row has left the screen, so the system frees them.
 */
object ImageCache {
    private const val MAX_BYTES = 48L * 1024 * 1024
    private val map = LinkedHashMap<String, ImageBitmap>(64, 0.75f, true)
    private var bytes = 0L

    private fun cost(b: ImageBitmap) = b.width.toLong() * b.height * 4

    @Synchronized
    fun get(key: String): ImageBitmap? = map[key]

    @Synchronized
    fun put(key: String, b: ImageBitmap) {
        map.put(key, b)?.let { bytes -= cost(it) }
        bytes += cost(b)
        val it = map.entries.iterator()
        while (bytes > MAX_BYTES && it.hasNext()) {
            val e = it.next()
            if (e.key == key) continue
            bytes -= cost(e.value)
            it.remove()
        }
    }

    /** Forgets everything (the profile closed). */
    @Synchronized
    fun clear() { map.clear(); bytes = 0 }

    @Synchronized
    fun size(): Int = map.size

    @Synchronized
    fun usedBytes(): Long = bytes
}

/**
 * A picture for [key]: from the cache at once, else loaded and decoded off
 * the main thread (at most [maxPx] on its longer side). The load stops when
 * the row leaves the screen before it finishes.
 */
@Composable
fun rememberImage(platform: TreePlatform, key: String?, maxPx: Int, load: suspend () -> ByteArray?): State<ImageBitmap?> =
    produceState(key?.let { ImageCache.get("$it@$maxPx") }, key, maxPx) {
        if (key == null || value != null) return@produceState
        val k = "$key@$maxPx"
        val bytes = load() ?: return@produceState
        val img = withContext(Dispatchers.Default) { platform.decodeImage(bytes, maxPx) } ?: return@produceState
        ImageCache.put(k, img)
        value = img
    }

/**
 * The chat wallpaper: small leaves, sprouts and dots scattered over the
 * background. Built once per size (drawWithCache); scrolling the messages
 * on top never redraws it.
 */
fun Modifier.treeWallpaper(base: Color, ink: Color): Modifier = drawWithCache {
    val tile = 180f * density / 2.6f * 2.6f
    val rnd = Random(7)
    data class Mark(val x: Float, val y: Float, val kind: Int, val angle: Float, val scale: Float)
    val marks = List(14) { Mark(rnd.nextFloat() * tile, rnd.nextFloat() * tile, rnd.nextInt(4), rnd.nextFloat() * 360f, 0.7f + rnd.nextFloat() * 0.6f) }
    val u = density
    val leaf = Path().apply {
        moveTo(0f, -9 * u); cubicTo(7 * u, -5 * u, 7 * u, 5 * u, 0f, 10 * u); cubicTo(-7 * u, 5 * u, -7 * u, -5 * u, 0f, -9 * u); close()
    }
    val sprout = Path().apply {
        moveTo(0f, 10 * u); lineTo(0f, -2 * u)
        moveTo(0f, 2 * u); cubicTo(-8 * u, 0f, -9 * u, -8 * u, -2 * u, -9 * u)
        moveTo(0f, -1 * u); cubicTo(7 * u, -3 * u, 9 * u, -10 * u, 3 * u, -11 * u)
    }
    val stroke = Stroke(width = 1.4f * u)
    onDrawBehind {
        drawRect(base)
        var ty = 0f
        while (ty < size.height) {
            var tx = 0f
            while (tx < size.width) {
                for (m in marks) {
                    val c = Offset(tx + m.x, ty + m.y)
                    rotate(m.angle, c) {
                        translate(c.x, c.y) {
                            scale(m.scale, Offset.Zero) {
                                when (m.kind) {
                                    0 -> drawPath(leaf, ink, style = stroke)
                                    1 -> drawPath(sprout, ink, style = stroke)
                                    2 -> drawCircle(ink, 2.2f * u, Offset.Zero)
                                    else -> drawCircle(ink, 5f * u, Offset.Zero, style = stroke)
                                }
                            }
                        }
                    }
                }
                tx += tile
            }
            ty += tile
        }
    }
}

private inline fun androidx.compose.ui.graphics.drawscope.DrawScope.translate(x: Float, y: Float, block: androidx.compose.ui.graphics.drawscope.DrawScope.() -> Unit) =
    drawContext.transform.let { t -> t.translate(x, y); block(); t.translate(-x, -y) }

private inline fun androidx.compose.ui.graphics.drawscope.DrawScope.scale(s: Float, pivot: Offset, block: androidx.compose.ui.graphics.drawscope.DrawScope.() -> Unit) =
    drawContext.transform.let { t -> t.scale(s, s, pivot); block(); t.scale(1 / s, 1 / s, pivot) }

@Suppress("unused")
private val unusedSize = Size.Zero

/** A profile or chat photo already in memory, decoded once per version through the cache. */
@Composable
fun rememberPhoto(platform: TreePlatform, id: String, bytes: ByteArray?, maxPx: Int = 192): ImageBitmap? =
    rememberImage(platform, bytes?.let { "photo:$id:${System.identityHashCode(it)}" }, maxPx) { bytes }.value
