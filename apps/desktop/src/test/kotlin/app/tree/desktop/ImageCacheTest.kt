package app.tree.desktop

import androidx.compose.ui.graphics.ImageBitmap
import app.tree.ui.ImageCache
import app.tree.ui.bigEmoji
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ImageCacheTest {
    /** Scrolling through many stickers keeps decoded pictures under the cache's memory limit. */
    @Test
    fun staysBounded() {
        ImageCache.clear()
        repeat(300) { i -> ImageCache.put("sticker:$i", ImageBitmap(512, 512)) } // 1 MiB each
        assertTrue(ImageCache.usedBytes() <= 48L * 1024 * 1024, "${ImageCache.usedBytes()}")
        assertEquals(48, ImageCache.size())
        // The newest are kept, the oldest went first.
        assertNotNull(ImageCache.get("sticker:299"))
        assertNull(ImageCache.get("sticker:0"))
        ImageCache.clear()
        assertEquals(0L, ImageCache.usedBytes())
    }

    /** A picture used again stays; replacing one does not count it twice. */
    @Test
    fun recentlyUsedStays() {
        ImageCache.clear()
        repeat(48) { i -> ImageCache.put("p$i", ImageBitmap(512, 512)) }
        ImageCache.get("p0")
        ImageCache.put("new", ImageBitmap(512, 512))
        assertNotNull(ImageCache.get("p0"))
        assertNull(ImageCache.get("p1"))
        ImageCache.put("new", ImageBitmap(512, 512))
        assertEquals(48L * 1024 * 1024, ImageCache.usedBytes())
        ImageCache.clear()
    }

    @Test
    fun bigEmojiOnlyForAFewEmoji() {
        assertTrue(bigEmoji("🔥🔥"))
        assertTrue(bigEmoji("👍🏽"))
        assertTrue(bigEmoji("❤️"))
        assertFalse(bigEmoji("🔥🔥🔥🔥"))
        assertFalse(bigEmoji("좋아 🔥"))
        assertFalse(bigEmoji("ok"))
        assertFalse(bigEmoji(""))
    }
}
