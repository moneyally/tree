package app.tree.desktop

import app.tree.shared.Look
import app.tree.shared.Looks
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals

/** The device's screen settings: saved, read back, bad lines ignored. */
class LookTest {
    @Test
    fun roundTrip() {
        val l = Look(theme = "light", textScale = 1.3f, wallpaper = false, compact = true, bigEmoji = false, swipeReply = false, enterSends = false, lang = "en", recentEmoji = listOf("🌱", "👍"))
        assertEquals(l, Look.parse(Look.format(l)))
        assertEquals(Look(), Look.parse(Look.format(Look())))
    }

    @Test
    fun badValuesKeepDefaults() {
        val l = Look.parse("theme=neon\ntextScale=9\nwallpaper=maybe\nlang=fr\nnonsense\n=x\ncompact=true")
        assertEquals("system", l.theme)
        assertEquals(1.4f, l.textScale) // clamped to the largest
        assertEquals(true, l.wallpaper)
        assertEquals(null, l.lang)
        assertEquals(true, l.compact)
    }

    @Test
    fun recentEmojiNewestFirstNoRepeats() {
        var l = Look()
        listOf("👍", "🔥", "👍").forEach { l = l.usedEmoji(it) }
        assertEquals(listOf("👍", "🔥"), l.recentEmoji)
        repeat(40) { l = l.usedEmoji("e$it") }
        assertEquals(Look.MAX_RECENT, l.recentEmoji.size)
        assertEquals("e39", l.recentEmoji.first())
    }

    @Test
    fun savedBesideTheProfile() {
        val dir = Files.createTempDirectory("tree-look").toString()
        Looks.open("$dir/p.db")
        Looks.update { it.copy(theme = "dark") }
        Looks.open("$dir/other.db")
        assertEquals("system", Looks.state.value.theme)
        Looks.open("$dir/p.db")
        assertEquals("dark", Looks.state.value.theme)
    }
}
