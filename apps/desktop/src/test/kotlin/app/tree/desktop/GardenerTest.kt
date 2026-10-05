package app.tree.desktop

import app.tree.shared.AppModel
import app.tree.shared.Lang
import app.tree.shared.Strings
import app.tree.shared.loadBots
import app.tree.ui.gardenerMatches
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** @gardenerbot, the app's own helper: bots and sticker packs by commands, on a real server. */
class GardenerTest {
    private val url = System.getenv("TREE_URL")!!

    @Test
    fun botsAndPacksByCommands() = runBlocking {
        Strings.lang = Lang.KO
        val dir = Files.createTempDirectory("tree-gardener").toString()
        val a = AppModel(this, Dispatchers.IO)
        val b = AppModel(this, Dispatchers.IO)
        a.createAccount("$dir/a.db", "pw", "A", url, 8u)
        b.createAccount("$dir/b.db", "pw", "B", url, 8u)
        val g = a.gardener
        g.greet()
        assertTrue(g.lines.value.single().fromBot)

        // A new bot: asked for a name, then the token is shown once, as a secret.
        g.send("/newbot")
        g.send("weathertest_bot")
        val made = g.lines.value.last()
        assertNotNull(made.secret, made.text)
        assertTrue(made.text.contains("@weathertest_bot"))
        assertEquals(null, a.state.value.bots.token)

        // The reserved names are refused by the server.
        g.send("/newbot gardener_helperbot")
        assertEquals(null, g.lines.value.last().secret)
        g.send("/newbot treehelpbot")
        assertEquals(null, g.lines.value.last().secret)

        g.send("/mybots")
        assertTrue(g.lines.value.last().text.contains("@weathertest_bot"))
        g.send("/setdescription")
        g.send("오늘 날씨를 알려줘요")
        assertEquals(Strings.t("g_saved"), g.lines.value.last().text)
        a.loadBots()
        assertEquals("오늘 날씨를 알려줘요", a.state.value.bots.mine.single().bot.description)
        g.send("/token @weathertest_bot")
        assertNotNull(g.lines.value.last().secret)

        // A sticker pack: title, a picture, its emoji, publish; another account adds it by link.
        val png = java.io.ByteArrayOutputStream().also { javax.imageio.ImageIO.write(java.awt.image.BufferedImage(8, 8, java.awt.image.BufferedImage.TYPE_INT_ARGB), "png", it) }.toByteArray()
        g.send("/newpack")
        g.send("산 스티커")
        g.sendImage(png, "image/png")
        g.send("🌲")
        g.send("/publish")
        val link = assertNotNull(g.lines.value.last().secret)
        b.gardener.send("/addpack $link")
        assertEquals(Strings.t("g_pack_installed"), b.gardener.lines.value.last().text)
        assertTrue(b.rich.state.value.packs.any { it.title == "산 스티커" })
        b.gardener.send("/delpack 산 스티커")
        assertFalse(b.rich.state.value.packs.any { it.title == "산 스티커" })

        // Delete needs the name typed back.
        g.send("/deletebot")
        g.send("아니")
        a.loadBots(); assertEquals(1, a.state.value.bots.mine.size)
        g.send("/deletebot")
        g.send("@weathertest_bot")
        a.loadBots(); assertEquals(0, a.state.value.bots.mine.size)
        a.stop(); b.stop()
    }

    @Test
    fun searchFindsIt() {
        assertTrue(gardenerMatches("@gardenerbot"))
        assertTrue(gardenerMatches("정원"))
        assertTrue(gardenerMatches("Garden"))
        assertFalse(gardenerMatches("민준"))
        assertFalse(gardenerMatches("g"))
    }
}
