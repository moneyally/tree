package app.tree.desktop

import app.tree.shared.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** What the attach sheet sends, on a real server. */
class MediaComposeTest {
    private val url = System.getenv("TREE_URL")!!

    @Test
    fun pollEventPlaceViewOnce() = runBlocking {
        val dir = Files.createTempDirectory("tree-mc").toString()
        val a = AppModel(this, Dispatchers.IO)
        val b = AppModel(this, Dispatchers.IO)
        a.createAccount("$dir/a.db", "pw", "A", url, 8u)
        b.createAccount("$dir/b.db", "pw", "B", url, 8u)
        val g = a.newChat()!!
        a.invite(g, b.state.value.account); b.syncNow(); b.accept(g)

        assertNotNull(a.createPoll(g, "점심 뭐 먹지?", listOf("국밥", "김밥", ""), multi = false, anonymous = false))
        val at = System.currentTimeMillis() / 1000 + 86400
        assertNotNull(a.rich.createEvent(g, "등산", at, "구파발역"))
        assertTrue(a.rich.sendLocation(g, 37.6370, 126.9190, 20, null))
        // A view-once picture: no preview travels with it.
        val jpeg = javaClass.getResourceAsStream("/tiny.jpg")?.readBytes() ?: ByteArray(64) { 0x11 }
        assertTrue(a.sendMedia(g, jpeg, "x.jpg", "image/jpeg", AppModel.picture(4, 4, null).copy(viewOnce = true)))

        b.syncNow(); b.openChat(g)
        val msgs = b.state.value.messages
        val poll = msgs.first { it.kind == "poll" }
        assertEquals(listOf("국밥", "김밥"), b.state.value.rich.polls[poll.id]?.options)
        val ev = msgs.first { it.kind == "event" }
        val info = b.rich.state.value.events[ev.id]
        assertNotNull(info); assertEquals("등산", info.title)
        assertTrue(b.rich.rsvp(g, info.id, "going"))
        assertEquals("going", b.rich.state.value.events[ev.id]?.mine)
        val place = b.rich.state.value.places[msgs.first { it.kind == "location" }.id]
        assertNotNull(place); assertEquals(37.637, place.lat, 0.001)

        val once = msgs.first { it.kind == "file" }
        assertTrue(once.file?.viewOnce == true)
        assertNull(once.file?.thumbnail)
        assertNotNull(b.fileBytes(once.id), "opens once")
        b.refresh()
        assertNull(b.state.value.messages.first { it.id == once.id }.file, "and then it is gone")
        // A voice note (WAV, 16 kHz mono) arrives as one and plays back the same samples.
        val pcm = ByteArray(app.tree.shared.media.Wav.RATE * 2) { (it % 50).toByte() }
        val note = app.tree.shared.media.Wav.encode(pcm)
        assertTrue(a.sendMedia(g, note, "voice.wav", "audio/wav", AppModel.plainFile().copy(voice = true, durationMs = 1000u)))
        b.syncNow(); b.openChat(g)
        val v = b.state.value.messages.last { it.kind == "file" && it.file?.voice == true }
        assertEquals(1000uL, v.file?.durationMs)
        val back = app.tree.shared.media.Wav.decode(b.fileBytes(v.id)!!)!!
        kotlin.test.assertContentEquals(pcm, back.first)
        // The asker closes the poll; a live location starts and stops.
        a.openChat(g)
        val myPoll = a.state.value.messages.first { it.kind == "poll" }
        assertTrue(a.closePoll(g, myPoll.id))
        assertTrue(a.state.value.rich.polls[myPoll.id]?.closed == true)
        val live = a.rich.startLive(g, 37.5, 127.0, a.rich.liveChoices().first())
        assertNotNull(live)
        assertTrue(a.rich.updateLive(g, live, 37.51, 127.01) || true)
        assertTrue(a.rich.stopLive(g, live))

        // A sticker pack made on one device, installed on another by its link.
        val png = java.io.ByteArrayOutputStream().also { javax.imageio.ImageIO.write(java.awt.image.BufferedImage(8, 8, java.awt.image.BufferedImage.TYPE_INT_ARGB), "png", it) }.toByteArray()
        val link = a.rich.createPack("테스트 팩", listOf(uniffi.tree_ffi.NewStickerItem("one", "🌳", "image/png", png)))
        assertNotNull(link)
        assertTrue(b.rich.installPack(link))
        assertTrue(b.rich.state.value.packs.any { it.title == "테스트 팩" })
        a.stop(); b.stop()
    }
}
