package app.tree.desktop

import app.tree.shared.AppModel
import app.tree.shared.forward
import app.tree.ui.hasMarkup
import app.tree.ui.mentionQuery
import app.tree.ui.mentionsIn
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The chat actions of the new screens, on a real server. */
class ChatActionsTest {
    private val url = System.getenv("TREE_URL")!!

    @Test
    fun formatMuteForward() = runBlocking {
        val dir = Files.createTempDirectory("tree-actions").toString()
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        alice.createAccount("$dir/a.db", "pw", "A", url, 8u)
        bob.createAccount("$dir/b.db", "pw", "B", url, 8u)
        val g = alice.newChat()!!
        alice.invite(g, bob.state.value.account)
        bob.syncNow(); bob.accept(g)

        // Markup and a silent send arrive as such.
        assertTrue(alice.send(g, "**굵게**", formatted = true))
        assertTrue(alice.send(g, "밤이라 조용히", silent = true))
        bob.syncNow(); bob.openChat(g)
        val got = bob.state.value.messages
        assertTrue(got.first { it.text == "**굵게**" }.formatted)
        assertTrue(got.first { it.text == "밤이라 조용히" }.silent)

        // Mute for one of the offered durations.
        val (_, hour) = alice.muteChoices().first { it.first == "1h" }
        assertTrue(alice.mute(g, hour))
        val muted = alice.state.value.chats.first { it.id == g }
        assertTrue(muted.muted)
        assertNotNull(muted.mutedUntil)

        // Forward into the notes chat.
        val notes = alice.openNotes()!!
        alice.openChat(g)
        val id = alice.state.value.messages.first { it.text == "**굵게**" }.id
        assertNotNull(alice.forward(g, id, notes))
        alice.openChat(notes)
        assertTrue(alice.state.value.messages.any { it.forwarded && it.text == "**굵게**" })
        alice.stop(); bob.stop()
    }

    @Test
    fun composerHelpers() {
        assertTrue(hasMarkup("**a**")); assertTrue(hasMarkup("> quote")); assertFalse(hasMarkup("2*3=6"))
        assertEquals("민", mentionQuery("안녕 @민"))
        assertNull(mentionQuery("메일 a@b"))
        assertNull(mentionQuery("@민준 다 왔어"))
        val (ids, all) = mentionsIn("@민준 @모두 와요", mapOf("m1" to "민준", "m2" to "서연", "me" to ""))
        assertEquals(listOf("m1"), ids); assertTrue(all)
    }
}
