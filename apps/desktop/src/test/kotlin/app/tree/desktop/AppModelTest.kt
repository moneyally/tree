package app.tree.desktop

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The screens' model against a real server (scripts/desktop_test.sh). */
class AppModelTest {
    private val url = System.getenv("TREE_URL")!!
    private val dir = Files.createTempDirectory("tree-desktop").toString()

    @Test
    fun stringsExistInBothLanguages() {
        assertEquals(emptySet(), Strings.missing())
        Strings.lang = Lang.KO
        assertEquals("보내기", Strings.t("send"))
        Strings.lang = Lang.EN
        assertEquals("Send", Strings.t("send"))
    }

    @Test
    fun twoPeopleChatThroughTheModel() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/alice.db", "alice pass", "alice", url, 8u))
        assertTrue(bob.createAccount("$dir/bob.db", "bob pass", "bob", url, 8u))

        val g = assertNotNull(alice.newChat())
        assertTrue(alice.invite(g, bob.state.value.account))
        bob.syncNow()
        // alice is a stranger to bob: the chat waits in the request inbox.
        val req = bob.state.value.chats.single()
        assertEquals("request", req.status)
        assertEquals(alice.state.value.account, req.requestFrom)
        bob.accept(g)
        assertEquals("accepted", bob.state.value.chats.single().status)

        alice.syncNow()
        assertTrue(alice.send(g, "안녕 밥"))
        bob.syncNow()
        assertEquals(1, bob.state.value.chats.single().unread)
        bob.openChat(g)
        assertEquals(listOf("안녕 밥"), bob.state.value.messages.map { it.text })
        assertEquals(0, bob.state.value.chats.single().unread)

        // Settings come from the registry; permanent ones say why.
        bob.loadFeatures()
        val warn = bob.state.value.features.single { it.key == "user.key_change_warning" }
        assertTrue(warn.applied && warn.lockedBy!!.startsWith("always"))
        bob.setFeature("user.search_index", false)
        assertTrue(!bob.state.value.features.single { it.key == "user.search_index" }.applied)

        // Errors become a message on screen, not a crash.
        assertTrue(!bob.invite(g, "@nobody_here"))
        assertNotNull(bob.state.value.error)
        bob.clearMessages()

        // Reopening with a wrong passphrase is refused with a clear message.
        val again = AppModel(this, Dispatchers.IO)
        assertTrue(!again.openProfile("$dir/bob.db", "wrong"))
        assertEquals(Strings.t("wrong_pass"), again.state.value.error)
        alice.stop(); bob.stop()
    }
}
