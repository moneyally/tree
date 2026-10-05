package app.tree.desktop

import app.tree.shared.AppModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import androidx.compose.ui.use
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertNotNull

/** What the running app does: the background loop brings in new messages by itself. */
class SyncLoopTest {
    private val url = System.getenv("TREE_URL")!!

    /**
     * The signed-in screens start receiving themselves: the sign-in screen's
     * own coroutine (which used to start it) is cancelled as that screen
     * closes, which on a slow phone happened before the loop started.
     */
    @Test
    fun signedInScreensStartReceiving() = runBlocking {
        val dir = Files.createTempDirectory("tree-loop2").toString()
        val m = AppModel(this, Dispatchers.IO)
        m.createAccount("$dir/a.db", "pw", "A", url, 8u)
        kotlin.test.assertFalse(m.receiving)
        val scope = kotlinx.coroutines.CoroutineScope(Dispatchers.IO)
        androidx.compose.ui.ImageComposeScene(400, 800) { app.tree.ui.TreeUi(m, DesktopPlatform(m, scope), app.tree.ui.TreeNav(), true) }.use { scene ->
            scene.render(0)
            scene.render(100_000_000L)
        }
        kotlin.test.assertTrue(m.receiving)
        m.stop()
    }

    @Test
    fun loopReceives() = runBlocking {
        val dir = Files.createTempDirectory("tree-loop").toString()
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        alice.createAccount("$dir/a.db", "pw", "A", url, 8u)
        bob.createAccount("$dir/b.db", "pw", "B", url, 8u)
        val g = alice.newChat()!!
        alice.invite(g, bob.state.value.account)
        bob.syncNow(); bob.accept(g)
        alice.startSyncLoop()
        delay(500)
        bob.send(g, "first")
        val got = withTimeoutOrNull(40_000) {
            while (alice.state.value.chats.firstOrNull { it.id == g }?.last?.text != "first") delay(200)
            true
        }
        println("LOOP state chats=" + alice.state.value.chats.map { it.last?.text } + " err=" + alice.state.value.error)
        assertNotNull(got, "the loop did not bring the message in")
        bob.send(g, "second")
        val got2 = withTimeoutOrNull(40_000) {
            while (alice.state.value.chats.firstOrNull { it.id == g }?.last?.text != "second") delay(200)
            true
        }
        assertNotNull(got2, "the loop did not bring the second message in")
        alice.stop(); bob.stop()
    }
}
