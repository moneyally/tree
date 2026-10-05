package app.tree.desktop

import app.tree.shared.AppModel
import app.tree.shared.ScanOutcome
import app.tree.shared.qr.CodeKind
import app.tree.shared.qr.TreeCodes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Safety number by QR, and blocking, on a real server. */
class SafetyBlockTest {
    private val url = System.getenv("TREE_URL")!!

    @Test
    fun safetyQrAndBlock() = runBlocking {
        val dir = Files.createTempDirectory("tree-safety").toString()
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        val eve = AppModel(this, Dispatchers.IO)
        alice.createAccount("$dir/a.db", "pw", "A", url, 8u)
        bob.createAccount("$dir/b.db", "pw", "B", url, 8u)
        eve.createAccount("$dir/e.db", "pw", "E", url, 8u)
        val a = alice.state.value.account
        val b = bob.state.value.account
        val g = alice.newChat()!!
        alice.invite(g, b)
        bob.syncNow(); bob.accept(g); alice.syncNow()

        // Bob shows his code; Alice scans it for Bob: verified.
        val (bobsText, _) = bob.safetyQr(a)!!
        assertEquals(CodeKind.SAFETY, TreeCodes.parse(bobsText).kind)
        alice.safetyTarget = b
        assertEquals(ScanOutcome.ACCEPTED, alice.useScanned(bobsText, CodeKind.SAFETY))
        alice.loadContacts()
        assertTrue(alice.state.value.contacts.first { it.account == b }.verified)

        // A code from someone else does not verify Bob (constant-time check in the core).
        val eg = eve.newChat()!!
        eve.invite(eg, b); bob.syncNow(); bob.accept(eg)
        val (evesText, _) = eve.safetyQr(b)!!
        bob.safetyTarget = a
        assertEquals(ScanOutcome.FAILED, bob.useScanned(evesText, CodeKind.SAFETY))
        bob.loadContacts()
        assertFalse(bob.state.value.contacts.first { it.account == a }.verified)
        // The wrong kind on the safety scanner is refused before anything runs.
        assertEquals(ScanOutcome.WRONG_KIND, bob.useScanned("tree://u/AAAAAAAAAAAAAAAAAAAAAA", CodeKind.SAFETY))

        // Block, then unblock.
        assertTrue(alice.block(b))
        assertTrue(alice.state.value.contacts.first { it.account == b }.blocked)
        assertTrue(alice.unblock(b))
        assertFalse(alice.state.value.contacts.first { it.account == b }.blocked)

        // My own screenshot block for the chat.
        alice.openChat(g)
        assertTrue(alice.setScreenshotBlock(g, true))
        assertTrue(alice.state.value.screenshotBlocked)
        assertNotNull(alice.recoveryStatus())
        alice.stop(); bob.stop(); eve.stop()
    }
}
