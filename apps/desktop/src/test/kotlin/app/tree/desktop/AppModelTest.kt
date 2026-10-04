package app.tree.desktop

import app.tree.shared.*

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

    /**
     * The chat list: pinned chats on top in order, archived chats in their
     * own section (an unmuted one comes back with a new message), muted
     * chats and silent messages never notify, drafts, unread markers,
     * quiet leave, stranger labels and the username link.
     */
    @Test
    fun chatListPinnedArchivedMuted() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/list-alice.db", "alice pass", "alice", url, 8u))
        assertTrue(bob.createAccount("$dir/list-bob.db", "bob pass", "bob", url, 8u))
        val shown = mutableListOf<Pair<String, String?>>()
        bob.notifier = { title, text -> shown += title to text }

        // bob adds alice by her username link (QR code), so her chats are no requests.
        assertNotNull(alice.setUsername("alice_list_test"))
        assertTrue(alice.setFeature("user.username_link", true))
        val link = assertNotNull(alice.state.value.usernameLink)
        assertTrue(link.startsWith("tree://u/"))
        assertEquals(alice.state.value.account, bob.addByLink(link))
        val g1 = assertNotNull(alice.newChat())
        val g2 = assertNotNull(alice.newChat())
        val g3 = assertNotNull(alice.newChat())
        for (g in listOf(g1, g2, g3)) assertTrue(alice.invite(g, bob.state.value.account))
        bob.syncNow()
        assertTrue(bob.state.value.chats.all { it.status == "accepted" })
        val main = { bob.visibleChats(bob.state.value).map { it.id } }

        // Pinned on top, in the order pinned.
        assertTrue(bob.pin(g3, true))
        assertTrue(bob.pin(g2, true))
        assertEquals(listOf(g3, g2, g1), main())
        assertTrue(bob.movePin(g2, 0))
        assertEquals(listOf(g2, g3, g1), main())

        // Archived: out of the main list, in the archive section.
        assertTrue(bob.archive(g1, true))
        assertEquals(listOf(g2, g3), main())
        bob.showArchived(true)
        assertEquals(listOf(g1), main())
        bob.showArchived(false)
        // A new message brings an unmuted chat back, and notifies.
        assertTrue(alice.send(g1, "back again"))
        bob.syncNow()
        assertEquals(listOf(g2, g3, g1), main())
        assertEquals(1, bob.state.value.notified)
        assertEquals(null, shown.single().second, "no text unless user.notification_content")

        // Muted (1 h): no notification, and an archived chat stays archived.
        assertTrue(bob.archive(g1, true))
        assertTrue(bob.mute(g1, bob.muteChoices().first { it.first == "1h" }.second))
        val muted = bob.state.value.chats.single { it.id == g1 }
        assertTrue(muted.muted && muted.mutedUntil != null)
        assertTrue(alice.send(g1, "anyone?"))
        bob.syncNow()
        assertTrue(bob.state.value.chats.single { it.id == g1 }.archived)
        assertEquals(1, bob.state.value.notified)
        // Until unmuted; then unmuted.
        assertTrue(bob.mute(g3, null))
        val forever = bob.state.value.chats.single { it.id == g3 }
        assertTrue(forever.muted && forever.mutedUntil == null)
        assertTrue(alice.send(g3, "muted chat"))
        bob.syncNow()
        assertEquals(1, bob.state.value.notified)
        assertTrue(bob.unmute(g3))
        assertTrue(!bob.state.value.chats.single { it.id == g3 }.muted)

        // Silent send: delivered and unread, but no notification.
        assertTrue(alice.send(g2, "late at night", silent = true))
        bob.syncNow()
        assertEquals(1, bob.state.value.notified)
        val c2 = bob.state.value.chats.single { it.id == g2 }
        assertTrue(c2.unread > 0)
        bob.openChat(g2)
        assertTrue(bob.state.value.messages.last().silent)
        bob.openChat(null)

        // Mark unread / read.
        assertTrue(bob.markUnread(g2, true))
        assertTrue(bob.state.value.chats.single { it.id == g2 }.markedUnread)
        assertTrue(bob.markUnread(g2, false))
        assertTrue(!bob.state.value.chats.single { it.id == g2 }.markedUnread)

        // Drafts come back when the chat opens and go when sent.
        bob.saveDraft(g3, "half a thought")
        bob.refresh()
        assertEquals("half a thought", bob.state.value.chats.single { it.id == g3 }.draft)
        assertTrue(bob.send(g3, "half a thought, finished"))
        assertEquals(null, bob.state.value.chats.single { it.id == g3 }.draft)

        // Stranger labels in the header: alice is bob's contact now, but not verified.
        val labels = bob.state.value.chats.single { it.id == g3 }.labels
        assertTrue("name_unverified" in labels && "not_contact" !in labels, "$labels")
        assertTrue(bob.setFeature("user.stranger_labels", false))
        assertTrue(bob.state.value.chats.all { it.labels.isEmpty() })

        // Quiet leave: alice (admin) removes bob, and no "left" line is shown.
        assertTrue(bob.leave(g2, quiet = true))
        alice.syncNow()
        alice.openChat(g2)
        assertTrue(alice.state.value.members.size == 1, "the member list changed")
        assertTrue(alice.state.value.messages.none { it.kind == "left" })
        // A normal leave shows one, with the name.
        assertTrue(bob.leave(g3, quiet = false))
        alice.syncNow()
        alice.openChat(g3)
        val line = alice.state.value.messages.single { it.kind == "left" }
        assertEquals("bob", line.who)
        alice.openChat(null)
        alice.stop(); bob.stop()
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
        // Through the outbox: confirmed by the server, nothing left waiting.
        alice.openChat(g)
        assertEquals("sent", alice.state.value.messages.last().status)
        assertTrue(!alice.state.value.sending)
        // Only failed messages can be retried or cancelled: an error, not a crash.
        assertTrue(!alice.retrySend(alice.state.value.messages.last().id))
        assertNotNull(alice.state.value.error)
        alice.clearMessages()
        alice.openChat(null)
        bob.syncNow()
        assertEquals(1, bob.state.value.chats.single().unread)
        bob.openChat(g)
        assertEquals(listOf("안녕 밥"), bob.state.value.messages.map { it.text })
        assertEquals(0, bob.state.value.chats.first { it.id == g }.unread)
        // Opening the chat sent a read receipt: alice sees "read".
        alice.openChat(g)
        alice.syncNow()
        assertEquals(alice.state.value.messages.map { it.id }.toSet(), alice.state.value.readMine)
        // Typing shows in the open chat.
        bob.typing(g, true)
        alice.syncNow()
        assertTrue(alice.state.value.typing.isNotEmpty())
        // Notes and folders.
        val notes = assertNotNull(bob.openNotes())
        assertEquals(notes, bob.openNotes(), "one notes chat")
        bob.openChat(g)
        assertTrue(bob.createFolder("가족"))
        assertTrue(bob.fileChat("가족", g))
        bob.showFolder("가족")
        assertEquals(listOf(g), bob.visibleChats(bob.state.value).map { it.id })
        bob.showFolder(null)
        alice.openChat(null)

        // Safety numbers: the same 60 digits on both sides; mark verified.
        val aliceAcc = alice.state.value.account
        val bobAcc = bob.state.value.account
        val n = assertNotNull(bob.safetyNumber(aliceAcc))
        assertEquals(n, alice.safetyNumber(bobAcc))
        assertTrue(!bob.isVerified(aliceAcc))
        assertTrue(bob.markVerified(aliceAcc))
        assertTrue(bob.isVerified(aliceAcc))
        assertEquals(aliceAcc, bob.state.value.members.first { it.account == aliceAcc }.account)

        // Files: sent, received, checked and saved.
        val src = java.io.File("$dir/note.txt").apply { writeText("파일 내용") }
        assertTrue(alice.sendFile(g, src))
        bob.syncNow()
        val fileMsg = bob.state.value.messages.last()
        assertEquals("file", fileMsg.kind)
        val dest = java.io.File("$dir/saved.txt")
        assertTrue(bob.saveFile(fileMsg.id, dest))
        assertEquals("파일 내용", dest.readText())

        // Group settings: the admin releases voice messages for everyone.
        alice.openChat(g)
        assertTrue(alice.state.value.chatFeatures.single { it.key == "chat.voice" }.applied)
        assertTrue(alice.setChatFeature(g, "chat.voice", false))
        assertTrue(!alice.state.value.chatFeatures.single { it.key == "chat.voice" }.applied)
        bob.syncNow()
        assertTrue(!bob.state.value.chatFeatures.single { it.key == "chat.voice" }.applied)
        assertTrue(!bob.setChatFeature(g, "chat.voice", true), "bob is not an admin")
        bob.clearMessages()
        // Options: the admin picks a disappearing time from the choices;
        // a value outside the format is refused with INVALID_OPTION.
        val dis = alice.state.value.chatFeatures.single { it.key == "chat.disappearing" }
        assertTrue("1h" in dis.choices)
        assertTrue(alice.setChatFeature(g, "chat.disappearing", true, "1h"))
        assertEquals("1h", alice.state.value.chatFeatures.single { it.key == "chat.disappearing" }.option)
        assertTrue(!alice.setChatFeature(g, "chat.disappearing", true, "forever"))
        assertTrue(alice.state.value.error!!.startsWith("INVALID_OPTION"))
        alice.clearMessages()
        assertTrue(alice.setChatFeature(g, "chat.disappearing", false))
        // e2e is locked on and shown so.
        val e2e = alice.state.value.chatFeatures.single { it.key == "chat.e2e" }
        assertTrue(e2e.applied && e2e.lockedBy != null && e2e.choices.isEmpty())

        // Settings come from the registry; permanent ones say why.
        bob.loadFeatures()
        val warn = bob.state.value.features.single { it.key == "user.key_change_warning" }
        assertTrue(warn.applied && warn.lockedBy!!.startsWith("always"))
        bob.setFeature("user.search_index", false)
        assertTrue(!bob.state.value.features.single { it.key == "user.search_index" }.applied)
        // A user option: nobody may add bob to groups.
        assertTrue(bob.setFeature("user.group_add", true, "nobody"))
        assertEquals("nobody", bob.state.value.features.single { it.key == "user.group_add" }.option)
        assertTrue(!bob.setFeature("user.group_add", true, "everyone"))
        bob.clearMessages()
        // The username is findable only while user.discoverable is applied.
        assertNotNull(bob.setUsername("bob_app_test"))
        assertNotNull(alice.session!!.find("bob_app_test"))
        assertTrue(bob.setFeature("user.discoverable", false))
        assertEquals(null, alice.session!!.find("bob_app_test"))
        assertTrue(bob.setFeature("user.discoverable", true))
        assertNotNull(alice.session!!.find("bob_app_test"))

        // Errors become a message on screen, not a crash.
        assertTrue(!bob.invite(g, "@nobody_here"))
        assertNotNull(bob.state.value.error)
        bob.clearMessages()

        // App lock: off by default; on, it closes the session.
        assertTrue(!alice.lockIfEnabled())
        alice.setFeature("user.app_lock", true)
        assertTrue(alice.lockIfEnabled())
        assertTrue(!alice.state.value.signedIn && alice.session == null)
        assertTrue(alice.openProfile("$dir/alice.db", "alice pass"))

        // Reopening with a wrong passphrase is refused with a clear message.
        val again = AppModel(this, Dispatchers.IO)
        assertTrue(!again.openProfile("$dir/bob.db", "wrong"))
        assertEquals(Strings.t("wrong_pass"), again.state.value.error)
        // Account deletion: back to the start, the profile file is gone.
        assertTrue(bob.deleteAccount())
        assertTrue(!bob.state.value.signedIn)
        assertTrue(!java.io.File("$dir/bob.db").exists())
        alice.syncNow()
        alice.stop(); bob.stop()
    }
}
