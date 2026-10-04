package app.tree.desktop

import app.tree.shared.*
import app.tree.shared.qr.CodeKind
import app.tree.shared.qr.QrCode
import app.tree.shared.qr.QrMatrix

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlin.test.assertTrue

/** The screens' model against a real server (scripts/desktop_test.sh). */
class AppModelTest {
    private val url = System.getenv("TREE_URL")!!
    private val dir = Files.createTempDirectory("tree-desktop").toString()

    /** What a camera would read from the QR code on the screen. */
    private fun scan(m: QrMatrix?): String {
        val q = assertNotNull(m, "a QR code is shown")
        return assertNotNull(QrCode.decode(QrCode.luminance(q, 4), q.size * 4, q.size * 4))
    }

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
        // bob scans her QR code: the code is the link text exactly.
        val scanned = scan(alice.state.value.usernameQr)
        assertEquals(link, scanned)
        // On the device-link scanner a friend code does nothing; anything
        // that is not a Tree code is never acted on.
        assertEquals(ScanOutcome.WRONG_KIND, bob.useScanned(scanned, CodeKind.DEVICE_LINK))
        assertEquals(ScanOutcome.NOT_TREE, bob.useScanned("https://example.com/", CodeKind.USERNAME))
        assertEquals(ScanOutcome.ACCEPTED, bob.useScanned(scanned, CodeKind.USERNAME))
        assertEquals(Strings.t("qr_friend_added"), bob.state.value.notice)
        bob.clearMessages()
        // A reset link has a new QR code.
        assertNotNull(alice.resetUsernameLink())
        assertTrue(alice.state.value.usernameLink != link)
        assertEquals(alice.state.value.usernameLink, scan(alice.state.value.usernameQr))
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
    fun linkASecondDeviceWithTheCode() = runBlocking {
        val phone = AppModel(this, Dispatchers.IO)
        assertTrue(phone.createAccount("$dir/phone.db", "phone pass", "carol", url, 8u))
        val g = assertNotNull(phone.newChat())
        val desk = AppModel(this, Dispatchers.IO)
        val text = assertNotNull(desk.startLinkNewDevice("$dir/desk.db", "desk pass", "carol", url))
        // The new device shows its link as a QR code; the phone's camera reads the same text.
        assertEquals(text, scan(desk.state.value.link?.qr))
        assertEquals(ScanOutcome.NOT_TREE, phone.useScanned("https://example.com/$text", CodeKind.DEVICE_LINK))
        assertEquals(ScanOutcome.WRONG_KIND, phone.useScanned(text, CodeKind.USERNAME))
        assertNull(phone.state.value.link, "nothing started")
        // The phone scans it (its watcher polls in the background, as on screen).
        assertEquals(ScanOutcome.ACCEPTED, phone.useScanned(scan(desk.state.value.link?.qr), CodeKind.DEVICE_LINK))
        assertNull(phone.state.value.link?.qr, "the existing device shows no QR code")
        assertEquals("code", desk.pollNewDevice())
        assertEquals(text, scan(desk.state.value.link?.qr), "the QR code stays the same while the code is shown")
        withTimeout(20_000) { while (phone.state.value.link?.state != "code") delay(100) }
        val code = assertNotNull(desk.state.value.link?.code)
        assertEquals(code, phone.state.value.link?.code, "the same digits on both screens")
        assertTrue(Regex("[0-9]{3} [0-9]{3}").matches(code))
        assertEquals("confirmed", desk.confirmNewDevice(true))
        assertEquals("linked", phone.confirmLink(true))
        assertEquals("linked", desk.pollNewDevice())
        // The watcher stops by itself and reports nothing wrong.
        delay(1500)
        assertNull(phone.state.value.error)
        assertTrue(desk.state.value.signedIn)
        assertEquals(phone.state.value.account, desk.state.value.account)
        desk.syncNow()
        assertTrue(desk.state.value.chats.any { it.id == g && it.status == "accepted" })
        assertEquals(2, phone.state.value.devices.size)
        val deskId = desk.session!!.deviceId()
        assertTrue(phone.removeDevice(deskId))
        assertEquals(listOf(phone.session!!.deviceId()), phone.state.value.devices)
        phone.stop(); desk.stop()
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

    /**
     * Wave 2 part A through the model: pins on top of the chat, a poll with
     * its tally, a scheduled message, forwarding (and chat.forwarding
     * hiding it), a reminder notification, export and storage clean-up.
     */
    @Test
    fun richChatsThroughTheModel() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/rich-alice.db", "alice pass", "alice", url, 8u))
        assertTrue(bob.createAccount("$dir/rich-bob.db", "bob pass", "bob", url, 8u))
        val g = assertNotNull(alice.newChat())
        assertTrue(alice.invite(g, bob.state.value.account))
        bob.syncNow()
        bob.accept(g)
        alice.syncNow()
        val now = { System.currentTimeMillis() / 1000 }

        // Pins: either person in a 1:1 pins; both see the bar.
        assertTrue(alice.send(g, "meet at 7"))
        alice.openChat(g)
        val msg = alice.state.value.messages.last().id
        assertTrue(alice.state.value.rich.mayPin)
        assertEquals(listOf("24h", "7d", "30d", "forever"), alice.pinChoices().map { it.first })
        assertTrue(alice.pinMessage(g, msg, alice.pinChoices().first().second))
        bob.syncNow()
        bob.openChat(g)
        assertEquals(listOf("meet at 7"), bob.state.value.rich.pins.map { it.text })

        // A poll and its tally on both sides.
        val poll = assertNotNull(alice.createPoll(g, "Lunch?", listOf("noodles", "rice", "")))
        bob.syncNow()
        assertEquals(listOf("noodles", "rice"), bob.state.value.rich.polls[poll]?.options)
        assertTrue(bob.vote(g, poll, listOf(1)))
        alice.syncNow()
        assertEquals(listOf(0u, 1u), alice.state.value.rich.polls[poll]?.counts)

        // A scheduled message waits on the device, then goes.
        assertNotNull(alice.schedule(g, "sent later", now() + 2))
        assertEquals(1, alice.state.value.rich.scheduled.size)
        kotlinx.coroutines.delay(3000)
        alice.syncNow()
        assertTrue(alice.state.value.rich.scheduled.isEmpty())
        bob.syncNow()
        assertTrue(bob.state.value.messages.any { it.text == "sent later" })

        // Forwarding into the notes chat: marked forwarded.
        val notes = assertNotNull(alice.openNotes())
        assertNotNull(alice.forward(g, msg, notes))
        alice.openChat(notes)
        assertTrue(alice.state.value.messages.last().forwarded)
        // Released: the chat hides forwarding and the client refuses.
        assertTrue(alice.setChatFeature(g, "chat.forwarding", false))
        alice.openChat(g)
        assertTrue(!alice.state.value.rich.forwardingAllowed)
        assertEquals(null, alice.forward(g, msg, notes))
        assertEquals("LOCKED_BY_CHAT", alice.state.value.error)
        alice.clearMessages()

        // A reminder shows a local notification once.
        val shown = mutableListOf<Pair<String, String?>>()
        alice.notifier = { title, text -> shown += title to text }
        assertNotNull(alice.remindMe(g, msg, now() + 1))
        kotlinx.coroutines.delay(2000)
        alice.syncNow()
        alice.syncNow()
        assertEquals(listOf("meet at 7"), shown.filter { it.first.startsWith(Strings.t("reminder")) }.map { it.second })

        // Export to two files.
        val files = assertNotNull(alice.exportChat(g, "$dir/rich-export"))
        assertTrue(files.all { java.io.File(it).readText().contains("meet at 7") })

        // Storage clean-up: only while applied.
        assertEquals(null, alice.cleanStorage())
        alice.clearMessages()
        assertTrue(alice.setFeature("user.storage_clean", true, "30d"))
        assertEquals(0u, alice.cleanStorage()?.files)
        alice.stop(); bob.stop()
    }

    /**
     * Rich chats through the model: a sticker pack shared by link, a sticker,
     * a place and a live location with its countdown, an event with replies
     * counted on both sides, a profile photo, a name for one chat only, and
     * the GIF button hidden while the server offers no relay.
     */
    @Test
    fun richMediaThroughTheModel() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/media-alice.db", "alice pass", "alice", url, 8u))
        assertTrue(bob.createAccount("$dir/media-bob.db", "bob pass", "bob", url, 8u))
        val g = assertNotNull(alice.newChat())
        assertTrue(alice.invite(g, bob.state.value.account))
        bob.syncNow()
        bob.accept(g)
        alice.syncNow()
        bob.openChat(g)

        // No relay on the test server: the GIF button is hidden.
        assertTrue(!bob.rich.state.value.relays.gif)
        assertTrue(!bob.rich.gifAvailable(bob.state.value))
        assertTrue(bob.rich.allowed(bob.state.value, "chat.stickers"))

        // A sticker pack: made by alice, installed by bob from its link.
        val png = byteArrayOf(0x89.toByte(), 0x50, 0x4e, 0x47, 1, 2, 3)
        val link = assertNotNull(alice.rich.createPack("model pack", listOf(uniffi.tree_ffi.NewStickerItem("one", "😀", "image/png", png))))
        assertTrue(bob.rich.installPack(link))
        assertEquals(listOf("model pack"), bob.rich.state.value.packs.map { it.title })
        val pack = alice.rich.state.value.packs.single().id
        assertTrue(alice.rich.sendSticker(g, pack, 0))
        bob.syncNow()
        val sticker = bob.state.value.messages.last()
        assertEquals("sticker", sticker.kind)
        assertEquals(pack, bob.rich.state.value.stickers[sticker.id]?.pack)
        assertTrue(png.contentEquals(bob.rich.stickerImage(pack, 0)))

        // A place, then a live location with a countdown.
        assertTrue(alice.rich.sendLocation(g, 37.5665, 126.978, 10, "시청"))
        bob.syncNow()
        val place = bob.rich.state.value.places[bob.state.value.messages.last().id]
        assertEquals("시청", place?.label)
        assertTrue(place!!.geoUri.startsWith("geo:37.5665"))
        val live = assertNotNull(alice.rich.startLive(g, 37.0, 127.0, 900))
        bob.syncNow()
        val lp = assertNotNull(bob.rich.state.value.places[live])
        assertTrue(lp.live)
        assertNotNull(bob.rich.countdown(lp))
        assertTrue(alice.rich.stopLive(g, live))
        bob.syncNow()
        assertTrue(bob.rich.state.value.places[live]!!.ended)

        // An event: bob answers, both devices count it.
        val ev = assertNotNull(alice.rich.createEvent(g, "저녁", 1_900_000_000L, "식당", null))
        bob.syncNow()
        assertTrue(bob.rich.rsvp(g, ev, "going"))
        alice.openChat(g)
        alice.syncNow()
        val me = bob.session!!.memberId()
        assertEquals(listOf(me), alice.rich.state.value.events[ev]?.going)
        assertEquals("going", bob.rich.state.value.events[ev]?.mine)

        // Profile photo: bob sees alice's in the chat and in the chat list.
        assertTrue(alice.rich.setPhoto(png, "image/png"))
        bob.syncNow()
        val aliceId = alice.session!!.memberId()
        assertTrue(png.contentEquals(bob.rich.state.value.photos[aliceId]?.bytes))
        assertTrue(png.contentEquals(bob.rich.state.value.chatPhotos[g]?.bytes))

        // A name for this chat only, once alice turned the feature on.
        assertTrue(!alice.rich.setChatName(g, "앨리스 (회사)"))
        alice.clearMessages()
        assertTrue(alice.setFeature("user.per_chat_profile", true))
        assertTrue(alice.rich.setChatName(g, "앨리스 (회사)"))
        bob.syncNow()
        assertEquals("앨리스 (회사)", bob.state.value.names[aliceId])
        assertTrue(alice.rich.clearChatProfile(g))
        bob.syncNow()
        assertEquals("alice", bob.state.value.names[aliceId])
        alice.stop(); bob.stop()
    }

    /**
     * Wave 3 through the model: topics with unread counts, roles as member
     * tags with a permission, the history-sharing notice, the welcome text,
     * the admin log, join requests from an invite link, restricting a
     * member, slow mode and a community with a chat to join.
     */
    @Test
    fun groupsThroughTheModel() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        val carol = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/g-alice.db", "alice pass", "alice", url, 8u))
        assertTrue(bob.createAccount("$dir/g-bob.db", "bob pass", "bob", url, 8u))
        assertTrue(carol.createAccount("$dir/g-carol.db", "carol pass", "carol", url, 8u))
        val g = assertNotNull(alice.newChat())
        assertTrue(alice.invite(g, bob.state.value.account))
        bob.syncNow()
        bob.accept(g)
        alice.syncNow()
        alice.openChat(g)
        bob.openChat(g)
        val bobId = bob.session!!.memberId()

        // Topics: released by default; applied, the admin makes one.
        assertTrue(alice.state.value.groups.topics.isEmpty())
        assertTrue(alice.setChatFeature(g, "chat.topics", true))
        val t = assertNotNull(alice.createTopic(g, "일정"))
        bob.syncNow()
        assertEquals(listOf("일정"), bob.state.value.groups.topics.map { it.name })
        assertTrue(!bob.state.value.groups.mayCreateTopics)
        alice.openTopic(t)
        assertTrue(alice.sendInTopic(g, "토요일?"))
        bob.syncNow()
        assertEquals(1u, bob.state.value.groups.topics.single().unread)
        bob.openTopic(t)
        assertEquals(listOf("토요일?"), bob.state.value.groups.topicMessages.map { it.text })
        assertEquals(0u, bob.state.value.groups.topics.single().unread)
        bob.openTopic(null)
        assertTrue(bob.state.value.messages.none { it.text == "토요일?" && it.topic == null })

        // Roles: a tag on bob with the delete permission.
        val role = assertNotNull(alice.createRole(g, "모더", "#ff8800", listOf("delete")))
        assertTrue(alice.assignRole(g, bobId, role, true))
        bob.syncNow()
        assertEquals(listOf("모더"), bob.state.value.members.single { it.id == bobId }.roles.map { it.name })
        assertTrue(bob.state.value.groups.mayDelete)
        alice.openTopic(null)
        assertTrue(alice.send(g, "oops"))
        bob.syncNow()
        val oops = bob.state.value.messages.last { it.text == "oops" }.id
        assertTrue(bob.deleteAsModerator(g, oops))
        alice.syncNow()
        assertTrue(alice.state.value.messages.single { it.id == oops }.deleted)

        // Notices and admin tools.
        assertTrue(alice.setChatFeature(g, "chat.history_share", true, "25"))
        assertTrue(alice.setWelcome(g, "어서 오세요"))
        bob.syncNow()
        assertEquals(25, bob.state.value.groups.historyShare)
        assertEquals("어서 오세요", bob.state.value.groups.welcome)
        val log = alice.state.value.groups.adminLog
        assertTrue(log.any { it.action == "role_assign" }, "$log")
        assertTrue(log.all { alice.describeLog(it, alice.state.value.names).isNotBlank() })
        assertTrue(bob.state.value.groups.adminLog.isEmpty(), "admins only")

        // Join approval: carol uses the link, alice approves.
        assertTrue(alice.setChatFeature(g, "chat.join_approval", true))
        val link = assertNotNull(alice.inviteLink(g))
        assertTrue(carol.joinLink(link))
        alice.syncNow()
        assertEquals(listOf(carol.state.value.account), alice.state.value.groups.joinRequests.map { it.account })
        assertTrue(alice.approveJoin(g, carol.state.value.account))
        carol.syncNow()
        assertEquals("accepted", carol.state.value.chats.single { it.id == g }.status)
        carol.openChat(g)
        assertTrue(carol.state.value.messages.any { it.kind == "welcome" })
        assertTrue(carol.state.value.messages.any { it.sharedBy == alice.session!!.memberId() })

        // Restricted: bob reads but cannot send.
        bob.syncNow()
        assertTrue(alice.restrict(g, bobId, 3600))
        bob.syncNow()
        assertNotNull(bob.state.value.groups.restrictedUntil)
        assertTrue(!bob.send(g, "hello?"))
        assertEquals("RESTRICTED", bob.state.value.error)
        bob.clearMessages()
        assertTrue(alice.restrict(g, bobId, null))
        // Slow mode for members.
        assertTrue(alice.setChatFeature(g, "chat.slow_mode", true, "1h"))
        bob.syncNow()
        assertEquals(3600L, bob.state.value.groups.slowMode)

        // A community with the chat in it; carol asks to join another chat.
        val c = assertNotNull(alice.createCommunity("동네 모임"))
        val other = assertNotNull(alice.newChat())
        assertTrue(alice.addCommunityChat(c, other))
        assertTrue(alice.invite(c, carol.state.value.account))
        carol.syncNow()
        val community = carol.state.value.groups.communities.single()
        assertEquals("동네 모임", community.name)
        assertTrue(!community.chats.single().joined)
        assertTrue(carol.joinCommunityChat(c, other))
        alice.syncNow()
        carol.syncNow()
        assertTrue(carol.state.value.groups.communities.single().chats.single().joined)
        alice.stop(); bob.stop(); carol.stop()
    }

    /**
     * Wave 4, public spaces (not end-to-end): every object is marked public
     * and the badge text exists in both languages; directory search by
     * @handle, subscribe, unread counts, channel posts by admins only,
     * comments and signatures applied and released.
     */
    @Test
    fun publicChannelWithBadgeCommentsAndSignatures() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/pub-alice.db", "alice pass", "alice", url, 8u))
        assertTrue(bob.createAccount("$dir/pub-bob.db", "bob pass", "bob", url, 8u))
        Strings.lang = Lang.KO
        assertEquals("공개", publicBadge())
        Strings.lang = Lang.EN
        assertEquals("Public", publicBadge())

        val id = assertNotNull(alice.createPublic("channel", "Tree news", "tree_news_app", "hello"))
        val mine = assertNotNull(alice.state.value.pub.open)
        assertTrue(mine.isPublic && mine.role == "owner")
        assertTrue(publicTitle(mine).startsWith("[Public]"))
        // Not listed: found by exact @handle only.
        bob.searchPublic("@tree_news_app")
        assertEquals(listOf(id), bob.state.value.pub.found.map { it.id })
        assertTrue(bob.state.value.pub.found.all { it.isPublic })
        assertTrue(bob.joinPublic(id))
        assertEquals(listOf(id), bob.state.value.pub.spaces.map { it.id })

        // Only admins post in a channel.
        assertTrue(!bob.postPublic("a member's post"))
        assertTrue(bob.state.value.error!!.contains("NOT_ADMIN"))
        bob.clearMessages()
        assertTrue(alice.postPublic("first news"))
        bob.openPublic(null)
        bob.syncPublic(force = true)
        assertEquals(1u, bob.state.value.pub.spaces.single().unread)
        bob.openPublic(id)
        val post = bob.state.value.pub.posts.single()
        assertTrue(post.isPublic && post.author == null, "signatures released: the channel is shown")
        assertEquals("Tree news", publicAuthor(post, bob.state.value.pub.open))
        assertEquals(0u, bob.state.value.pub.spaces.single().unread, "opening reads it")

        // Comments: released, applied, released.
        assertTrue(!bob.postPublic("nice", post.id))
        bob.clearMessages()
        assertTrue(alice.setPublicFeature("channel.comments", true))
        bob.openPublic(id)
        assertTrue(bob.postPublic("nice", post.id))
        bob.loadPublicComments(post.id)
        assertEquals(listOf("nice"), bob.state.value.pub.comments[post.id]!!.map { it.text })
        assertTrue(alice.setPublicFeature("channel.comments", false))
        assertTrue(!bob.postPublic("again", post.id))
        bob.clearMessages()

        // Signatures applied: bob sees alice's name; released: the channel again.
        assertTrue(alice.setPublicFeature("channel.signatures", true))
        bob.openPublic(id)
        assertEquals("alice", publicAuthor(bob.state.value.pub.posts.single(), bob.state.value.pub.open))
        assertTrue(alice.setPublicFeature("channel.signatures", false))
        bob.openPublic(id)
        assertEquals("Tree news", publicAuthor(bob.state.value.pub.posts.single(), bob.state.value.pub.open))
        // Listing applied: in the directory; notifications on and off.
        assertTrue(alice.setPublicFeature("chat.public_listing", true))
        bob.searchPublic("Tree")
        assertTrue(bob.state.value.pub.found.any { it.id == id })
        assertTrue(bob.setPublicNotify(true) && bob.state.value.pub.open!!.notify)
        assertTrue(bob.setPublicNotify(false) && !bob.state.value.pub.open!!.notify)
        assertTrue(bob.leavePublic(id))
        assertTrue(bob.state.value.pub.spaces.isEmpty())
        alice.stop(); bob.stop()
    }

    /** Wave 4, private channels (end-to-end): only admins post; comments while applied. */
    @Test
    fun privateChannelOnlyAdminsPost() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/chan-alice.db", "alice pass", "alice", url, 8u))
        assertTrue(bob.createAccount("$dir/chan-bob.db", "bob pass", "bob", url, 8u))
        val ch = assertNotNull(alice.createChannel("비밀 채널"))
        assertTrue(alice.state.value.channel.isChannel && alice.state.value.channel.mayPost)
        assertTrue(alice.state.value.chats.single { it.id == ch }.channel)
        assertTrue(alice.invite(ch, bob.state.value.account))
        bob.syncNow()
        bob.accept(ch)
        bob.openChat(ch)
        assertTrue(bob.state.value.channel.isChannel && !bob.state.value.channel.mayPost)
        assertTrue(!bob.send(ch, "member post"))
        assertEquals("NOT_ADMIN", bob.state.value.error)
        bob.clearMessages()
        assertTrue(alice.send(ch, "공지"))
        bob.syncNow()
        val post = bob.state.value.messages.single { it.text == "공지" }
        assertTrue(!bob.commentOn(ch, post.id, "댓글"))
        bob.clearMessages()
        assertTrue(alice.setChatFeature(ch, "channel.comments", true))
        bob.syncNow()
        assertTrue(bob.state.value.channel.mayComment)
        assertTrue(bob.commentOn(ch, post.id, "댓글"))
        alice.syncNow()
        assertEquals(listOf("댓글"), alice.state.value.channel.comments[post.id]!!.map { it.text })
        assertEquals(post.id, alice.state.value.messages.single { it.text == "댓글" }.replyTo)
        // Signatures: released by default, applied, released.
        assertTrue(!bob.state.value.channel.signatures)
        assertTrue(alice.setChatFeature(ch, "channel.signatures", true))
        bob.syncNow()
        assertTrue(bob.state.value.channel.signatures)
        assertTrue(alice.setChatFeature(ch, "channel.signatures", false))
        bob.syncNow()
        assertTrue(!bob.state.value.channel.signatures)
        alice.stop(); bob.stop()
    }
}
