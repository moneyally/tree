package app.tree.desktop

import app.tree.shared.*

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import uniffi.tree_ffi.BotButton
import uniffi.tree_ffi.TreeEvent
import uniffi.tree_ffi.TreeSession
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Wave 5: the bot factory and a bot in a chat, against a real server (scripts/desktop_test.sh). */
class BotsModelTest {
    private val url = System.getenv("TREE_URL")!!
    private val dir = Files.createTempDirectory("tree-bots").toString()

    /**
     * The factory: the token is shown once, the money features stay locked,
     * switches and the profile work both ways, rotate and revoke. In a
     * chat the bot carries its label, its buttons are shown and a press
     * reaches it; its answer comes back as a notice.
     */
    @Test
    fun botFactoryLabelAndButtons() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/bot-alice.db", "pw", "alice", url, 8u))
        assertTrue(alice.createBot("desk_test_bot"))
        val (botAccount, token) = assertNotNull(alice.state.value.bots.token)
        alice.dismissToken()
        assertEquals(null, alice.state.value.bots.token, "shown once")
        val mine = alice.state.value.bots.mine.single()
        assertEquals("desk_test_bot", mine.bot.username)
        assertTrue(mine.bot.privacyMode, "privacy mode by default")
        for (k in listOf("bot.payments", "bot.tips", "bot.pay_out_points")) {
            assertNotNull(mine.features.single { it.key == k }.locked, k)
        }
        assertFalse(alice.setBotFeature(botAccount, "bot.payments", true))
        alice.clearMessages()
        assertTrue(alice.setBotFeature(botAccount, "bot.directory", true))
        assertTrue(alice.state.value.bots.mine.single().bot.directory)
        assertTrue(alice.setBotFeature(botAccount, "bot.directory", false))
        assertFalse(alice.state.value.bots.mine.single().bot.directory)
        assertTrue(alice.setBotFeature(botAccount, "bot.directory", true))
        assertTrue(alice.setBotProfile(botAccount, "desk test", "/start begin\n/help help me"))
        assertEquals(listOf("start", "help"), alice.state.value.bots.mine.single().bot.commands.map { it.command })
        alice.searchBots("desk_test")
        assertTrue(alice.state.value.bots.found.any { it.account == botAccount })

        // The bot's device, as its gateway runs it.
        val bot = TreeSession.createBotDevice("$dir/bot-device.db", "pw", url, token)
        val g = assertNotNull(alice.newChat())
        assertTrue(alice.addBot(g, "@desk_test_bot"))
        bot.sync(0u)
        bot.sendButtons(g, "Pick one", listOf(listOf(BotButton("One", "1"), BotButton("Two", "2"))), null)
        alice.syncNow()
        alice.openChat(g)
        val st = alice.state.value
        val m = st.messages.single { it.text == "Pick one" }
        assertNotNull(botSender(st, m), "labelled by the server's word")
        assertTrue(senderLine(st, m, "desk_test_bot").contains(botLabel()))
        assertEquals(listOf("1", "2"), m.buttons.single().map { it.data })
        assertTrue(alice.pressButton(g, m.id, "2"))
        val q = bot.sync(0u).filterIsInstance<TreeEvent.CallbackQuery>().single()
        assertEquals("2", q.data)
        bot.answerCallback(g, q.id, "Two it is", false)
        alice.syncNow()
        assertEquals("Two it is", alice.state.value.bots.answer)

        // Rotate: a new token, shown once; revoke: none works; delete.
        assertTrue(alice.rotateBotToken(botAccount))
        assertNotEquals(token, alice.state.value.bots.token!!.second)
        assertTrue(alice.revokeBotToken(botAccount))
        assertFalse(alice.state.value.bots.mine.single().tokenActive)
        assertTrue(alice.deleteBot(botAccount))
        assertTrue(alice.state.value.bots.mine.isEmpty())
        alice.stop()
    }
}
