package app.tree.shared

import kotlinx.coroutines.flow.update
import uniffi.tree_ffi.Bot
import uniffi.tree_ffi.BotCommandInfo
import uniffi.tree_ffi.Member
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.MyBot

// Wave 5: bots (PROTOCOL.md 8.16). Tree runs no bots: people create them
// here (the bot factory) and run them on their own server with the bot
// gateway. A bot is always shown with the "bot" label, taken from the
// server's word (Member.bot), never from a name it chose. State in
// UiState.bots ([BotsUi]); every rule is in tree_client (bots.rs) and on
// the server.

/** The bot factory and the bot directory. */
data class BotsUi(
    /** This account's bots (owner's view). */
    val mine: List<MyBot> = emptyList(),
    /**
     * A token just made (bot account -> token): shown once, with the
     * warning to give it only to the bot's gateway. Gone after [dismissToken].
     */
    val token: Pair<String, String>? = null,
    /** Directory results, or a bot found by @username. */
    val found: List<Bot> = emptyList(),
    /** The latest answer of a bot to a button press. */
    val answer: String? = null,
)

/** The "bot" label text. */
fun botLabel(): String = Strings.t("bot_badge")

/** Is this member a bot (the server's label)? */
fun isBot(m: Member?): Boolean = m?.bot != null

/** The sender of a message, if the open chat knows it as a bot. */
fun botSender(state: UiState, m: Message): Member? = state.members.firstOrNull { it.id == m.sender && it.bot != null }

/** The name a message line shows: a bot always with its label. */
fun senderLine(state: UiState, m: Message, fallback: String): String =
    if (botSender(state, m) != null) "[${botLabel()}] $fallback" else fallback

/** Reloads the owner's bots. */
suspend fun AppModel.loadBots() {
    val mine = call { it.myBots() } ?: return
    _state.update { it.copy(bots = it.bots.copy(mine = mine)) }
}

/** Creates a bot; its token is shown once ([BotsUi.token]). */
suspend fun AppModel.createBot(username: String): Boolean {
    val n = call { it.createBot(username.trim(), botPowBits) } ?: return false
    _state.update { it.copy(bots = it.bots.copy(token = n.bot.bot.account to n.token)) }
    loadBots()
    return true
}

/** The token was copied to the gateway: never shown again. */
fun AppModel.dismissToken() = _state.update { it.copy(bots = it.bots.copy(token = null)) }

/** A new token (shown once); the old one and its gateway stop at once. */
suspend fun AppModel.rotateBotToken(account: String): Boolean {
    val t = call { it.rotateBotToken(account) } ?: return false
    _state.update { it.copy(bots = it.bots.copy(token = account to t)) }
    loadBots()
    return true
}

suspend fun AppModel.revokeBotToken(account: String): Boolean = (call { it.revokeBotToken(account) } != null).also { loadBots() }

suspend fun AppModel.deleteBot(account: String): Boolean = (call { it.deleteBot(account) } != null).also { loadBots() }

/** `bot.privacy_mode`, `bot.join_groups`, `bot.inline`, `bot.directory` (payments and tips are locked off). */
suspend fun AppModel.setBotFeature(account: String, key: String, on: Boolean): Boolean =
    (call { it.setBotFeature(account, key, on) } != null).also { loadBots() }

/**
 * Description, and commands one per line as `/command description`.
 */
suspend fun AppModel.setBotProfile(account: String, description: String, commands: String): Boolean {
    val list = commands.lines().map { it.trim() }.filter { it.isNotEmpty() }.map { line ->
        val cmd = line.substringBefore(' ').removePrefix("/")
        BotCommandInfo(cmd, line.substringAfter(' ', "").trim())
    }
    return (call { it.setBotProfile(account, description.trim(), list) } != null).also { loadBots() }
}

/** Searches the bot directory; a query starting with @ also looks the exact username up. */
suspend fun AppModel.searchBots(query: String) {
    val q = query.trim()
    val listed = call { it.botDirectory(q.removePrefix("@")) } ?: emptyList()
    val exact = if (q.startsWith("@")) call { it.findBot(q) } else null
    _state.update { it.copy(bots = it.bots.copy(found = (listOfNotNull(exact) + listed).distinctBy { b -> b.account })) }
}

/** Adds a bot (@username or account id) to the chat (refused while the chat releases chat.bots). */
suspend fun AppModel.addBot(group: String, who: String): Boolean =
    (call { it.addBot(group, who.trim()) }?.accepted == true).also { refresh() }

/** Presses a bot's button; its answer arrives as a notice. */
suspend fun AppModel.pressButton(group: String, msgId: String, data: String): Boolean =
    call { it.pressButton(group, msgId, data) } != null

/** Blocks a bot: its messages are dropped and it can no longer reach this account. */
suspend fun AppModel.blockBot(account: String): Boolean = (call { it.blockBot(account) } != null).also { refresh() }

/** A bot answered a button press of this device. */
internal fun AppModel.onBotAnswer(text: String?) {
    val t = text ?: Strings.t("bot_answer_empty")
    _state.update { it.copy(bots = it.bots.copy(answer = t), notice = t) }
}
