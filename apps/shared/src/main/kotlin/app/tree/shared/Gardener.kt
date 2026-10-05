package app.tree.shared

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import uniffi.tree_ffi.MyBot
import uniffi.tree_ffi.NewStickerItem

/**
 * @gardenerbot: the app's own helper, talked to like a bot, for making and
 * running bots and sticker packs. It runs inside the app on this device:
 * nothing typed here goes to any server except the calls it makes on the
 * person's behalf (the same ones the account makes anyway), so a bot token
 * it hands out is seen by nobody else. The server reserves the name, so no
 * real bot can pass for it. The conversation lives only in memory.
 */
class Gardener internal constructor(private val model: AppModel) {
    /** One line of the conversation. `buttons`: commands to tap; `secret`: a token, shown with a copy button. */
    data class Line(val fromBot: Boolean, val text: String, val at: Long, val buttons: List<String> = emptyList(), val secret: String? = null)

    private val _lines = MutableStateFlow<List<Line>>(emptyList())
    val lines: StateFlow<List<Line>> = _lines.asStateFlow()

    /** What the next plain text answers (a multi-step command), or null. */
    private var waiting: Step? = null

    private sealed interface Step {
        data object NewBotName : Step
        data class Description(val bot: MyBot) : Step
        data class Commands(val bot: MyBot) : Step
        data class ConfirmDelete(val bot: MyBot) : Step
        data object PackTitle : Step
        data class PackItems(val title: String, val items: List<NewStickerItem>) : Step
        data class PackEmoji(val title: String, val items: List<NewStickerItem>, val image: ByteArray, val mime: String) : Step
        data object InstallLink : Step
    }

    private fun now() = System.currentTimeMillis() / 1000
    private fun me(text: String) = _lines.update { it + Line(false, text, now()) }
    private fun say(text: String, buttons: List<String> = emptyList(), secret: String? = null) =
        _lines.update { it + Line(true, text, now(), buttons, secret) }

    /** The first lines, when the chat opens empty. */
    fun greet() {
        if (_lines.value.isNotEmpty()) return
        say(Strings.t("gardener_hello"), listOf("/newbot", "/mybots", "/newpack", "/help"))
    }

    /** Commands for the "/" menu: command and what it does. */
    fun commands(): List<Pair<String, String>> = listOf(
        "/newbot" to Strings.t("g_cmd_newbot"),
        "/mybots" to Strings.t("g_cmd_mybots"),
        "/token" to Strings.t("g_cmd_token"),
        "/revoke" to Strings.t("g_cmd_revoke"),
        "/setdescription" to Strings.t("g_cmd_setdescription"),
        "/setcommands" to Strings.t("g_cmd_setcommands"),
        "/setprivacy" to Strings.t("g_cmd_setprivacy"),
        "/setjoingroups" to Strings.t("g_cmd_setjoingroups"),
        "/setinline" to Strings.t("g_cmd_setinline"),
        "/setdirectory" to Strings.t("g_cmd_setdirectory"),
        "/deletebot" to Strings.t("g_cmd_deletebot"),
        "/newpack" to Strings.t("g_cmd_newpack"),
        "/addpack" to Strings.t("g_cmd_addpack"),
        "/mypacks" to Strings.t("g_cmd_mypacks"),
        "/delpack" to Strings.t("g_cmd_delpack"),
        "/cancel" to Strings.t("g_cmd_cancel"),
        "/help" to Strings.t("g_cmd_help"),
    )

    /** The person sent [raw]. */
    suspend fun send(raw: String) {
        val text = raw.trim()
        if (text.isEmpty()) return
        me(text)
        if (text.startsWith("/")) {
            // Any command ends a multi-step one, except /publish, which finishes the pack being made.
            if (!text.lowercase().startsWith("/publish")) waiting = null
            command(text); return
        }
        when (val w = waiting) {
            null -> say(Strings.t("g_unknown"), listOf("/help"))
            is Step.NewBotName -> newBot(text)
            is Step.Description -> { waiting = null; done(model.setBotProfile(w.bot.bot.account, text, w.bot.bot.commands.joinToString("\n") { "/${it.command} ${it.description}" }), "g_saved") }
            is Step.Commands -> { waiting = null; done(model.setBotProfile(w.bot.bot.account, w.bot.bot.description, text), "g_saved") }
            is Step.ConfirmDelete -> {
                waiting = null
                if (text == "@" + w.bot.bot.username || text == w.bot.bot.username) done(model.deleteBot(w.bot.bot.account), "g_deleted")
                else say(Strings.t("g_not_deleted"))
            }
            is Step.PackTitle -> { waiting = Step.PackItems(text.take(64), emptyList()); say(Strings.t("g_pack_send_image")) }
            is Step.PackItems -> say(Strings.t("g_pack_send_image"), listOf("/publish", "/cancel"))
            is Step.PackEmoji -> {
                val emoji = text.take(8)
                val items = w.items + NewStickerItem("s${w.items.size + 1}", emoji, w.mime, w.image)
                waiting = Step.PackItems(w.title, items)
                say(Strings.t("g_pack_added").replace("%d", items.size.toString()), listOf("/publish"))
            }
            is Step.InstallLink -> { waiting = null; done(model.rich.installPack(text), "g_pack_installed") }
        }
    }

    /** The person sent a picture (only used while making a sticker pack). */
    fun sendImage(bytes: ByteArray, mime: String) {
        _lines.update { it + Line(false, "🖼", now()) }
        val w = waiting
        if (w !is Step.PackItems) { say(Strings.t("g_image_unexpected"), listOf("/newpack")); return }
        if (w.items.size >= 120) { say(Strings.t("g_pack_full"), listOf("/publish")); return }
        waiting = Step.PackEmoji(w.title, w.items, bytes, mime)
        say(Strings.t("g_pack_emoji"))
    }

    private fun done(ok: Boolean, key: String) = if (ok) say(Strings.t(key), listOf("/mybots")) else say(Strings.t("g_failed"))

    private suspend fun bots(): List<MyBot> {
        model.loadBots()
        return model.state.value.bots.mine
    }

    /** The bot a command names (`/token @weatherbot`), or the only one, or a question. */
    private suspend fun pick(arg: String, cmd: String): MyBot? {
        val list = bots()
        if (list.isEmpty()) { say(Strings.t("g_no_bots"), listOf("/newbot")); return null }
        val name = arg.trim().removePrefix("@").lowercase()
        if (name.isNotEmpty()) return list.firstOrNull { it.bot.username == name } ?: run { say(Strings.t("g_no_such_bot")); null }
        if (list.size == 1) return list.first()
        say(Strings.t("g_which_bot"), list.map { "$cmd @${it.bot.username}" })
        return null
    }

    private suspend fun command(text: String) {
        val cmd = text.substringBefore(' ').lowercase()
        val arg = text.substringAfter(' ', "")
        when (cmd) {
            "/start", "/help" -> say(commands().joinToString("\n") { (c, d) -> "$c — $d" })
            "/cancel" -> say(Strings.t("g_cancelled"))
            "/newbot" -> if (arg.isNotBlank()) newBot(arg) else { waiting = Step.NewBotName; say(Strings.t("g_newbot_name")) }
            "/mybots" -> {
                val list = bots()
                if (list.isEmpty()) say(Strings.t("g_no_bots"), listOf("/newbot"))
                else say(list.joinToString("\n") { b ->
                    "@${b.bot.username} · " + (if (b.tokenActive) Strings.t("g_token_on") else Strings.t("g_token_off")) +
                        " · " + Strings.t("g_gateways").replace("%d", b.gatewayDevices.toString())
                }, list.map { "/token @${it.bot.username}" })
            }
            "/token" -> pick(arg, cmd)?.let { b ->
                if (model.rotateBotToken(b.bot.account)) {
                    val tok = model.state.value.bots.token?.second
                    model.dismissToken()
                    say(Strings.t("g_token").replace("%s", "@" + b.bot.username), secret = tok)
                } else say(Strings.t("g_failed"))
            }
            "/revoke" -> pick(arg, cmd)?.let { done(model.revokeBotToken(it.bot.account), "g_revoked") }
            "/setdescription" -> pick(arg, cmd)?.let { waiting = Step.Description(it); say(Strings.t("g_ask_description")) }
            "/setcommands" -> pick(arg, cmd)?.let { waiting = Step.Commands(it); say(Strings.t("g_ask_commands")) }
            "/setprivacy" -> pick(arg, cmd)?.let { toggle(it, "bot.privacy_mode") }
            "/setjoingroups" -> pick(arg, cmd)?.let { toggle(it, "bot.join_groups") }
            "/setinline" -> pick(arg, cmd)?.let { toggle(it, "bot.inline") }
            "/setdirectory" -> pick(arg, cmd)?.let { toggle(it, "bot.directory") }
            "/deletebot" -> pick(arg, cmd)?.let { waiting = Step.ConfirmDelete(it); say(Strings.t("g_confirm_delete").replace("%s", "@" + it.bot.username)) }
            "/newpack" -> { waiting = Step.PackTitle; say(Strings.t("g_pack_title")) }
            "/publish" -> {
                val w = when (val c = waiting) { is Step.PackItems -> c; is Step.PackEmoji -> Step.PackItems(c.title, c.items); else -> null }
                if (w == null || w.items.isEmpty()) { say(Strings.t("g_pack_empty"), listOf("/newpack")); return }
                waiting = null
                val link = model.rich.createPack(w.title, w.items)
                if (link == null) say(Strings.t("g_failed")) else say(Strings.t("g_pack_made").replace("%s", w.title), secret = link)
            }
            "/addpack" -> if (arg.isNotBlank()) done(model.rich.installPack(arg), "g_pack_installed") else { waiting = Step.InstallLink; say(Strings.t("g_ask_link")) }
            "/mypacks" -> {
                val packs = model.rich.state.value.packs
                if (packs.isEmpty()) say(Strings.t("g_no_packs"), listOf("/newpack", "/addpack"))
                else say(packs.joinToString("\n") { "${it.title} · ${it.items.size}" }, packs.map { "/delpack ${it.title}" })
            }
            "/delpack" -> {
                val p = model.rich.state.value.packs.firstOrNull { it.title == arg.trim() }
                if (p == null) say(Strings.t("g_no_such_pack"), listOf("/mypacks")) else done(model.rich.removePack(p.id), "g_pack_removed")
            }
            else -> say(Strings.t("g_unknown"), listOf("/help"))
        }
    }

    private suspend fun newBot(name: String) {
        waiting = null
        val n = name.trim().removePrefix("@").lowercase()
        if (model.createBot(n)) {
            val tok = model.state.value.bots.token?.second
            model.dismissToken()
            say(Strings.t("g_bot_made").replace("%s", "@$n"), secret = tok)
        } else {
            // The server says why (taken, reserved, not ending in bot...).
            say(Strings.t("g_bot_failed") + (model.state.value.error?.let { "\n$it" } ?: ""), listOf("/newbot"))
            model.clearMessages()
        }
    }

    private suspend fun toggle(b: MyBot, key: String) {
        val f = b.features.firstOrNull { it.key == key }
        if (f == null || f.locked != null) { say(Strings.t("g_locked")); return }
        val ok = model.setBotFeature(b.bot.account, key, !f.applied)
        say(if (ok) Strings.t(if (!f.applied) "g_on" else "g_off").replace("%s", "@" + b.bot.username) else Strings.t("g_failed"))
    }

    companion object {
        /** The helper's @name (reserved on the server) and how it shows. */
        const val USERNAME = "gardenerbot"
    }
}
