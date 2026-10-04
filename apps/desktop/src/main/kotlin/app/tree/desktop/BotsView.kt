package app.tree.desktop

import app.tree.shared.*

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.MyBot

/** The "bot" label: a bot is never shown without it. */
@Composable
fun BotBadge() {
    Text(
        " ${botLabel()} ",
        Modifier.background(Color(0xFFD1E4FF)).padding(horizontal = 4.dp),
        color = Color(0xFF00315F),
        style = MaterialTheme.typography.labelMedium,
    )
}

/** The bot factory (create, token once, rotate / revoke, profile, switches) and the directory. */
@Composable
fun BotsScreen(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var username by remember { mutableStateOf("") }
    var query by remember { mutableStateOf("") }
    LaunchedEffect(Unit) { model.loadBots() }
    Row(Modifier.fillMaxSize()) {
        Column(Modifier.width(420.dp).fillMaxHeight().padding(8.dp)) {
            Text(Strings.t("bot_factory"), style = MaterialTheme.typography.titleMedium)
            Text(Strings.t("bot_factory_note"), style = MaterialTheme.typography.bodySmall)
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(username, { username = it }, label = { Text(Strings.t("bot_username")) }, singleLine = true, modifier = Modifier.weight(1f))
                Button(onClick = { scope.launch { if (model.createBot(username)) username = "" } }) { Text(Strings.t("bot_create")) }
            }
            state.bots.token?.let { (account, token) -> TokenOnce(model, state, account, token) }
            HorizontalDivider()
            LazyColumn {
                items(state.bots.mine, key = { it.bot.account }) { b -> MyBotCard(model, b) }
            }
        }
        Column(Modifier.fillMaxSize().padding(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(query, { query = it }, label = { Text(Strings.t("bot_search")) }, singleLine = true, modifier = Modifier.weight(1f))
                TextButton(onClick = { scope.launch { model.searchBots(query) } }) { Text(Strings.t("public_search_go")) }
            }
            if (query.isNotBlank() && state.bots.found.isEmpty()) Text(Strings.t("bot_none"), style = MaterialTheme.typography.bodySmall)
            state.bots.found.forEach { b ->
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(4.dp)) {
                    BotBadge()
                    Column(Modifier.padding(start = 6.dp)) {
                        Text("@${b.username}")
                        if (b.description.isNotEmpty()) Text(b.description, style = MaterialTheme.typography.bodySmall)
                        Text(Strings.t(if (b.privacyMode) "bot_privacy_note" else "bot_reads_all_note"), style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

/** A new token: shown once, with the warning; gone once dismissed. */
@Composable
private fun TokenOnce(model: AppModel, state: UiState, account: String, token: String) {
    val name = state.bots.mine.firstOrNull { it.bot.account == account }?.bot?.username ?: account.take(8)
    Column(Modifier.fillMaxWidth().background(Color(0xFFFFF3E0)).padding(8.dp)) {
        Text("${Strings.t("bot_token")} · @$name", style = MaterialTheme.typography.titleSmall)
        Text(Strings.t("bot_token_note"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        SelectionContainer { Text(token, style = MaterialTheme.typography.bodySmall) }
        TextButton(onClick = { model.dismissToken() }) { Text(Strings.t("bot_token_done")) }
    }
}

private fun featureText(key: String): String = when (key) {
    "bot.privacy_mode" -> Strings.t("bot_feature_privacy")
    "bot.join_groups" -> Strings.t("bot_feature_groups")
    "bot.inline" -> Strings.t("bot_feature_inline")
    "bot.directory" -> Strings.t("bot_feature_directory")
    "bot.payments" -> Strings.t("bot_feature_payments")
    "bot.tips" -> Strings.t("bot_feature_tips")
    "bot.pay_out_points" -> Strings.t("bot_feature_pay_out_points")
    else -> key
}

@Composable
private fun MyBotCard(model: AppModel, b: MyBot) {
    val scope = rememberCoroutineScope()
    var desc by remember(b.bot.account) { mutableStateOf(b.bot.description) }
    var cmds by remember(b.bot.account) { mutableStateOf(b.bot.commands.joinToString("\n") { "/${it.command} ${it.description}".trim() }) }
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            BotBadge()
            Text("  @${b.bot.username}", style = MaterialTheme.typography.titleSmall)
        }
        Text(
            listOf(
                if (!b.tokenActive) Strings.t("bot_token_off") else if (b.gatewayDevices > 0u) Strings.t("bot_gateway_on") else Strings.t("bot_gateway_off"),
                "${Strings.t("bot_contacts")}: ${b.contacts}",
                "${Strings.t("bot_reports")}: ${b.reportsOpen}",
            ).joinToString(" · "),
            style = MaterialTheme.typography.bodySmall,
        )
        b.features.forEach { f ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(featureText(f.key), Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                if (f.locked != null) {
                    Text("${Strings.t("bot_locked")}: ${f.locked}", style = MaterialTheme.typography.labelSmall)
                } else {
                    Switch(f.applied, { on -> scope.launch { model.setBotFeature(b.bot.account, f.key, on) } })
                }
            }
        }
        OutlinedTextField(desc, { desc = it }, label = { Text(Strings.t("bot_description")) }, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(cmds, { cmds = it }, label = { Text(Strings.t("bot_commands")) }, modifier = Modifier.fillMaxWidth())
        Row {
            TextButton(onClick = { scope.launch { model.setBotProfile(b.bot.account, desc, cmds) } }) { Text(Strings.t("bot_save")) }
            TextButton(onClick = { scope.launch { model.rotateBotToken(b.bot.account) } }) { Text(Strings.t("bot_rotate")) }
            TextButton(onClick = { scope.launch { model.revokeBotToken(b.bot.account) } }) { Text(Strings.t("bot_revoke")) }
            TextButton(onClick = { scope.launch { model.deleteBot(b.bot.account) } }) { Text(Strings.t("bot_delete"), color = MaterialTheme.colorScheme.error) }
        }
        HorizontalDivider()
    }
}

/** In a chat: its bots with their label and privacy note, block; adding a bot. */
@Composable
fun BotBar(model: AppModel, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    var who by remember(chat.id) { mutableStateOf("") }
    val bots = state.members.filter { it.bot != null }
    val allowed = state.chatFeatures.firstOrNull { it.key == "chat.bots" }?.applied ?: true
    bots.forEach { m ->
        Row(verticalAlignment = Alignment.CenterVertically) {
            BotBadge()
            Text("  ${m.name ?: m.id.take(6)}", Modifier.weight(1f))
            TextButton(onClick = { scope.launch { model.blockBot(m.bot!!) } }) { Text(Strings.t("bot_block")) }
        }
    }
    if (!allowed) {
        Text(Strings.t("chat_bots_off"), style = MaterialTheme.typography.bodySmall)
    } else Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(who, { who = it }, label = { Text(Strings.t("bot_add")) }, singleLine = true)
        TextButton(onClick = { scope.launch { if (model.addBot(chat.id, who)) who = "" } }) { Text("+") }
    }
}

/** A bot's inline buttons under its message; a press goes to that bot only. */
@Composable
fun BotButtons(model: AppModel, group: String, m: Message) {
    val scope = rememberCoroutineScope()
    Column(Modifier.padding(start = 24.dp)) {
        m.buttons.forEach { row ->
            Row {
                row.forEach { b ->
                    OutlinedButton(onClick = { scope.launch { model.pressButton(group, m.id, b.data) } }, modifier = Modifier.padding(2.dp)) { Text(b.text) }
                }
            }
        }
    }
}
