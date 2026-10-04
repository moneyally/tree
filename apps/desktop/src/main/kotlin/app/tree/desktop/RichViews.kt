package app.tree.desktop

import app.tree.shared.*

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message

private fun nowSecs(): Long = System.currentTimeMillis() / 1000

private fun hhmm(t: Long): String =
    java.time.format.DateTimeFormatter.ofPattern("MM-dd HH:mm")
        .format(java.time.Instant.ofEpochSecond(t).atZone(java.time.ZoneId.systemDefault()))

/** When to send or remind: label and seconds from now. */
private fun laterChoices() = listOf("in_10m" to 600L, "in_1h" to 3600L, "tomorrow" to 86400L)

/** The pins bar on top of the chat (chat.pins): newest pin first, unpin for those who may. */
@Composable
fun PinsBar(model: AppModel, state: UiState, group: String) {
    val scope = rememberCoroutineScope()
    val pins = state.rich.pins
    if (pins.isEmpty()) return
    Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surfaceVariant).padding(4.dp)) {
        Text("📌 " + Strings.t("pinned") + " (${pins.size})", style = MaterialTheme.typography.labelMedium)
        pins.forEach { p ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                val until = p.until?.let { " · ${Strings.t("until")} ${hhmm(it)}" } ?: ""
                Text((p.text ?: p.kind).take(80) + until, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                if (state.rich.mayPin) {
                    TextButton(onClick = { scope.launch { model.unpinMessage(group, p.messageId) } }) { Text(Strings.t("unpin_msg")) }
                }
            }
        }
    }
}

/** A poll with a bar per option; tap an option to vote (one, or several). */
@Composable
fun PollWidget(model: AppModel, state: UiState, group: String, m: Message) {
    val scope = rememberCoroutineScope()
    val p = state.rich.polls[m.id] ?: return
    val total = p.counts.sumOf { it.toInt() }.coerceAtLeast(1)
    val mine = p.mine.map { it.toInt() }
    Column(Modifier.padding(start = 16.dp, bottom = 8.dp).width(420.dp)) {
        Text("📊 " + p.question + if (p.closed) "  (${Strings.t("poll_closed")})" else "", style = MaterialTheme.typography.titleSmall)
        p.options.forEachIndexed { i, o ->
            val n = p.counts.getOrNull(i)?.toInt() ?: 0
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(enabled = !p.closed, onClick = {
                    val next = when {
                        i in mine -> mine - i
                        p.multi -> mine + i
                        else -> listOf(i)
                    }
                    scope.launch { model.vote(group, p.id, next) }
                }) { Text((if (i in mine) "● " else "○ ") + o) }
                Box(Modifier.width((160 * n / total).dp).height(10.dp).background(MaterialTheme.colorScheme.primary))
                Text("  $n", style = MaterialTheme.typography.bodySmall)
                // Names only for polls that are not anonymous.
                if (!p.anonymous) {
                    val who = p.votersByOption.getOrNull(i).orEmpty().map { state.names[it]?.ifEmpty { Strings.t("me") } ?: it.take(6) }
                    if (who.isNotEmpty()) Text("  " + who.joinToString(", "), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("${p.voters} ${Strings.t("poll_votes")}" + (p.closesAt?.let { " · ${Strings.t("until")} ${hhmm(it)}" } ?: ""),
                style = MaterialTheme.typography.bodySmall)
            if (mine.isNotEmpty() && !p.closed) TextButton(onClick = { scope.launch { model.vote(group, p.id, emptyList()) } }) { Text(Strings.t("poll_retract")) }
            if (p.creator == model.session?.memberId() && !p.closed) {
                TextButton(onClick = { scope.launch { model.closePoll(group, p.id) } }) { Text(Strings.t("poll_close")) }
            }
        }
        if (p.anonymous) Text(Strings.t("poll_anon_note"), style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * The actions of one message: pin (with expiry), forward, copy, remind me.
 * Forward and copy are hidden while the chat released chat.forwarding.
 */
@Composable
fun MessageMenu(model: AppModel, state: UiState, group: String, m: Message) {
    val scope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    var open by remember { mutableStateOf(false) }
    var picker by remember { mutableStateOf(false) }
    if (m.deleted || m.kind == "left" || m.kind == "removed") return
    Box {
        TextButton(onClick = { open = true }) { Text("⋯") }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            val items = buildList<Pair<String, suspend () -> Unit>> {
                if (state.rich.mayPin) {
                    if (state.rich.pins.any { it.messageId == m.id }) add(Strings.t("unpin_msg") to { model.unpinMessage(group, m.id) })
                    else model.pinChoices().forEach { (label, secs) ->
                        add("${Strings.t("pin_msg")}: ${Strings.t("pin_$label")}" to { model.pinMessage(group, m.id, secs) })
                    }
                }
                if (state.rich.forwardingAllowed && (m.kind == "text" || m.kind == "file")) {
                    add(Strings.t("forward") to { picker = true })
                    if (m.kind == "text") add(Strings.t("copy") to { clipboard.setText(AnnotatedString(m.text ?: "")) })
                }
                laterChoices().forEach { (k, secs) ->
                    add("${Strings.t("remind_me")}: ${Strings.t(k)}" to { model.remindMe(group, m.id, nowSecs() + secs) })
                }
            }
            items.forEach { (label, act) -> DropdownMenuItem(text = { Text(label) }, onClick = { open = false; scope.launch { act() } }) }
        }
    }
    if (picker) {
        AlertDialog(
            onDismissRequest = { picker = false },
            confirmButton = { TextButton(onClick = { picker = false }) { Text(Strings.t("cancel_action")) } },
            title = { Text(Strings.t("forward_to")) },
            text = {
                Column {
                    state.chats.filter { it.id != group && it.status == "accepted" }.forEach { c ->
                        TextButton(onClick = { picker = false; scope.launch { model.forward(group, m.id, c.id) } }) { Text(c.title) }
                    }
                }
            },
        )
    }
}

/** Composer extras: schedule the draft, start a poll. */
@Composable
fun ComposerExtras(model: AppModel, group: String, draft: String, silent: Boolean, onScheduled: () -> Unit) {
    val scope = rememberCoroutineScope()
    var scheduleMenu by remember { mutableStateOf(false) }
    var pollOpen by remember { mutableStateOf(false) }
    Box {
        TextButton(enabled = draft.isNotBlank(), onClick = { scheduleMenu = true }) { Text("⏰ " + Strings.t("schedule")) }
        DropdownMenu(expanded = scheduleMenu, onDismissRequest = { scheduleMenu = false }) {
            laterChoices().forEach { (k, secs) ->
                DropdownMenuItem(text = { Text(Strings.t(k)) }, onClick = {
                    scheduleMenu = false
                    scope.launch { if (model.schedule(group, draft, nowSecs() + secs, silent) != null) onScheduled() }
                })
            }
        }
    }
    TextButton(onClick = { pollOpen = true }) { Text("📊 " + Strings.t("poll")) }
    if (pollOpen) PollDialog(model, group) { pollOpen = false }
}

@Composable
private fun PollDialog(model: AppModel, group: String, close: () -> Unit) {
    val scope = rememberCoroutineScope()
    var question by remember { mutableStateOf("") }
    var options by remember { mutableStateOf("") }
    var multi by remember { mutableStateOf(false) }
    var anon by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = close,
        title = { Text(Strings.t("poll_new")) },
        confirmButton = {
            TextButton(onClick = {
                scope.launch { if (model.createPoll(group, question, options.lines(), multi, anon) != null) close() }
            }) { Text(Strings.t("send")) }
        },
        dismissButton = { TextButton(onClick = close) { Text(Strings.t("cancel_action")) } },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                OutlinedTextField(question, { question = it }, label = { Text(Strings.t("poll_question")) })
                OutlinedTextField(options, { options = it }, label = { Text(Strings.t("poll_options")) }, minLines = 3)
                Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(multi, { multi = it }); Text(Strings.t("poll_multi")) }
                Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(anon, { anon = it }); Text(Strings.t("poll_anon")) }
                if (anon) Text(Strings.t("poll_anon_note"), style = MaterialTheme.typography.bodySmall)
            }
        },
    )
}

/** Scheduled messages of the chat (edit time, cancel), export, upcoming reminders. */
@Composable
fun ChatExtras(model: AppModel, state: UiState, group: String) {
    val scope = rememberCoroutineScope()
    var exported by remember(group) { mutableStateOf<List<String>?>(null) }
    if (state.rich.scheduled.isNotEmpty()) {
        Text("⏰ " + Strings.t("scheduled"), style = MaterialTheme.typography.labelMedium)
        state.rich.scheduled.forEach { s ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("${hhmm(s.at)}  ${s.text.take(60)}", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { scope.launch { model.editScheduled(s.id, null, s.at + 3600) } }) { Text("+1h") }
                TextButton(onClick = { scope.launch { model.cancelScheduled(s.id) } }) { Text(Strings.t("cancel_action")) }
            }
        }
        Text(Strings.t("schedule_note"), style = MaterialTheme.typography.bodySmall)
    }
    val reminders = state.rich.reminders.filter { it.group == group }
    if (reminders.isNotEmpty()) {
        Text("🔔 " + Strings.t("reminders"), style = MaterialTheme.typography.labelMedium)
        reminders.forEach { r ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("${hhmm(r.at)}  ${(r.text ?: "").take(60)}", Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                TextButton(onClick = { scope.launch { model.cancelReminder(r.id) } }) { Text(Strings.t("cancel_action")) }
            }
        }
    }
    if (state.rich.exportAllowed) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = {
                val d = java.awt.FileDialog(null as java.awt.Frame?, Strings.t("export"), java.awt.FileDialog.SAVE)
                d.file = "tree-chat"
                d.isVisible = true
                if (d.file != null) scope.launch {
                    exported = model.exportChat(group, java.io.File(d.directory, d.file.removeSuffix(".txt").removeSuffix(".json")).path)
                }
            }) { Text(Strings.t("export")) }
            exported?.let { Text("${Strings.t("exported")}: ${it.joinToString(", ")}", style = MaterialTheme.typography.bodySmall) }
        }
    }
}

/** Settings: clean old downloaded media now (user.storage_clean sets the period). */
@Composable
fun StorageCleanButton(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var result by remember { mutableStateOf<String?>(null) }
    val on = state.features.any { it.key == "user.storage_clean" && it.applied }
    if (!on) return
    Row(verticalAlignment = Alignment.CenterVertically) {
        TextButton(onClick = {
            scope.launch { model.cleanStorage()?.let { result = "${Strings.t("storage_cleaned")}: ${it.files} (${it.bytes} B)" } }
        }) { Text(Strings.t("storage_clean_now")) }
        result?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
    }
}
