package app.tree.desktop

import app.tree.shared.*

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import app.tree.shared.media.Raster
import kotlinx.coroutines.launch
import uniffi.tree_ffi.NetworkKind
import java.io.File

/** Where profiles live: one encrypted database per account on this computer. */
fun profilePath(): String {
    val dir = File(System.getProperty("user.home"), ".tree")
    dir.mkdirs()
    return File(dir, "profile.db").path
}

/** A computer counts as an unmetered network; files that download by themselves go here. */
suspend fun desktopMedia(model: AppModel) {
    model.downloadDir = File(System.getProperty("user.home"), ".tree/downloads")
    model.setNetwork(NetworkKind.WIFI)
}

/** A preview picture from the message, decoded for Compose. */
private fun thumbnailBitmap(bytes: ByteArray): ImageBitmap? =
    runCatching { org.jetbrains.skia.Image.makeFromEncoded(bytes).toComposeImageBitmap() }.getOrNull()

@Composable
fun App(model: AppModel) {
    val state by model.state.collectAsState()
    MaterialTheme {
        Box(Modifier.fillMaxSize()) {
            if (!state.signedIn) SignIn(model) else Main(model, state)
            state.error?.let { msg ->
                AlertDialog(
                    onDismissRequest = model::clearMessages,
                    confirmButton = { TextButton(onClick = model::clearMessages) { Text("OK") } },
                    text = { Text(msg) },
                )
            }
            state.notice?.let { msg ->
                AlertDialog(
                    onDismissRequest = model::clearMessages,
                    confirmButton = { TextButton(onClick = model::clearMessages) { Text("OK") } },
                    text = { Text(msg) },
                )
            }
        }
    }
}

@Composable
private fun SignIn(model: AppModel) {
    val scope = rememberCoroutineScope()
    val path = remember { profilePath() }
    val exists = remember { File(path).exists() }
    var name by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var server by remember { mutableStateOf(System.getenv("TREE_URL") ?: "https://") }
    Column(Modifier.padding(32.dp).width(420.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(Strings.t("app"), style = MaterialTheme.typography.headlineMedium)
        if (!exists) {
            OutlinedTextField(name, { name = it }, label = { Text(Strings.t("name")) }, singleLine = true)
            OutlinedTextField(server, { server = it }, label = { Text(Strings.t("server")) }, singleLine = true)
        }
        OutlinedTextField(
            pass, { pass = it },
            label = { Text(Strings.t("passphrase")) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
        )
        Button(onClick = {
            scope.launch {
                val ok = if (exists) model.openProfile(path, pass) else model.createAccount(path, pass, name, server)
                if (ok) {
                    desktopMedia(model)
                    model.startSyncLoop()
                }
            }
        }) { Text(if (exists) Strings.t("open") else Strings.t("create")) }
        if (!exists) {
            // A second device of an existing account: show a link, compare the code.
            TextButton(onClick = {
                scope.launch { if (model.startLinkNewDevice(path, pass, name, server) != null) model.watchLink { model.startSyncLoop() } }
            }) { Text(Strings.t("link_new")) }
            LinkPanel(model, newDevice = true)
        }
    }
}

/**
 * A device link in progress: the link to show (new device), the code to
 * compare, and the two answers. Nothing links until both devices confirm.
 */
@Composable
private fun LinkPanel(model: AppModel, newDevice: Boolean) {
    val scope = rememberCoroutineScope()
    val state by model.state.collectAsState()
    val link = state.link ?: return
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        link.text?.let {
            Text(Strings.t("link_show"))
            SelectionContainer { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        when (link.state) {
            "code" -> {
                Text(Strings.t("link_code"))
                Text(link.code ?: "", style = MaterialTheme.typography.headlineMedium)
                Row {
                    Button(onClick = {
                        scope.launch { if (newDevice) model.confirmNewDevice(true) else model.confirmLink(true) }
                    }) { Text(Strings.t("link_match")) }
                    Spacer(Modifier.width(8.dp))
                    TextButton(onClick = {
                        scope.launch { if (newDevice) model.confirmNewDevice(false) else model.confirmLink(false) }
                    }) { Text(Strings.t("link_differ")) }
                }
            }
            "confirmed", "waiting" -> {
                link.code?.let { Text(it, style = MaterialTheme.typography.headlineMedium) }
                Text(Strings.t("link_wait"))
            }
            "linked" -> Text(Strings.t("link_done"))
            else -> Text(Strings.t("link_cancelled") + (link.reason?.let { ": $it" } ?: ""))
        }
    }
}

@Composable
private fun Main(model: AppModel, state: UiState) {
    var tab by remember { mutableStateOf(0) }
    Column(Modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = tab) {
            listOf("chats", "requests", "settings").forEachIndexed { i, k ->
                Tab(selected = tab == i, onClick = { tab = i }, text = { Text(Strings.t(k)) })
            }
        }
        when (tab) {
            0 -> Chats(model, state, requests = false)
            1 -> Chats(model, state, requests = true)
            else -> Settings(model, state)
        }
    }
}

@Composable
private fun Chats(model: AppModel, state: UiState, requests: Boolean) {
    val scope = rememberCoroutineScope()
    val shown = model.visibleChats(state).filter { (it.status == "request") == requests && it.status != "declined" }
    Row(Modifier.fillMaxSize()) {
        Column(Modifier.width(260.dp).fillMaxHeight().padding(8.dp)) {
            if (!requests) {
                Button(onClick = { scope.launch { model.newChat() } }) { Text(Strings.t("new_group")) }
                JoinLink(model)
                // Folders: all, user folders, built-in ones.
                Row {
                    TextButton(onClick = { model.showFolder(null) }) { Text(Strings.t("all")) }
                    state.folders.forEach { f ->
                        TextButton(onClick = { model.showFolder(f.name) }) {
                            Text(if (f.kind == "user") f.name else Strings.t(f.kind))
                        }
                    }
                }
                Text(Strings.t("notes"), Modifier.fillMaxWidth().clickable { scope.launch { model.openNotes() } }.padding(8.dp))
            }
            if (!requests) {
                // The archive is its own list; archived chats leave the main one.
                val archived = state.chats.count { it.archived && it.status != "declined" }
                if (state.showArchived) {
                    TextButton(onClick = { model.showArchived(false) }) { Text("← " + Strings.t("back_to_list")) }
                } else if (archived > 0) {
                    TextButton(onClick = { model.showArchived(true) }) { Text("${Strings.t("archived")} ($archived)") }
                }
            }
            LazyColumn {
                items(shown, key = { it.id }) { c ->
                    ChatRow(model, c, requests)
                    HorizontalDivider()
                }
            }
        }
        val open = state.open
        val chat = state.chats.firstOrNull { it.id == open }
        if (chat != null && (chat.status == "request") == requests) ChatView(model, state, chat)
    }
}

/** "Muted", "muted until <time>", for the list and the chat header. */
private fun muteNote(c: Chat): String? = when {
    !c.muted -> null
    c.mutedUntil == null -> Strings.t("muted")
    else -> {
        val t = java.time.Instant.ofEpochSecond(c.mutedUntil!!).atZone(java.time.ZoneId.systemDefault())
        "${Strings.t("muted")} (${Strings.t("until")} ${java.time.format.DateTimeFormatter.ofPattern("MM-dd HH:mm").format(t)})"
    }
}

/** Stranger labels as text ("not a contact · no groups in common · ..."). */
private fun labelText(c: Chat): String? = c.labels.takeIf { it.isNotEmpty() }?.joinToString(" · ") { Strings.t(it) }

/** One chat in the list, with its menu: pin, mute, archive, unread, leave. */
@Composable
private fun ChatRow(model: AppModel, c: Chat, requests: Boolean) {
    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).clickable { scope.launch { model.openChat(c.id) } }.padding(8.dp)) {
            val marks = listOfNotNull(
                "^".takeIf { c.pinned },
                "(${c.unread})".takeIf { c.unread > 0 },
                "•".takeIf { c.markedUnread && c.unread == 0 },
            ).joinToString(" ")
            Text(c.title + if (marks.isEmpty()) "" else "  $marks")
            muteNote(c)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            c.draft?.let { Text("${Strings.t("draft")}: ${it.take(30)}", style = MaterialTheme.typography.bodySmall) }
            if (requests) labelText(c)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
        if (!requests) {
            Box {
                TextButton(onClick = { menu = true }) { Text("⋮") }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    val items = buildList<Pair<String, suspend () -> Unit>> {
                        if (!c.archived) add(Strings.t(if (c.pinned) "unpin" else "pin") to { model.pin(c.id, !c.pinned) })
                        if (c.muted) add(Strings.t("unmute") to { model.unmute(c.id) })
                        else model.muteChoices().forEach { (label, secs) ->
                            add("${Strings.t("mute")}: ${if (secs == null) Strings.t("forever") else label}" to { model.mute(c.id, secs) })
                        }
                        add(Strings.t(if (c.archived) "unarchive" else "archive") to { model.archive(c.id, !c.archived) })
                        add(Strings.t(if (c.markedUnread) "mark_read" else "mark_unread") to { model.markUnread(c.id, !c.markedUnread) })
                        add(Strings.t("leave") to { model.leave(c.id, false) })
                        add(Strings.t("leave_quietly") to { model.leave(c.id, true) })
                    }
                    items.forEach { (label, act) ->
                        DropdownMenuItem(text = { Text(label) }, onClick = { menu = false; scope.launch { act() } })
                    }
                }
            }
        }
    }
}

@Composable
private fun JoinLink(model: AppModel) {
    val scope = rememberCoroutineScope()
    var link by remember { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(link, { link = it }, label = { Text(Strings.t("join")) }, singleLine = true, modifier = Modifier.width(170.dp))
        TextButton(onClick = { scope.launch { if (model.joinLink(link)) link = "" } }) { Text("→") }
    }
}

/** Safety numbers of the other members, with "mark verified". */
@Composable
private fun SafetyPanel(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var shown by remember { mutableStateOf<Pair<String, String>?>(null) }
    var verified by remember { mutableStateOf(false) }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(Strings.t("safety") + ":")
        state.members.filter { state.names[it.id] != "" && it.account != null }.forEach { m ->
            TextButton(onClick = {
                scope.launch {
                    val acc = m.account!!
                    shown = model.safetyNumber(acc)?.let { acc to it }
                    verified = model.isVerified(acc)
                }
            }) { Text(state.names[m.id] ?: m.id.take(6)) }
        }
    }
    shown?.let { (acc, digits) ->
        Text(Strings.t("compare"), style = MaterialTheme.typography.bodySmall)
        SelectionContainer { Text(digits, style = MaterialTheme.typography.titleMedium) }
        if (verified) Text("✓ " + Strings.t("verified"))
        else TextButton(onClick = { scope.launch { verified = model.markVerified(acc) } }) { Text(Strings.t("verify")) }
    }
}

/**
 * One setting: its key and option, why it is locked or when a release takes
 * effect, the option choices (applying with that option), and the switch.
 * Switching on keeps the current option (null: the feature's default).
 */
@Composable
private fun FeatureRow(model: AppModel, f: uniffi.tree_ffi.Feature, switchable: Boolean, set: (Boolean, String?) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(f.key + (f.option?.let { " ($it)" } ?: ""))
            f.lockedBy?.let { Text("${Strings.t("locked")}: $it", style = MaterialTheme.typography.bodySmall) }
            model.pendingNote(f)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
            if (f.lockedBy == null && f.choices.isNotEmpty()) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(Strings.t("option") + ":", style = MaterialTheme.typography.bodySmall)
                    f.choices.forEach { c ->
                        TextButton(onClick = { set(true, c) }) { Text(if (f.applied && f.option == c) "[$c]" else c) }
                    }
                }
            }
        }
        Switch(
            checked = f.applied,
            enabled = switchable && f.lockedBy == null,
            onCheckedChange = { on -> set(on, if (on) f.option else null) },
        )
    }
}

/** Admins: every chat setting with apply / release and its option. */
@Composable
private fun GroupSettingsPanel(model: AppModel, state: UiState, group: String) {
    val scope = rememberCoroutineScope()
    Text(Strings.t("group_settings"), style = MaterialTheme.typography.titleSmall)
    state.chatFeatures.forEach { f ->
        FeatureRow(model, f, switchable = true) { on, option -> scope.launch { model.setChatFeature(group, f.key, on, option) } }
    }
}

@Composable
private fun ChatView(model: AppModel, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    var settingsOpen by remember(chat.id) { mutableStateOf(false) }
    // The chat's draft comes back when it opens (user.drafts).
    var draft by remember(chat.id) { mutableStateOf(chat.draft ?: "") }
    var silent by remember(chat.id) { mutableStateOf(false) }
    var who by remember(chat.id) { mutableStateOf("") }
    var link by remember(chat.id) { mutableStateOf<String?>(null) }
    var editing by remember(chat.id) { mutableStateOf<Pair<String, Raster>?>(null) }
    Column(Modifier.fillMaxSize().padding(8.dp)) {
        Text(chat.title, style = MaterialTheme.typography.titleLarge)
        // Who this person is to the user (user.stranger_labels), and the mute.
        labelText(chat)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        muteNote(chat)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        if (chat.status == "request") {
            Text(Strings.t("request_from") + ": " + (chat.requestFrom ?: "?"))
            Row {
                Button(onClick = { scope.launch { model.accept(chat.id) } }) { Text(Strings.t("accept")) }
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = { scope.launch { model.decline(chat.id, false) } }) { Text(Strings.t("decline")) }
                TextButton(onClick = { scope.launch { model.decline(chat.id, true) } }) { Text(Strings.t("block")) }
            }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(who, { who = it }, label = { Text(Strings.t("invite")) }, singleLine = true)
                TextButton(onClick = { scope.launch { if (model.invite(chat.id, who)) who = "" } }) { Text("+") }
                TextButton(onClick = { scope.launch { link = model.inviteLink(chat.id) } }) { Text(Strings.t("invite_link")) }
            }
            link?.let { SelectionContainer { Text(it) } }
            SafetyPanel(model, state)
            TextButton(onClick = { settingsOpen = !settingsOpen }) { Text(Strings.t("group_settings")) }
            if (settingsOpen) GroupSettingsPanel(model, state, chat.id)
        }
        if (state.typing.isNotEmpty()) {
            Text(state.typing.joinToString(", ") { state.names[it] ?: it.take(6) } + " " + Strings.t("typing"),
                style = MaterialTheme.typography.bodySmall)
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
            items(state.messages, key = { it.id }) { m ->
                val body = when {
                    m.kind == "left" || m.kind == "removed" -> "${m.who ?: m.sender.take(6)} ${Strings.t(m.kind)}"
                    m.deleted -> Strings.t("deleted")
                    else -> (m.text ?: "") + if (m.edited) " (${Strings.t("edited")})" else ""
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val who = state.names[m.sender]?.ifEmpty { Strings.t("me") } ?: m.sender.take(6)
                    val read = if (m.id in state.readMine) "  ✓ " + Strings.t("read") else ""
                    Text("$who: $body$read", Modifier.weight(1f).padding(4.dp))
                    // Own messages on their way: a small marker; failed ones offer retry and cancel.
                    when (m.status) {
                        "pending" -> Text("… " + Strings.t("pending"), style = MaterialTheme.typography.bodySmall)
                        "failed" -> {
                            Text("! " + Strings.t("failed"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                            TextButton(onClick = { scope.launch { model.retrySend(m.id) } }) { Text(Strings.t("retry")) }
                            TextButton(onClick = { scope.launch { model.cancelSend(m.id) } }) { Text(Strings.t("cancel_send")) }
                        }
                    }
                    // In a request, files stay closed until the user accepts (design: requests).
                    if (m.kind == "file" && chat.status == "request") {
                        Text(Strings.t("after_accept"), style = MaterialTheme.typography.bodySmall)
                    } else if (m.kind == "file") {
                        FileRow(model, state, m.id)
                    }
                    TextButton(onClick = { scope.launch { model.report(chat.id, listOf(m.id), "user report") } }) {
                        Text(Strings.t("report"))
                    }
                }
            }
        }
        editing?.let { (name, picture) ->
            EditorDialog(picture, onSend = { jpeg, w, h, thumb ->
                editing = null
                val sendName = name.substringBeforeLast('.') + ".jpg"
                scope.launch { model.sendMedia(chat.id, jpeg, sendName, "image/jpeg", AppModel.picture(w, h, thumb)) }
            }, onCancel = { editing = null })
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = {
                val d = java.awt.FileDialog(null as java.awt.Frame?, Strings.t("attach"), java.awt.FileDialog.LOAD)
                d.isVisible = true
                if (d.file != null) scope.launch { model.sendFile(chat.id, java.io.File(d.directory, d.file)) }
            }) { Text(Strings.t("attach")) }
            // Pictures go through the editor: the original stays here.
            TextButton(onClick = {
                val d = java.awt.FileDialog(null as java.awt.Frame?, Strings.t("photo"), java.awt.FileDialog.LOAD)
                d.isVisible = true
                if (d.file != null) {
                    val f = java.io.File(d.directory, d.file)
                    DesktopMedia.load(f)?.let { editing = f.name to it }
                }
            }) { Text(Strings.t("photo")) }
            OutlinedTextField(draft, { v ->
                if (draft.isEmpty() != v.isEmpty()) scope.launch { model.typing(chat.id, v.isNotEmpty()) }
                draft = v
                scope.launch { model.saveDraft(chat.id, v) }
            }, label = { Text(Strings.t("message")) }, modifier = Modifier.weight(1f))
            Checkbox(silent, { silent = it })
            Text(Strings.t("silent"), style = MaterialTheme.typography.bodySmall)
            Button(onClick = { scope.launch { if (model.send(chat.id, draft, silent)) { model.typing(chat.id, false); draft = "" } } }) { Text(Strings.t("send")) }
        }
    }
}

@Composable
private fun Settings(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var phrase by remember { mutableStateOf<String?>(null) }
    var username by remember { mutableStateOf("") }
    var confirmDelete by remember { mutableStateOf(false) }
    var newLink by remember { mutableStateOf("") }
    remember { scope.launch { model.loadDevices() } }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            confirmButton = { TextButton(onClick = { confirmDelete = false; scope.launch { model.deleteAccount() } }) { Text(Strings.t("delete_account")) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
            text = { Text(Strings.t("delete_confirm")) },
        )
    }
    var friendLink by remember { mutableStateOf("") }
    remember { scope.launch { model.loadFeatures(); model.loadUsernameLink() } }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("${state.name}  ·  ${state.account}")
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(username, { username = it }, label = { Text(Strings.t("username")) }, singleLine = true)
            TextButton(onClick = { scope.launch { model.setUsername(username) } }) { Text("✓") }
        }
        // Username link and QR code (user.username_link below turns it on).
        // The QR image is drawn from this text; until a QR library is part of
        // the build, the link itself is shown to copy.
        state.usernameLink?.let { l ->
            Text(Strings.t("username_link"), style = MaterialTheme.typography.bodySmall)
            Row(verticalAlignment = Alignment.CenterVertically) {
                SelectionContainer { Text(l) }
                TextButton(onClick = { scope.launch { model.resetUsernameLink() } }) { Text(Strings.t("reset_link")) }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(friendLink, { friendLink = it }, label = { Text(Strings.t("add_by_link")) }, singleLine = true)
            TextButton(onClick = { scope.launch { if (model.addByLink(friendLink) != null) friendLink = "" } }) { Text("+") }
        }
        Button(onClick = { scope.launch { phrase = model.recoveryPhrase(Strings.lang == Lang.KO) } }) { Text(Strings.t("recovery")) }
        phrase?.let {
            Text(Strings.t("recovery_note"))
            SelectionContainer { Text(it, style = MaterialTheme.typography.titleMedium) }
        }
        TextButton(onClick = { confirmDelete = true }) { Text(Strings.t("delete_account")) }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        // Linking a new device: paste its link, compare the code on both.
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(newLink, { newLink = it }, label = { Text(Strings.t("link_scan")) }, singleLine = true)
            TextButton(onClick = { scope.launch { if (model.scanLink(newLink) != null) { newLink = ""; model.watchLink() } } }) { Text("→") }
        }
        LinkPanel(model, newDevice = false)
        Text(Strings.t("devices"), style = MaterialTheme.typography.titleSmall)
        state.devices.forEach { d ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(d, Modifier.weight(1f))
                if (d != model.session?.deviceId()) {
                    TextButton(onClick = { scope.launch { model.removeDevice(d) } }) { Text(Strings.t("remove_device")) }
                }
            }
        }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        // Every user setting with apply / release; locked ones say why.
        LazyColumn {
            items(state.features, key = { it.key }) { f ->
                // The recovery phrase is made with the button above (the words are
                // shown once); the switch only releases it, which the server
                // completes after 7 days (shown as pending until then).
                val recovery = f.key == "user.recovery_phrase"
                FeatureRow(model, f, switchable = !recovery || (f.applied && f.releasePendingUntil == null)) { on, option ->
                    scope.launch { model.setFeature(f.key, on, option) }
                }
            }
        }
    }
}

/** A file in the chat: preview picture, name and size, progress, pause / resume, save as. */
@Composable
private fun FileRow(model: AppModel, state: UiState, msgId: String) {
    val scope = rememberCoroutineScope()
    val f = model.fileOf(msgId) ?: return
    val t = state.transfers[msgId]
    Column(Modifier.width(220.dp)) {
        f.thumbnail?.let { bytes -> thumbnailBitmap(bytes)?.let { Image(it, null, Modifier.size(160.dp)) } }
        val dims = if (f.width != null && f.height != null) "  ${f.width}x${f.height}" else ""
        Text("${f.name}  ${f.size.toLong() / 1024} KiB$dims", style = MaterialTheme.typography.bodySmall)
        if (t != null && t.total > 0u) {
            val what = when {
                t.state == "paused" -> Strings.t("paused")
                t.upload -> Strings.t("uploading")
                else -> Strings.t("downloading")
            }
            LinearProgressIndicator(progress = { (t.done.toDouble() / t.total.toDouble()).toFloat() }, modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("$what ${t.done.toLong() * 100 / t.total.toLong()}%", style = MaterialTheme.typography.bodySmall)
                if (t.upload && t.state == "paused") {
                    TextButton(onClick = { scope.launch { model.resumeTransfer(msgId) } }) { Text(Strings.t("resume")) }
                } else if (t.upload) {
                    TextButton(onClick = { scope.launch { model.pauseTransfer(msgId) } }) { Text(Strings.t("pause")) }
                }
            }
        }
        if (msgId in state.downloaded) Text("\u2713 " + Strings.t("downloaded"), style = MaterialTheme.typography.bodySmall)
        if (f.id.isNotEmpty()) {
            TextButton(onClick = {
                val d = java.awt.FileDialog(null as java.awt.Frame?, Strings.t("save_as"), java.awt.FileDialog.SAVE)
                d.file = AppModel.safeName(f.name)
                d.isVisible = true
                if (d.file != null) scope.launch { model.saveFile(msgId, java.io.File(d.directory, d.file)) }
            }) { Text(Strings.t("save_as")) }
        }
    }
}
