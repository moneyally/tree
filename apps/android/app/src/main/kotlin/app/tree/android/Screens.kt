package app.tree.android

import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import app.tree.shared.qr.CodeKind
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.Strings
import app.tree.shared.UiState
import kotlinx.coroutines.launch
import java.io.File

@Composable
fun TreeApp(model: AppModel, profile: String) {
    val state by model.state.collectAsState()
    MaterialTheme {
        if (!state.signedIn) SignIn(model, profile) else Home(model, state)
        (state.error ?: state.notice)?.let { msg ->
            AlertDialog(
                onDismissRequest = model::clearMessages,
                confirmButton = { TextButton(onClick = model::clearMessages) { Text("OK") } },
                text = { Text(msg) },
            )
        }
    }
}

@Composable
private fun SignIn(model: AppModel, profile: String) {
    val scope = rememberCoroutineScope()
    val exists = remember { File(profile).exists() }
    var name by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var server by remember { mutableStateOf("https://") }
    val link = model.state.collectAsState().value.link
    if (!exists && link != null) {
        // This phone is being linked to an account: its QR code, then the digits.
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(Strings.t("qr_new_device"), style = MaterialTheme.typography.titleLarge)
            LinkSteps(model, link, newDevice = true)
            if (link.state == "cancelled") TextButton(onClick = model::closeLink) { Text(Strings.t("qr_close")) }
        }
        return
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(Strings.t("app"), style = MaterialTheme.typography.headlineMedium)
        if (!exists) {
            OutlinedTextField(name, { name = it }, label = { Text(Strings.t("name")) }, singleLine = true)
            OutlinedTextField(server, { server = it }, label = { Text(Strings.t("server")) }, singleLine = true)
        }
        OutlinedTextField(pass, { pass = it }, label = { Text(Strings.t("passphrase")) }, singleLine = true,
            visualTransformation = PasswordVisualTransformation())
        Button(onClick = {
            scope.launch {
                val ok = if (exists) model.openProfile(profile, pass) else model.createAccount(profile, pass, name, server)
                if (ok) model.startSyncLoop()
            }
        }) { Text(if (exists) Strings.t("open") else Strings.t("create")) }
        // App lock with a PIN or biometrics (user.app_lock), when set up here.
        if (exists) UnlockOptions(model, profile) { model.startSyncLoop() }
        if (!exists) {
            // A second device of an account used on another phone or computer:
            // this phone shows a QR code that the other device scans.
            HorizontalDivider()
            OutlinedButton(onClick = {
                scope.launch { if (model.startLinkNewDevice(profile, pass, name, server) != null) model.watchLink { model.startSyncLoop() } }
            }, modifier = Modifier.fillMaxWidth()) { Text(Strings.t("qr_new_device")) }
        }
    }
}

@Composable
private fun Home(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var tab by remember { mutableStateOf(0) }
    var scanning by remember { mutableStateOf<CodeKind?>(null) }
    // A device link in progress takes the whole screen until it ends.
    state.link?.let { LinkInProgressScreen(model, it); return }
    scanning?.let { want -> ScanScreen(model, want) { scanning = null }; return }
    val open = state.chats.firstOrNull { it.id == state.open }
    if (open != null) {
        BackHandler { scope.launch { model.openChat(null) } }
        ChatScreen(model, state, open)
        return
    }
    Column(Modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = tab) {
            listOf("chats", "requests", "settings").forEachIndexed { i, k ->
                Tab(selected = tab == i, onClick = { tab = i }, text = { Text(Strings.t(k)) })
            }
        }
        when (tab) {
            0, 1 -> ChatList(model, state, requests = tab == 1)
            else -> SettingsScreen(model, state) { scanning = it }
        }
    }
}

@Composable
private fun ChatList(model: AppModel, state: UiState, requests: Boolean) {
    val scope = rememberCoroutineScope()
    var link by remember { mutableStateOf("") }
    Column(Modifier.padding(8.dp)) {
        if (!requests) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Button(onClick = { scope.launch { model.newChat() } }) { Text(Strings.t("new_group")) }
                OutlinedTextField(link, { link = it }, label = { Text(Strings.t("join")) }, singleLine = true, modifier = Modifier.weight(1f))
                TextButton(onClick = { scope.launch { if (model.joinLink(link)) link = "" } }) { Text("→") }
            }
        }
        if (!requests) {
            Row {
                TextButton(onClick = { model.showFolder(null) }) { Text(Strings.t("all")) }
                state.folders.forEach { f ->
                    TextButton(onClick = { model.showFolder(f.name) }) { Text(if (f.kind == "user") f.name else Strings.t(f.kind)) }
                }
            }
            SearchBar(model)
            Text(Strings.t("notes"), Modifier.fillMaxWidth().clickable { scope.launch { model.openNotes() } }.padding(14.dp))
            HorizontalDivider()
        }
        LazyColumn {
            items(model.visibleChats(state).filter { (it.status == "request") == requests && it.status != "declined" }, key = { it.id }) { c ->
                Text(c.title + if (c.unread > 0) "  (${c.unread})" else "",
                    Modifier.fillMaxWidth().clickable { scope.launch { model.openChat(c.id) } }.padding(14.dp))
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun ChatScreen(model: AppModel, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    // The chat's draft comes back when it opens (user.drafts).
    var draft by remember(chat.id) { mutableStateOf(chat.draft ?: "") }
    var who by remember(chat.id) { mutableStateOf("") }
    var extra by remember(chat.id) { mutableStateOf<String?>(null) }
    var saving by remember { mutableStateOf<String?>(null) }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) scope.launch {
            val r = context.contentResolver
            val bytes = r.openInputStream(uri)?.use { it.readBytes() } ?: return@launch
            model.sendBytes(chat.id, bytes, uri.lastPathSegment ?: "file", r.getType(uri) ?: "application/octet-stream")
        }
    }
    val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val id = saving
        if (uri != null && id != null) scope.launch {
            val bytes = model.fileBytes(id) ?: return@launch
            context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
        }
    }
    Column(Modifier.fillMaxSize().padding(8.dp).imePadding()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { scope.launch { model.openChat(null) } }) { Text("←") }
            Text(chat.title, style = MaterialTheme.typography.titleLarge)
        }
        // Who this person is to the user (user.stranger_labels).
        if (chat.labels.isNotEmpty()) {
            Text(chat.labels.joinToString(" · ") { Strings.t(it) }, style = MaterialTheme.typography.bodySmall)
        }
        if (chat.status == "request") {
            Text(Strings.t("request_from") + ": " + (chat.requestFrom ?: "?"))
            Row {
                Button(onClick = { scope.launch { model.accept(chat.id) } }) { Text(Strings.t("accept")) }
                TextButton(onClick = { scope.launch { model.decline(chat.id, false) } }) { Text(Strings.t("decline")) }
                TextButton(onClick = { scope.launch { model.decline(chat.id, true) } }) { Text(Strings.t("block")) }
            }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(who, { who = it }, label = { Text(Strings.t("invite")) }, singleLine = true, modifier = Modifier.weight(1f))
                TextButton(onClick = { scope.launch { if (model.invite(chat.id, who)) who = "" } }) { Text("+") }
            }
            Row {
                TextButton(onClick = { scope.launch { extra = model.inviteLink(chat.id) } }) { Text(Strings.t("invite_link")) }
                state.members.filter { state.names[it.id] != "" && it.account != null }.take(3).forEach { m ->
                    TextButton(onClick = { scope.launch { extra = model.safetyNumber(m.account!!) } }) {
                        Text(Strings.t("safety") + " · " + (state.names[m.id] ?: ""))
                    }
                }
            }
            extra?.let { SelectionContainer { Text(it) } }
        }
        if (state.typing.isNotEmpty()) {
            Text(state.typing.joinToString(", ") { state.names[it] ?: it.take(6) } + " " + Strings.t("typing"),
                style = MaterialTheme.typography.bodySmall)
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
            items(state.messages, key = { it.id }) { m ->
                val who2 = state.names[m.sender]?.ifEmpty { Strings.t("me") } ?: m.sender.take(6)
                val body = (if (m.kind == "left" || m.kind == "removed") "${m.who ?: ""} ${Strings.t(m.kind)}"
                    else if (m.deleted) Strings.t("deleted") else (m.text ?: "")) +
                    if (m.id in state.readMine) "  ✓ " + Strings.t("read") else ""
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text("$who2: $body", Modifier.weight(1f).padding(4.dp))
                    when (m.status) {
                        "pending" -> Text("… " + Strings.t("pending"), style = MaterialTheme.typography.bodySmall)
                        "failed" -> {
                            TextButton(onClick = { scope.launch { model.retrySend(m.id) } }) { Text(Strings.t("retry")) }
                            TextButton(onClick = { scope.launch { model.cancelSend(m.id) } }) { Text(Strings.t("cancel_send")) }
                        }
                    }
                    if (m.kind == "file" && chat.status == "request") {
                        Text(Strings.t("after_accept"), style = MaterialTheme.typography.bodySmall)
                    } else if (m.kind == "file" && state.files.containsKey(m.id)) {
                        TextButton(onClick = { saving = m.id; save.launch(m.text ?: "file") }) { Text(Strings.t("save")) }
                    }
                    TextButton(onClick = { scope.launch { model.report(chat.id, listOf(m.id), "user report") } }) { Text(Strings.t("report")) }
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = { pick.launch("*/*") }) { Text(Strings.t("attach")) }
            OutlinedTextField(draft, { v ->
                if (draft.isEmpty() != v.isEmpty()) scope.launch { model.typing(chat.id, v.isNotEmpty()) }
                draft = v
                scope.launch { model.saveDraft(chat.id, v) }
            }, label = { Text(Strings.t("message")) }, modifier = Modifier.weight(1f))
            Button(onClick = { scope.launch { if (model.send(chat.id, draft)) { model.typing(chat.id, false); draft = "" } } }) { Text(Strings.t("send")) }
        }
    }
}

@Composable
private fun SettingsScreen(model: AppModel, state: UiState, onScan: (CodeKind) -> Unit) {
    val scope = rememberCoroutineScope()
    var phrase by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            confirmButton = { TextButton(onClick = { confirmDelete = false; scope.launch { model.deleteAccount() } }) { Text(Strings.t("delete_account")) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } },
            text = { Text(Strings.t("delete_confirm")) },
        )
    }
    LazyColumn(Modifier.fillMaxSize().padding(16.dp)) {
        item {
            Text("${state.name} · ${state.account}")
            Button(onClick = { scope.launch { phrase = model.recoveryPhrase(Strings.lang == app.tree.shared.Lang.KO) } }) {
                Text(Strings.t("recovery"))
            }
            phrase?.let {
                Text(Strings.t("recovery_note"))
                SelectionContainer { Text(it, style = MaterialTheme.typography.titleMedium) }
            }
            TextButton(onClick = { confirmDelete = true }) { Text(Strings.t("delete_account")) }
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            QrSettings(model, onScan)
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
            AppLockSettings(model, state, (LocalContext.current.applicationContext as TreeApplication).profile)
            HorizontalDivider(Modifier.padding(vertical = 8.dp))
        }
        items(state.features, key = { it.key }) { f ->
            Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(f.key + (f.option?.let { " ($it)" } ?: ""))
                    f.lockedBy?.let { Text("${Strings.t("locked")}: $it", style = MaterialTheme.typography.bodySmall) }
                    model.pendingNote(f)?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                    if (f.lockedBy == null && f.choices.isNotEmpty()) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            f.choices.forEach { c ->
                                TextButton(onClick = { scope.launch { model.setFeature(f.key, true, c) } }) {
                                    Text(if (f.applied && f.option == c) "[$c]" else c)
                                }
                            }
                        }
                    }
                }
                // The recovery phrase is made with the button above; the
                // switch only releases it (pending for 7 days on the server).
                val switchable = f.key != "user.recovery_phrase" || (f.applied && f.releasePendingUntil == null)
                Switch(checked = f.applied, enabled = f.lockedBy == null && switchable,
                    onCheckedChange = { on -> scope.launch { model.setFeature(f.key, on, if (on) f.option else null) } })
            }
        }
    }
}
