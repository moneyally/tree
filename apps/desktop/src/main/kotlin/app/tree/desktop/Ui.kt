package app.tree.desktop

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
import kotlinx.coroutines.launch
import java.io.File

/** Where profiles live: one encrypted database per account on this computer. */
fun profilePath(): String {
    val dir = File(System.getProperty("user.home"), ".tree")
    dir.mkdirs()
    return File(dir, "profile.db").path
}

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
                if (ok) model.startSyncLoop()
            }
        }) { Text(if (exists) Strings.t("open") else Strings.t("create")) }
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
    val shown = state.chats.filter { (it.status == "request") == requests && it.status != "declined" }
    Row(Modifier.fillMaxSize()) {
        Column(Modifier.width(260.dp).fillMaxHeight().padding(8.dp)) {
            if (!requests) {
                Button(onClick = { scope.launch { model.newChat() } }) { Text(Strings.t("new_group")) }
                JoinLink(model)
            }
            LazyColumn {
                items(shown, key = { it.id }) { c ->
                    Text(
                        c.title + if (c.unread > 0) "  (${c.unread})" else "",
                        Modifier.fillMaxWidth().clickable { scope.launch { model.openChat(c.id) } }.padding(8.dp),
                    )
                    HorizontalDivider()
                }
            }
        }
        val open = state.open
        val chat = state.chats.firstOrNull { it.id == open }
        if (chat != null && (chat.status == "request") == requests) ChatView(model, state, chat)
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

@Composable
private fun ChatView(model: AppModel, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    var draft by remember(chat.id) { mutableStateOf("") }
    var who by remember(chat.id) { mutableStateOf("") }
    var link by remember(chat.id) { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().padding(8.dp)) {
        Text(chat.title, style = MaterialTheme.typography.titleLarge)
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
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
            items(state.messages, key = { it.id }) { m ->
                val body = when {
                    m.deleted -> Strings.t("deleted")
                    else -> (m.text ?: "") + if (m.edited) " (${Strings.t("edited")})" else ""
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val who = state.names[m.sender]?.ifEmpty { Strings.t("me") } ?: m.sender.take(6)
                    Text("$who: $body", Modifier.weight(1f).padding(4.dp))
                    TextButton(onClick = { scope.launch { model.report(chat.id, listOf(m.id), "user report") } }) {
                        Text(Strings.t("report"))
                    }
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(draft, { draft = it }, label = { Text(Strings.t("message")) }, modifier = Modifier.weight(1f))
            Button(onClick = { scope.launch { if (model.send(chat.id, draft)) draft = "" } }) { Text(Strings.t("send")) }
        }
    }
}

@Composable
private fun Settings(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var phrase by remember { mutableStateOf<String?>(null) }
    var username by remember { mutableStateOf("") }
    remember { scope.launch { model.loadFeatures() } }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Text("${state.name}  ·  ${state.account}")
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(username, { username = it }, label = { Text(Strings.t("username")) }, singleLine = true)
            TextButton(onClick = { scope.launch { model.setUsername(username) } }) { Text("✓") }
        }
        Button(onClick = { scope.launch { phrase = model.recoveryPhrase(Strings.lang == Lang.KO) } }) { Text(Strings.t("recovery")) }
        phrase?.let {
            Text(Strings.t("recovery_note"))
            SelectionContainer { Text(it, style = MaterialTheme.typography.titleMedium) }
        }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        // Every user setting with apply / release; locked ones say why.
        LazyColumn {
            items(state.features, key = { it.key }) { f ->
                Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(f.key)
                        f.lockedBy?.let { Text("${Strings.t("locked")}: $it", style = MaterialTheme.typography.bodySmall) }
                    }
                    Switch(
                        checked = f.applied,
                        enabled = f.lockedBy == null && f.key != "user.recovery_phrase",
                        onCheckedChange = { on -> scope.launch { model.setFeature(f.key, on) } },
                    )
                }
            }
        }
    }
}
