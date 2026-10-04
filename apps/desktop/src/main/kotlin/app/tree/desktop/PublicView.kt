package app.tree.desktop

import app.tree.shared.*

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.PublicPostInfo
import uniffi.tree_ffi.PublicSpaceInfo

/** The "Public" badge: public content is never shown without it. */
@Composable
fun PublicBadge() {
    Text(
        " ${publicBadge()} ",
        Modifier.background(Color(0xFFFFE0B2)).padding(horizontal = 4.dp),
        color = Color(0xFF8A4B00),
        style = MaterialTheme.typography.labelMedium,
    )
}

/** Public groups and channels: search, create, the subscribed list, the open space. */
@Composable
fun PublicScreen(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    Row(Modifier.fillMaxSize()) {
        Column(Modifier.width(300.dp).fillMaxHeight().padding(8.dp)) {
            Text(Strings.t("public_warning"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(query, { query = it }, label = { Text(Strings.t("public_search")) }, singleLine = true, modifier = Modifier.weight(1f))
                TextButton(onClick = { scope.launch { model.searchPublic(query) } }) { Text(Strings.t("public_search_go")) }
            }
            state.pub.found.forEach { s -> SpaceRow(model, s) }
            if (query.isNotBlank() && state.pub.found.isEmpty()) Text(Strings.t("public_none"), style = MaterialTheme.typography.bodySmall)
            HorizontalDivider()
            CreatePublic(model)
            HorizontalDivider()
            Text(Strings.t("public_spaces"), style = MaterialTheme.typography.titleSmall)
            LazyColumn {
                items(state.pub.spaces, key = { it.id }) { s -> SpaceRow(model, s) }
            }
        }
        state.pub.open?.let { PublicSpaceView(model, state, it) }
    }
}

@Composable
private fun SpaceRow(model: AppModel, s: PublicSpaceInfo) {
    val scope = rememberCoroutineScope()
    Row(Modifier.fillMaxWidth().clickable { scope.launch { model.openPublic(s.id) } }.padding(4.dp), verticalAlignment = Alignment.CenterVertically) {
        PublicBadge()
        Column(Modifier.weight(1f).padding(start = 6.dp)) {
            Text(s.name + if (s.unread > 0u) "  (${s.unread})" else "")
            Text("@${s.handle} · " + Strings.t(if (s.kind == "channel") "public_channel" else "public_group") + " · ${s.members} " + Strings.t("public_members"),
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

/** The create dialog: kind, name, @handle, description; the warning stays visible. */
@Composable
private fun CreatePublic(model: AppModel) {
    val scope = rememberCoroutineScope()
    var kind by remember { mutableStateOf("group") }
    var name by remember { mutableStateOf("") }
    var handle by remember { mutableStateOf("") }
    var desc by remember { mutableStateOf("") }
    Text(Strings.t("public_create"), style = MaterialTheme.typography.titleSmall)
    Row {
        FilterChip(kind == "group", onClick = { kind = "group" }, label = { Text(Strings.t("public_group")) })
        FilterChip(kind == "channel", onClick = { kind = "channel" }, label = { Text(Strings.t("public_channel")) })
    }
    OutlinedTextField(name, { name = it }, label = { Text(Strings.t("public_name")) }, singleLine = true)
    OutlinedTextField(handle, { handle = it }, label = { Text(Strings.t("public_handle")) }, singleLine = true)
    OutlinedTextField(desc, { desc = it }, label = { Text(Strings.t("public_description")) })
    Row(verticalAlignment = Alignment.CenterVertically) {
        PublicBadge()
        Button(onClick = {
            scope.launch { if (model.createPublic(kind, name, handle, desc) != null) { name = ""; handle = ""; desc = "" } }
        }) { Text(Strings.t(if (kind == "channel") "public_create_channel" else "public_create_group")) }
    }
}

@Composable
private fun PublicSpaceView(model: AppModel, state: UiState, s: PublicSpaceInfo) {
    val scope = rememberCoroutineScope()
    var draft by remember(s.id) { mutableStateOf("") }
    var tools by remember(s.id) { mutableStateOf(false) }
    val admin = s.role == "owner" || s.role == "admin"
    Column(Modifier.fillMaxSize().padding(8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            PublicBadge()
            Text(" " + s.name, style = MaterialTheme.typography.titleLarge)
            Text("  @${s.handle}", style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = { scope.launch { model.openPublic(null) } }) { Text(Strings.t("public_back")) }
        }
        Text(publicTitle(s) + " · ${s.members} " + Strings.t("public_members"), style = MaterialTheme.typography.bodySmall)
        if (s.description.isNotEmpty()) Text(s.description)
        Text(Strings.t("public_warning"), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
        if (s.banned) Text(Strings.t("public_banned"), color = MaterialTheme.colorScheme.error)
        Row(verticalAlignment = Alignment.CenterVertically) {
            when {
                s.role == null -> Button(onClick = { scope.launch { model.joinPublic(s.id) } }, enabled = !s.banned) { Text(Strings.t("public_join")) }
                s.role != "owner" -> TextButton(onClick = { scope.launch { model.leavePublic(s.id) } }) { Text(Strings.t("public_leave")) }
            }
            if (s.role != null) {
                Switch(s.notify, { on -> scope.launch { model.setPublicNotify(on) } })
                Text(" " + Strings.t("public_notify"))
            }
            if (admin) TextButton(onClick = { tools = !tools }) { Text(Strings.t("public_admin_tools")) }
        }
        if (admin && tools) PublicAdminTools(model, s)
        LazyColumn(Modifier.weight(1f).fillMaxWidth()) {
            items(state.pub.posts, key = { it.id }) { p ->
                PublicPostRow(model, state, s, p)
                HorizontalDivider()
            }
        }
        val mayPost = s.role != null && !s.banned && (s.kind != "channel" || admin)
        if (mayPost) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                PublicBadge()
                OutlinedTextField(draft, { draft = it }, label = { Text(Strings.t("public_post_hint")) }, modifier = Modifier.weight(1f))
                Button(onClick = { scope.launch { if (model.postPublic(draft)) draft = "" } }) { Text(Strings.t("public_post")) }
            }
        } else if (s.kind == "channel" && s.role != null) {
            Text(Strings.t("public_admins_only"), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun PublicPostRow(model: AppModel, state: UiState, s: PublicSpaceInfo, p: PublicPostInfo) {
    val scope = rememberCoroutineScope()
    var comment by remember(p.id) { mutableStateOf("") }
    var open by remember(p.id) { mutableStateOf(false) }
    val admin = s.role == "owner" || s.role == "admin"
    Column(Modifier.padding(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(publicAuthor(p, s) + ": " + (p.text ?: "") + if (p.edited) " (${Strings.t("edited")})" else "", Modifier.weight(1f))
            if (p.mine || admin) TextButton(onClick = { scope.launch { model.deletePublic(p.id) } }) { Text(Strings.t("public_delete")) }
            if (!p.mine) TextButton(onClick = { scope.launch { model.reportPublic(p.id, "user report") } }) { Text(Strings.t("public_report")) }
        }
        if (s.kind == "channel") {
            val comments = state.pub.comments[p.id] ?: emptyList()
            TextButton(onClick = { open = !open; if (open) scope.launch { model.loadPublicComments(p.id) } }) {
                Text(Strings.t("public_comments") + " (${maxOf(p.comments.toInt(), comments.size)})")
            }
            if (open) {
                comments.forEach { c -> Text("   ↳ " + publicAuthor(c, s) + ": " + (c.text ?: ""), style = MaterialTheme.typography.bodySmall) }
                if (s.comments && s.role != null) Row(verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(comment, { comment = it }, label = { Text(Strings.t("public_comment_hint")) }, singleLine = true, modifier = Modifier.weight(1f))
                    TextButton(onClick = { scope.launch { if (model.postPublic(comment, p.id)) { comment = ""; model.loadPublicComments(p.id) } } }) {
                        Text(Strings.t("public_comment"))
                    }
                }
            }
        }
    }
}

/** Space settings (apply / release each), bans and admins. */
@Composable
private fun PublicAdminTools(model: AppModel, s: PublicSpaceInfo) {
    val scope = rememberCoroutineScope()
    var account by remember(s.id) { mutableStateOf("") }
    Column(Modifier.padding(4.dp)) {
        PublicToggle(model, "public_listing", s.listed, "chat.public_listing")
        if (s.kind == "channel") {
            PublicToggle(model, "public_allow_comments", s.comments, "channel.comments")
            PublicToggle(model, "public_signatures", s.signatures, "channel.signatures")
        }
        PublicToggle(model, "public_slow_mode", s.slowMode != null, "chat.slow_mode", "30s")
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(account, { account = it }, label = { Text(Strings.t("public_account")) }, singleLine = true, modifier = Modifier.weight(1f))
            TextButton(onClick = { scope.launch { model.publicBan(account, true) } }) { Text(Strings.t("public_ban")) }
            TextButton(onClick = { scope.launch { model.publicBan(account, false) } }) { Text(Strings.t("public_unban")) }
            TextButton(onClick = { scope.launch { model.publicSetAdmin(account, true) } }) { Text(Strings.t("public_make_admin")) }
            TextButton(onClick = { scope.launch { model.publicSetAdmin(account, false) } }) { Text(Strings.t("public_drop_admin")) }
        }
        if (s.bans.isNotEmpty()) Text(Strings.t("public_ban") + ": " + s.bans.joinToString(", ") { it.take(8) }, style = MaterialTheme.typography.bodySmall)
    }
}

/** One space setting: apply / release (`option` is sent when applying). */
@Composable
private fun PublicToggle(model: AppModel, label: String, on: Boolean, key: String, option: String? = null) {
    val scope = rememberCoroutineScope()
    Row(verticalAlignment = Alignment.CenterVertically) {
        Switch(on, { v -> scope.launch { model.setPublicFeature(key, v, if (v) option else null) } })
        Text(" " + Strings.t(label))
    }
}

/** "Create private channel" with a name (end-to-end; only admins post). */
@Composable
fun NewChannel(model: AppModel) {
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(name, { name = it }, label = { Text(Strings.t("channel_name")) }, singleLine = true, modifier = Modifier.width(150.dp))
        TextButton(onClick = { scope.launch { if (model.createChannel(name) != null) name = "" } }) { Text(Strings.t("channel_new")) }
    }
}

/** Comments under a private channel's post, and the comment field (channel.comments). */
@Composable
fun ChannelComments(model: AppModel, state: UiState, chat: Chat, post: Message) {
    val scope = rememberCoroutineScope()
    var text by remember(post.id) { mutableStateOf("") }
    val comments = state.channel.comments[post.id] ?: emptyList()
    Column(Modifier.padding(start = 24.dp)) {
        comments.forEach { c ->
            val who = state.names[c.sender]?.ifEmpty { Strings.t("me") } ?: c.sender.take(6)
            Text("↳ $who: " + (if (c.deleted) Strings.t("deleted") else c.text ?: ""), style = MaterialTheme.typography.bodySmall)
        }
        if (state.channel.mayComment) Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(text, { text = it }, label = { Text(Strings.t("channel_comment")) }, singleLine = true, modifier = Modifier.weight(1f))
            TextButton(onClick = { scope.launch { if (model.commentOn(chat.id, post.id, text)) text = "" } }) { Text("→") }
        }
    }
}
