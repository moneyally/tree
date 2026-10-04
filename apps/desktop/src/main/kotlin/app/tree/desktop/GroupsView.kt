package app.tree.desktop

import app.tree.shared.*

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
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

/** A role's tag colour (`#rrggbb`), grey if it does not parse. */
private fun tagColor(hex: String): Color =
    runCatching { Color(0xFF000000 or hex.removePrefix("#").toLong(16)) }.getOrDefault(Color.Gray)

private fun time(secs: Long): String =
    java.time.Instant.ofEpochSecond(secs).atZone(java.time.ZoneId.systemDefault()).toLocalDateTime().toString().replace('T', ' ')

/** The communities this device is in, with their chats (left column). */
@Composable
fun CommunitySidebar(model: AppModel, state: UiState) {
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    Text(Strings.t("communities"), style = MaterialTheme.typography.titleSmall)
    state.groups.communities.forEach { c ->
        Text(c.name, Modifier.fillMaxWidth().clickable { scope.launch { model.openChat(c.id) } }.padding(4.dp))
        c.chats.forEach { ch ->
            Row(Modifier.padding(start = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("# " + ch.name.ifEmpty { ch.id.take(8) }, Modifier.weight(1f).clickable(enabled = ch.joined) { scope.launch { model.openChat(ch.id) } })
                if (ch.joined) {
                    Text(Strings.t("community_joined"), style = MaterialTheme.typography.bodySmall)
                } else {
                    TextButton(onClick = { scope.launch { model.joinCommunityChat(c.id, ch.id) } }) { Text(Strings.t("community_join")) }
                }
                if (c.admin) TextButton(onClick = { scope.launch { model.removeCommunityChat(c.id, ch.id) } }) { Text("×") }
            }
        }
        // An admin of the community adds the open chat to it.
        val open = state.open
        if (c.admin && open != null && open != c.id && c.chats.none { it.id == open }) {
            TextButton(onClick = { scope.launch { model.addCommunityChat(c.id, open) } }) { Text(Strings.t("community_add_chat")) }
        }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(name, { name = it }, label = { Text(Strings.t("community_name")) }, singleLine = true, modifier = Modifier.weight(1f))
        TextButton(onClick = { scope.launch { if (model.createCommunity(name) != null) name = "" } }) { Text(Strings.t("community_new")) }
    }
}

/** Topics of the open chat: the main chat, each topic with its unread count. */
@Composable
fun TopicBar(model: AppModel, state: UiState, chat: Chat) {
    val g = state.groups
    if (g.topics.isEmpty() && !g.mayCreateTopics) return
    val scope = rememberCoroutineScope()
    var name by remember(chat.id) { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(Strings.t("topics") + ": ", style = MaterialTheme.typography.bodySmall)
        FilterChip(g.topic == null, onClick = { scope.launch { model.openTopic(null) } }, label = { Text(Strings.t("topic_main")) })
        g.topics.forEach { t ->
            val label = t.name.ifEmpty { Strings.t("topic_unnamed") } +
                (if (t.closed) " (${Strings.t("topic_closed")})" else "") + (if (t.unread > 0u) " ${t.unread}" else "")
            FilterChip(g.topic == t.id, onClick = { scope.launch { model.openTopic(t.id) } }, label = { Text(label) })
        }
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        if (g.mayCreateTopics || g.mayManageTopics) {
            OutlinedTextField(name, { name = it }, label = { Text(Strings.t("topic_name")) }, singleLine = true)
        }
        if (g.mayCreateTopics) TextButton(onClick = { scope.launch { if (model.createTopic(chat.id, name) != null) name = "" } }) { Text(Strings.t("topic_new")) }
        val sel = g.topics.firstOrNull { it.id == g.topic }
        if (sel != null && g.mayManageTopics) {
            TextButton(onClick = { scope.launch { if (model.renameTopic(chat.id, sel.id, name)) name = "" } }) { Text(Strings.t("topic_rename")) }
            TextButton(onClick = { scope.launch { model.closeTopic(chat.id, sel.id, !sel.closed) } }) {
                Text(Strings.t(if (sel.closed) "topic_reopen" else "topic_close"))
            }
        }
    }
}

/** Messages the chat view shows: those of the topic shown, or all. */
fun shownMessages(state: UiState): List<Message> =
    if (state.groups.topic != null) state.groups.topicMessages else state.messages

/** A line above the chat for what the group's settings mean for this user. */
@Composable
fun GroupNotices(state: UiState) {
    val g = state.groups
    if (g.historyShare != null) Text("ⓘ " + Strings.t("history_share_notice"), style = MaterialTheme.typography.bodySmall)
    g.restrictedUntil?.let { Text(Strings.t("restricted_you") + " " + time(it), color = MaterialTheme.colorScheme.error) }
    g.slowMode?.let { s ->
        Text(Strings.t("slow_mode") + ": ${s}s" + (g.slowWait?.let { w -> " · " + Strings.t("slow_mode_wait") + " $w" } ?: ""),
            style = MaterialTheme.typography.bodySmall)
    }
}

/** "shared by X" for a message that came in a history bundle. */
fun sharedLabel(state: UiState, m: Message): String? = m.sharedBy?.let { by ->
    "(" + Strings.t("shared_by") + " " + (state.names[by]?.ifEmpty { Strings.t("me") } ?: by.take(6)) + ")"
}

/** Moderation for one message: delete another member's message for everyone. */
@Composable
fun ModeratorDelete(model: AppModel, state: UiState, group: String, m: Message) {
    val scope = rememberCoroutineScope()
    if (state.groups.mayDelete && !m.deleted && m.sender != model.session?.memberId() && m.kind in setOf("text", "file", "sticker", "poll", "location", "event")) {
        TextButton(onClick = { scope.launch { model.deleteAsModerator(group, m.id) } }) { Text(Strings.t("delete_for_everyone_mod")) }
    }
}

/**
 * Admins' group tools: welcome text, history sharing with its notice, slow
 * mode, roles editor, members with their tags and restrict action, join
 * requests and the admin log. Members see the tags and the notices.
 */
@Composable
fun GroupTools(model: AppModel, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    val g = state.groups
    var welcome by remember(chat.id) { mutableStateOf(g.welcome ?: "") }
    var roleName by remember(chat.id) { mutableStateOf("") }
    var roleColor by remember(chat.id) { mutableStateOf("#3366ff") }
    var perms by remember(chat.id) { mutableStateOf(setOf<String>()) }
    Column(Modifier.padding(4.dp)) {
        Text(Strings.t("group_tools"), style = MaterialTheme.typography.titleSmall)
        g.successor?.let { s -> Text(Strings.t("successor_note") + ": " + (state.names[s] ?: s.take(6)), style = MaterialTheme.typography.bodySmall) }
        if (g.admin) {
            // Welcome text (chat.welcome).
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(welcome, { if (it.length <= 500) welcome = it }, label = { Text(Strings.t("welcome_text")) }, modifier = Modifier.weight(1f))
                TextButton(onClick = { scope.launch { model.setWelcome(chat.id, welcome) } }) { Text(Strings.t("welcome_save")) }
            }
            // History for new members (chat.history_share), with its notice.
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(Strings.t("history_share"), Modifier.weight(1f))
                listOf("25", "50", "100").forEach { n ->
                    TextButton(onClick = { scope.launch { model.setChatFeature(chat.id, "chat.history_share", true, n) } }) {
                        Text(if (g.historyShare?.toString() == n) "[$n]" else n)
                    }
                }
                Switch(g.historyShare != null, { on -> scope.launch { model.setChatFeature(chat.id, "chat.history_share", on) } })
            }
            Text(Strings.t("history_share_note"), style = MaterialTheme.typography.bodySmall)
            // Slow mode (chat.slow_mode).
            val slow = state.chatFeatures.firstOrNull { it.key == "chat.slow_mode" }
            if (slow != null) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(Strings.t("slow_mode"), Modifier.weight(1f))
                    slow.choices.forEach { c ->
                        TextButton(onClick = { scope.launch { model.setChatFeature(chat.id, "chat.slow_mode", true, c) } }) {
                            Text(if (slow.applied && slow.option == c) "[$c]" else c)
                        }
                    }
                    Switch(slow.applied, { on -> scope.launch { model.setChatFeature(chat.id, "chat.slow_mode", on) } })
                }
            }
            HorizontalDivider()
            // Roles editor (chat.roles).
            Text(Strings.t("roles"), style = MaterialTheme.typography.titleSmall)
            g.roles.forEach { r ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(12.dp).background(tagColor(r.color)))
                    Text(" " + r.name + " · " + r.perms.joinToString(", ") { Strings.t("perm_$it") }, Modifier.weight(1f))
                    TextButton(onClick = { scope.launch { model.updateRole(chat.id, r.id, roleName.ifBlank { r.name }, roleColor, perms.toList()) } }) { Text(Strings.t("role_save")) }
                    TextButton(onClick = { scope.launch { model.deleteRole(chat.id, r.id) } }) { Text(Strings.t("role_delete")) }
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(roleName, { roleName = it }, label = { Text(Strings.t("role_name")) }, singleLine = true, modifier = Modifier.weight(1f))
                OutlinedTextField(roleColor, { roleColor = it }, label = { Text(Strings.t("role_color")) }, singleLine = true, modifier = Modifier.weight(1f))
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                model.rolePermissions().forEach { p ->
                    Checkbox(p in perms, { on -> perms = if (on) perms + p else perms - p })
                    Text(Strings.t("perm_$p"), style = MaterialTheme.typography.bodySmall)
                }
                TextButton(onClick = { scope.launch { if (model.createRole(chat.id, roleName, roleColor, perms.toList()) != null) roleName = "" } }) {
                    Text(Strings.t("role_new"))
                }
            }
        }
        // Members with their tags; admins give roles and restrict.
        val me = model.session?.memberId()
        state.members.forEach { m ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text((m.name ?: m.id.take(6)) + if (m.admin) " ★" else "", Modifier.weight(1f))
                m.roles.forEach { r ->
                    Text(" " + r.name + " ", Modifier.background(tagColor(r.color)).padding(2.dp), color = Color.White, style = MaterialTheme.typography.bodySmall)
                }
                m.restrictedUntil?.let { Text(" " + Strings.t("restricted"), color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
                if (g.admin && m.id != me && !m.admin) {
                    g.roles.forEach { r ->
                        val has = m.roles.any { it.id == r.id }
                        TextButton(onClick = { scope.launch { model.assignRole(chat.id, m.id, r.id, !has) } }) {
                            Text((if (has) "− " else "+ ") + r.name)
                        }
                    }
                    if (m.restrictedUntil != null) {
                        TextButton(onClick = { scope.launch { model.restrict(chat.id, m.id, null) } }) { Text(Strings.t("unrestrict")) }
                    } else {
                        model.restrictChoices().forEach { (label, secs) ->
                            TextButton(onClick = { scope.launch { model.restrict(chat.id, m.id, secs) } }) { Text(Strings.t("restrict") + " " + label) }
                        }
                    }
                }
            }
        }
        if (g.admin) {
            // Join requests (chat.join_approval).
            if (g.joinRequests.isNotEmpty()) {
                Text(Strings.t("join_requests"), style = MaterialTheme.typography.titleSmall)
                g.joinRequests.forEach { r ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(r.account, Modifier.weight(1f))
                        Button(onClick = { scope.launch { model.approveJoin(chat.id, r.account) } }) { Text(Strings.t("approve")) }
                        TextButton(onClick = { scope.launch { model.declineJoin(chat.id, r.account) } }) { Text(Strings.t("decline")) }
                    }
                }
            }
            // Admin log (chat.admin_log).
            Text(Strings.t("admin_log"), style = MaterialTheme.typography.titleSmall)
            Text(Strings.t("admin_log_note"), style = MaterialTheme.typography.bodySmall)
            g.adminLog.takeLast(30).reversed().forEach { e ->
                Text(time(e.at) + "  " + model.describeLog(e, state.names), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
