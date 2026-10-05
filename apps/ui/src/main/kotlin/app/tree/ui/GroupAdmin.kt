package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import app.tree.shared.addBot
import androidx.compose.material.icons.rounded.SmartToy
import androidx.compose.material.icons.automirrored.rounded.Chat
import androidx.compose.material.icons.automirrored.rounded.Logout
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.AdminPanelSettings
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.LinkOff
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.Label
import androidx.compose.material.icons.rounded.MicOff
import androidx.compose.material.icons.rounded.Tag
import androidx.compose.material.icons.rounded.WavingHand
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.UiState
import app.tree.shared.approveJoin
import app.tree.shared.assignRole
import app.tree.shared.createRole
import app.tree.shared.createTopic
import app.tree.shared.declineJoin
import app.tree.shared.deleteRole
import app.tree.shared.describeLog
import app.tree.shared.makeAdmin
import app.tree.shared.openTopic
import app.tree.shared.removeMember
import app.tree.shared.restrict
import app.tree.shared.restrictChoices
import app.tree.shared.revokeInviteLinks
import app.tree.shared.rolePermissions
import app.tree.shared.setWelcome
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Member

private val ROLE_COLORS = listOf("#3FCB8E", "#3B82F6", "#F59E0B", "#EF4444", "#8B5CF6", "#EC4899", "#14B8A6", "#6B7280")

private fun hexColor(hex: String, fallback: Color): Color =
    runCatching { Color(("FF" + hex.removePrefix("#")).toLong(16)) }.getOrDefault(fallback)

private fun restrictLabel(key: String) = when (key) {
    "1h" -> t("1시간", "1 hour")
    "1d" -> t("하루", "1 day")
    "1w" -> t("1주일", "1 week")
    else -> key
}

private fun permLabel(p: String) = when (p) {
    "pin" -> t("메시지 고정", "Pin messages")
    "delete" -> t("다른 사람 메시지 삭제", "Delete others' messages")
    "add" -> t("멤버 초대", "Add members")
    "topics" -> t("주제 관리", "Manage topics")
    else -> p
}

/** What can be done about one member: a chat with them, and for admins roles, admin, restrict, remove. */
@Composable
fun MemberDialog(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState, chat: Chat, m: Member, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    val name = m.name ?: m.id.take(6)
    val iAmAdmin = state.groups.admin
    val rolesOn = state.chatFeatures.any { it.key == "chat.roles" && it.applied }
    val restrictOn = state.chatFeatures.any { it.key == "chat.restrict" && it.applied }
    val restricted = state.groups.restricted.firstOrNull { it.member == m.id }
    var removing by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onClose,
        title = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Avatar(name, m.account ?: m.id, 44.dp)
                Spacer(Modifier.width(12.dp))
                Column {
                    Text(name, style = MaterialTheme.typography.titleMedium)
                    Text(Format.seenLabel(state.seen[m.id]), style = MaterialTheme.typography.bodySmall, color = extra.muted)
                }
            }
        },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                m.account?.let { acc ->
                    ActionLine(Icons.AutoMirrored.Rounded.Chat, t("1:1 대화", "Message")) {
                        onClose(); scope.launch { model.chatWith(acc)?.let { nav.home(); nav.push(Route.Chat(it)) } }
                    }
                }
                if (iAmAdmin) {
                    ActionLine(Icons.Rounded.AdminPanelSettings, if (m.admin) t("관리자 해제", "Remove admin") else t("관리자로 지정", "Make admin")) {
                        onClose(); scope.launch { model.makeAdmin(chat.id, m.id, !m.admin) }
                    }
                    if (rolesOn && state.groups.roles.isNotEmpty()) {
                        HorizontalDivider(Modifier.padding(vertical = 6.dp), color = extra.divider)
                        Text(t("역할", "Roles"), style = MaterialTheme.typography.labelLarge, color = extra.muted, modifier = Modifier.padding(start = 4.dp, bottom = 2.dp))
                        state.groups.roles.forEach { r ->
                            val has = m.roles.any { it.id == r.id }
                            Row(
                                Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).clickable { scope.launch { model.assignRole(chat.id, m.id, r.id, !has) } }.padding(vertical = 4.dp),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(has, { on -> scope.launch { model.assignRole(chat.id, m.id, r.id, on) } })
                                Box(Modifier.size(10.dp).clip(CircleShape).background(hexColor(r.color, MaterialTheme.colorScheme.primary)))
                                Spacer(Modifier.width(8.dp))
                                Text(r.name)
                            }
                        }
                    }
                    if (restrictOn) {
                        HorizontalDivider(Modifier.padding(vertical = 6.dp), color = extra.divider)
                        if (restricted != null) {
                            ActionLine(Icons.Rounded.MicOff, t("발언 제한 풀기", "Lift restriction")) { onClose(); scope.launch { model.restrict(chat.id, m.id, null) } }
                        } else {
                            Text(t("발언 제한", "Restrict"), style = MaterialTheme.typography.labelLarge, color = extra.muted, modifier = Modifier.padding(start = 4.dp))
                            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                model.restrictChoices().forEach { (key, secs) ->
                                    Chip(restrictLabel(key)) { onClose(); scope.launch { model.restrict(chat.id, m.id, secs) } }
                                }
                            }
                        }
                    }
                    HorizontalDivider(Modifier.padding(vertical = 6.dp), color = extra.divider)
                    ActionLine(Icons.AutoMirrored.Rounded.Logout, t("내보내기", "Remove from chat"), extra.danger) { removing = true }
                }
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text(t("닫기", "Close")) } },
    )
    if (removing) {
        AlertDialog(
            onDismissRequest = { removing = false },
            title = { Text(t("$name 님을 내보낼까요?", "Remove $name?")) },
            confirmButton = { TextButton(onClick = { removing = false; onClose(); scope.launch { model.removeMember(chat.id, m.id) } }) { Text(t("내보내기", "Remove"), color = extra.danger, fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { removing = false }) { Text(t("취소", "Cancel")) } },
        )
    }
}

@Composable
private fun ActionLine(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, color: Color = MaterialTheme.colorScheme.onSurface, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick).padding(horizontal = 4.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(icon, null, tint = if (color == extra.danger) color else extra.muted, modifier = Modifier.size(22.dp))
        Spacer(Modifier.width(14.dp))
        Text(label, color = color, style = MaterialTheme.typography.bodyLarge)
    }
}

@Composable
private fun Chip(label: String, selected: Boolean = false, onClick: () -> Unit) {
    Text(
        label, style = MaterialTheme.typography.labelLarge,
        color = if (selected) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface,
        modifier = Modifier.clip(RoundedCornerShape(16.dp))
            .background(if (selected) MaterialTheme.colorScheme.primary else extra.card)
            .clickable(onClick = onClick).padding(horizontal = 14.dp, vertical = 8.dp),
    )
}

/** Invite-link joins waiting for an admin. */
@Composable
fun JoinRequestsCard(model: AppModel, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    val reqs = state.groups.joinRequests
    if (reqs.isEmpty()) return
    CardGroup(title = t("가입 요청 ${reqs.size}", "Join requests (${reqs.size})")) {
        reqs.forEach { r ->
            Row(Modifier.fillMaxWidth().padding(start = 18.dp, end = 8.dp, top = 6.dp, bottom = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Avatar(r.account, r.account, 40.dp)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(r.account.take(10) + "…", style = MaterialTheme.typography.bodyLarge)
                    Text(Format.listTime(r.at), style = MaterialTheme.typography.bodySmall, color = extra.muted)
                }
                TextButton(onClick = { scope.launch { model.declineJoin(chat.id, r.account) } }) { Text(t("거절", "Decline"), color = extra.muted) }
                TextButton(onClick = { scope.launch { model.approveJoin(chat.id, r.account) } }) { Text(t("수락", "Approve"), fontWeight = FontWeight.SemiBold) }
            }
        }
    }
}

/** The admin rows of a group's info: roles, welcome, log, links. */
@Composable
fun AdminCard(model: AppModel, nav: TreeNav, state: UiState, chat: Chat, onLink: () -> Unit) {
    val scope = rememberCoroutineScope()
    var welcome by remember { mutableStateOf(false) }
    var revoke by remember { mutableStateOf(false) }
    var addingBot by remember { mutableStateOf(false) }
    val on = { key: String -> state.chatFeatures.any { it.key == key && it.applied } }
    CardGroup(title = t("관리", "Manage")) {
        if (on("chat.roles")) SettingsRow(t("역할", "Roles"), if (state.groups.roles.isEmpty()) t("없음", "None") else state.groups.roles.joinToString(", ") { it.name },
            Icons.Rounded.Label, TreeColors.TileViolet, onClick = { nav.push(Route.GroupAdmin(chat.id, "roles")) })
        SettingsRow(t("환영 메시지", "Welcome message"), state.groups.welcome ?: t("없음", "None"), Icons.Rounded.WavingHand, TreeColors.TileAmber, onClick = { welcome = true })
        if (on("chat.admin_log")) SettingsRow(t("관리 기록", "Admin log"), null, Icons.Rounded.History, TreeColors.TileGrey, onClick = { nav.push(Route.GroupAdmin(chat.id, "log")) })
        if (on("chat.bots")) SettingsRow(t("봇 추가", "Add a bot"), t("@이름으로", "By @name"), Icons.Rounded.SmartToy, TreeColors.TileBlue, onClick = { addingBot = true }, trailing = null)
        SettingsRow(t("초대 링크 만들기", "Make invite link"), t("24시간 동안 10명까지", "24 hours, up to 10 people"), Icons.Rounded.Link, TreeColors.TileIndigo, onClick = onLink, trailing = null)
        SettingsRow(t("초대 링크 모두 취소", "Revoke invite links"), null, Icons.Rounded.LinkOff, TreeColors.TileRed, onClick = { revoke = true }, trailing = null)
    }
    if (welcome) {
        var text by remember { mutableStateOf(state.groups.welcome ?: "") }
        AlertDialog(
            onDismissRequest = { welcome = false },
            title = { Text(t("환영 메시지", "Welcome message")) },
            text = { OutlinedTextField(text, { text = it }, placeholder = { Text(t("새로 온 사람에게 보여줄 말", "Shown to new members")) }, shape = RoundedCornerShape(14.dp), minLines = 3) },
            confirmButton = { TextButton(onClick = { welcome = false; scope.launch { model.setWelcome(chat.id, text) } }) { Text(t("저장", "Save"), fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { welcome = false }) { Text(t("취소", "Cancel")) } },
        )
    }
    if (addingBot) {
        var who by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { addingBot = false },
            title = { Text(t("봇 추가", "Add a bot")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(who, { who = it }, placeholder = { Text("@...bot") }, singleLine = true, shape = RoundedCornerShape(14.dp))
                    Text(t("봇을 운영하는 사람은 봇에게 온 메시지를 읽을 수 있어요.", "Whoever runs the bot reads what it is sent."), style = MaterialTheme.typography.bodySmall, color = extra.warning)
                }
            },
            confirmButton = { TextButton(onClick = { addingBot = false; scope.launch { model.addBot(chat.id, who) } }, enabled = who.isNotBlank()) { Text(t("추가", "Add"), fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { addingBot = false }) { Text(t("취소", "Cancel")) } },
        )
    }
    if (revoke) {
        AlertDialog(
            onDismissRequest = { revoke = false },
            title = { Text(t("초대 링크를 모두 취소할까요?", "Revoke all invite links?")) },
            text = { Text(t("내가 만든 링크로는 더 이상 들어올 수 없어요.", "Nobody can join with the links you made."), color = extra.muted) },
            confirmButton = { TextButton(onClick = { revoke = false; scope.launch { if (model.revokeInviteLinks(chat.id)) model.notice(t("링크를 취소했어요", "Links revoked")) } }) { Text(t("취소하기", "Revoke"), color = extra.danger, fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { revoke = false }) { Text(t("닫기", "Close")) } },
        )
    }
}

/** Admin pages: roles and the admin log. */
@Composable
fun GroupAdminScreen(model: AppModel, nav: TreeNav, state: UiState, chat: Chat, page: String) {
    val scope = rememberCoroutineScope()
    var creating by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
        BackHeader(if (page == "roles") t("역할", "Roles") else t("관리 기록", "Admin log"), { nav.pop() }) {
            if (page == "roles") androidx.compose.material3.IconButton(onClick = { creating = true }) { Icon(Icons.Rounded.Add, t("역할 만들기", "New role")) }
        }
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 30.dp)) {
            when (page) {
                "roles" -> {
                    if (state.groups.roles.isEmpty()) EmptyState(Icons.Rounded.Tag, t("역할이 없어요", "No roles yet"), t("역할로 멤버 이름 옆에 태그를 달고 권한을 나눠요.", "Roles tag members and share permissions."), Modifier.padding(top = 40.dp)) {
                        PillButton(t("역할 만들기", "New role"), { creating = true }, Modifier.padding(horizontal = 40.dp))
                    }
                    else CardGroup {
                        state.groups.roles.forEach { r ->
                            val holders = state.members.count { m -> m.roles.any { it.id == r.id } }
                            SettingsRow(r.name, (if (r.perms.isEmpty()) t("태그만", "Tag only") else r.perms.joinToString(", ") { permLabel(it) }) + " · " + t("${holders}명", "$holders"),
                                Icons.Rounded.Label, hexColor(r.color, TreeColors.TileGrey),
                                trailing = { TextButton(onClick = { scope.launch { model.deleteRole(chat.id, r.id) } }) { Text(t("삭제", "Delete"), color = extra.danger) } })
                        }
                    }
                    Caption(t("역할은 멤버 목록에서 사람을 눌러 줄 수 있어요.", "Give roles by tapping a member in the member list."))
                }
                else -> {
                    if (state.groups.adminLog.isEmpty()) EmptyState(Icons.Rounded.History, t("기록이 없어요", "Nothing yet"), "", Modifier.padding(top = 40.dp))
                    else CardGroup {
                        state.groups.adminLog.sortedByDescending { it.at }.forEach { e ->
                            Column(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 10.dp)) {
                                Text(model.describeLog(e, state.names), style = MaterialTheme.typography.bodyMedium)
                                Text(Format.stamp(e.at), style = MaterialTheme.typography.bodySmall, color = extra.muted)
                            }
                        }
                    }
                    Caption(app.tree.shared.Strings.t("admin_log_note"))
                }
            }
        }
    }
    if (creating) {
        var name by remember { mutableStateOf("") }
        var color by remember { mutableStateOf(ROLE_COLORS.first()) }
        val perms = remember { mutableStateListOf<String>() }
        AlertDialog(
            onDismissRequest = { creating = false },
            title = { Text(t("새 역할", "New role")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(name, { name = it.take(32) }, placeholder = { Text(t("이름 (예: 운영진)", "Name (e.g. Moderators)")) }, singleLine = true, shape = RoundedCornerShape(14.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        ROLE_COLORS.forEach { c ->
                            Box(
                                Modifier.size(28.dp).clip(CircleShape).background(hexColor(c, Color.Gray))
                                    .let { if (c == color) it.border(3.dp, MaterialTheme.colorScheme.onSurface, CircleShape) else it }
                                    .clickable { color = c },
                            )
                        }
                    }
                    model.rolePermissions().forEach { p ->
                        Row(Modifier.fillMaxWidth().clickable { if (p in perms) perms.remove(p) else perms.add(p) }, verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(p in perms, { on -> if (on) perms.add(p) else perms.remove(p) })
                            Text(permLabel(p))
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { creating = false; scope.launch { model.createRole(chat.id, name, color, perms.toList()) } }, enabled = name.isNotBlank()) { Text(t("만들기", "Create"), fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { creating = false }) { Text(t("취소", "Cancel")) } },
        )
    }
}

/** Topics of a group as chips under the top bar: all, each topic, and a new one. */
@Composable
fun TopicBar(model: AppModel, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    var creating by remember { mutableStateOf(false) }
    val g = state.groups
    if (g.topics.isEmpty() && !g.mayCreateTopics) return
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Chip(t("전체", "All"), g.topic == null) { scope.launch { model.openTopic(null) } }
        g.topics.filter { !it.closed || g.mayManageTopics }.forEach { tp ->
            Chip("# " + tp.name.ifBlank { tp.id } + if (tp.unread > 0u) "  ${tp.unread}" else "", g.topic == tp.id) { scope.launch { model.openTopic(tp.id) } }
        }
        if (g.mayCreateTopics) Box(
            Modifier.clip(RoundedCornerShape(16.dp)).background(extra.card).clickable { creating = true }.padding(horizontal = 10.dp, vertical = 6.dp),
        ) { Icon(Icons.Rounded.Add, t("주제 만들기", "New topic"), modifier = Modifier.size(20.dp)) }
    }
    if (creating) {
        var name by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { creating = false },
            title = { Text(t("새 주제", "New topic")) },
            text = { OutlinedTextField(name, { name = it.take(64) }, placeholder = { Text(t("예: 공지, 일정, 잡담", "e.g. News, Plans, Chat")) }, singleLine = true, shape = RoundedCornerShape(14.dp)) },
            confirmButton = { TextButton(onClick = { creating = false; scope.launch { model.createTopic(chat.id, name)?.let { model.openTopic(it) } } }, enabled = name.isNotBlank()) { Text(t("만들기", "Create"), fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { creating = false }) { Text(t("취소", "Cancel")) } },
        )
    }
}
