package app.tree.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Note
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Done
import androidx.compose.material.icons.rounded.DoneAll
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.GroupAdd
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.MailOutline
import androidx.compose.material.icons.rounded.NotificationsOff
import androidx.compose.material.icons.rounded.PushPin
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Bookmark
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.UiState
import app.tree.shared.qr.CodeKind
import kotlinx.coroutines.launch

@Composable
fun ChatListScreen(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState) {
    val scope = rememberCoroutineScope()
    var searching by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var fabMenu by remember { mutableStateOf(false) }
    var joinDialog by remember { mutableStateOf(false) }
    val search by model.device.search.collectAsState()
    val requests = state.chats.filter { it.status == "request" }
    val list = model.visibleChats(state).filter { it.status != "request" && it.status != "declined" }

    Box(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize()) {
            if (searching) {
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp)) {
                    Box(Modifier.weight(1f)) {
                        SearchField(query, { query = it; scope.launch { model.device.search(it) } }, t("메시지 검색", "Search messages"))
                    }
                    IconButton(onClick = { searching = false; query = ""; model.device.clearSearch() }) { Icon(Icons.Rounded.Close, t("닫기", "Close")) }
                }
            } else {
                BigHeader("Tree") {
                    IconButton(onClick = { nav.push(Route.Scan(CodeKind.USERNAME)) }) { Icon(Icons.Rounded.QrCodeScanner, t("QR로 친구 추가", "Add friend by QR")) }
                    IconButton(onClick = { searching = true }) { Icon(Icons.Rounded.Search, t("검색", "Search")) }
                }
                FolderChips(model, state)
            }
            if (searching && query.isNotBlank()) {
                SearchResults(model, nav, state, search.results)
                return@Column
            }
            LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 110.dp)) {
                if (requests.isNotEmpty() && !state.showArchived) {
                    item {
                        RequestsBanner(requests.size) { model.showArchived(false); scope.launch { model.openChat(requests.first().id) }; nav.push(Route.Chat(requests.first().id)) }
                    }
                }
                if (state.showArchived) {
                    item {
                        Row(Modifier.fillMaxWidth().clickable { model.showArchived(false) }.padding(horizontal = 20.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Rounded.Archive, null, tint = extra.muted)
                            Spacer(Modifier.width(12.dp))
                            Text(t("보관된 대화 · 목록으로 돌아가기", "Archived chats · back to list"), color = extra.muted)
                        }
                    }
                } else if (state.chats.any { it.archived }) {
                    item {
                        Row(Modifier.fillMaxWidth().clickable { model.showArchived(true) }.padding(horizontal = 20.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(54.dp).clip(CircleShape).background(extra.card), contentAlignment = Alignment.Center) { Icon(Icons.Rounded.Archive, null, tint = extra.muted) }
                            Spacer(Modifier.width(14.dp))
                            Text(t("보관된 대화", "Archived chats"), style = MaterialTheme.typography.titleSmall)
                            Spacer(Modifier.weight(1f))
                            Text(state.chats.count { it.archived }.toString(), color = extra.muted)
                        }
                    }
                }
                items(list, key = { it.id }) { c -> ChatRow(model, nav, state, c) }
                if (list.isEmpty() && requests.isEmpty()) {
                    item {
                        EmptyState(
                            Icons.Outlined.ChatBubbleOutline, t("아직 대화가 없어요", "No chats yet"),
                            t("친구의 QR을 찍거나 아이디로 초대해서 첫 대화를 시작해 보세요.", "Scan a friend's QR code or invite them by username to start."),
                        ) { PillButton(t("친구 추가", "Add a friend"), { nav.push(Route.Scan(CodeKind.USERNAME)) }) }
                    }
                }
            }
        }
        // New chat: pencil button with a small menu.
        Box(Modifier.align(Alignment.BottomEnd).navigationBarsPadding().padding(end = 22.dp, bottom = 96.dp)) {
            FloatingActionButton(
                onClick = { fabMenu = true }, shape = CircleShape,
                containerColor = MaterialTheme.colorScheme.primary, contentColor = MaterialTheme.colorScheme.onPrimary,
            ) { Icon(Icons.Rounded.Edit, t("새 대화", "New chat")) }
            DropdownMenu(fabMenu, { fabMenu = false }) {
                DropdownMenuItem({ Text(t("새 그룹", "New group")) }, leadingIcon = { Icon(Icons.Rounded.GroupAdd, null) }, onClick = { fabMenu = false; nav.push(Route.NewGroup) })
                DropdownMenuItem({ Text(t("QR로 친구 추가", "Add friend by QR")) }, leadingIcon = { Icon(Icons.Rounded.QrCodeScanner, null) }, onClick = { fabMenu = false; nav.push(Route.Scan(CodeKind.USERNAME)) })
                DropdownMenuItem({ Text(t("초대 링크로 참여", "Join with a link")) }, leadingIcon = { Icon(Icons.Rounded.Link, null) }, onClick = { fabMenu = false; joinDialog = true })
                DropdownMenuItem({ Text(t("나에게 메모", "Note to self")) }, leadingIcon = { Icon(Icons.Rounded.Bookmark, null) }, onClick = {
                    fabMenu = false
                    scope.launch { model.openNotes()?.let { nav.push(Route.Chat(it)) } }
                })
            }
        }
    }
    if (joinDialog) JoinDialog(model) { joinDialog = false }
}

@Composable
private fun FolderChips(model: AppModel, state: UiState) {
    val folders = listOf<Pair<String?, String>>(null to t("전체", "All")) + state.folders.map { f ->
        f.name to when (f.kind) {
            "unread" -> t("안 읽음", "Unread")
            "direct" -> t("1:1", "1:1")
            "groups" -> t("그룹", "Groups")
            "quiet" -> t("조용한 대화", "Quiet")
            else -> f.name
        }
    }
    if (folders.size <= 1) return
    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 14.dp, vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        folders.forEach { (key, label) ->
            val on = state.folder == key
            Box(
                Modifier.clip(RoundedCornerShape(18.dp))
                    .background(if (on) MaterialTheme.colorScheme.primary else extra.card)
                    .clickable { model.showFolder(key) }.padding(horizontal = 16.dp, vertical = 8.dp),
            ) { Text(label, style = MaterialTheme.typography.labelLarge, color = if (on) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface) }
        }
    }
}

@Composable
private fun RequestsBanner(count: Int, onOpen: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp).clip(RoundedCornerShape(18.dp))
            .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.12f)).clickable(onClick = onOpen).padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Rounded.MailOutline, null, tint = MaterialTheme.colorScheme.primary)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Text(t("메시지 요청 ${count}개", "$count message request" + if (count > 1) "s" else ""), style = MaterialTheme.typography.titleSmall)
            Text(t("모르는 사람이 보낸 대화예요. 수락하기 전엔 상대가 읽음 여부를 몰라요.", "Chats from people you don't know. They can't see you read them until you accept."), style = MaterialTheme.typography.bodySmall, color = extra.muted)
        }
        Chevron()
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun ChatRow(model: AppModel, nav: TreeNav, state: UiState, c: Chat) {
    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    val me = model.session?.memberId()
    val last = c.last
    val isNotes = c.id == state.notes
    Box {
        Row(
            Modifier.fillMaxWidth()
                .background(if (state.open == c.id) MaterialTheme.colorScheme.primary.copy(alpha = 0.10f) else androidx.compose.ui.graphics.Color.Transparent)
                .combinedClickable(onClick = { nav.push(Route.Chat(c.id)) }, onLongClick = { menu = true })
                .padding(horizontal = 16.dp, vertical = 9.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (isNotes) {
                Box(Modifier.size(56.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary), contentAlignment = Alignment.Center) {
                    Icon(Icons.Rounded.Bookmark, null, tint = MaterialTheme.colorScheme.onPrimary)
                }
            } else {
                Avatar(c.title, c.id, 56.dp)
            }
            Spacer(Modifier.width(14.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(c.title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                    if (c.channel) { Spacer(Modifier.width(6.dp)); Tag(t("채널", "Channel"), MaterialTheme.colorScheme.primary) }
                    if (c.muted) { Spacer(Modifier.width(4.dp)); Icon(Icons.Rounded.NotificationsOff, t("알림 꺼짐", "Muted"), tint = extra.muted, modifier = Modifier.size(15.dp)) }
                    Spacer(Modifier.weight(1f))
                    if (last != null && last.sender == me) {
                        val tick = when (last.status) {
                            "pending" -> Icons.Rounded.Schedule
                            "failed" -> Icons.Rounded.ErrorOutline
                            else -> if (last.id in state.readMine) Icons.Rounded.DoneAll else Icons.Rounded.Done
                        }
                        Icon(tick, null, tint = if (last.status == "failed") extra.danger else MaterialTheme.colorScheme.primary, modifier = Modifier.size(16.dp))
                        Spacer(Modifier.width(4.dp))
                    }
                    Text(last?.let { Format.listTime(it.receivedAt) } ?: "", style = MaterialTheme.typography.bodySmall,
                        color = if (c.unread > 0 && !c.muted) MaterialTheme.colorScheme.primary else extra.muted)
                }
                Spacer(Modifier.height(3.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    val preview = when {
                        c.draft?.isNotBlank() == true -> null
                        last == null -> t("대화를 시작해 보세요", "Say hello")
                        else -> {
                            val who = if (last.sender == me) t("나: ", "You: ") else if (c.others > 1) (state.names[last.sender]?.let { "$it: " } ?: "") else ""
                            who + Format.preview(last)
                        }
                    }
                    if (preview == null) {
                        Text(t("임시 저장: ", "Draft: "), color = extra.danger, style = MaterialTheme.typography.bodyMedium)
                        Text(c.draft ?: "", color = extra.muted, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    } else {
                        Text(preview, color = extra.muted, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                    }
                    if (c.pinned && c.unread == 0) Icon(Icons.Rounded.PushPin, t("고정됨", "Pinned"), tint = extra.muted, modifier = Modifier.size(16.dp))
                    if (c.markedUnread && c.unread == 0) Box(Modifier.size(12.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary))
                    Spacer(Modifier.width(4.dp))
                    CountBadge(c.unread, c.muted)
                }
            }
        }
        DropdownMenu(menu, { menu = false }) {
            DropdownMenuItem({ Text(if (c.pinned) t("고정 해제", "Unpin") else t("위에 고정", "Pin to top")) }, leadingIcon = { Icon(Icons.Rounded.PushPin, null) }, onClick = { menu = false; scope.launch { model.pin(c.id, !c.pinned) } })
            DropdownMenuItem({ Text(if (c.muted) t("알림 켜기", "Unmute") else t("알림 끄기", "Mute")) }, leadingIcon = { Icon(Icons.Rounded.NotificationsOff, null) }, onClick = {
                menu = false
                scope.launch { if (c.muted) model.unmute(c.id) else model.mute(c.id, null) }
            })
            DropdownMenuItem({ Text(if (c.archived) t("보관 해제", "Unarchive") else t("보관", "Archive")) }, leadingIcon = { Icon(Icons.Rounded.Archive, null) }, onClick = { menu = false; scope.launch { model.archive(c.id, !c.archived) } })
            DropdownMenuItem({ Text(if (c.unread > 0 || c.markedUnread) t("읽음으로 표시", "Mark as read") else t("안 읽음으로 표시", "Mark as unread")) }, leadingIcon = { Icon(Icons.AutoMirrored.Rounded.Note, null) }, onClick = {
                menu = false
                scope.launch { model.markUnread(c.id, !(c.unread > 0 || c.markedUnread)) }
            })
        }
    }
}

@Composable
private fun SearchResults(model: AppModel, nav: TreeNav, state: UiState, results: List<uniffi.tree_ffi.Message>) {
    if (results.isEmpty()) {
        EmptyState(Icons.Rounded.Search, t("찾는 메시지가 없어요", "No messages found"), t("검색은 이 기기 안에서만 해요. 서버는 검색어를 몰라요.", "Search runs on this device only. The server never sees it."))
        return
    }
    LazyColumn(contentPadding = PaddingValues(bottom = 110.dp)) {
        items(results, key = { it.group + it.id }) { m ->
            val chat = state.chats.firstOrNull { it.id == m.group }
            Row(Modifier.fillMaxWidth().clickable { nav.push(Route.Chat(m.group)) }.padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Avatar(chat?.title ?: "?", m.group, 46.dp)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Row {
                        Text(chat?.title ?: "", style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f), maxLines = 1)
                        Text(Format.listTime(m.receivedAt), style = MaterialTheme.typography.bodySmall, color = extra.muted)
                    }
                    Text(Format.preview(m), color = extra.muted, maxLines = 2, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyMedium)
                }
            }
        }
    }
}

@Composable
private fun JoinDialog(model: AppModel, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var link by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(t("초대 링크로 참여", "Join with a link")) },
        text = { OutlinedTextField(link, { link = it }, placeholder = { Text("tree://join/…") }, singleLine = true, shape = RoundedCornerShape(14.dp)) },
        confirmButton = { TextButton(onClick = { scope.launch { if (model.joinLink(link)) onClose() } }, enabled = link.isNotBlank()) { Text(t("참여", "Join"), fontWeight = FontWeight.SemiBold) } },
        dismissButton = { TextButton(onClick = onClose) { Text(t("취소", "Cancel")) } },
    )
}
