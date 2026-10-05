package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.SmartToy
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.UiState
import app.tree.shared.commentOn
import app.tree.shared.createPublic
import app.tree.shared.joinPublic
import app.tree.shared.leavePublic
import app.tree.shared.loadPublic
import app.tree.shared.openPublic
import app.tree.shared.postPublic
import app.tree.shared.pressButton
import app.tree.shared.searchPublic
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.PublicPostInfo
import uniffi.tree_ffi.PublicSpaceInfo

// --- bot buttons ------------------------------------------------------------

/** A bot's buttons under its message; the bot's answer comes back as a notice. */
@Composable
fun BotButtons(model: AppModel, group: String, m: Message) {
    val scope = rememberCoroutineScope()
    Column(Modifier.padding(top = 4.dp, start = 44.dp).widthCap(), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        m.buttons.forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                row.forEach { b ->
                    Box(
                        Modifier.weight(1f).clip(RoundedCornerShape(12.dp)).background(extra.floating)
                            .clickable { scope.launch { model.pressButton(group, m.id, b.data) } }.padding(vertical = 10.dp, horizontal = 8.dp),
                        contentAlignment = Alignment.Center,
                    ) { Text(b.text, style = MaterialTheme.typography.labelLarge, maxLines = 1, overflow = TextOverflow.Ellipsis) }
                }
            }
        }
    }
}

private fun Modifier.widthCap() = this.then(Modifier.width(300.dp))

// --- private channel comments ------------------------------------------------

/** "N comments" under a channel post. */
@Composable
fun CommentsLink(state: UiState, nav: TreeNav, chat: Chat, post: Message, mine: Boolean) {
    val n = state.channel.comments[post.id]?.size ?: 0
    if (n == 0 && !state.channel.mayComment) return
    Row(
        Modifier.fillMaxWidth().padding(top = 2.dp, start = if (mine) 0.dp else 44.dp),
        horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
    ) {
        Row(
            Modifier.clip(RoundedCornerShape(12.dp)).background(extra.floating).clickable { nav.push(Route.Comments(chat.id, post.id)) }.padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Outlined.ChatBubbleOutline, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(15.dp))
            Spacer(Modifier.width(5.dp))
            Text(if (n > 0) t("댓글 $n", "$n comments") else t("댓글 달기", "Comment"), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium)
        }
    }
}

/** A channel post with its comments (end-to-end, members only) and a field to add one. */
@Composable
fun CommentsScreen(model: AppModel, nav: TreeNav, state: UiState, chat: Chat, postId: String) {
    val post = state.messages.firstOrNull { it.id == postId }
    val comments = state.channel.comments[postId].orEmpty()
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding()) {
        BackHeader(t("댓글", "Comments"), { nav.pop() })
        LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            post?.let { p ->
                item {
                    Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(18.dp)).background(extra.card).padding(14.dp)) {
                        Text(chat.title, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge)
                        Text(p.text ?: Format.preview(p), style = MaterialTheme.typography.bodyLarge)
                        Text(Format.stamp(p.receivedAt), color = extra.muted, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            if (comments.isEmpty()) item { Text(t("아직 댓글이 없어요", "No comments yet"), color = extra.muted, modifier = Modifier.padding(8.dp)) }
            items(comments, key = { it.id }) { c ->
                val name = state.names[c.sender]?.takeIf { it.isNotBlank() } ?: if (c.sender == model.session?.memberId()) t("나", "You") else c.sender.take(6)
                Row(verticalAlignment = Alignment.Top) {
                    Avatar(name, c.sender, 34.dp)
                    Spacer(Modifier.width(8.dp))
                    Column(Modifier.clip(RoundedCornerShape(16.dp)).background(extra.bubbleTheirs).padding(horizontal = 12.dp, vertical = 8.dp)) {
                        Text(name, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge)
                        Text(c.text ?: Format.preview(c), color = extra.bubbleTheirsText)
                        Text(Format.clock(c.receivedAt), color = extra.bubbleMeta, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }
        }
        if (state.channel.mayComment) MiniComposer(t("댓글", "Comment")) { text -> model.commentOn(chat.id, postId, text) }
    }
}

/** A one-line field with a send button, for comments and public posts. */
@Composable
private fun MiniComposer(hint: String, send: suspend (String) -> Boolean) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    Row(
        Modifier.fillMaxWidth().padding(10.dp).clip(RoundedCornerShape(26.dp)).background(extra.floating).padding(start = 16.dp, end = 4.dp, top = 4.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.weight(1f).padding(vertical = 10.dp)) {
            if (text.isEmpty()) Text(hint, color = extra.muted)
            BasicTextField(text, { text = it }, textStyle = MaterialTheme.typography.bodyLarge.copy(color = MaterialTheme.colorScheme.onSurface),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary), maxLines = 5, modifier = Modifier.fillMaxWidth())
        }
        IconButton(onClick = { val v = text.trim(); if (v.isNotEmpty()) scope.launch { if (send(v)) text = "" } }, enabled = text.isNotBlank()) {
            Icon(Icons.AutoMirrored.Rounded.Send, t("보내기", "Send"), tint = if (text.isNotBlank()) MaterialTheme.colorScheme.primary else extra.muted)
        }
    }
}

// --- public spaces -------------------------------------------------------------

@Composable
private fun PublicTag() = Tag(t("공개", "Public"), extra.publicBadge)

/** Public groups and channels: mine, search the directory or a @handle, make one. Not end-to-end. */
@Composable
fun PublicScreen(model: AppModel, nav: TreeNav, state: UiState) {
    val scope = rememberCoroutineScope()
    var q by remember { mutableStateOf("") }
    var creating by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.loadPublic() }
    LaunchedEffect(q) { if (q.isNotBlank()) { kotlinx.coroutines.delay(350); model.searchPublic(q) } }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
        BackHeader(t("공개 공간", "Public spaces"), { nav.pop() }) {
            IconButton(onClick = { creating = true }) { Icon(Icons.Rounded.Add, t("만들기", "Create")) }
        }
        LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(bottom = 24.dp)) {
            item { SearchField(q, { q = it }, t("이름이나 @주소로 찾기", "Search by name or @handle")) }
            item {
                Text(t("공개 공간의 글은 누구나 볼 수 있고 끝단 암호화되지 않아요.", "Anyone can read public spaces; they are not end-to-end encrypted."),
                    style = MaterialTheme.typography.bodySmall, color = extra.warning, modifier = Modifier.padding(horizontal = 22.dp, vertical = 6.dp))
            }
            val list = if (q.isBlank()) state.pub.spaces else state.pub.found
            if (q.isBlank() && list.isEmpty()) item { EmptyState(Icons.Rounded.Public, t("구독한 공간이 없어요", "No spaces yet"), t("찾거나 직접 만들어요.", "Search for one or make your own.")) }
            items(list, key = { it.id }) { s -> SpaceRow(s) { scope.launch { model.openPublic(s.id); nav.push(Route.PublicSpace(s.id)) } } }
        }
    }
    if (creating) CreateSpaceDialog(model, nav) { creating = false }
}

@Composable
private fun SpaceRow(s: PublicSpaceInfo, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 18.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Avatar(s.name, s.id, 50.dp)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(s.name, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                Spacer(Modifier.width(6.dp)); PublicTag()
            }
            Text("@${s.handle} · " + (if (s.kind == "channel") t("채널", "Channel") else t("그룹", "Group")) + " · " + t("${s.members}명", "${s.members}"),
                style = MaterialTheme.typography.bodySmall, color = extra.muted, maxLines = 1)
        }
        if (s.unread > 0u) CountBadge(s.unread.toInt(), !s.notify)
    }
}

@Composable
private fun CreateSpaceDialog(model: AppModel, nav: TreeNav, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    var kind by remember { mutableStateOf("channel") }
    var name by remember { mutableStateOf("") }
    var handle by remember { mutableStateOf("") }
    var about by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(t("공개 공간 만들기", "New public space")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf("channel" to t("채널", "Channel"), "group" to t("그룹", "Group")).forEach { (k, l) ->
                        Text(l, color = if (kind == k) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface, style = MaterialTheme.typography.labelLarge,
                            modifier = Modifier.clip(RoundedCornerShape(14.dp)).background(if (kind == k) MaterialTheme.colorScheme.primary else extra.card).clickable { kind = k }.padding(horizontal = 14.dp, vertical = 8.dp))
                    }
                }
                OutlinedTextField(name, { name = it.take(64) }, placeholder = { Text(t("이름", "Name")) }, singleLine = true, shape = RoundedCornerShape(14.dp))
                OutlinedTextField(handle, { handle = it.take(32).filter { c -> c.isLetterOrDigit() || c == '_' } }, placeholder = { Text("@주소") }, singleLine = true, shape = RoundedCornerShape(14.dp))
                OutlinedTextField(about, { about = it.take(255) }, placeholder = { Text(t("소개 (선택)", "About (optional)")) }, shape = RoundedCornerShape(14.dp))
                Text(t("누구나 읽을 수 있고, 서버가 글을 그대로 보관해요. 내 이름도 공개돼요.", "Anyone can read it and the server keeps posts as they are. Your name is shown."), style = MaterialTheme.typography.bodySmall, color = extra.warning)
            }
        },
        confirmButton = {
            TextButton(onClick = { scope.launch { model.createPublic(kind, name, handle, about)?.let { id -> onDone(); nav.push(Route.PublicSpace(id)) } } }, enabled = name.isNotBlank() && handle.length >= 5) {
                Text(t("만들기", "Create"), fontWeight = FontWeight.SemiBold)
            }
        },
        dismissButton = { TextButton(onClick = onDone) { Text(t("취소", "Cancel")) } },
    )
}

/** One public space: its posts (oldest at the top), subscribe / leave, post where allowed. */
@Composable
fun PublicSpaceScreen(model: AppModel, nav: TreeNav, state: UiState, id: String) {
    val scope = rememberCoroutineScope()
    val s = state.pub.open?.takeIf { it.id == id }
    LaunchedEffect(id) { if (state.pub.open?.id != id) model.openPublic(id) }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding()) {
        BackHeader(s?.name ?: "", { scope.launch { model.openPublic(null) }; nav.pop() }) {
            if (s != null) {
                if (s.role == null) TextButton(onClick = { scope.launch { model.joinPublic(s.id) } }) { Text(t("구독", "Join"), fontWeight = FontWeight.SemiBold) }
                else if (s.role != "owner") TextButton(onClick = { scope.launch { model.leavePublic(s.id); nav.pop() } }) { Text(t("나가기", "Leave"), color = extra.danger) }
            }
        }
        if (s != null) Row(Modifier.padding(horizontal = 20.dp), verticalAlignment = Alignment.CenterVertically) {
            PublicTag(); Spacer(Modifier.width(8.dp))
            Text("@${s.handle} · " + t("${s.members}명", "${s.members}"), style = MaterialTheme.typography.bodySmall, color = extra.muted)
        }
        LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (s?.description?.isNotBlank() == true) item { Text(s.description, color = extra.muted, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(horizontal = 8.dp)) }
            items(state.pub.posts.filter { it.replyTo == null }, key = { it.id }) { p -> PostCard(p, s) }
        }
        val mayPost = s != null && (s.kind == "group" && s.role != null && !s.banned || s.kind == "channel" && (s.role == "owner" || s.role == "admin"))
        if (mayPost) MiniComposer(t("공개 글쓰기", "Write in public")) { text -> model.postPublic(text) }
    }
}

@Composable
private fun PostCard(p: PublicPostInfo, s: PublicSpaceInfo?) {
    Column(Modifier.fillMaxWidth().heightIn(min = 40.dp).clip(RoundedCornerShape(18.dp)).background(extra.card).padding(14.dp)) {
        Text(app.tree.shared.publicAuthor(p, s), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge)
        Text(p.text ?: "", style = MaterialTheme.typography.bodyLarge)
        Row {
            Text(Format.stamp(p.createdAt) + if (p.edited) t(" · 수정됨", " · edited") else "", color = extra.muted, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
            if (p.comments > 0u) Text(t("댓글 ${p.comments}", "${p.comments} comments"), color = extra.muted, style = MaterialTheme.typography.bodySmall)
        }
    }
}
