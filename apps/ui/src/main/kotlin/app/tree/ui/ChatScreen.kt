package app.tree.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.AttachFile
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.Bookmark
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Done
import androidx.compose.material.icons.rounded.DoneAll
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.Flag
import androidx.compose.material.icons.rounded.Image
import androidx.compose.material.icons.rounded.InsertDriveFile
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.MoreVert
import androidx.compose.material.icons.rounded.PushPin
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.UiState
import app.tree.shared.pinChoices
import app.tree.shared.pinMessage
import app.tree.shared.unpinMessage
import app.tree.shared.vote
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message

private val QUICK_REACTIONS = listOf("👍", "❤️", "😂", "😮", "😢", "🙏")

@Composable
fun ChatScreen(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    val me = model.session?.memberId()
    val isNotes = chat.id == state.notes
    val group = chat.others > 1 || chat.channel
    Column(Modifier.fillMaxSize().background(extra.chatBackground).let { if (platform.isPhone) it.statusBarsPadding() else it }) {
        ChatTopBar(platform, nav, state, chat, isNotes, group)
        state.rich.pins.firstOrNull()?.let { p ->
            Row(
                Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Box(Modifier.width(3.dp).height(32.dp).clip(RoundedCornerShape(2.dp)).background(MaterialTheme.colorScheme.primary))
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(t("고정된 메시지", "Pinned message"), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelMedium)
                    Text(p.text ?: "", maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyMedium)
                }
                Icon(Icons.Rounded.PushPin, null, tint = extra.muted, modifier = Modifier.size(18.dp))
            }
        }
        if (chat.status == "request") RequestBanner(model, chat)
        val listState = rememberLazyListState()
        val msgs = state.messages
        LaunchedEffect(msgs.size) { if (msgs.isNotEmpty()) listState.scrollToItem(0) }
        LazyColumn(
            Modifier.weight(1f).fillMaxWidth(), state = listState, reverseLayout = true,
            contentPadding = PaddingValues(horizontal = 10.dp, vertical = 10.dp),
        ) {
            val rev = msgs.asReversed()
            items(rev.size, key = { rev[it].id }) { i ->
                val m = rev[i]
                val older = rev.getOrNull(i + 1)
                val newer = rev.getOrNull(i - 1)
                val firstOfRun = older == null || older.sender != m.sender || m.receivedAt - older.receivedAt > 300 || isSystem(older)
                val lastOfRun = newer == null || newer.sender != m.sender || newer.receivedAt - m.receivedAt > 300 || isSystem(newer)
                Column {
                    if (older == null || !Format.sameDay(older.receivedAt, m.receivedAt)) DaySeparator(m.receivedAt)
                    if (isSystem(m)) SystemLine(Format.preview(m))
                    else MessageBubble(model, platform, state, chat, m, mine = m.sender == me, group = group && !isNotes, firstOfRun = firstOfRun, lastOfRun = lastOfRun)
                }
            }
            if (msgs.isEmpty()) {
                item {
                    Box(Modifier.fillMaxWidth().padding(top = 80.dp), contentAlignment = Alignment.Center) {
                        Column(
                            Modifier.clip(RoundedCornerShape(20.dp)).background(MaterialTheme.colorScheme.surface.copy(alpha = 0.85f)).padding(22.dp),
                            horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            Icon(if (isNotes) Icons.Rounded.Bookmark else Icons.Rounded.Lock, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(34.dp))
                            Text(
                                if (isNotes) t("나에게 보내는 메모", "Notes to yourself") else t("끝단 암호화된 대화", "End-to-end encrypted"),
                                style = MaterialTheme.typography.titleSmall,
                            )
                            Text(
                                if (isNotes) t("생각, 링크, 파일을 여기에 모아 두세요.\n내 기기들끼리만 보여요.", "Keep thoughts, links and files here.\nOnly your devices see them.")
                                else t("이 대화는 나와 상대의 기기만 읽을 수 있어요.\n서버도 내용을 볼 수 없어요.", "Only your devices and theirs can read this chat.\nNot even the server."),
                                style = MaterialTheme.typography.bodySmall, color = extra.muted, textAlign = TextAlign.Center,
                            )
                        }
                    }
                }
            }
        }
        if (state.typing.isNotEmpty()) {
            Text(
                state.typing.joinToString(", ") { state.names[it] ?: "" } + t(" 입력 중…", " typing…"),
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(start = 20.dp, bottom = 4.dp),
            )
        }
        if (chat.status != "request") Composer(model, platform, chat)
    }
}

private fun isSystem(m: Message) = m.kind == "left" || m.kind == "removed" || m.kind == "welcome"

@Composable
private fun ChatTopBar(platform: TreePlatform, nav: TreeNav, state: UiState, chat: Chat, isNotes: Boolean, group: Boolean) {
    Row(
        Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).padding(start = 4.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (platform.isPhone) IconButton(onClick = { nav.pop() }) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, t("뒤로", "Back")) }
        else Spacer(Modifier.width(12.dp))
        Row(
            Modifier.weight(1f).clip(RoundedCornerShape(12.dp)).clickable(enabled = !isNotes) { nav.push(Route.ChatInfo(chat.id)) }.padding(vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (isNotes) {
                Box(Modifier.size(42.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary), contentAlignment = Alignment.Center) {
                    Icon(Icons.Rounded.Bookmark, null, tint = MaterialTheme.colorScheme.onPrimary, modifier = Modifier.size(22.dp))
                }
            } else Avatar(chat.title, chat.id, 42.dp)
            Spacer(Modifier.width(12.dp))
            Column {
                Text(chat.title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                val sub = when {
                    isNotes -> t("내 기기에만 보여요", "Only on your devices")
                    state.typing.isNotEmpty() -> t("입력 중…", "typing…")
                    chat.channel -> t("채널 · 구독자 ${chat.others + 1}명", "Channel · ${chat.others + 1} subscribers")
                    group -> t("멤버 ${chat.others + 1}명", "${chat.others + 1} members")
                    chat.labels.contains("not_contact") -> t("연락처에 없는 사람", "Not in your contacts")
                    else -> t("끝단 암호화", "End-to-end encrypted")
                }
                Text(sub, style = MaterialTheme.typography.bodySmall, color = if (state.typing.isNotEmpty()) MaterialTheme.colorScheme.primary else extra.muted, maxLines = 1)
            }
        }
        if (!isNotes) IconButton(onClick = { nav.push(Route.ChatInfo(chat.id)) }) { Icon(Icons.Rounded.MoreVert, t("대화 정보", "Chat info")) }
    }
}

@Composable
private fun RequestBanner(model: AppModel, chat: Chat) {
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(t("메시지 요청", "Message request"), style = MaterialTheme.typography.titleSmall)
        val labels = chat.labels.map {
            when (it) {
                "not_contact" -> t("연락처 아님", "Not a contact")
                "no_common_group" -> t("함께 있는 그룹 없음", "No groups in common")
                "name_unverified" -> t("이름 확인 안 됨", "Name not verified")
                else -> it
            }
        }
        if (labels.isNotEmpty()) Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) { labels.forEach { Tag(it, extra.warning) } }
        Text(t("수락하기 전에는 상대가 내가 읽었는지 알 수 없어요. 모르는 사람이 돈이나 코드를 요구하면 사기를 조심하세요.", "Until you accept, they can't tell you read it. Be careful if a stranger asks for money or codes."), style = MaterialTheme.typography.bodySmall, color = extra.muted)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(Modifier.weight(1f)) { PillButton(t("수락", "Accept"), { scope.launch { model.accept(chat.id) } }) }
            OutlinedButton(onClick = { scope.launch { model.decline(chat.id, false) } }, modifier = Modifier.height(54.dp), shape = RoundedCornerShape(27.dp)) { Text(t("거절", "Decline")) }
            OutlinedButton(onClick = { scope.launch { model.decline(chat.id, true) } }, modifier = Modifier.height(54.dp), shape = RoundedCornerShape(27.dp)) {
                Icon(Icons.Rounded.Block, null, tint = extra.danger, modifier = Modifier.size(18.dp)); Spacer(Modifier.width(6.dp)); Text(t("차단", "Block"), color = extra.danger)
            }
        }
    }
}

@Composable
private fun DaySeparator(at: Long) {
    Box(Modifier.fillMaxWidth().padding(vertical = 10.dp), contentAlignment = Alignment.Center) {
        Text(
            Format.day(at), style = MaterialTheme.typography.labelMedium, color = Color.White,
            modifier = Modifier.clip(RoundedCornerShape(12.dp)).background(Color(0x66000000)).padding(horizontal = 12.dp, vertical = 4.dp),
        )
    }
}

@Composable
private fun SystemLine(text: String) {
    Box(Modifier.fillMaxWidth().padding(vertical = 6.dp), contentAlignment = Alignment.Center) {
        Text(text, style = MaterialTheme.typography.labelMedium, color = extra.muted,
            modifier = Modifier.clip(RoundedCornerShape(12.dp)).background(MaterialTheme.colorScheme.surface.copy(alpha = 0.8f)).padding(horizontal = 12.dp, vertical = 5.dp))
    }
}

/** A colour per member for names in groups. */
private fun nameColor(id: String): Color = TreeColors.Avatars[(id.hashCode() and 0x7fffffff) % TreeColors.Avatars.size]

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageBubble(
    model: AppModel, platform: TreePlatform, state: UiState, chat: Chat, m: Message,
    mine: Boolean, group: Boolean, firstOfRun: Boolean, lastOfRun: Boolean,
) {
    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf(false) }
    val bubble = if (mine) extra.bubbleMine else extra.bubbleTheirs
    val textColor = if (mine) extra.bubbleMineText else extra.bubbleTheirsText
    val r = 18.dp
    val tail = 5.dp
    val shape = if (mine) RoundedCornerShape(r, if (firstOfRun) r else tail, if (lastOfRun) tail else tail, r)
    else RoundedCornerShape(if (firstOfRun) r else tail, r, r, if (lastOfRun) tail else tail)
    Row(
        Modifier.fillMaxWidth().padding(top = if (firstOfRun) 6.dp else 2.dp),
        horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
        verticalAlignment = Alignment.Bottom,
    ) {
        if (group && !mine) {
            if (lastOfRun) Avatar(state.names[m.sender] ?: "?", m.sender, 34.dp) else Spacer(Modifier.width(34.dp))
            Spacer(Modifier.width(6.dp))
        }
        Box {
            Column(
                Modifier.widthIn(max = 320.dp).clip(shape).background(bubble)
                    .combinedClickable(onClick = {}, onLongClick = { menu = true })
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                if (group && !mine && firstOfRun) {
                    Text(state.names[m.sender] ?: m.sender.take(6), color = nameColor(m.sender), style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.height(2.dp))
                }
                if (m.forwarded) Text(t("전달된 메시지", "Forwarded"), style = MaterialTheme.typography.labelMedium, color = extra.bubbleMeta)
                m.sharedBy?.let { Text(t("$it 님이 공유", "Shared by $it"), style = MaterialTheme.typography.labelMedium, color = extra.bubbleMeta) }
                when {
                    m.deleted -> Text(t("삭제된 메시지입니다", "This message was deleted"), color = extra.bubbleMeta, style = MaterialTheme.typography.bodyMedium)
                    m.kind == "file" -> FileContent(model, platform, state, m, textColor)
                    m.kind == "poll" -> state.rich.polls[m.id]?.let { PollContent(model, chat.id, it, textColor) } ?: Text(Format.preview(m), color = textColor)
                    else -> Text(m.text ?: Format.preview(m), color = textColor, style = MaterialTheme.typography.bodyLarge)
                }
                Row(Modifier.align(Alignment.End).padding(top = 2.dp), verticalAlignment = Alignment.CenterVertically) {
                    if (m.edited) Text(t("수정됨 ", "edited "), style = MaterialTheme.typography.labelSmall, color = extra.bubbleMeta)
                    Text(Format.clock(m.receivedAt), style = MaterialTheme.typography.labelSmall, color = extra.bubbleMeta)
                    if (mine) {
                        Spacer(Modifier.width(3.dp))
                        when (m.status) {
                            "pending" -> Icon(Icons.Rounded.Schedule, t("보내는 중", "Sending"), tint = extra.bubbleMeta, modifier = Modifier.size(14.dp))
                            "failed" -> Icon(Icons.Rounded.ErrorOutline, t("보내지 못함", "Not sent"), tint = extra.danger, modifier = Modifier.size(14.dp))
                            else -> Icon(if (m.id in state.readMine) Icons.Rounded.DoneAll else Icons.Rounded.Done, null,
                                tint = if (m.id in state.readMine) MaterialTheme.colorScheme.primary else extra.bubbleMeta, modifier = Modifier.size(15.dp))
                        }
                    }
                }
            }
            DropdownMenu(menu, { menu = false }) {
                Row(Modifier.padding(horizontal = 10.dp, vertical = 4.dp)) {
                    QUICK_REACTIONS.forEach { e ->
                        Text(e, style = MaterialTheme.typography.titleLarge, modifier = Modifier.clip(CircleShape).clickable { menu = false; scope.launch { model.react(chat.id, m.id, e) } }.padding(6.dp))
                    }
                }
                HorizontalDivider()
                if (m.kind == "text" && state.rich.forwardingAllowed) DropdownMenuItem({ Text(t("복사", "Copy")) }, leadingIcon = { Icon(Icons.Rounded.ContentCopy, null) }, onClick = { menu = false; platform.copy(m.text ?: "") })
                if (state.rich.mayPin) DropdownMenuItem({ Text(t("고정", "Pin")) }, leadingIcon = { Icon(Icons.Rounded.PushPin, null) }, onClick = {
                    menu = false
                    scope.launch { if (state.rich.pins.any { it.messageId == m.id }) model.unpinMessage(chat.id, m.id) else model.pinMessage(chat.id, m.id, model.pinChoices().firstOrNull()?.second) }
                })
                if (mine && m.kind == "text" && !m.deleted) DropdownMenuItem({ Text(t("수정", "Edit")) }, leadingIcon = { Icon(Icons.Rounded.Edit, null) }, onClick = { menu = false; editing = true })
                if (mine && m.status == "failed") DropdownMenuItem({ Text(t("다시 보내기", "Retry")) }, leadingIcon = { Icon(Icons.Rounded.Refresh, null) }, onClick = { menu = false; scope.launch { model.retrySend(m.id) } })
                if (mine && !m.deleted) DropdownMenuItem({ Text(t("모두에게서 삭제", "Delete for everyone"), color = extra.danger) }, leadingIcon = { Icon(Icons.Rounded.Delete, null, tint = extra.danger) }, onClick = {
                    menu = false
                    scope.launch { if (m.status == "failed" || m.status == "pending") model.cancelSend(m.id) else model.deleteForAll(chat.id, m.id) }
                })
                if (!mine) DropdownMenuItem({ Text(t("신고", "Report"), color = extra.danger) }, leadingIcon = { Icon(Icons.Rounded.Flag, null, tint = extra.danger) }, onClick = {
                    menu = false
                    scope.launch { if (model.report(chat.id, listOf(m.id), "user report") != null) model.notice(t("신고했어요. 운영팀이 확인해요.", "Reported. The team will review it.")) }
                })
            }
        }
    }
    if (m.reactions.isNotEmpty()) {
        Row(
            Modifier.fillMaxWidth().padding(top = 2.dp, start = if (group && !mine) 40.dp else 0.dp),
            horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
        ) {
            m.reactions.forEach { rx ->
                val own = model.session?.memberId() in rx.members
                Row(
                    Modifier.padding(end = 4.dp).clip(RoundedCornerShape(12.dp))
                        .background(if (own) MaterialTheme.colorScheme.primary.copy(alpha = 0.25f) else MaterialTheme.colorScheme.surface)
                        .clickable { scope.launch { model.react(chat.id, m.id, rx.emoji, remove = own) } }.padding(horizontal = 8.dp, vertical = 2.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(rx.emoji)
                    if (rx.members.size > 1) { Spacer(Modifier.width(3.dp)); Text(rx.members.size.toString(), style = MaterialTheme.typography.labelMedium) }
                }
            }
        }
    }
    if (editing) EditDialog(m.text ?: "", onClose = { editing = false }) { text -> scope.launch { model.edit(chat.id, m.id, text) }; editing = false }
}

@Composable
private fun FileContent(model: AppModel, platform: TreePlatform, state: UiState, m: Message, textColor: Color) {
    val f = m.file ?: state.files[m.id]
    val image = f?.mime?.startsWith("image/") == true
    val thumb = f?.thumbnail
    val bitmap = remember(m.id, thumb) { thumb?.let { platform.decodeImage(it) } }
    if (image && bitmap != null) {
        Image(
            bitmap, contentDescription = f.name, contentScale = ContentScale.Crop,
            modifier = Modifier.widthIn(max = 280.dp).heightIn(max = 300.dp).clip(RoundedCornerShape(12.dp))
                .clickable { platform.saveAs(m.id, f.name) },
        )
        return
    }
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.clickable { f?.let { platform.saveAs(m.id, it.name) } }) {
        Box(Modifier.size(46.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary), contentAlignment = Alignment.Center) {
            Icon(if (image) Icons.Rounded.Image else if (m.id in state.downloaded) Icons.Rounded.InsertDriveFile else Icons.Rounded.Download, null, tint = MaterialTheme.colorScheme.onPrimary)
        }
        Spacer(Modifier.width(10.dp))
        Column {
            Text(f?.name ?: m.text ?: t("파일", "File"), color = textColor, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(f?.let { Format.size(it.size.toLong()) } ?: "", color = extra.bubbleMeta, style = MaterialTheme.typography.bodySmall)
        }
    }
    state.transfers[m.id]?.let { tr ->
        val p = if (tr.total.toLong() > 0) tr.done.toFloat() / tr.total.toFloat() else 0f
        LinearProgressIndicator(progress = { p }, modifier = Modifier.padding(top = 6.dp).width(200.dp))
    }
}

@Composable
private fun PollContent(model: AppModel, group: String, p: uniffi.tree_ffi.PollInfo, textColor: Color) {
    val scope = rememberCoroutineScope()
    val total = p.counts.sum().toInt().coerceAtLeast(1)
    Column(Modifier.width(260.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(p.question, color = textColor, style = MaterialTheme.typography.titleSmall)
        Text(
            (if (p.anonymous) t("익명 투표", "Anonymous poll") else t("투표", "Poll")) + " · " + t("${p.voters}명 참여", "${p.voters} voted") + if (p.closed) t(" · 마감", " · closed") else "",
            color = extra.bubbleMeta, style = MaterialTheme.typography.bodySmall,
        )
        p.options.forEachIndexed { i, o ->
            val n = p.counts.getOrNull(i)?.toInt() ?: 0
            val chosen = i.toUInt() in p.mine
            Column(Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).clickable(enabled = !p.closed) {
                val now = if (p.multi) (if (chosen) p.mine - i.toUInt() else p.mine + i.toUInt()) else listOf(i.toUInt())
                scope.launch { model.vote(group, p.id, now.map { it.toInt() }) }
            }.padding(vertical = 2.dp)) {
                Row {
                    Text((if (chosen) "✓ " else "") + o, color = textColor, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                    Text("${n * 100 / total}%", color = extra.bubbleMeta, style = MaterialTheme.typography.bodySmall)
                }
                LinearProgressIndicator(progress = { n.toFloat() / total }, modifier = Modifier.fillMaxWidth().padding(top = 3.dp).height(5.dp).clip(RoundedCornerShape(3.dp)))
            }
        }
    }
}

@Composable
private fun Composer(model: AppModel, platform: TreePlatform, chat: Chat) {
    val scope = rememberCoroutineScope()
    var text by remember(chat.id) { mutableStateOf(chat.draft ?: "") }
    var attach by remember { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).let { if (platform.isPhone) it.navigationBarsPadding().imePadding() else it }
            .padding(horizontal = 8.dp, vertical = 8.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        Box {
            IconButton(onClick = { attach = true }) { Icon(Icons.Rounded.AttachFile, t("첨부", "Attach"), tint = extra.muted) }
            DropdownMenu(attach, { attach = false }) {
                DropdownMenuItem({ Text(t("사진", "Photo")) }, leadingIcon = { Icon(Icons.Rounded.Image, null) }, onClick = { attach = false; platform.pickAndSend(chat.id, AttachKind.PHOTO) })
                DropdownMenuItem({ Text(t("파일", "File")) }, leadingIcon = { Icon(Icons.Rounded.InsertDriveFile, null) }, onClick = { attach = false; platform.pickAndSend(chat.id, AttachKind.FILE) })
            }
        }
        Box(
            Modifier.weight(1f).heightIn(min = 44.dp).clip(RoundedCornerShape(22.dp)).background(extra.chatBackground).padding(horizontal = 16.dp, vertical = 11.dp),
        ) {
            if (text.isEmpty()) Text(t("메시지", "Message"), color = extra.muted, style = MaterialTheme.typography.bodyLarge)
            BasicTextField(
                text, { v -> text = v; scope.launch { model.saveDraft(chat.id, v); model.typing(chat.id, v.isNotEmpty()) } },
                textStyle = MaterialTheme.typography.bodyLarge.copy(color = MaterialTheme.colorScheme.onSurface),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary), maxLines = 6,
                modifier = Modifier.fillMaxWidth(),
            )
        }
        Spacer(Modifier.width(6.dp))
        val canSend = text.isNotBlank()
        Box(
            Modifier.size(44.dp).clip(CircleShape).background(if (canSend) MaterialTheme.colorScheme.primary else extra.card)
                .clickable(enabled = canSend) {
                    val v = text
                    text = ""
                    scope.launch { model.send(chat.id, v.trim()); model.typing(chat.id, false) }
                },
            contentAlignment = Alignment.Center,
        ) { Icon(Icons.AutoMirrored.Rounded.Send, t("보내기", "Send"), tint = if (canSend) MaterialTheme.colorScheme.onPrimary else extra.muted, modifier = Modifier.size(21.dp)) }
    }
}

@Composable
private fun EditDialog(initial: String, onClose: () -> Unit, onSave: (String) -> Unit) {
    var v by remember { mutableStateOf(initial) }
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onClose,
        title = { Text(t("메시지 수정", "Edit message")) },
        text = { androidx.compose.material3.OutlinedTextField(v, { v = it }, shape = RoundedCornerShape(14.dp)) },
        confirmButton = { androidx.compose.material3.TextButton(onClick = { onSave(v) }, enabled = v.isNotBlank()) { Text(t("저장", "Save"), fontWeight = FontWeight.SemiBold) } },
        dismissButton = { androidx.compose.material3.TextButton(onClick = onClose) { Text(t("취소", "Cancel")) } },
    )
}
