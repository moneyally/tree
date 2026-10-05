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
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.automirrored.rounded.Reply
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.EmojiEmotions
import androidx.compose.material.icons.rounded.Keyboard
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material.icons.rounded.NotificationsOff
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.material.icons.automirrored.rounded.Forward
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Mic
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.sp
import app.tree.shared.RichState
import app.tree.shared.typersIn
import app.tree.shared.sendInTopic
import app.tree.shared.deleteAsModerator
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message

private val QUICK_REACTIONS = listOf("👍", "❤️", "😂", "😮", "😢", "🙏")
private val QUICK_EMOJI = listOf("😀", "😂", "🥹", "😍", "😎", "🤔", "😭", "😡", "👍", "👏", "🙏", "🔥", "🎉", "❤️", "💯", "✅", "🌱", "🌳")

@Composable
fun ChatScreen(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    val media by model.rich.state.collectAsState()
    val density = LocalDensity.current
    val me = model.session?.memberId()
    val isNotes = chat.id == state.notes
    val group = chat.others > 1 || chat.channel
    // A topic shown (chat.topics): only its messages.
    val msgs = if (state.groups.topic != null) state.groups.topicMessages else state.messages
    val byId = remember(msgs) { msgs.associateBy { it.id } }
    val replies = remember(msgs) { msgs.mapNotNull { it.replyTo }.groupingBy { it }.eachCount() }
    // How many were unread when the chat opened: the "unread" line stays there while it is open.
    val unreadAtOpen = remember(chat.id) { chat.unread }
    var replyTo by remember(chat.id) { mutableStateOf<Message?>(null) }
    var selected by remember(chat.id) { mutableStateOf(setOf<String>()) }
    var forwarding by remember(chat.id) { mutableStateOf<List<String>?>(null) }
    var headerPx by remember { mutableStateOf(0) }
    var footerPx by remember { mutableStateOf(0) }
    val listState = rememberLazyListState()
    val now = rememberNow(state.typingIn[chat.id] != null)
    val typers = state.typersIn(chat.id, now)

    // New messages: follow them when already at the bottom, or when they are mine.
    LaunchedEffect(msgs.lastOrNull()?.id) {
        val last = msgs.lastOrNull() ?: return@LaunchedEffect
        if (listState.firstVisibleItemIndex <= 2 || last.sender == me) listState.animateScrollToItem(0)
    }
    // Back from search: show the message picked there.
    LaunchedEffect(nav.focusMessage, msgs.size) {
        val id = nav.focusMessage ?: return@LaunchedEffect
        val idx = msgs.asReversed().indexOfFirst { it.id == id }
        if (idx >= 0) { listState.animateScrollToItem(idx); nav.focusMessage = null }
    }
    Box(Modifier.fillMaxSize().treeWallpaper(extra.chatBackground, extra.wallpaperInk)) {
        LazyColumn(
            Modifier.fillMaxSize(), state = listState, reverseLayout = true,
            contentPadding = PaddingValues(
                start = 8.dp, end = 8.dp,
                top = with(density) { headerPx.toDp() } + 6.dp,
                bottom = with(density) { footerPx.toDp() } + 6.dp,
            ),
        ) {
            val rev = msgs.asReversed()
            items(rev.size, key = { rev[it].id }, contentType = { if (isSystem(rev[it])) 1 else 0 }) { i ->
                val m = rev[i]
                val older = rev.getOrNull(i + 1)
                val newer = rev.getOrNull(i - 1)
                val firstOfRun = older == null || older.sender != m.sender || m.receivedAt - older.receivedAt > 300 || isSystem(older) || i == unreadAtOpen - 1
                val lastOfRun = newer == null || newer.sender != m.sender || newer.receivedAt - m.receivedAt > 300 || isSystem(newer) || i == unreadAtOpen
                Column {
                    if (older == null || !Format.sameDay(older.receivedAt, m.receivedAt)) DaySeparator(m.receivedAt)
                    if (unreadAtOpen > 0 && i == unreadAtOpen - 1) UnreadLine()
                    if (isSystem(m)) SystemLine(Format.preview(m))
                    else MessageBubble(
                        model, platform, state, media, chat, m, byId, replies[m.id] ?: 0,
                        mine = m.sender == me, group = group && !isNotes, firstOfRun = firstOfRun, lastOfRun = lastOfRun,
                        onReply = { replyTo = m },
                        selecting = selected.isNotEmpty(), isSelected = m.id in selected,
                        onSelect = { selected = if (m.id in selected) selected - m.id else selected + m.id },
                        onForward = { forwarding = listOf(m.id) },
                    )
                }
            }
            if (msgs.isEmpty()) item { EmptyChat(isNotes) }
        }

        // The floating bars on top of the messages.
        Column(
            Modifier.align(Alignment.TopCenter).fillMaxWidth().let { if (platform.isPhone) it.statusBarsPadding() else it }
                .onSizeChanged { headerPx = it.height }.padding(top = 6.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (selected.isNotEmpty()) {
                val picked = msgs.filter { it.id in selected }
                SelectionBar(
                    selected.size,
                    canCopy = state.rich.forwardingAllowed && picked.all { it.kind == "text" && !it.deleted },
                    canForward = state.rich.forwardingAllowed && picked.none { it.deleted },
                    canDelete = picked.all { it.sender == me && !it.deleted },
                    onClose = { selected = emptySet() },
                    onCopy = { platform.copy(picked.joinToString("\n") { it.text ?: "" }); model.notice(t("복사했어요", "Copied")); selected = emptySet() },
                    onForward = { forwarding = picked.map { it.id } },
                    onDelete = {
                        val ids = picked.map { it.id }
                        selected = emptySet()
                        scope.launch { ids.forEach { model.deleteForAll(chat.id, it) } }
                    },
                )
            } else ChatTopBar(platform, nav, state, media, chat, isNotes, group, typers)
            if (group && !isNotes && (state.groups.topics.isNotEmpty() || state.groups.mayCreateTopics)) TopicBar(model, state, chat)
            if (state.rich.pins.isNotEmpty()) PinnedBar(state, listState, msgs)
            if (chat.status == "request") RequestBanner(model, chat)
        }

        // Back to the newest message, with how many are below.
        val below by remember { derivedStateOf { listState.firstVisibleItemIndex } }
        androidx.compose.animation.AnimatedVisibility(
            visible = below > 2,
            enter = androidx.compose.animation.fadeIn() + androidx.compose.animation.scaleIn(),
            exit = androidx.compose.animation.fadeOut() + androidx.compose.animation.scaleOut(),
            modifier = Modifier.align(Alignment.BottomEnd).padding(end = 14.dp, bottom = with(density) { footerPx.toDp() } + 12.dp),
        ) {
            Box {
                Box(
                    Modifier.padding(top = 12.dp).size(46.dp).shadow(6.dp, CircleShape).clip(CircleShape).background(extra.floating)
                        .clickable { scope.launch { listState.animateScrollToItem(0) } },
                    contentAlignment = Alignment.Center,
                ) { Icon(Icons.Rounded.KeyboardArrowDown, t("맨 아래로", "To the newest"), modifier = Modifier.size(28.dp)) }
                Box(Modifier.align(Alignment.TopCenter)) { CountBadge(below, false) }
            }
        }

        if (chat.status != "request") {
            Column(
                Modifier.align(Alignment.BottomCenter).fillMaxWidth()
                    .let { if (platform.isPhone) it.navigationBarsPadding().imePadding() else it }
                    .onSizeChanged { footerPx = it.height },
            ) {
                Composer(model, platform, state, media, chat, replyTo, byId) { replyTo = null }
            }
        }
    }
    forwarding?.let { ids -> ForwardDialog(model, platform, state, chat.id, ids) { forwarding = null; selected = emptySet() } }
}

private fun isSystem(m: Message) = m.kind == "left" || m.kind == "removed" || m.kind == "welcome"

@Composable
private fun EmptyChat(isNotes: Boolean) {
    Box(Modifier.fillMaxWidth().padding(top = 60.dp, bottom = 60.dp), contentAlignment = Alignment.Center) {
        Column(
            Modifier.clip(RoundedCornerShape(22.dp)).background(extra.floating).padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Icon(if (isNotes) Icons.Rounded.Bookmark else Icons.Rounded.Lock, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(34.dp))
            Text(if (isNotes) t("나에게 보내는 메모", "Notes to yourself") else t("끝단 암호화된 대화", "End-to-end encrypted"), style = MaterialTheme.typography.titleSmall)
            Text(
                if (isNotes) t("생각, 링크, 파일을 여기에 모아 두세요.\n내 기기들끼리만 보여요.", "Keep thoughts, links and files here.\nOnly your devices see them.")
                else t("이 대화는 나와 상대의 기기만 읽을 수 있어요.\n서버도 내용을 볼 수 없어요.", "Only your devices and theirs can read this chat.\nNot even the server."),
                style = MaterialTheme.typography.bodySmall, color = extra.muted, textAlign = TextAlign.Center,
            )
        }
    }
}

/** Back, the chat's name and state in a floating pill, and the menu. */
@Composable
private fun ChatTopBar(platform: TreePlatform, nav: TreeNav, state: UiState, media: RichState, chat: Chat, isNotes: Boolean, group: Boolean, typers: List<String>) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        if (platform.isPhone) {
            RoundButton(Icons.AutoMirrored.Rounded.ArrowBack, t("뒤로", "Back")) { nav.pop() }
            Spacer(Modifier.width(8.dp))
        }
        Row(
            Modifier.weight(1f).height(56.dp).shadow(4.dp, RoundedCornerShape(28.dp)).clip(RoundedCornerShape(28.dp)).background(extra.floating)
                .clickable(enabled = !isNotes) { nav.push(Route.ChatInfo(chat.id)) }.padding(horizontal = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (isNotes) {
                Box(Modifier.size(42.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary), contentAlignment = Alignment.Center) {
                    Icon(Icons.Rounded.Bookmark, null, tint = MaterialTheme.colorScheme.onPrimary, modifier = Modifier.size(22.dp))
                }
            } else Avatar(chat.title, chat.peer ?: chat.id, 42.dp, image = rememberPhoto(platform, chat.id, media.chatPhotos[chat.id]?.bytes))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(chat.title, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                    if (chat.muted) { Spacer(Modifier.width(4.dp)); Icon(Icons.Rounded.NotificationsOff, t("알림 꺼짐", "Muted"), tint = extra.muted, modifier = Modifier.size(15.dp)) }
                }
                if (typers.isNotEmpty() && !isNotes) {
                    TypingLine(if (group) typers else emptyList())
                } else {
                    val now = rememberNow(true) / 1000
                    val onlineCount = state.seen.values.count { Format.online(it, now) }
                    val peerSeen = state.seen.values.singleOrNull()
                    val sub = when {
                        isNotes -> t("내 기기에만 보여요", "Only on your devices")
                        chat.channel -> t("구독자 ${chat.others + 1}명", "${chat.others + 1} subscribers")
                        group -> t("멤버 ${chat.others + 1}명", "${chat.others + 1} members") +
                            if (onlineCount > 0) t(", 온라인 ${onlineCount}명", ", $onlineCount online") else ""
                        chat.status == "request" -> t("메시지 요청", "Message request")
                        else -> Format.seenLabel(peerSeen, now)
                    }
                    val live = !group && !isNotes && Format.online(peerSeen, now)
                    Text(sub, style = MaterialTheme.typography.bodySmall, color = if (live) MaterialTheme.colorScheme.primary else extra.muted, maxLines = 1)
                }
            }
        }
        if (!isNotes) {
            Spacer(Modifier.width(8.dp))
            RoundButton(Icons.Rounded.MoreVert, t("대화 정보", "Chat info")) { nav.push(Route.ChatInfo(chat.id)) }
        }
    }
}

@Composable
private fun RoundButton(icon: ImageVector, label: String, onClick: () -> Unit) {
    Box(
        Modifier.size(50.dp).shadow(4.dp, CircleShape).clip(CircleShape).background(extra.floating).clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) { Icon(icon, label) }
}

/** The pinned messages: the one shown, tap for the next and jump to it. */
@Composable
private fun PinnedBar(state: UiState, listState: androidx.compose.foundation.lazy.LazyListState, msgs: List<Message>) {
    val scope = rememberCoroutineScope()
    val pins = state.rich.pins
    var at by remember(pins.size) { mutableStateOf(0) }
    val p = pins[at.coerceIn(0, pins.lastIndex)]
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 10.dp).shadow(3.dp, RoundedCornerShape(20.dp)).clip(RoundedCornerShape(20.dp))
            .background(extra.floating).clickable {
                val idx = msgs.asReversed().indexOfFirst { it.id == p.messageId }
                if (idx >= 0) scope.launch { listState.animateScrollToItem(idx) }
                at = (at + 1) % pins.size
            }.padding(horizontal = 14.dp, vertical = 9.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // One segment per pin; the shown one is bright.
        Column(Modifier.height(36.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            pins.take(4).indices.forEach { i ->
                Box(Modifier.width(3.dp).weight(1f).clip(RoundedCornerShape(2.dp))
                    .background(MaterialTheme.colorScheme.primary.copy(alpha = if (i == at.coerceAtMost(3)) 1f else 0.35f)))
            }
        }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(
                if (pins.size > 1) t("고정된 메시지 ${at + 1}/${pins.size}", "Pinned ${at + 1}/${pins.size}") else t("고정된 메시지", "Pinned message"),
                color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge,
            )
            Text(p.text ?: t("메시지", "Message"), maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.bodyMedium)
        }
        Icon(Icons.Rounded.PushPin, null, tint = extra.muted, modifier = Modifier.size(18.dp))
    }
}

@Composable
private fun UnreadLine() {
    Box(Modifier.fillMaxWidth().padding(vertical = 8.dp).background(Color(0x55000000)).padding(vertical = 6.dp), contentAlignment = Alignment.Center) {
        Text(t("안 읽은 메시지", "Unread messages"), color = Color.White, style = MaterialTheme.typography.labelLarge)
    }
}

/** A colour per member for names in groups. */
private fun nameColor(id: String): Color = TreeColors.Avatars[(id.hashCode() and 0x7fffffff) % TreeColors.Avatars.size]

private fun roleColor(hex: String, fallback: Color): Color =
    runCatching { Color(("FF" + hex.removePrefix("#")).toLong(16)) }.getOrDefault(fallback)

/** One to three emoji and nothing else: shown large, without a bubble. */
internal fun bigEmoji(text: String?): Boolean {
    if (text == null || text.isBlank() || text.length > 16) return false
    var count = 0
    var i = 0
    while (i < text.length) {
        val cp = text.codePointAt(i)
        i += Character.charCount(cp)
        when {
            cp == 0x200D || cp in 0xFE00..0xFE0F || cp in 0x1F3FB..0x1F3FF || cp in 0xE0020..0xE007F -> {}
            cp in 0x1F000..0x1FAFF || cp in 0x2600..0x27BF || cp in 0x2B00..0x2BFF || cp in 0x2190..0x21FF || cp in 0x1F1E6..0x1F1FF -> count++
            cp == ' '.code -> {}
            else -> return false
        }
    }
    return count in 1..3
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageBubble(
    model: AppModel, platform: TreePlatform, state: UiState, media: RichState, chat: Chat, m: Message,
    byId: Map<String, Message>, replyCount: Int,
    mine: Boolean, group: Boolean, firstOfRun: Boolean, lastOfRun: Boolean, onReply: () -> Unit,
    selecting: Boolean = false, isSelected: Boolean = false, onSelect: () -> Unit = {}, onForward: () -> Unit = {},
) {
    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    var revealed by remember(m.id) { mutableStateOf(false) }
    var editing by remember { mutableStateOf(false) }
    val sticker = if (m.kind == "sticker" && !m.deleted) media.stickers[m.id] else null
    val bare = sticker != null || (m.kind == "text" && !m.deleted && m.replyTo == null && bigEmoji(m.text))
    val bubble = if (mine) extra.bubbleMine else extra.bubbleTheirs
    val textColor = if (mine) extra.bubbleMineText else extra.bubbleTheirsText
    val shape = remember(mine, firstOfRun, lastOfRun) { BubbleShape(mine, firstOfRun, lastOfRun) }
    val tail = shape.tail
    val member = state.members.firstOrNull { it.id == m.sender }
    val senderName = state.names[m.sender] ?: member?.name ?: m.sender.take(6)
    Row(
        Modifier.fillMaxWidth()
            .background(if (isSelected) MaterialTheme.colorScheme.primary.copy(alpha = 0.16f) else Color.Transparent)
            .let { if (selecting) it.clickable(onClick = onSelect) else it }
            .padding(top = if (firstOfRun) 6.dp else 2.dp),
        horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
        verticalAlignment = Alignment.Bottom,
    ) {
        if (group && !mine) {
            if (lastOfRun) Avatar(senderName, member?.account ?: m.sender, 38.dp, image = rememberPhoto(platform, "m:" + m.sender, media.photos[m.sender]?.bytes, 128))
            else Spacer(Modifier.width(38.dp))
            Spacer(Modifier.width(2.dp))
        }
        Box {
            val click = if (selecting) Modifier.clickable(onClick = onSelect)
                else Modifier.combinedClickable(onClick = { revealed = true }, onDoubleClick = onReply, onLongClick = { menu = true })
            if (bare) {
                Column(click.padding(4.dp), horizontalAlignment = if (mine) Alignment.End else Alignment.Start) {
                    if (group && !mine && firstOfRun) Text(senderName, color = nameColor(m.sender), style = MaterialTheme.typography.labelLarge)
                    if (sticker != null) StickerImage(model, platform, sticker.pack, sticker.index.toInt(), m.text, 150.dp)
                    else Text(m.text ?: "", fontSize = 46.sp, lineHeight = 54.sp)
                    MetaPill(m, mine, state, replyCount)
                }
            } else {
                Column(
                    Modifier.widthIn(min = 64.dp, max = 336.dp).clip(shape).background(bubble).then(click)
                        .padding(start = 12.dp + if (mine) 0.dp else tail, end = 12.dp + if (mine) tail else 0.dp, top = 7.dp, bottom = 7.dp),
                ) {
                    if (group && !mine && firstOfRun) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(senderName, color = nameColor(m.sender), style = MaterialTheme.typography.labelLarge, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f, fill = false))
                            val role = member?.roles?.firstOrNull()
                            val tag = role?.name ?: if (member?.admin == true) t("관리자", "Admin") else null
                            if (member?.bot != null) { Spacer(Modifier.width(6.dp)); RoleTag(t("봇", "Bot"), extra.botBadge) }
                            if (tag != null) { Spacer(Modifier.width(8.dp)); RoleTag(tag, role?.let { roleColor(it.color, MaterialTheme.colorScheme.primary) } ?: MaterialTheme.colorScheme.primary) }
                        }
                        Spacer(Modifier.height(1.dp))
                    }
                    if (m.forwarded) Text(t("전달된 메시지", "Forwarded"), style = MaterialTheme.typography.labelMedium, color = extra.bubbleMeta)
                    m.sharedBy?.let { Text(t("$it 님이 공유", "Shared by $it"), style = MaterialTheme.typography.labelMedium, color = extra.bubbleMeta) }
                    m.replyTo?.let { id -> ReplyQuote(byId[id], state, mine) }
                    when {
                        m.deleted -> TextWithMeta(AnnotatedString(t("삭제된 메시지입니다", "This message was deleted")), extra.bubbleMeta, m, mine, state, replyCount)
                        m.kind == "file" && (m.file?.viewOnce == true || (m.file == null && state.files[m.id] == null && m.text == null)) -> { ViewOnceContent(model, platform, m, mine, textColor); MetaRow(m, mine, state, replyCount, Modifier.align(Alignment.End)) }
                        m.kind == "file" && m.file?.voice == true -> { VoiceContent(model, platform, m, mine, textColor); MetaRow(m, mine, state, replyCount, Modifier.align(Alignment.End)) }
                        m.kind == "file" -> { FileContent(model, platform, state, m, textColor); MetaRow(m, mine, state, replyCount, Modifier.align(Alignment.End)) }
                        m.kind == "location" -> { LocationContent(model, platform, media, m, textColor); MetaRow(m, mine, state, replyCount, Modifier.align(Alignment.End)) }
                        m.kind == "event" -> { EventContent(model, chat, media, m, textColor); MetaRow(m, mine, state, replyCount, Modifier.align(Alignment.End)) }
                        m.kind == "poll" -> { state.rich.polls[m.id]?.let { PollContent(model, chat.id, it, textColor) } ?: Text(Format.preview(m), color = textColor); MetaRow(m, mine, state, replyCount, Modifier.align(Alignment.End)) }
                        else -> {
                            val formatted = m.formatted && state.chatFeatures.none { it.key == "chat.formatting" && !it.applied }
                            val ink = TextInk(
                                mention = if (mine) textColor else MaterialTheme.colorScheme.primary,
                                code = textColor.copy(alpha = 0.10f), spoiler = textColor.copy(alpha = 0.55f), quote = MaterialTheme.colorScheme.primary,
                            )
                            TextWithMeta(remember(m.text, formatted, revealed, ink) { messageText(m.text ?: Format.preview(m), formatted, ink, revealed) }, textColor, m, mine, state, replyCount)
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
                if (!m.deleted && chat.status != "request") DropdownMenuItem({ Text(t("답장", "Reply")) }, leadingIcon = { Icon(Icons.AutoMirrored.Rounded.Reply, null) }, onClick = { menu = false; onReply() })
                if (!m.deleted && state.rich.forwardingAllowed) DropdownMenuItem({ Text(t("전달", "Forward")) }, leadingIcon = { Icon(Icons.AutoMirrored.Rounded.Forward, null) }, onClick = { menu = false; onForward() })
                DropdownMenuItem({ Text(t("선택", "Select")) }, leadingIcon = { Icon(Icons.Rounded.CheckCircle, null) }, onClick = { menu = false; onSelect() })
                if (m.kind == "text" && state.rich.forwardingAllowed) DropdownMenuItem({ Text(t("복사", "Copy")) }, leadingIcon = { Icon(Icons.Rounded.ContentCopy, null) }, onClick = { menu = false; platform.copy(m.text ?: ""); model.notice(t("복사했어요", "Copied")) })
                if (state.rich.mayPin) DropdownMenuItem({ Text(if (state.rich.pins.any { it.messageId == m.id }) t("고정 해제", "Unpin") else t("고정", "Pin")) }, leadingIcon = { Icon(Icons.Rounded.PushPin, null) }, onClick = {
                    menu = false
                    scope.launch { if (state.rich.pins.any { it.messageId == m.id }) model.unpinMessage(chat.id, m.id) else model.pinMessage(chat.id, m.id, model.pinChoices().firstOrNull()?.second) }
                })
                if (mine && m.kind == "text" && !m.deleted) DropdownMenuItem({ Text(t("수정", "Edit")) }, leadingIcon = { Icon(Icons.Rounded.Edit, null) }, onClick = { menu = false; editing = true })
                if (mine && m.status == "failed") DropdownMenuItem({ Text(t("다시 보내기", "Retry")) }, leadingIcon = { Icon(Icons.Rounded.Refresh, null) }, onClick = { menu = false; scope.launch { model.retrySend(m.id) } })
                if (mine && !m.deleted) DropdownMenuItem({ Text(t("모두에게서 삭제", "Delete for everyone"), color = extra.danger) }, leadingIcon = { Icon(Icons.Rounded.Delete, null, tint = extra.danger) }, onClick = {
                    menu = false
                    scope.launch { if (m.status == "failed" || m.status == "pending") model.cancelSend(m.id) else model.deleteForAll(chat.id, m.id) }
                })
                if (!mine && !m.deleted && state.groups.mayDelete) DropdownMenuItem({ Text(t("삭제 (관리자)", "Delete (admin)"), color = extra.danger) }, leadingIcon = { Icon(Icons.Rounded.Delete, null, tint = extra.danger) }, onClick = {
                    menu = false
                    scope.launch { model.deleteAsModerator(chat.id, m.id) }
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
            Modifier.fillMaxWidth().padding(top = 3.dp, start = if (group && !mine) 44.dp else 0.dp),
            horizontalArrangement = if (mine) Arrangement.End else Arrangement.Start,
        ) {
            m.reactions.forEach { rx ->
                val own = model.session?.memberId() in rx.members
                Row(
                    Modifier.padding(end = 4.dp).clip(RoundedCornerShape(14.dp))
                        .background(if (own) MaterialTheme.colorScheme.primary.copy(alpha = 0.30f) else extra.floating)
                        .clickable { scope.launch { model.react(chat.id, m.id, rx.emoji, remove = own) } }.padding(horizontal = 9.dp, vertical = 3.dp),
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
private fun RoleTag(text: String, color: Color) {
    Text(
        text, color = color, style = MaterialTheme.typography.labelMedium, maxLines = 1,
        modifier = Modifier.clip(RoundedCornerShape(10.dp)).background(color.copy(alpha = 0.16f)).padding(horizontal = 7.dp, vertical = 1.dp),
    )
}

/** The answered message, quoted above the reply. */
@Composable
private fun ReplyQuote(original: Message?, state: UiState, mine: Boolean) {
    val accent = if (original != null) nameColor(original.sender) else extra.bubbleMeta
    Row(
        Modifier.padding(top = 2.dp, bottom = 4.dp).clip(RoundedCornerShape(8.dp)).background(accent.copy(alpha = if (mine) 0.20f else 0.14f)),
    ) {
        Box(Modifier.width(3.dp).height(40.dp).background(accent))
        Column(Modifier.padding(horizontal = 8.dp, vertical = 4.dp)) {
            Text(original?.let { state.names[it.sender] ?: it.sender.take(6) } ?: t("메시지", "Message"), color = accent, style = MaterialTheme.typography.labelLarge, maxLines = 1)
            Text(original?.let { if (it.deleted) t("삭제된 메시지", "Deleted message") else Format.preview(it) } ?: t("이전 메시지", "Earlier message"),
                style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis, color = extra.bubbleMeta)
        }
    }
}

/**
 * The text with the time tucked into its last line: an invisible copy of the
 * time at the end reserves the room, so the real one sits beside short
 * lines and drops below only when the line is full.
 */
@Composable
private fun TextWithMeta(text: AnnotatedString, color: Color, m: Message, mine: Boolean, state: UiState, replyCount: Int) {
    val reserve = metaText(m, replyCount) + if (mine) "    " else ""
    Box {
        Text(
            buildAnnotatedString {
                append(text)
                withStyle(SpanStyle(color = Color.Transparent, fontSize = 12.sp)) { append("  $reserve") }
            },
            color = color, style = MaterialTheme.typography.bodyLarge,
        )
        MetaRow(m, mine, state, replyCount, Modifier.align(Alignment.BottomEnd))
    }
}

private fun metaText(m: Message, replyCount: Int): String =
    (if (replyCount > 0) "↩ $replyCount  " else "") + (if (m.edited) t("수정됨 ", "edited ") else "") + Format.clock(m.receivedAt)

@Composable
private fun MetaRow(m: Message, mine: Boolean, state: UiState, replyCount: Int, modifier: Modifier = Modifier, color: Color = extra.bubbleMeta) {
    Row(modifier.padding(top = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        if (replyCount > 0) {
            Icon(Icons.AutoMirrored.Rounded.Reply, t("답장", "Replies"), tint = color, modifier = Modifier.size(13.dp))
            Text(" $replyCount  ", style = MaterialTheme.typography.labelSmall, color = color)
        }
        if (m.edited) Text(t("수정됨 ", "edited "), style = MaterialTheme.typography.labelSmall, color = color)
        Text(Format.clock(m.receivedAt), style = MaterialTheme.typography.labelSmall, color = color)
        if (mine) {
            Spacer(Modifier.width(3.dp))
            when (m.status) {
                "pending" -> Icon(Icons.Rounded.Schedule, t("보내는 중", "Sending"), tint = color, modifier = Modifier.size(14.dp))
                "failed" -> Icon(Icons.Rounded.ErrorOutline, t("보내지 못함", "Not sent"), tint = extra.danger, modifier = Modifier.size(14.dp))
                else -> Icon(if (m.id in state.readMine) Icons.Rounded.DoneAll else Icons.Rounded.Done, if (m.id in state.readMine) t("읽음", "Read") else t("보냄", "Sent"),
                    tint = if (m.id in state.readMine) MaterialTheme.colorScheme.primary else color, modifier = Modifier.size(15.dp))
            }
        }
    }
}

/** Time on its own small pill (stickers and big emoji have no bubble). */
@Composable
private fun MetaPill(m: Message, mine: Boolean, state: UiState, replyCount: Int) {
    Box(Modifier.padding(top = 2.dp).clip(RoundedCornerShape(10.dp)).background(Color(0x66000000)).padding(horizontal = 7.dp, vertical = 1.dp)) {
        MetaRow(m, mine, state, replyCount, color = Color.White)
    }
}

/** A sticker picture, from the shared cache; its emoji while it loads or if it cannot. */
@Composable
private fun StickerImage(model: AppModel, platform: TreePlatform, pack: String, index: Int, emoji: String?, size: androidx.compose.ui.unit.Dp) {
    val px = with(LocalDensity.current) { size.roundToPx() }
    val img by rememberImage(platform, "sticker:$pack:$index", px) { model.rich.stickerImage(pack, index) }
    Box(Modifier.size(size), contentAlignment = Alignment.Center) {
        val b = img
        if (b != null) Image(b, emoji, Modifier.fillMaxSize(), contentScale = ContentScale.Fit)
        else Text(emoji ?: "🙂", fontSize = (size.value * 0.45f).sp)
    }
}

/** The floating composer: emoji and stickers, the field, attach, send. */
@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun Composer(model: AppModel, platform: TreePlatform, state: UiState, media: RichState, chat: Chat, replyTo: Message?, byId: Map<String, Message>, clearReply: () -> Unit) {
    val scope = rememberCoroutineScope()
    var text by remember(chat.id) { mutableStateOf(chat.draft ?: "") }
    var attach by remember { mutableStateOf(false) }
    var panel by remember { mutableStateOf(false) }
    var recordingSince by remember(chat.id) { mutableStateOf<Long?>(null) }
    if (state.channel.isChannel && !state.channel.mayPost) {
        Box(Modifier.fillMaxWidth().padding(10.dp).clip(RoundedCornerShape(26.dp)).background(extra.floating).padding(16.dp), contentAlignment = Alignment.Center) {
            Text(t("관리자만 글을 쓸 수 있는 채널이에요", "Only admins post in this channel"), color = extra.muted, style = MaterialTheme.typography.bodyMedium)
        }
        return
    }
    Column(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 8.dp)) {
        Column(Modifier.fillMaxWidth().shadow(6.dp, RoundedCornerShape(28.dp)).clip(RoundedCornerShape(28.dp)).background(extra.floating)) {
            replyTo?.let { r ->
                Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 6.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.AutoMirrored.Rounded.Reply, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(t("${state.names[r.sender] ?: "나"}에게 답장", "Reply to ${state.names[r.sender] ?: "yourself"}"), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge, maxLines = 1)
                        Text(Format.preview(r), style = MaterialTheme.typography.bodySmall, color = extra.muted, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    IconButton(onClick = clearReply) { Icon(Icons.Rounded.Close, t("답장 취소", "Cancel reply"), tint = extra.muted) }
                }
            }
            if (chat.others > 1) mentionQuery(text)?.let { q ->
                MentionBar(state, q) { name -> text = text.substring(0, text.lastIndexOf('@')) + "@" + name + " " }
            }
            Row(Modifier.fillMaxWidth().padding(4.dp), verticalAlignment = Alignment.Bottom) {
                IconButton(onClick = { panel = !panel; attach = false }) {
                    Icon(if (panel) Icons.Rounded.Keyboard else Icons.Rounded.EmojiEmotions, t("이모지와 스티커", "Emoji and stickers"), tint = extra.muted)
                }
                if (recordingSince != null) Box(Modifier.weight(1f)) {
                    RecordingBar(recordingSince!!) { platform.stopRecording(cancel = true); recordingSince = null }
                } else Box(Modifier.weight(1f).heightIn(min = 48.dp).padding(vertical = 13.dp)) {
                    if (text.isEmpty()) Text(t("메시지", "Message"), color = extra.muted, style = MaterialTheme.typography.bodyLarge)
                    BasicTextField(
                        text, { v ->
                            val was = text.isNotEmpty()
                            text = v
                            scope.launch { model.saveDraft(chat.id, v); if (was != v.isNotEmpty()) model.typing(chat.id, v.isNotEmpty()) }
                        },
                        textStyle = MaterialTheme.typography.bodyLarge.copy(color = MaterialTheme.colorScheme.onSurface),
                        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary), maxLines = 6,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                if (recordingSince == null) IconButton(onClick = { attach = !attach; panel = false }) { Icon(Icons.Rounded.AttachFile, t("첨부", "Attach"), tint = if (attach) MaterialTheme.colorScheme.primary else extra.muted) }
                val voiceOk = platform.canRecord && state.chatFeatures.none { (it.key == "chat.voice" || it.key == "chat.media") && !it.applied }
                val mic = text.isBlank() && voiceOk && recordingSince == null
                val canSend = text.isNotBlank() || mic || recordingSince != null
                var sendMenu by remember { mutableStateOf(false) }
                fun send(silent: Boolean) {
                    val v = text.trim()
                    val r = replyTo
                    text = ""
                    clearReply()
                    // Markup only where the chat allows it; mentions by the names shown here.
                    val formatted = hasMarkup(v) && state.chatFeatures.none { it.key == "chat.formatting" && !it.applied }
                    val (mentions, all) = if (chat.others > 1) mentionsIn(v, state.names) else emptyList<String>() to false
                    scope.launch {
                        if (state.groups.topic != null) model.sendInTopic(chat.id, v)
                        else model.send(chat.id, v, silent = silent, formatted = formatted, mentions = mentions, all = all, replyTo = r?.id)
                        model.typing(chat.id, false)
                        model.saveDraft(chat.id, "")
                    }
                }
                Box {
                    Box(
                        Modifier.padding(start = 2.dp, end = 2.dp, bottom = 2.dp).size(46.dp).clip(CircleShape)
                            .background(if (canSend) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.primary.copy(alpha = 0.35f))
                            .combinedClickable(enabled = canSend, onClick = {
                                when {
                                    recordingSince != null -> {
                                        val started = recordingSince!!
                                        recordingSince = null
                                        val wav = platform.stopRecording(cancel = false)
                                        if (wav != null) scope.launch {
                                            val ms = System.currentTimeMillis() - started
                                            model.sendMedia(chat.id, wav, "voice.wav", "audio/wav",
                                                AppModel.plainFile().copy(voice = true, durationMs = ms.toULong()))
                                        }
                                    }
                                    mic -> platform.startRecording { ok ->
                                        if (ok) recordingSince = System.currentTimeMillis()
                                        else model.notice(t("마이크를 쓸 수 없어요", "Can't use the microphone"))
                                    }
                                    else -> send(false)
                                }
                            }, onLongClick = { if (text.isNotBlank()) sendMenu = true }),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(if (mic) Icons.Rounded.Mic else Icons.AutoMirrored.Rounded.Send, if (mic) t("음성 녹음", "Record voice") else t("보내기", "Send"),
                            tint = MaterialTheme.colorScheme.onPrimary, modifier = Modifier.size(21.dp))
                    }
                    // Hold the button: send without a sound on the others' phones.
                    DropdownMenu(sendMenu, { sendMenu = false }) {
                        DropdownMenuItem({ Text(t("조용히 보내기", "Send without sound")) }, leadingIcon = { Icon(Icons.Rounded.NotificationsOff, null) }, onClick = { sendMenu = false; send(true) })
                    }
                }
            }
            if (panel) StickerPanel(model, platform, media, chat) { e -> text += e }
            if (attach) {
                HorizontalDivider(color = extra.divider)
                AttachSheet(model, platform, state, chat) { attach = false }
            }
        }
    }
}

/** Emoji to type, and the installed sticker packs (a recycling grid: only what is on screen is held). */
@Composable
private fun StickerPanel(model: AppModel, platform: TreePlatform, media: RichState, chat: Chat, onEmoji: (String) -> Unit) {
    val scope = rememberCoroutineScope()
    val packs = media.packs.filter { !it.emojiPack }
    var tab by remember { mutableStateOf(0) }
    Column(Modifier.fillMaxWidth().height(290.dp)) {
        HorizontalDivider(color = extra.divider)
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 8.dp, vertical = 6.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            PanelTab(t("이모지", "Emoji"), tab == 0) { tab = 0 }
            packs.forEachIndexed { i, p -> PanelTab(p.title, tab == i + 1) { tab = i + 1 } }
        }
        if (tab == 0) {
            LazyVerticalGrid(GridCells.Adaptive(48.dp), Modifier.fillMaxSize(), contentPadding = PaddingValues(8.dp)) {
                items(QUICK_EMOJI.size) { i ->
                    Box(Modifier.size(48.dp).clip(CircleShape).clickable { onEmoji(QUICK_EMOJI[i]) }, contentAlignment = Alignment.Center) { Text(QUICK_EMOJI[i], fontSize = 26.sp) }
                }
            }
        } else {
            val p = packs.getOrNull(tab - 1)
            if (p == null) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text(t("스티커 팩이 없어요", "No sticker packs"), color = extra.muted) }
            } else {
                LazyVerticalGrid(GridCells.Adaptive(84.dp), Modifier.fillMaxSize(), contentPadding = PaddingValues(8.dp)) {
                    items(p.items.size, key = { "${p.id}:$it" }) { i ->
                        Box(Modifier.padding(4.dp).clip(RoundedCornerShape(14.dp)).clickable { scope.launch { model.rich.sendSticker(chat.id, p.id, i) } }.padding(4.dp)) {
                            StickerImage(model, platform, p.id, i, p.items[i].emoji, 72.dp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun PanelTab(label: String, selected: Boolean, onClick: () -> Unit) {
    Text(
        label, style = MaterialTheme.typography.labelLarge, maxLines = 1,
        color = if (selected) MaterialTheme.colorScheme.primary else extra.muted,
        modifier = Modifier.clip(RoundedCornerShape(14.dp))
            .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.15f) else Color.Transparent)
            .clickable(onClick = onClick).padding(horizontal = 12.dp, vertical = 6.dp),
    )
}

@Composable
private fun RequestBanner(model: AppModel, chat: Chat) {
    val scope = rememberCoroutineScope()
    Column(Modifier.fillMaxWidth().padding(horizontal = 10.dp).clip(RoundedCornerShape(22.dp)).background(extra.floating).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
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
                Box(Modifier.fillMaxWidth().padding(top = 4.dp).height(6.dp).clip(RoundedCornerShape(3.dp)).background(textColor.copy(alpha = 0.12f))) {
                    Box(Modifier.fillMaxWidth(n.toFloat() / total).height(6.dp).clip(RoundedCornerShape(3.dp)).background(if (chosen) MaterialTheme.colorScheme.primary else textColor.copy(alpha = 0.45f)))
                }
            }
        }
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
