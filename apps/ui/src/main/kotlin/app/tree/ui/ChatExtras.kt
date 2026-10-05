package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Forward
import androidx.compose.material.icons.outlined.Search
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.UiState
import app.tree.shared.forward
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message

// --- text: markup and mentions --------------------------------------------

private val INLINE = Regex("""\*\*(.+?)\*\*|~~(.+?)~~|\|\|(.+?)\|\||`([^`\n]+)`|(?<![\p{L}\p{N}])_(.+?)_(?![\p{L}\p{N}])""")
private val MENTION = Regex("""@[\p{L}\p{N}_]+""")

/** Colours a message text needs: mentions, code background, a hidden spoiler. */
data class TextInk(val mention: Color, val code: Color, val spoiler: Color, val quote: Color)

/**
 * A message text as drawn: Tree markup (APP_PROTOCOL.md 1.1) when the
 * message was sent with it, and @mentions in colour either way. Spoilers stay
 * covered until [revealed].
 */
fun messageText(text: String, formatted: Boolean, ink: TextInk, revealed: Boolean): AnnotatedString = buildAnnotatedString {
    val lines = text.split('\n')
    lines.forEachIndexed { i, raw ->
        var line = raw
        if (formatted && line.startsWith("> ")) {
            withStyle(SpanStyle(color = ink.quote, fontWeight = FontWeight.Bold)) { append("▍ ") }
            line = line.removePrefix("> ")
            withStyle(SpanStyle(fontStyle = FontStyle.Italic)) { inline(line, formatted, ink, revealed) }
        } else if (formatted && line.startsWith("- ")) {
            append("•  ")
            inline(line.removePrefix("- "), formatted, ink, revealed)
        } else inline(line, formatted, ink, revealed)
        if (i < lines.lastIndex) append('\n')
    }
}

private fun AnnotatedString.Builder.inline(s: String, formatted: Boolean, ink: TextInk, revealed: Boolean) {
    if (!formatted) { mentions(s, ink); return }
    var at = 0
    for (m in INLINE.findAll(s)) {
        mentions(s.substring(at, m.range.first), ink)
        val g = m.groupValues
        when {
            g[1].isNotEmpty() -> withStyle(SpanStyle(fontWeight = FontWeight.Bold)) { mentions(g[1], ink) }
            g[2].isNotEmpty() -> withStyle(SpanStyle(textDecoration = TextDecoration.LineThrough)) { mentions(g[2], ink) }
            g[3].isNotEmpty() -> if (revealed) withStyle(SpanStyle(background = ink.spoiler.copy(alpha = 0.18f))) { append(g[3]) }
                else withStyle(SpanStyle(color = ink.spoiler, background = ink.spoiler)) { append(g[3]) }
            g[4].isNotEmpty() -> withStyle(SpanStyle(fontFamily = FontFamily.Monospace, background = ink.code)) { append(" ${g[4]} ") }
            else -> withStyle(SpanStyle(fontStyle = FontStyle.Italic)) { mentions(g[5], ink) }
        }
        at = m.range.last + 1
    }
    mentions(s.substring(at), ink)
}

private fun AnnotatedString.Builder.mentions(s: String, ink: TextInk) {
    var at = 0
    for (m in MENTION.findAll(s)) {
        append(s.substring(at, m.range.first))
        withStyle(SpanStyle(color = ink.mention, fontWeight = FontWeight.SemiBold)) { append(m.value) }
        at = m.range.last + 1
    }
    append(s.substring(at))
}

/** The text has markup worth sending as such. */
fun hasMarkup(text: String): Boolean = INLINE.containsMatchIn(text) || text.lines().any { it.startsWith("> ") || it.startsWith("- ") }

/** "@이름" words of [text] that name a member: their ids, and whether @모두/@all is there. */
fun mentionsIn(text: String, names: Map<String, String>): Pair<List<String>, Boolean> {
    val words = MENTION.findAll(text).map { it.value.drop(1) }.toSet()
    val ids = names.filter { (_, n) -> n.isNotBlank() && n.replace(' ', '_') in words }.keys.toList()
    return ids to (words.contains("모두") || words.contains("all"))
}

/** Members whose name starts with what follows the last "@" being typed; null when not typing one. */
fun mentionQuery(text: String): String? {
    val at = text.lastIndexOf('@')
    if (at < 0 || (at > 0 && !text[at - 1].isWhitespace())) return null
    val q = text.substring(at + 1)
    return if (q.any { it.isWhitespace() }) null else q
}

/** The suggestions above the composer while an @name is being typed. */
@Composable
fun MentionBar(state: UiState, query: String, onPick: (String) -> Unit) {
    val names = state.names.filter { (_, n) -> n.isNotBlank() && n.startsWith(query, ignoreCase = true) }
    val all = "모두".startsWith(query) || "all".startsWith(query, ignoreCase = true)
    if (names.isEmpty() && !all) return
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 6.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        names.forEach { (id, n) ->
            Row(
                Modifier.clip(RoundedCornerShape(18.dp)).background(MaterialTheme.colorScheme.primary.copy(alpha = 0.14f))
                    .clickable { onPick(n.replace(' ', '_')) }.padding(start = 4.dp, end = 12.dp, top = 4.dp, bottom = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Avatar(n, id, 26.dp)
                Spacer(Modifier.width(6.dp))
                Text(n, style = MaterialTheme.typography.labelLarge)
            }
        }
        if (all) Text(
            "@모두", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.clip(RoundedCornerShape(18.dp)).background(MaterialTheme.colorScheme.primary.copy(alpha = 0.14f))
                .clickable { onPick("모두") }.padding(horizontal = 12.dp, vertical = 8.dp),
        )
    }
}

// --- selecting messages ----------------------------------------------------

/** The bar that replaces the chat's top bar while messages are selected. */
@Composable
fun SelectionBar(count: Int, canCopy: Boolean, canForward: Boolean, canDelete: Boolean, onClose: () -> Unit, onCopy: () -> Unit, onForward: () -> Unit, onDelete: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 10.dp).height56().shadow(4.dp, RoundedCornerShape(28.dp)).clip(RoundedCornerShape(28.dp))
            .background(extra.floating).padding(horizontal = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onClose) { Icon(Icons.Rounded.Close, t("선택 취소", "Cancel")) }
        Text(t("${count}개 선택", "$count selected"), style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
        if (canCopy) IconButton(onClick = onCopy) { Icon(Icons.Rounded.ContentCopy, t("복사", "Copy")) }
        if (canForward) IconButton(onClick = onForward) { Icon(Icons.AutoMirrored.Rounded.Forward, t("전달", "Forward")) }
        if (canDelete) IconButton(onClick = onDelete) { Icon(Icons.Rounded.Delete, t("삭제", "Delete"), tint = extra.danger) }
    }
}

private fun Modifier.height56() = this.then(Modifier.heightIn(min = 56.dp, max = 56.dp))

// --- forwarding ------------------------------------------------------------

/** Picks the chat to forward [ids] of [from] to, then forwards them in order. */
@Composable
fun ForwardDialog(model: AppModel, platform: TreePlatform, state: UiState, from: String, ids: List<String>, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    val media by model.rich.state.collectAsState()
    val targets = state.chats.filter { it.status == "accepted" }
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(t("전달할 대화", "Forward to")) },
        text = {
            LazyColumn(Modifier.heightIn(max = 420.dp)) {
                items(targets, key = { it.id }) { c ->
                    Row(
                        Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).clickable {
                            scope.launch {
                                var ok = 0
                                for (id in ids) if (model.forward(from, id, c.id) != null) ok++
                                if (ok > 0) model.notice(t("${c.title}에 전달했어요", "Forwarded to ${c.title}"))
                                onDone()
                            }
                        }.padding(vertical = 8.dp, horizontal = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (c.id == state.notes) Box(Modifier.size(40.dp).clip(RoundedCornerShape(20.dp)).background(MaterialTheme.colorScheme.primary))
                        else Avatar(c.title, c.peer ?: c.id, 40.dp, image = rememberPhoto(platform, c.id, media.chatPhotos[c.id]?.bytes))
                        Spacer(Modifier.width(12.dp))
                        Text(c.title, style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDone) { Text(t("취소", "Cancel")) } },
    )
}

// --- mute for how long -----------------------------------------------------

/** "1시간" ... for the core's mute choices. */
fun muteLabel(key: String): String = when (key) {
    "1h" -> t("1시간", "1 hour")
    "8h" -> t("8시간", "8 hours")
    "1w" -> t("1주일", "1 week")
    else -> t("계속", "Until I turn it back on")
}

/** Choose how long to mute [chat]; unmutes if it is muted. */
@Composable
fun MuteDialog(model: AppModel, chat: Chat, onDone: () -> Unit) {
    val scope = rememberCoroutineScope()
    AlertDialog(
        onDismissRequest = onDone,
        title = { Text(t("알림 끄기", "Mute")) },
        text = {
            Column {
                model.muteChoices().forEach { (key, seconds) ->
                    Text(
                        muteLabel(key), style = MaterialTheme.typography.bodyLarge,
                        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
                            .clickable { scope.launch { model.mute(chat.id, seconds); onDone() } }.padding(vertical = 14.dp, horizontal = 6.dp),
                    )
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDone) { Text(t("취소", "Cancel")) } },
    )
}

// --- search in one chat ----------------------------------------------------

/** Searches this chat's messages on this device; picking one goes back to it in the chat. */
@Composable
fun ChatSearchScreen(model: AppModel, nav: TreeNav, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    var q by remember { mutableStateOf("") }
    var results by remember { mutableStateOf<List<Message>>(emptyList()) }
    LaunchedEffect(q) {
        kotlinx.coroutines.delay(250)
        results = if (q.isBlank()) emptyList() else model.device.search(q).filter { it.group == chat.id }.sortedByDescending { it.receivedAt }
    }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(start = 4.dp, end = 12.dp, top = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = { nav.pop() }) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, t("뒤로", "Back")) }
            Box(Modifier.weight(1f)) { SearchField(q, { q = it }, t("${chat.title}에서 검색", "Search ${chat.title}")) }
        }
        if (q.isNotBlank() && results.isEmpty()) {
            EmptyState(Icons.Outlined.Search, t("찾는 메시지가 없어요", "No messages found"), "", Modifier.padding(top = 60.dp))
        }
        LazyColumn(contentPadding = PaddingValues(vertical = 6.dp)) {
            items(results, key = { it.id }) { m ->
                val name = state.names[m.sender]?.takeIf { it.isNotBlank() } ?: if (m.sender == model.session?.memberId()) t("나", "You") else m.sender.take(6)
                Row(
                    Modifier.fillMaxWidth().clickable { nav.focusMessage = m.id; nav.pop() }.padding(horizontal = 18.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(name, m.sender, 42.dp)
                    Spacer(Modifier.width(12.dp))
                    Column(Modifier.weight(1f)) {
                        Row {
                            Text(name, style = MaterialTheme.typography.titleSmall, modifier = Modifier.weight(1f))
                            Text(Format.listTime(m.receivedAt), style = MaterialTheme.typography.bodySmall, color = extra.muted)
                        }
                        Text(Format.preview(m), style = MaterialTheme.typography.bodyMedium, color = extra.muted, maxLines = 2, overflow = TextOverflow.Ellipsis)
                    }
                }
            }
        }
    }
}
