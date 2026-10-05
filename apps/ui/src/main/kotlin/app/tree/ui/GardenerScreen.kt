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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.AttachFile
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Park
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
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
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Gardener
import app.tree.shared.Strings
import kotlinx.coroutines.launch

/** The helper's round picture: a tree on the app's green. */
@Composable
fun GardenerAvatar(size: androidx.compose.ui.unit.Dp) {
    Box(Modifier.size(size).clip(CircleShape).background(MaterialTheme.colorScheme.primary), contentAlignment = Alignment.Center) {
        Icon(Icons.Rounded.Park, null, tint = MaterialTheme.colorScheme.onPrimary, modifier = Modifier.size(size * 0.56f))
    }
}

/** Name with the mark only the app's own helper carries (it cannot be registered by anyone). */
@Composable
fun GardenerName(style: androidx.compose.ui.text.TextStyle = MaterialTheme.typography.titleMedium) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(Strings.t("gardener_name"), style = style)
        Spacer(Modifier.width(4.dp))
        Icon(Icons.Rounded.Verified, t("Tree 기본 봇", "Tree's own bot"), tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
    }
}

/** The conversation with @gardenerbot, in the chat's look: bubbles, tappable commands, the "/" menu. */
@Composable
fun GardenerScreen(model: AppModel, platform: TreePlatform, nav: TreeNav) {
    val scope = rememberCoroutineScope()
    val g = model.gardener
    val lines by g.lines.collectAsState()
    val list = rememberLazyListState()
    var text by remember { mutableStateOf("") }
    var menu by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { g.greet() }
    LaunchedEffect(lines.size) { if (lines.isNotEmpty()) list.animateScrollToItem(lines.lastIndex) }
    fun send(v: String) { scope.launch { g.send(v) } }
    Column(Modifier.fillMaxSize().treeWallpaper(extra.chatBackground, extra.wallpaperInk).let { if (platform.isPhone) it.statusBarsPadding() else it }) {
        Row(Modifier.fillMaxWidth().padding(10.dp), verticalAlignment = Alignment.CenterVertically) {
            if (platform.isPhone) {
                Box(Modifier.size(50.dp).shadow(4.dp, CircleShape).clip(CircleShape).background(extra.floating).clickable { nav.pop() }, contentAlignment = Alignment.Center) {
                    Icon(Icons.AutoMirrored.Rounded.ArrowBack, t("뒤로", "Back"))
                }
                Spacer(Modifier.width(8.dp))
            }
            Row(
                Modifier.weight(1f).heightIn(min = 56.dp).shadow(4.dp, RoundedCornerShape(28.dp)).clip(RoundedCornerShape(28.dp)).background(extra.floating).padding(horizontal = 8.dp, vertical = 7.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                GardenerAvatar(42.dp)
                Spacer(Modifier.width(10.dp))
                Column {
                    GardenerName()
                    Text("@" + Gardener.USERNAME + " · " + t("봇", "bot"), style = MaterialTheme.typography.bodySmall, color = extra.muted)
                }
            }
        }
        LazyColumn(Modifier.weight(1f).fillMaxWidth(), state = list, contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            items(lines.size) { i ->
                val l = lines[i]
                Column(Modifier.fillMaxWidth(), horizontalAlignment = if (l.fromBot) Alignment.Start else Alignment.End) {
                    Column(
                        Modifier.widthIn(max = 330.dp).clip(RoundedCornerShape(20.dp))
                            .background(if (l.fromBot) extra.bubbleTheirs else extra.bubbleMine).padding(horizontal = 14.dp, vertical = 9.dp),
                    ) {
                        Text(l.text, color = if (l.fromBot) extra.bubbleTheirsText else extra.bubbleMineText, style = MaterialTheme.typography.bodyLarge)
                        l.secret?.let { s ->
                            Spacer(Modifier.size(8.dp))
                            Row(Modifier.clip(RoundedCornerShape(10.dp)).background(extra.chatBackground).clickable { platform.copy(s); model.notice(t("복사했어요", "Copied")) }.padding(10.dp),
                                verticalAlignment = Alignment.CenterVertically) {
                                Text(s, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f, fill = false))
                                Spacer(Modifier.width(8.dp))
                                Icon(Icons.Rounded.ContentCopy, Strings.t("g_copy"), tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                            }
                        }
                        Text(Format.clock(l.at), color = extra.bubbleMeta, style = MaterialTheme.typography.labelSmall, modifier = Modifier.align(Alignment.End))
                    }
                    if (l.buttons.isNotEmpty() && i == lines.lastIndex) Row(Modifier.padding(top = 4.dp).horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        l.buttons.forEach { b ->
                            Text(b, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.labelLarge,
                                modifier = Modifier.clip(RoundedCornerShape(14.dp)).background(extra.floating).clickable { send(b) }.padding(horizontal = 12.dp, vertical = 8.dp))
                        }
                    }
                }
            }
        }
        Row(
            Modifier.fillMaxWidth().let { if (platform.isPhone) it.navigationBarsPadding().imePadding() else it }.padding(10.dp)
                .shadow(6.dp, RoundedCornerShape(28.dp)).clip(RoundedCornerShape(28.dp)).background(extra.floating).padding(4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box {
                Text("/", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.clip(CircleShape).clickable { menu = true }.padding(horizontal = 16.dp, vertical = 8.dp))
                DropdownMenu(menu, { menu = false }) {
                    g.commands().forEach { (c, d) ->
                        DropdownMenuItem({ Column { Text(c, color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.SemiBold); Text(d, style = MaterialTheme.typography.bodySmall, color = extra.muted) } },
                            onClick = { menu = false; send(c) })
                    }
                }
            }
            Box(Modifier.weight(1f).padding(vertical = 12.dp)) {
                if (text.isEmpty()) Text(t("메시지", "Message"), color = extra.muted)
                BasicTextField(text, { text = it }, textStyle = MaterialTheme.typography.bodyLarge.copy(color = MaterialTheme.colorScheme.onSurface),
                    cursorBrush = SolidColor(MaterialTheme.colorScheme.primary), maxLines = 5, modifier = Modifier.fillMaxWidth())
            }
            IconButton(onClick = { platform.pickImage { bytes, mime -> g.sendImage(bytes, mime) } }) { Icon(Icons.Rounded.AttachFile, t("사진", "Picture"), tint = extra.muted) }
            Box(
                Modifier.size(46.dp).clip(CircleShape).background(if (text.isNotBlank()) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.primary.copy(alpha = 0.35f))
                    .clickable(enabled = text.isNotBlank()) { val v = text; text = ""; send(v) },
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.AutoMirrored.Rounded.Send, t("보내기", "Send"), tint = MaterialTheme.colorScheme.onPrimary, modifier = Modifier.size(21.dp)) }
        }
    }
}
