package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Reply
import androidx.compose.material.icons.rounded.EmojiEmotions
import androidx.compose.material.icons.automirrored.rounded.KeyboardReturn
import androidx.compose.material.icons.rounded.ViewAgenda
import androidx.compose.material.icons.rounded.Wallpaper
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import app.tree.shared.Look
import app.tree.shared.Looks

/** 화면: theme, text size and how chats look, on this device. */
@Composable
internal fun LookPage() {
    val look by Looks.state.collectAsState()
    CardGroup(title = t("테마", "Theme")) {
        Choices(
            listOf("system" to t("기기 설정", "System"), "dark" to t("어둡게", "Dark"), "light" to t("밝게", "Light")),
            look.theme,
        ) { v -> Looks.update { it.copy(theme = v) } }
    }
    val sizeNames = listOf(t("작게", "Small"), t("보통", "Normal"), t("크게", "Large"), t("더 크게", "Larger"), t("가장 크게", "Largest"))
    CardGroup(title = t("글자 크기", "Text size") + " · " + (sizeNames.getOrNull(Look.SCALES.indexOf(look.textScale)) ?: "")) {
        // Each option is a 가 in its own size, kept the same whatever size is chosen, so the row always fits.
        val density = LocalDensity.current
        Choices(Look.SCALES.map { it to "" }, look.textScale, label = { v, on ->
            Text(t("가", "A"), fontSize = with(density) { (15 * v).dp.toSp() }, fontWeight = if (on) FontWeight.SemiBold else null,
                color = if (on) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface)
        }) { v -> Looks.update { it.copy(textScale = v) } }
        Preview(look)
    }
    CardGroup(title = t("대화 화면", "Chats")) {
        SwitchRow(t("배경 무늬", "Background pattern"), t("끄면 단색 배경이에요", "Off: a plain background"), look.wallpaper, Icons.Rounded.Wallpaper, TreeColors.TileTeal) { on -> Looks.update { it.copy(wallpaper = on) } }
        RowDivider()
        SwitchRow(t("촘촘하게 보기", "Compact"), t("말풍선 사이를 좁혀 한 화면에 더 많이 보여요", "Tighter bubbles, more on screen"), look.compact, Icons.Rounded.ViewAgenda, TreeColors.TileIndigo) { on -> Looks.update { it.copy(compact = on) } }
        RowDivider()
        SwitchRow(t("이모지 크게 보기", "Large emoji"), t("이모지만 1~3개 보내면 크게 보여요", "1–3 emoji alone show large"), look.bigEmoji, Icons.Rounded.EmojiEmotions, TreeColors.TileAmber) { on -> Looks.update { it.copy(bigEmoji = on) } }
    }
    Caption(t("화면 설정은 이 기기에만 저장돼요.", "These are saved on this device only."))
}

/** The device-only handling rows on the 대화 설정 page. */
@Composable
internal fun ChatHandlingCard(platform: TreePlatform) {
    val look by Looks.state.collectAsState()
    CardGroup(title = t("이 기기에서", "On this device")) {
        SwitchRow(t("밀어서 답장", "Swipe to reply"), t("말풍선을 오른쪽으로 밀면 답장해요", "Swipe a bubble right to answer it"), look.swipeReply, Icons.AutoMirrored.Rounded.Reply, TreeColors.TileBlue) { on -> Looks.update { it.copy(swipeReply = on) } }
        if (!platform.isPhone) {
            RowDivider()
            SwitchRow(
                t("Enter로 보내기", "Enter sends"),
                if (look.enterSends) t("줄 바꿈은 Shift+Enter", "Shift+Enter for a new line") else t("보내기는 Ctrl+Enter", "Ctrl+Enter sends"),
                look.enterSends, Icons.AutoMirrored.Rounded.KeyboardReturn, TreeColors.TileGrey,
            ) { on -> Looks.update { it.copy(enterSends = on) } }
        }
    }
}

/** A row of pills; the chosen one filled. */
@Composable
private fun <T> Choices(
    options: List<Pair<T, String>>, current: T,
    label: @Composable (T, Boolean) -> Unit = { v, on ->
        Text(options.first { it.first == v }.second, style = MaterialTheme.typography.labelLarge, maxLines = 1, fontWeight = if (on) FontWeight.SemiBold else null,
            color = if (on) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface)
    },
    onPick: (T) -> Unit,
) {
    Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        options.forEach { (v, _) ->
            val on = v == current
            Box(
                Modifier.weight(1f).height(42.dp).clip(RoundedCornerShape(21.dp))
                    .background(if (on) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.primary.copy(alpha = 0.10f))
                    .clickable { onPick(v) },
                contentAlignment = Alignment.Center,
            ) { label(v, on) }
        }
    }
}

/** Two bubbles as the chat draws them, in the chosen size, so the change shows right away. */
@Composable
private fun Preview(look: Look) {
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 8.dp).clip(RoundedCornerShape(18.dp))
            .let { if (look.wallpaper) it.treeWallpaper(extra.chatBackground, extra.wallpaperInk) else it.background(extra.chatBackground) }
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(if (look.compact) 3.dp else 6.dp),
    ) {
        Bubble(t("글자 크기는 이 정도가 어때요?", "How does this size look?"), mine = false)
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.CenterEnd) { Bubble(t("읽기 편해요", "Easy to read"), mine = true) }
    }
}

@Composable
private fun Bubble(text: String, mine: Boolean) {
    val shape = remember(mine) { BubbleShape(mine, first = true, last = true) }
    Text(
        text, style = MaterialTheme.typography.bodyLarge, color = if (mine) extra.bubbleMineText else extra.bubbleTheirsText,
        modifier = Modifier.widthIn(max = 260.dp).clip(shape).background(if (mine) extra.bubbleMine else extra.bubbleTheirs)
            .padding(start = 12.dp + if (mine) 0.dp else shape.tail, end = 12.dp + if (mine) shape.tail else 0.dp, top = 7.dp, bottom = 7.dp),
    )
}
