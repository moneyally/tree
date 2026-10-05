package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.KeyboardArrowRight
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.animation.core.animateFloat
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Round picture of a person or chat: initials on a colour chosen by `seed`. */
@Composable
fun Avatar(name: String, seed: String, size: Dp = 54.dp, modifier: Modifier = Modifier, image: androidx.compose.ui.graphics.ImageBitmap? = null) {
    if (image != null) {
        androidx.compose.foundation.Image(image, name, modifier.size(size).clip(CircleShape), contentScale = androidx.compose.ui.layout.ContentScale.Crop)
        return
    }
    val color = TreeColors.Avatars[(seed.hashCode() and 0x7fffffff) % TreeColors.Avatars.size]
    Box(
        modifier.size(size).clip(CircleShape).background(color),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            initials(name),
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = (size.value * 0.38f).sp,
            maxLines = 1,
        )
    }
}

/** Up to two letters for an avatar: Korean names keep their last two syllables' first. */
fun initials(name: String): String {
    val n = name.trim()
    if (n.isEmpty()) return "?"
    val first = n.codePointAt(0)
    // A Hangul name: the first one or two syllables read best.
    if (first in 0xAC00..0xD7A3) return n.take(if (n.length >= 2) 2 else 1)
    val parts = n.split(' ', '_', '-').filter { it.isNotEmpty() }
    return if (parts.size >= 2) (parts[0].take(1) + parts[1].take(1)).uppercase() else n.take(2).uppercase()
}

/** Unread count pill (grey when the chat is muted). */
@Composable
fun CountBadge(count: Int, muted: Boolean) {
    if (count <= 0) return
    Box(
        Modifier.defaultMinSize(minWidth = 22.dp, minHeight = 22.dp).clip(RoundedCornerShape(11.dp))
            .background(if (muted) extra.badgeMuted else MaterialTheme.colorScheme.primary)
            .padding(horizontal = 7.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            if (count > 999) "999+" else count.toString(),
            color = if (muted) Color.White else MaterialTheme.colorScheme.onPrimary,
            style = MaterialTheme.typography.labelSmall,
        )
    }
}

/** Small coloured word next to a name: 공개, 봇, 채널 ... */
@Composable
fun Tag(text: String, color: Color) {
    Box(
        Modifier.clip(RoundedCornerShape(6.dp)).background(color.copy(alpha = 0.16f)).padding(horizontal = 6.dp, vertical = 1.dp),
    ) { Text(text, color = color, style = MaterialTheme.typography.labelSmall) }
}

/** Rounded card holding related rows. */
@Composable
fun CardGroup(modifier: Modifier = Modifier, title: String? = null, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp)
            .clip(MaterialTheme.shapes.large).background(extra.card).padding(vertical = 6.dp),
    ) {
        if (title != null) {
            Text(
                title, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(start = 20.dp, top = 10.dp, bottom = 4.dp),
            )
        }
        content()
    }
}

/** Square-ish coloured tile with a white symbol (settings rows). */
@Composable
fun IconTile(icon: ImageVector, color: Color, size: Dp = 36.dp) {
    Box(Modifier.size(size).clip(RoundedCornerShape(size / 3.4f)).background(color), contentAlignment = Alignment.Center) {
        Icon(icon, contentDescription = null, tint = Color.White, modifier = Modifier.size(size * 0.58f))
    }
}

/** One row of a settings card: tile, title, one-line explanation, then a chevron or a trailing control. */
@Composable
fun SettingsRow(
    title: String,
    subtitle: String? = null,
    icon: ImageVector? = null,
    tile: Color = TreeColors.TileGrey,
    titleColor: Color = MaterialTheme.colorScheme.onSurface,
    onClick: (() -> Unit)? = null,
    trailing: (@Composable RowScope.() -> Unit)? = if (onClick != null) ({ Chevron() }) else null,
) {
    Row(
        Modifier.fillMaxWidth().let { if (onClick != null) it.clickable(onClick = onClick) else it }
            .padding(horizontal = 18.dp, vertical = 11.dp).defaultMinSize(minHeight = 40.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (icon != null) {
            IconTile(icon, tile)
            Spacer(Modifier.width(16.dp))
        }
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = titleColor)
            if (subtitle != null) {
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = extra.muted, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
        }
        if (trailing != null) {
            Spacer(Modifier.width(8.dp))
            trailing()
        }
    }
}

@Composable
fun Chevron() {
    Icon(Icons.AutoMirrored.Rounded.KeyboardArrowRight, contentDescription = null, tint = extra.muted)
}

/** A settings row with a switch; `locked` shows a lock and why instead. */
@Composable
fun SwitchRow(
    title: String,
    subtitle: String?,
    checked: Boolean,
    icon: ImageVector? = null,
    tile: Color = TreeColors.TileGrey,
    locked: String? = null,
    onChange: (Boolean) -> Unit,
) {
    SettingsRow(
        title = title,
        subtitle = locked ?: subtitle,
        icon = icon,
        tile = tile,
        onClick = if (locked == null) ({ onChange(!checked) }) else null,
        trailing = {
            if (locked != null) {
                Icon(Icons.Rounded.Lock, contentDescription = locked, tint = extra.muted, modifier = Modifier.size(20.dp))
            } else {
                Switch(
                    checked = checked, onCheckedChange = onChange,
                    colors = SwitchDefaults.colors(checkedTrackColor = MaterialTheme.colorScheme.primary),
                )
            }
        },
    )
}

@Composable
fun RowDivider(inset: Dp = 70.dp) {
    HorizontalDivider(Modifier.padding(start = inset), thickness = 0.6.dp, color = extra.divider)
}

/** Big screen title with actions on the right (main tabs). */
@Composable
fun BigHeader(title: String, actions: @Composable RowScope.() -> Unit = {}) {
    Row(
        Modifier.fillMaxWidth().padding(start = 22.dp, end = 10.dp, top = 14.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(title, style = MaterialTheme.typography.headlineMedium, modifier = Modifier.weight(1f))
        actions()
    }
}

/** Back arrow and a title (inner screens). */
@Composable
fun BackHeader(title: String, onBack: () -> Unit, actions: @Composable RowScope.() -> Unit = {}) {
    Row(
        Modifier.fillMaxWidth().padding(start = 4.dp, end = 8.dp, top = 8.dp, bottom = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = "뒤로") }
        Text(title, style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f).padding(start = 6.dp), maxLines = 1, overflow = TextOverflow.Ellipsis)
        actions()
    }
}

/** Pill-shaped search field. */
@Composable
fun SearchField(value: String, onChange: (String) -> Unit, placeholder: String, onSearch: () -> Unit = {}, modifier: Modifier = Modifier) {
    Row(
        modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp).height(48.dp)
            .clip(RoundedCornerShape(24.dp)).background(extra.card).padding(horizontal = 16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Rounded.Search, contentDescription = null, tint = extra.muted)
        Spacer(Modifier.width(12.dp))
        Box(Modifier.weight(1f)) {
            if (value.isEmpty()) Text(placeholder, color = extra.muted, style = MaterialTheme.typography.bodyLarge)
            BasicTextField(
                value, onChange, singleLine = true,
                textStyle = MaterialTheme.typography.bodyLarge.copy(color = MaterialTheme.colorScheme.onSurface),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(onSearch = { onSearch() }),
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

/** Full-width pill button (main action of a screen). */
@Composable
fun PillButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, icon: ImageVector? = null) {
    Button(
        onClick = onClick, enabled = enabled,
        modifier = modifier.fillMaxWidth().height(54.dp),
        shape = RoundedCornerShape(27.dp),
        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
        contentPadding = PaddingValues(horizontal = 20.dp),
    ) {
        if (icon != null) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(10.dp))
        }
        Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun QuietButton(text: String, onClick: () -> Unit, color: Color = MaterialTheme.colorScheme.primary) {
    TextButton(onClick = onClick) { Text(text, color = color, style = MaterialTheme.typography.labelLarge) }
}

/** Friendly empty screen: a tinted symbol, a title and one line. */
@Composable
fun EmptyState(icon: ImageVector, title: String, text: String, modifier: Modifier = Modifier, action: (@Composable () -> Unit)? = null) {
    Column(
        modifier.fillMaxWidth().padding(horizontal = 40.dp, vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Box(
            Modifier.size(96.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center,
        ) { Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(46.dp)) }
        Spacer(Modifier.height(6.dp))
        Text(title, style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
        Text(text, style = MaterialTheme.typography.bodyMedium, color = extra.muted, textAlign = TextAlign.Center)
        if (action != null) {
            Spacer(Modifier.height(8.dp))
            Box(Modifier.widthIn(max = 280.dp)) { action() }
        }
    }
}

/** Grey caption under a card. */
@Composable
fun Caption(text: String) {
    Text(text, style = MaterialTheme.typography.bodySmall, color = extra.muted, modifier = Modifier.padding(horizontal = 30.dp, vertical = 4.dp))
}

/** Three dots rising in turn, for "typing". */
@Composable
fun TypingDots(color: Color = MaterialTheme.colorScheme.primary, dot: Dp = 4.dp) {
    val tr = androidx.compose.animation.core.rememberInfiniteTransition(label = "typing")
    val phase by tr.animateFloat(
        0f, 3f,
        androidx.compose.animation.core.infiniteRepeatable(androidx.compose.animation.core.tween(1200, easing = androidx.compose.animation.core.LinearEasing)),
        label = "phase",
    )
    Row(horizontalArrangement = Arrangement.spacedBy(dot * 0.7f), verticalAlignment = Alignment.CenterVertically, modifier = Modifier.height(dot * 3)) {
        for (i in 0 until 3) {
            val d = ((phase - i + 3f) % 3f)
            val lift = if (d < 1f) kotlin.math.sin(d * Math.PI).toFloat() else 0f
            Box(Modifier.padding(bottom = dot * lift).size(dot).clip(CircleShape).background(color.copy(alpha = 0.5f + 0.5f * lift)))
        }
    }
}

/** "A 님이 입력 중", "A, B 님이 입력 중", "A, B 님 외 2명이 입력 중". */
fun typingText(names: List<String>): String = when {
    names.isEmpty() -> t("입력 중", "typing")
    names.size == 1 -> t("${names[0]} 님이 입력 중", "${names[0]} is typing")
    names.size == 2 -> t("${names[0]}, ${names[1]} 님이 입력 중", "${names[0]} and ${names[1]} are typing")
    else -> t("${names[0]}, ${names[1]} 님 외 ${names.size - 2}명이 입력 중", "${names[0]}, ${names[1]} and ${names.size - 2} more are typing")
}

/** The clock, ticking each second only while [active] (typing indicators lapse by it). */
@Composable
fun rememberNow(active: Boolean): Long {
    val now = androidx.compose.runtime.produceState(System.currentTimeMillis(), active) {
        value = System.currentTimeMillis()
        while (active) { kotlinx.coroutines.delay(1000); value = System.currentTimeMillis() }
    }
    return now.value
}

/** The typing line: dots and who. */
@Composable
fun TypingLine(names: List<String>, modifier: Modifier = Modifier) {
    Row(modifier, verticalAlignment = Alignment.CenterVertically) {
        TypingDots()
        Spacer(Modifier.width(6.dp))
        Text(typingText(names), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
    }
}
