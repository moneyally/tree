package app.tree.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Tree's look: one calm green accent on near-black (dark) or soft grey
 * (light) backgrounds, grouped content on rounded cards, and a few signal
 * colours for icon tiles. Every text colour on its background keeps a
 * contrast of at least 4.5:1.
 */
object TreeColors {
    val Green = Color(0xFF3FCB8E)
    val GreenDeep = Color(0xFF1E8A5D)

    // Icon tiles in settings (white symbol on these).
    val TileBlue = Color(0xFF3B82F6)
    val TileAmber = Color(0xFFF59E0B)
    val TileGreen = Color(0xFF22B573)
    val TileRed = Color(0xFFEF4444)
    val TileIndigo = Color(0xFF6366F1)
    val TileSky = Color(0xFF0EA5E9)
    val TileTeal = Color(0xFF14B8A6)
    val TileOrange = Color(0xFFF97316)
    val TileViolet = Color(0xFF8B5CF6)
    val TilePink = Color(0xFFEC4899)
    val TileGrey = Color(0xFF6B7280)

    /** Avatars without a photo: initials on one of these, chosen by id. */
    val Avatars = listOf(
        Color(0xFFE57373), Color(0xFFF0A04B), Color(0xFF4DB6AC), Color(0xFF64B5F6),
        Color(0xFF9575CD), Color(0xFF4FC38A), Color(0xFFF06292), Color(0xFF7986CB),
    )
}

/** Colours the Material scheme does not name. */
@Immutable
data class TreeExtra(
    val chatBackground: Color,
    val bubbleMine: Color,
    val bubbleMineText: Color,
    val bubbleTheirs: Color,
    val bubbleTheirsText: Color,
    val bubbleMeta: Color,
    val muted: Color,
    val divider: Color,
    val card: Color,
    val navBar: Color,
    val badgeMuted: Color,
    val danger: Color,
    val publicBadge: Color,
    val botBadge: Color,
    val warning: Color,
    /** The faint drawings on the chat wallpaper. */
    val wallpaperInk: Color = Color(0x1A9FD8BF),
    /** Floating bars over the chat (top bar, composer). */
    val floating: Color = Color(0xFA1C1D21),
)

private val DarkScheme: ColorScheme = darkColorScheme(
    primary = TreeColors.Green,
    onPrimary = Color(0xFF04140D),
    primaryContainer = Color(0xFF173B2B),
    onPrimaryContainer = Color(0xFFBDF2D8),
    secondary = Color(0xFF9FD8BF),
    background = Color(0xFF0B0C0E),
    onBackground = Color(0xFFECEDEF),
    surface = Color(0xFF0B0C0E),
    onSurface = Color(0xFFECEDEF),
    surfaceVariant = Color(0xFF1C1D21),
    onSurfaceVariant = Color(0xFF9A9CA3),
    surfaceContainer = Color(0xFF1C1D21),
    surfaceContainerHigh = Color(0xFF26272C),
    outline = Color(0xFF3A3B41),
    outlineVariant = Color(0xFF2A2B30),
    error = Color(0xFFFF6B6B),
)

private val LightScheme: ColorScheme = lightColorScheme(
    primary = TreeColors.GreenDeep,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD5F3E4),
    onPrimaryContainer = Color(0xFF0B3A25),
    secondary = Color(0xFF2E6B52),
    background = Color(0xFFF2F3F5),
    onBackground = Color(0xFF15161A),
    surface = Color(0xFFF2F3F5),
    onSurface = Color(0xFF15161A),
    surfaceVariant = Color(0xFFFFFFFF),
    onSurfaceVariant = Color(0xFF5F626B),
    surfaceContainer = Color(0xFFFFFFFF),
    surfaceContainerHigh = Color(0xFFE9EAEE),
    outline = Color(0xFFCDD0D6),
    outlineVariant = Color(0xFFE3E5E9),
    error = Color(0xFFD93636),
)

private val DarkExtra = TreeExtra(
    chatBackground = Color(0xFF0A0D0C),
    bubbleMine = Color(0xFF1F5A41),
    bubbleMineText = Color(0xFFF1FBF6),
    bubbleTheirs = Color(0xFF1F2025),
    bubbleTheirsText = Color(0xFFECEDEF),
    bubbleMeta = Color(0xFFA6B2AD),
    muted = Color(0xFF9A9CA3),
    divider = Color(0xFF24252A),
    card = Color(0xFF1C1D21),
    navBar = Color(0xF21C1D21),
    badgeMuted = Color(0xFF55575E),
    danger = Color(0xFFFF6B6B),
    publicBadge = Color(0xFFF0A04B),
    botBadge = Color(0xFF64B5F6),
    warning = Color(0xFFF5B942),
)

private val LightExtra = TreeExtra(
    chatBackground = Color(0xFFE8EEEA),
    wallpaperInk = Color(0x241E8A5D),
    floating = Color(0xFCFFFFFF),
    bubbleMine = Color(0xFFD3F2E2),
    bubbleMineText = Color(0xFF0E241A),
    bubbleTheirs = Color(0xFFFFFFFF),
    bubbleTheirsText = Color(0xFF15161A),
    bubbleMeta = Color(0xFF5F6B66),
    muted = Color(0xFF5F626B),
    divider = Color(0xFFE6E7EB),
    card = Color(0xFFFFFFFF),
    navBar = Color(0xF2FFFFFF),
    badgeMuted = Color(0xFFA3A6AE),
    danger = Color(0xFFD93636),
    publicBadge = Color(0xFFC46E12),
    botBadge = Color(0xFF1E6FC0),
    warning = Color(0xFF9A6A00),
)

val LocalTreeExtra = staticCompositionLocalOf { DarkExtra }

/** The type scale, in the app's font (Pretendard, OFL; bundled) with slightly tight tracking. */
private fun treeTypography(f: FontFamily?): Typography {
    fun st(size: Int, weight: FontWeight, line: Int? = null, track: Float = -0.2f) = TextStyle(
        fontFamily = f, fontSize = size.sp, fontWeight = weight, letterSpacing = track.sp,
        lineHeight = line?.sp ?: androidx.compose.ui.unit.TextUnit.Unspecified,
    )
    return Typography(
        headlineLarge = st(30, FontWeight.Bold, 38, -0.6f),
        headlineMedium = st(26, FontWeight.Bold, 32, -0.5f),
        titleLarge = st(22, FontWeight.Bold, 28, -0.4f),
        titleMedium = st(17, FontWeight.SemiBold, 22, -0.3f),
        titleSmall = st(15, FontWeight.SemiBold, 20),
        bodyLarge = st(16, FontWeight.Normal, 23),
        bodyMedium = st(15, FontWeight.Normal, 21),
        bodySmall = st(13, FontWeight.Normal, 18, -0.1f),
        labelLarge = st(15, FontWeight.SemiBold, 20),
        labelMedium = st(13, FontWeight.Medium, 17, -0.1f),
        labelSmall = st(11, FontWeight.Medium, 14, 0f),
    )
}

private val TreeShapes = Shapes(
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(22.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

@Composable
fun TreeTheme(dark: Boolean = isSystemInDarkTheme(), font: FontFamily? = null, content: @Composable () -> Unit) {
    val typography = androidx.compose.runtime.remember(font) { treeTypography(font) }
    CompositionLocalProvider(LocalTreeExtra provides if (dark) DarkExtra else LightExtra) {
        MaterialTheme(
            colorScheme = if (dark) DarkScheme else LightScheme,
            typography = typography,
            shapes = TreeShapes,
            content = content,
        )
    }
}

/** Shortcut: `extra.muted`, `extra.card`, ... */
val extra: TreeExtra @Composable get() = LocalTreeExtra.current
