package app.tree.shared

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.File

/**
 * How the app looks and handles on this device: theme, text size, chat
 * extras. Display choices only (nothing about people or chats), so they
 * live in a small plain file beside the profile and are not synced.
 */
data class Look(
    /** "system", "dark" or "light". */
    val theme: String = "system",
    /** Text size, 0.85 to 1.4 of the system size. */
    val textScale: Float = 1f,
    /** The patterned chat background; off: a plain one. */
    val wallpaper: Boolean = true,
    /** Tighter bubbles and gaps: more messages on screen. */
    val compact: Boolean = false,
    /** One to three emoji alone in a message: shown large. */
    val bigEmoji: Boolean = true,
    /** Swipe a message sideways to answer it. */
    val swipeReply: Boolean = true,
    /** Computer: Enter sends, Shift+Enter breaks the line. Off: the other way round. */
    val enterSends: Boolean = true,
    /** "ko" or "en"; null: the system's. */
    val lang: String? = null,
    /** Emoji used lately, newest first, for the emoji panel and reactions. */
    val recentEmoji: List<String> = emptyList(),
) {
    fun usedEmoji(e: String): Look = copy(recentEmoji = (listOf(e) + recentEmoji.filter { it != e }).take(MAX_RECENT))

    companion object {
        const val MAX_RECENT = 24
        val SCALES = listOf(0.85f, 1f, 1.15f, 1.3f, 1.4f)
        val THEMES = listOf("system", "dark", "light")

        /** One `key=value` per line; unknown or bad lines keep the default. */
        fun parse(text: String): Look {
            val kv = text.lines().mapNotNull { l -> l.indexOf('=').takeIf { it > 0 }?.let { l.substring(0, it) to l.substring(it + 1) } }.toMap()
            val d = Look()
            fun bool(k: String, def: Boolean) = kv[k]?.toBooleanStrictOrNull() ?: def
            return Look(
                theme = kv["theme"]?.takeIf { it in THEMES } ?: d.theme,
                textScale = kv["textScale"]?.toFloatOrNull()?.coerceIn(SCALES.first(), SCALES.last()) ?: d.textScale,
                wallpaper = bool("wallpaper", d.wallpaper),
                compact = bool("compact", d.compact),
                bigEmoji = bool("bigEmoji", d.bigEmoji),
                swipeReply = bool("swipeReply", d.swipeReply),
                enterSends = bool("enterSends", d.enterSends),
                lang = kv["lang"]?.takeIf { it == "ko" || it == "en" },
                recentEmoji = kv["recentEmoji"]?.split(' ')?.filter { it.isNotBlank() && it.length <= 16 }?.distinct()?.take(MAX_RECENT) ?: emptyList(),
            )
        }

        fun format(l: Look): String = buildString {
            appendLine("theme=${l.theme}")
            appendLine("textScale=${l.textScale}")
            appendLine("wallpaper=${l.wallpaper}")
            appendLine("compact=${l.compact}")
            appendLine("bigEmoji=${l.bigEmoji}")
            appendLine("swipeReply=${l.swipeReply}")
            appendLine("enterSends=${l.enterSends}")
            l.lang?.let { appendLine("lang=$it") }
            appendLine("recentEmoji=${l.recentEmoji.joinToString(" ")}")
        }
    }
}

/** The device's [Look], kept in `<profile>.look`. */
object Looks {
    private val flow = MutableStateFlow(Look())
    val state: StateFlow<Look> = flow
    private var file: File? = null

    /** Reads the file beside this profile (once per profile). */
    fun open(profilePath: String) {
        val f = File("$profilePath.look")
        if (f == file) return
        file = f
        flow.value = runCatching { Look.parse(f.readText()) }.getOrDefault(Look())
        applyLang(flow.value)
    }

    fun update(change: (Look) -> Look) {
        val next = change(flow.value)
        if (next == flow.value) return
        flow.value = next
        applyLang(next)
        file?.let { f -> runCatching { f.parentFile?.mkdirs(); f.writeText(Look.format(next)) } }
    }

    private fun applyLang(l: Look) {
        when (l.lang) {
            "ko" -> Strings.lang = Lang.KO
            "en" -> Strings.lang = Lang.EN
        }
    }
}
