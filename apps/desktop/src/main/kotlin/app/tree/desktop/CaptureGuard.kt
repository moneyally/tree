package app.tree.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Keeps the app window out of screen captures (`user.pc_screen_security`,
 * and while a chat with `chat.screenshot_block` is open) where the system
 * offers a way for an app to ask for it.
 *
 * - Windows 10 version 2004 and later: the window display affinity call
 *   with "exclude from capture"; the window is left out of screenshots,
 *   recordings and the system's own screen-capture history. Older versions
 *   accept only "monitor" affinity, where the window is captured as black.
 *   Reached through JNA, which the app already ships.
 * - Linux: no such call. Under X11 any client can read the screen; under
 *   Wayland the compositor decides and asks the user before sharing, but
 *   offers apps no way to exclude a window. Not available.
 * - macOS: the window sharing setting exists, but current system capture
 *   paths ignore it, so this build does not claim protection there. Not
 *   available.
 *
 * None of this stops a camera pointed at the screen or a modified system.
 */
interface CaptureGuard {
    /** The system offers a way to exclude the window. */
    val available: Boolean

    /** Excludes the window (or lets it be captured again). True if the system took it. */
    fun setExcluded(window: java.awt.Window, excluded: Boolean): Boolean
}

/** Systems without a way to exclude a window: does nothing and says so. */
object NoCaptureGuard : CaptureGuard {
    override val available = false
    override fun setExcluded(window: java.awt.Window, excluded: Boolean) = false
}

/** The window display affinity call (see [CaptureGuard]). */
class DisplayAffinityGuard : CaptureGuard {
    @Suppress("FunctionName")
    private interface User32 : Library {
        fun SetWindowDisplayAffinity(hWnd: Pointer, dwAffinity: Int): Boolean
    }

    private val user32: User32? = runCatching { Native.load("user32", User32::class.java) }.getOrNull()

    override val available: Boolean get() = user32 != null

    override fun setExcluded(window: java.awt.Window, excluded: Boolean): Boolean {
        val u = user32 ?: return false
        val hwnd = runCatching { Native.getWindowPointer(window) }.getOrNull() ?: return false
        if (!excluded) return u.SetWindowDisplayAffinity(hwnd, WDA_NONE)
        return u.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) || u.SetWindowDisplayAffinity(hwnd, WDA_MONITOR)
    }

    private companion object {
        const val WDA_NONE = 0x00
        const val WDA_MONITOR = 0x01
        const val WDA_EXCLUDEFROMCAPTURE = 0x11
    }
}

/** The guard for this computer, and whether the window is excluded right now. */
object DesktopProtection {
    val guard: CaptureGuard by lazy {
        if (System.getProperty("os.name").lowercase().startsWith("win")) DisplayAffinityGuard() else NoCaptureGuard
    }

    private val _active = MutableStateFlow(false)
    /** The window is excluded from captures now (the system accepted it). */
    val active: StateFlow<Boolean> = _active.asStateFlow()

    fun apply(window: java.awt.Window, excluded: Boolean) {
        _active.value = guard.available && guard.setExcluded(window, excluded) && excluded
    }
}
