package app.tree.desktop

import app.tree.shared.*

import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalWindowInfo
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application

fun main() = application {
    Window(
        onCloseRequest = ::exitApplication, title = Strings.t("app"),
        state = androidx.compose.ui.window.rememberWindowState(width = 1180.dp, height = 800.dp),
    ) {
        val scope = rememberCoroutineScope()
        val model = remember { AppModel(scope).also { it.notifier = ::notify } }
        val state by model.state.collectAsState()
        // Out of screen captures where the system allows it
        // (user.pc_screen_security, or an open chat that blocks screenshots).
        val excluded = DeviceProtection.desktopCaptureExcluded(state)
        LaunchedEffect(excluded) { DesktopProtection.apply(window, excluded) }
        // App lock: five minutes without focus close the profile.
        val focused = LocalWindowInfo.current.isWindowFocused
        LaunchedEffect(focused) {
            model.foreground = focused
            if (focused) model.announceSeen()
            if (!focused) {
                delay(5 * 60 * 1000L)
                model.lockIfEnabled()
            }
        }
        val platform = remember { DesktopPlatform(model, scope) }
        val nav = remember { app.tree.ui.TreeNav() }
        // Downloads and the network kind, once a profile is open.
        LaunchedEffect(state.signedIn) { if (state.signedIn) desktopMedia(model) }
        app.tree.ui.TreeUi(model, platform, nav)
    }
}

/** A system notification through the tray, where the desktop has one. */
private val tray: java.awt.TrayIcon? by lazy {
    if (!java.awt.SystemTray.isSupported()) return@lazy null
    val img = java.awt.image.BufferedImage(16, 16, java.awt.image.BufferedImage.TYPE_INT_ARGB)
    runCatching { java.awt.TrayIcon(img, Strings.t("app")).also { java.awt.SystemTray.getSystemTray().add(it) } }.getOrNull()
}

/**
 * Shows what the model decided (DeviceSafety.notify): the chat's name, and
 * the text only where user.notification_content allows it.
 */
private fun notify(title: String, text: String?) {
    tray?.displayMessage(title, text ?: "", java.awt.TrayIcon.MessageType.NONE)
}
