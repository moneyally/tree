package app.tree.desktop

import app.tree.shared.*

import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.platform.LocalWindowInfo
import kotlinx.coroutines.delay
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application

fun main() = application {
    Window(onCloseRequest = ::exitApplication, title = Strings.t("app")) {
        val scope = rememberCoroutineScope()
        val model = remember { AppModel(scope).also { it.notifier = ::notify } }
        // App lock: five minutes without focus close the profile.
        val focused = LocalWindowInfo.current.isWindowFocused
        LaunchedEffect(focused) {
            if (!focused) {
                delay(5 * 60 * 1000L)
                model.lockIfEnabled()
            }
        }
        App(model)
    }
}

/** A system notification through the tray, where the desktop has one. */
private val tray: java.awt.TrayIcon? by lazy {
    if (!java.awt.SystemTray.isSupported()) return@lazy null
    val img = java.awt.image.BufferedImage(16, 16, java.awt.image.BufferedImage.TYPE_INT_ARGB)
    runCatching { java.awt.TrayIcon(img, Strings.t("app")).also { java.awt.SystemTray.getSystemTray().add(it) } }.getOrNull()
}

private fun notify(title: String, text: String?) {
    tray?.displayMessage(title, text ?: "", java.awt.TrayIcon.MessageType.NONE)
}
