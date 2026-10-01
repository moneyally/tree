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
        val model = remember { AppModel(scope) }
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
