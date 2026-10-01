package app.tree.desktop

import app.tree.shared.*

import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application

fun main() = application {
    Window(onCloseRequest = ::exitApplication, title = Strings.t("app")) {
        val scope = rememberCoroutineScope()
        val model = remember { AppModel(scope) }
        App(model)
    }
}
