package app.tree.android

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import app.tree.shared.AppModel
import app.tree.shared.Lang
import app.tree.shared.Strings
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private var pendingLink: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Strings.lang = if (resources.configuration.locales[0].language == "ko") Lang.KO else Lang.EN
        pendingLink = intent?.dataString
        val profile = filesDir.resolve("profile.db").path
        setContent {
            val scope = rememberCoroutineScope()
            val model = remember { AppModel(scope) }
            val state by model.state.collectAsState()
            // Screenshots and the app-switcher preview are blocked while a chat
            // asks for it (chat.screenshot_block) or the user wants it
            // (user.app_switcher_blur). Honest-app protection only.
            val secure = state.screenshotBlocked || state.features.any { it.key == "user.app_switcher_blur" && it.applied }
            LaunchedEffect(secure) {
                if (secure) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
            LaunchedEffect(state.signedIn) {
                if (state.signedIn) {
                    model.loadFeatures()
                    pendingLink?.let { link -> scope.launch { model.joinLink(link) }; pendingLink = null }
                }
            }
            TreeApp(model, profile)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        pendingLink = intent.dataString
    }
}
