package app.tree.android

import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.lifecycle.lifecycleScope
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import app.tree.shared.AppModel
import app.tree.shared.Lang
import app.tree.shared.Strings
import kotlinx.coroutines.launch
import uniffi.tree_ffi.NetworkKind

class MainActivity : ComponentActivity() {
    private var pendingLink: String? = null
    private var model: AppModel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Strings.lang = if (resources.configuration.locales[0].language == "ko") Lang.KO else Lang.EN
        pendingLink = intent?.dataString
        val profile = filesDir.resolve("profile.db").path
        setContent {
            val scope = rememberCoroutineScope()
            val model = remember { AppModel(scope).also { this@MainActivity.model = it } }
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
                    model.downloadDir = cacheDir.resolve("downloads")
                    model.setNetwork(networkKind())
                    model.loadFeatures()
                    pendingLink?.let { link -> scope.launch { model.joinLink(link) }; pendingLink = null }
                }
            }
            TreeApp(model, profile)
        }
    }

    /** Unmetered (Wi-Fi, wired) or metered (mobile) for user.auto_download. */
    private fun networkKind(): NetworkKind {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return NetworkKind.NONE
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return NetworkKind.NONE
        return if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)) NetworkKind.WIFI else NetworkKind.MOBILE
    }

    override fun onResume() {
        super.onResume()
        model?.let { m -> lifecycleScope.launch { m.setNetwork(networkKind()) } }
    }

    // App lock: leaving the app closes the profile when user.app_lock is on.
    override fun onStop() {
        super.onStop()
        model?.let { m -> lifecycleScope.launch { m.lockIfEnabled() } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        pendingLink = intent.dataString
    }
}
