package app.tree.android

import android.Manifest
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import app.tree.ui.TreeNav
import app.tree.ui.TreeUi
import androidx.lifecycle.lifecycleScope
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import app.tree.shared.AppModel
import app.tree.shared.DeviceProtection
import app.tree.shared.UiState
import kotlinx.coroutines.launch
import uniffi.tree_ffi.NetworkKind

class MainActivity : ComponentActivity() {
    private var pendingLink: String? = null
    private val app get() = application as TreeApplication
    private val model: AppModel get() = app.model
    private var inBackground = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingLink = intent?.dataString
        val profile = app.profile
        val platform = AndroidPlatform(this, model, profile)
        val nav = TreeNav()
        enableEdgeToEdge()
        setContent {
            val state by model.state.collectAsState()
            // Screenshots and the recent-apps preview (APP_PROTOCOL.md 6.3).
            LaunchedEffect(state.screenshotBlocked, state.features) { applyWindow(state) }
            LaunchedEffect(state.signedIn) {
                if (state.signedIn) {
                    model.downloadDir = cacheDir.resolve("downloads")
                    model.setNetwork(networkKind())
                    model.loadFeatures()
                    askForNotifications()
                    // Push wake-ups: the endpoint the distributor gave earlier, or ask now.
                    Push.endpoint(this@MainActivity)?.let { model.device.registerPushEndpoint(it) } ?: Push.register(this@MainActivity)
                    pendingLink?.let { link -> lifecycleScope.launch { model.joinLink(link) }; pendingLink = null }
                }
            }
            // An unlock method no longer chosen leaves no wrapped key behind.
            LaunchedEffect(state.signedIn, state.features) {
                if (state.signedIn && state.features.isNotEmpty()) {
                    val m = DeviceProtection.lockMethod(state.features)
                    if (m != "bio") BiometricUnlock.disable(profile)
                    if (m != "pin") DeviceSecret.forget(profile)
                }
            }
            // user.incognito_keyboard: every text field asks the keyboard not to learn.
            IncognitoKeyboard(DeviceProtection.incognitoKeyboard(state)) {
                platform.Launchers()
                // The system back button walks back through the app's screens.
                androidx.activity.compose.BackHandler(enabled = nav.canPop) { nav.pop() }
                TreeUi(model, platform, nav)
            }
        }
    }

    /**
     * `chat.screenshot_block` (or the user's block of the open chat): the
     * secure flag while that chat is open. `user.app_switcher_blur`: no
     * content in the recent-apps view; on Android 13+ through the recents
     * snapshot switch, below that by the secure flag while in the background.
     */
    private fun applyWindow(state: UiState) {
        val w = DeviceProtection.androidWindow(state, inBackground, Build.VERSION.SDK_INT)
        if (w.secure) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(!w.hideFromRecents)
    }

    private fun askForNotifications() {
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
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
        inBackground = false
        applyWindow(model.state.value)
        lifecycleScope.launch { model.setNetwork(networkKind()) }
    }

    // Older Android takes the recent-apps snapshot when the app leaves the
    // foreground: the secure flag must be on by then.
    override fun onPause() {
        inBackground = true
        applyWindow(model.state.value)
        super.onPause()
    }

    // App lock: leaving the app closes the profile when user.app_lock is on.
    override fun onStop() {
        super.onStop()
        lifecycleScope.launch { model.lockIfEnabled() }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        pendingLink = intent.dataString
    }
}
