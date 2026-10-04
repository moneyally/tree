package app.tree.shared

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import uniffi.tree_ffi.Feature
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.PinUnlockState
import uniffi.tree_ffi.TreeException
import uniffi.tree_ffi.TreeSession

// Wave 1 items 7-10: device protections, app lock with PIN / biometric,
// on-device search, notifications after a push wake-up, settings sync.
// The decisions live here (tested headless); the platforms only apply them.

/** How the Android window must be flagged right now. */
data class AndroidWindow(
    /** The system's "secure window" flag: no screenshots, no recording, blank in recents. */
    val secure: Boolean,
    /** API 33+: keep the app out of the recent-apps snapshots without blocking screenshots. */
    val hideFromRecents: Boolean,
)

/** Pure rules for the device-level switches (APP_PROTOCOL.md 6.3). */
object DeviceProtection {
    fun applied(features: List<Feature>, key: String): Boolean = features.any { it.key == key && it.applied }

    /**
     * `chat.screenshot_block` (or the user's own block of the open chat):
     * secure window while that chat is open. `user.app_switcher_blur`: the
     * recent-apps view shows no content; on API 33+ through the recents
     * snapshot switch (screenshots stay allowed), below that by the secure
     * flag while the app is in the background only.
     */
    fun androidWindow(state: UiState, inBackground: Boolean, apiLevel: Int): AndroidWindow {
        val blur = applied(state.features, "user.app_switcher_blur")
        val chatBlock = state.screenshotBlocked
        return if (apiLevel >= 33) AndroidWindow(secure = chatBlock, hideFromRecents = blur)
        else AndroidWindow(secure = chatBlock || (blur && inBackground), hideFromRecents = false)
    }

    /** `user.incognito_keyboard`: every text field asks the keyboard not to learn (Android). */
    fun incognitoKeyboard(state: UiState): Boolean = applied(state.features, "user.incognito_keyboard")

    /**
     * Desktop: keep the window out of screen captures while
     * `user.pc_screen_security` is applied, and while a chat that blocks
     * screenshots is open.
     */
    fun desktopCaptureExcluded(state: UiState): Boolean =
        applied(state.features, "user.pc_screen_security") || state.screenshotBlocked

    /** How the app unlocks after the lock (`user.app_lock` option); null while the lock is off. */
    fun lockMethod(features: List<Feature>): String? =
        features.firstOrNull { it.key == "user.app_lock" && it.applied }?.let { it.option ?: "passphrase" }
}

/** On-device search results (`user.search_index`). */
data class SearchUi(val query: String = "", val results: List<Message> = emptyList(), val indexed: Long? = null)

/**
 * App lock, search, push wake-ups and notifications for [AppModel]
 * (`model.device`). Kept apart so the shared model changes in one place.
 */
class DeviceSafety internal constructor(private val model: AppModel) {
    private val _search = MutableStateFlow(SearchUi())
    val search: StateFlow<SearchUi> = _search.asStateFlow()

    // --- app lock: PIN and platform key ---

    /** PIN unlock for the profile at `path` (readable while locked: the PIN file is outside the database). */
    fun pinState(path: String): PinUnlockState = uniffi.tree_ffi.pinUnlockState(path)

    /**
     * Turns PIN unlock on: needs the passphrase (it rebuilds the database
     * key, which is checked). `deviceSecret`: a secret the platform keeps in
     * hardware-backed storage (Android), or null (desktop). Sets
     * `user.app_lock` to `pin`.
     */
    suspend fun enablePin(path: String, passphrase: String, pin: String, deviceSecret: ByteArray?): Boolean {
        if (!model.setFeature("user.app_lock", true, "pin")) return false
        return guarded { uniffi.tree_ffi.enablePinUnlock(path, passphrase, pin, deviceSecret) } != null
    }

    /** Back to the passphrase (the PIN file is wiped). */
    suspend fun disablePin(path: String): Boolean {
        guarded { uniffi.tree_ffi.disablePinUnlock(path) } ?: return false
        return model.setFeature("user.app_lock", true, "passphrase")
    }

    /** Unlocks with the PIN; a wrong one says how many attempts are left (in `error`). */
    suspend fun openWithPin(path: String, pin: String, deviceSecret: ByteArray?): Boolean =
        model.signIn(path) { TreeSession.openWithPin(path, pin, deviceSecret) }

    /** Biometric unlock: the platform unwrapped the database key after the check. */
    suspend fun openWithPlatformKey(path: String, key: ByteArray): Boolean =
        model.signIn(path) { TreeSession.openWithPlatformKey(path, key) }.also { key.fill(0) }

    /** The database key for the platform keystore to wrap (biometric enrolment); wipe it after use. */
    suspend fun keyForPlatformWrap(path: String, passphrase: String): ByteArray? =
        guarded { uniffi.tree_ffi.keyForPlatformWrap(path, passphrase) }

    private suspend fun <T> guarded(block: () -> T): T? = try {
        withContext(model.io) { block() }
    } catch (e: TreeException) {
        model.showError(e)
        null
    }

    // --- search ---

    /** Searches the history on this device (words match by their start). */
    suspend fun search(query: String): List<Message> {
        if (query.isBlank()) {
            _search.value = SearchUi()
            return emptyList()
        }
        val r = model.call { it.search(query) } ?: emptyList()
        val n = model.call { it.searchIndexState() }?.messages?.toLong()
        _search.value = SearchUi(query, r, n)
        return r
    }

    fun clearSearch() {
        _search.value = SearchUi()
    }

    // --- notifications and push wake-ups ---

    /**
     * Shows a notification for a new message if the client says so (mute,
     * silent send, declined chat), with the text only where
     * `user.notification_content` allows it (never for a request or a chat
     * that blocks screenshots).
     */
    internal suspend fun notify(group: String, silent: Boolean, text: String?) {
        if (group == model.state.value.open) return
        val plan = model.call { it.notificationPlan(group, silent) } ?: return
        if (!plan.notify) return
        model.countNotification()
        val title = model.state.value.chats.firstOrNull { it.id == group }?.title ?: group.take(8)
        model.notifier?.invoke(title, if (plan.showText) text else null)
    }

    /** The endpoint a push distributor gave this app (null: none any more); the server sends only "wake" there. */
    var pushEndpoint: String? = null
        private set

    suspend fun registerPushEndpoint(endpoint: String?): Boolean {
        pushEndpoint = endpoint
        return model.call { it.setPushEndpoint(endpoint) } != null
    }

    /**
     * A wake-up arrived (push or a periodic job). With an open profile it
     * syncs, and notifications follow from what arrived; returns false
     * while the profile is locked: the database key is not in memory, so
     * the platform may only say that something arrived.
     */
    suspend fun onWake(): Boolean {
        if (model.session == null) return false
        model.syncNow()
        return true
    }
}
