package app.tree.shared

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.tree_ffi.Attachment
import uniffi.tree_ffi.Feature
import uniffi.tree_ffi.Member
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.TreeEvent
import uniffi.tree_ffi.TreeException
import uniffi.tree_ffi.TreeSession

/** One chat as the list shows it. */
data class Chat(
    val id: String,
    val title: String,
    val status: String,
    val requestFrom: String?,
    val unread: Int,
)

data class UiState(
    val signedIn: Boolean = false,
    val name: String = "",
    val account: String = "",
    val chats: List<Chat> = emptyList(),
    val open: String? = null,
    val messages: List<Message> = emptyList(),
    /** Member id -> display name in the open chat ("" = this device). */
    val names: Map<String, String> = emptyMap(),
    val features: List<Feature> = emptyList(),
    /** Members of the open chat, and its chat settings. */
    val members: List<Member> = emptyList(),
    val chatFeatures: List<Feature> = emptyList(),
    /** The open chat asks the app to block screenshots (chat.screenshot_block). */
    val screenshotBlocked: Boolean = false,
    /** Files received in this session: message id -> reference. */
    val files: Map<String, Attachment> = emptyMap(),
    val notice: String? = null,
    val error: String? = null,
)

/**
 * Everything the screens need, without any UI code, so it is tested
 * headless against a real server. All Rust calls run on [io]; the session
 * object serialises them itself.
 */
class AppModel(
    private val scope: CoroutineScope,
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    var session: TreeSession? = null
        private set
    private var profilePath: String? = null
    private var loop: Job? = null
    private val unread = mutableMapOf<String, Int>()

    private suspend fun <T> call(block: (TreeSession) -> T): T? {
        val s = session ?: return null
        return try {
            withContext(io) { block(s) }
        } catch (e: TreeException) {
            _state.update { it.copy(error = describe(e)) }
            null
        }
    }

    private fun describe(e: TreeException): String = when (e) {
        is TreeException.WrongKey -> Strings.t("wrong_pass")
        is TreeException.Server -> "${e.code} (${e.status})"
        is TreeException.Feature -> e.code
        is TreeException.Network -> e.reason
        is TreeException.Usage -> e.reason
        is TreeException.Other -> e.reason
    }

    suspend fun createAccount(path: String, passphrase: String, name: String, server: String, powBits: UInt = 20u): Boolean =
        signIn(path) { TreeSession.create(path, passphrase, name, server, powBits) }

    suspend fun openProfile(path: String, passphrase: String): Boolean =
        signIn(path) { TreeSession.open(path, passphrase) }

    /** Deletes the account everywhere and this device's profile; back to sign-up. */
    suspend fun deleteAccount(): Boolean {
        val path = profilePath ?: return false
        call { it.deleteAccount(path) } ?: return false
        stop()
        session = null
        _state.value = UiState()
        return true
    }

    private suspend fun signIn(path: String, make: () -> TreeSession): Boolean {
        val s = try {
            withContext(io) { make() }
        } catch (e: TreeException) {
            _state.update { it.copy(error = describe(e)) }
            return false
        }
        session = s
        profilePath = path
        _state.update { it.copy(signedIn = true, name = s.name(), account = s.accountId(), error = null) }
        refresh()
        return true
    }

    /** Long-polls in the background; every arrival is synced and shown. */
    fun startSyncLoop() {
        loop?.cancel()
        loop = scope.launch {
            while (isActive && session != null) {
                val pending = call { it.wait(25u) } ?: false
                if (pending) syncNow()
            }
        }
    }

    fun stop() {
        loop?.cancel()
    }

    suspend fun syncNow() {
        val events = call { it.sync(0u) } ?: return
        for (e in events) onEvent(e)
        refresh()
    }

    private fun onEvent(e: TreeEvent) {
        when (e) {
            is TreeEvent.Text -> if (e.group != _state.value.open) unread[e.group] = (unread[e.group] ?: 0) + 1
            is TreeEvent.File -> {
                if (e.group != _state.value.open) unread[e.group] = (unread[e.group] ?: 0) + 1
                _state.update { it.copy(files = it.files + (e.file.msgId to e.file)) }
            }
            is TreeEvent.KeyChanged -> _state.update { it.copy(notice = Strings.t("key_changed")) }
            else -> {}
        }
    }

    suspend fun refresh() {
        val chats = call { s ->
            s.groups().map { g ->
                val info = s.group(g)
                val names = s.members(g).filter { it.id != s.memberId() }.mapNotNull { it.name }
                Chat(g, info.name ?: names.joinToString(", ").ifEmpty { g.take(8) }, info.status, info.requestFrom, unread[g] ?: 0)
            }
        } ?: return
        val open = _state.value.open
        val messages = if (open != null) call { it.history(open, 200u) } ?: emptyList() else emptyList()
        val members = if (open != null) call { it.members(open) } ?: emptyList() else emptyList()
        val me = session?.memberId()
        val names = members.associate { m -> m.id to if (m.id == me) "" else (m.name ?: m.id.take(6)) }
        val chatFeatures = if (open != null) call { it.chatFeatures(open) } ?: emptyList() else emptyList()
        val blocked = open != null && (call { it.screenshotBlocked(open) } ?: false)
        _state.update {
            it.copy(chats = chats, messages = messages, names = names, members = members, chatFeatures = chatFeatures, screenshotBlocked = blocked)
        }
    }

    suspend fun openChat(group: String?) {
        if (group != null) unread.remove(group)
        _state.update { it.copy(open = group) }
        refresh()
    }

    suspend fun newChat(): String? = call { it.createGroup() }?.also { refresh(); openChat(it) }

    suspend fun invite(group: String, who: String): Boolean = (call { it.invite(group, who.trim()) }?.accepted == true).also { refresh() }

    suspend fun send(group: String, text: String): Boolean {
        if (text.isBlank()) return false
        return (call { it.sendText(group, text) } != null).also { refresh() }
    }

    suspend fun accept(group: String) { call { it.acceptRequest(group) }; refresh() }

    suspend fun decline(group: String, block: Boolean) { call { it.declineRequest(group, block) }; refresh() }

    suspend fun report(group: String, ids: List<String>, reason: String): Boolean? = call { it.report(group, ids, reason) }?.verified

    suspend fun safetyNumber(account: String): String? = call { it.safetyNumber(account) }

    /** After comparing the digits in person or on a call. */
    suspend fun markVerified(account: String): Boolean = call { it.verify(account, null) } != null

    suspend fun isVerified(account: String): Boolean = call { s -> s.contacts().any { it.account == account && it.verified } } ?: false

    /** Admins: apply or release a chat setting for everyone in the group. */
    suspend fun setChatFeature(group: String, key: String, on: Boolean, option: String? = null): Boolean =
        (call { it.setChatFeature(group, key, on, option) }?.accepted == true).also { refresh() }

    suspend fun sendFile(group: String, file: java.io.File): Boolean {
        val bytes = withContext(io) { file.readBytes() }
        val mime = withContext(io) { java.nio.file.Files.probeContentType(file.toPath()) } ?: "application/octet-stream"
        return sendBytes(group, bytes, file.name, mime)
    }

    /** For platforms that hand over file contents (Android content URIs). */
    suspend fun sendBytes(group: String, bytes: ByteArray, name: String, mime: String): Boolean =
        (call { it.sendFile(group, bytes, name, mime, false) } != null).also { refresh() }

    /** Decrypted contents of a received file, for platforms that write via streams. */
    suspend fun fileBytes(msgId: String): ByteArray? {
        val f = _state.value.files[msgId] ?: return null
        return call { it.download(f) }
    }

    /** Downloads, checks and decrypts a received file into `dest`. */
    suspend fun saveFile(msgId: String, dest: java.io.File): Boolean {
        val f = _state.value.files[msgId] ?: return false
        val bytes = call { it.download(f) } ?: return false
        withContext(io) { dest.writeBytes(bytes) }
        return true
    }

    suspend fun loadFeatures() {
        val f = call { it.features() } ?: return
        _state.update { it.copy(features = f) }
    }

    suspend fun setFeature(key: String, on: Boolean) {
        call { if (on) it.applyFeature(key, null) else it.releaseFeature(key) }
        loadFeatures()
    }

    suspend fun recoveryPhrase(korean: Boolean): String? = call { it.newRecoveryPhrase(24u, korean, null) }?.words

    suspend fun inviteLink(group: String): String? = call { it.createInviteLink(group, 24L * 3600, 10u) }

    suspend fun joinLink(link: String): Boolean = call { it.joinInviteLink(link.trim()) } != null

    suspend fun setUsername(name: String): String? = call { it.setUsername(name, true) }

    fun clearMessages() = _state.update { it.copy(error = null, notice = null) }
}
