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
import uniffi.tree_ffi.MediaOptions
import uniffi.tree_ffi.Member
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.NetworkKind
import uniffi.tree_ffi.Transfer
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
    /** Members typing in the open chat (member ids). */
    val typing: Set<String> = emptySet(),
    /** My messages in the open chat that someone has read. */
    val readMine: Set<String> = emptySet(),
    /** Folders (user and built-in) and the one selected (null = all chats). */
    val folders: List<uniffi.tree_ffi.ChatFolder> = emptyList(),
    val folder: String? = null,
    /** The notes chat, once the user opened it. */
    val notes: String? = null,
    /** The open chat asks the app to block screenshots (chat.screenshot_block). */
    val screenshotBlocked: Boolean = false,
    /** Files received in this session: message id -> reference. */
    val files: Map<String, Attachment> = emptyMap(),
    /** Uploads and downloads in progress: message id -> progress. */
    val transfers: Map<String, Transfer> = emptyMap(),
    /** Files already on this device (auto-downloaded or saved): message id -> path. */
    val downloaded: Map<String, String> = emptyMap(),
    /** Own messages still in the outbox and not failed: sync sends them. */
    val sending: Boolean = false,
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

    /** Where files that download by themselves (`user.auto_download`) go; set by the platform. */
    var downloadDir: java.io.File? = null


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

    /**
     * Long-polls in the background; every arrival is synced and shown.
     * While own messages wait in the outbox it polls briefly and syncs
     * every round, which sends them when they are due.
     */
    fun startSyncLoop() {
        loop?.cancel()
        loop = scope.launch {
            while (isActive && session != null) {
                val outbox = _state.value.sending
                val pending = call { it.wait(if (outbox) 5u else 25u) } ?: false
                if (pending || outbox) syncNow()
            }
        }
    }

    fun stop() {
        loop?.cancel()
    }

    /**
     * App lock (`user.app_lock`): closes the session, which drops the open
     * database and its key from memory; the passphrase is needed again.
     * Returns true if it locked.
     */
    suspend fun lockIfEnabled(): Boolean {
        val s = session ?: return false
        val on = call { it.features().any { f -> f.key == "user.app_lock" && f.applied } } ?: false
        if (!on) return false
        stop()
        session = null
        withContext(io) { s.close() }
        _state.value = UiState()
        return true
    }

    suspend fun syncNow() {
        val events = call { it.sync(0u) } ?: return
        for (e in events) onEvent(e)
        // A contact's file on the right network: fetched now (user.auto_download).
        for (e in events) if (e is TreeEvent.File && e.autoDownload) autoDownload(e.file)
        pumpUploads()
        refresh()
    }

    /** The app reports the network the device is on (decides auto-download). */
    suspend fun setNetwork(kind: NetworkKind) {
        call { it.setNetwork(kind) }
    }

    private suspend fun autoDownload(f: Attachment) {
        val dir = downloadDir ?: return
        withContext(io) { dir.mkdirs() }
        val dest = java.io.File(dir, "${f.msgId.take(16)}-${safeName(f.name)}")
        if (call { it.downloadTo(f, dest.path) } != null) {
            _state.update { it.copy(downloaded = it.downloaded + (f.msgId to dest.path)) }
        }
    }

    /** Uploads progress (read without waiting for the session). */
    fun updateTransfers() {
        val s = session ?: return
        _state.update { it.copy(transfers = s.transfers().associateBy { t -> t.messageId }) }
    }

    /**
     * Keeps a long upload going: the session uploads one slice per call and
     * is free for other calls in between. Stops when nothing moves (offline:
     * the outbox retries later).
     */
    suspend fun pumpUploads() {
        while (call { it.uploading() } == true) {
            val before = session?.transfers()?.sumOf { it.done.toLong() } ?: 0L
            val events = call { it.sendPending() } ?: break
            for (e in events) onEvent(e)
            updateTransfers()
            val after = session?.transfers()?.sumOf { it.done.toLong() } ?: 0L
            if (after == before) break
        }
        updateTransfers()
    }

    suspend fun pauseTransfer(msgId: String) {
        call { it.pauseTransfer(msgId) }
        updateTransfers()
    }

    suspend fun resumeTransfer(msgId: String) {
        call { it.resumeTransfer(msgId) }
        pumpUploads()
        refresh()
    }

    private fun onEvent(e: TreeEvent) {
        when (e) {
            is TreeEvent.File -> _state.update { it.copy(files = it.files + (e.file.msgId to e.file)) }
            is TreeEvent.Typing -> if (e.group == _state.value.open) {
                _state.update { it.copy(typing = if (e.on) it.typing + e.from else it.typing - e.from) }
            }
            is TreeEvent.GroupSafetyNotice -> _state.update { it.copy(notice = Strings.t("group_notice")) }
            is TreeEvent.KeyChanged -> _state.update { it.copy(notice = Strings.t("key_changed")) }
            is TreeEvent.SendFailed -> _state.update { it.copy(notice = Strings.t("send_failed")) }
            else -> {}
        }
    }

    suspend fun refresh() {
        val chats = call { s ->
            s.groups().map { g ->
                val info = s.group(g)
                val names = s.members(g).filter { it.id != s.memberId() }.mapNotNull { it.name }
                Chat(g, info.name ?: names.joinToString(", ").ifEmpty { g.take(8) }, info.status, info.requestFrom, s.unread(g).toInt())
            }
        } ?: return
        val open = _state.value.open
        val messages = if (open != null) call { it.history(open, 200u) } ?: emptyList() else emptyList()
        // Opening a chat reads it (a receipt if user.read_receipts is applied).
        if (open != null && chats.any { it.id == open && it.unread > 0 }) {
            call { it.markRead(open, messages.filter { m -> m.sender != session?.memberId() }.takeLast(100).map { m -> m.id }) }
        }
        val folders = call { it.folders() } ?: emptyList()
        val me0 = session?.memberId()
        val readMine = if (open != null) {
            messages.filter { it.sender == me0 }.filter { m -> (call { s -> s.readBy(open, m.id) } ?: emptyList()).isNotEmpty() }.map { it.id }.toSet()
        } else emptySet()
        val members = if (open != null) call { it.members(open) } ?: emptyList() else emptyList()
        val me = session?.memberId()
        val names = members.associate { m -> m.id to if (m.id == me) "" else (m.name ?: m.id.take(6)) }
        val chatFeatures = if (open != null) call { it.chatFeatures(open) } ?: emptyList() else emptyList()
        val blocked = open != null && (call { it.screenshotBlocked(open) } ?: false)
        val sending = call { s -> s.outbox().any { it.state != "failed" } } ?: false
        _state.update {
            it.copy(
                chats = chats.map { c -> if (c.id == open) c.copy(unread = 0) else c },
                messages = messages, names = names, members = members, chatFeatures = chatFeatures,
                screenshotBlocked = blocked, folders = folders, readMine = readMine, sending = sending,
            )
        }
    }

    suspend fun openChat(group: String?) {
        _state.update { it.copy(open = group, typing = emptySet()) }
        refresh()
    }

    /** Opens the notes chat (made on first use; none if the user hid it). */
    suspend fun openNotes(): String? {
        val n = call { it.noteToSelf() } ?: return null
        _state.update { it.copy(notes = n) }
        openChat(n)
        return n
    }

    /** Shows only the chats of one folder (null: all). */
    fun showFolder(name: String?) = _state.update { it.copy(folder = name) }

    /** Chats the list shows under the selected folder. */
    fun visibleChats(s: UiState): List<Chat> {
        val f = s.folder ?: return s.chats
        val ids = s.folders.firstOrNull { it.name == f }?.chats?.toSet() ?: return s.chats
        return s.chats.filter { it.id in ids }
    }

    suspend fun typing(group: String, on: Boolean) {
        call { it.setTyping(group, on) }
    }

    suspend fun createFolder(name: String): Boolean = (call { it.createFolder(name) } != null).also { refresh() }

    suspend fun fileChat(folder: String, group: String): Boolean = (call { it.fileChat(folder, group, true) } != null).also { refresh() }

    suspend fun newChat(): String? = call { it.createGroup() }?.also { refresh(); openChat(it) }

    suspend fun invite(group: String, who: String): Boolean = (call { it.invite(group, who.trim()) }?.accepted == true).also { refresh() }

    suspend fun send(group: String, text: String): Boolean {
        if (text.isBlank()) return false
        return (call { it.sendText(group, text) } != null).also { refresh() }
    }

    /** A failed message (status "failed"): try again now. True if it went out. */
    suspend fun retrySend(messageId: String): Boolean = (call { it.retrySend(messageId) } == true).also { refresh() }

    /** A failed message: give up; it leaves the chat on this device. */
    suspend fun cancelSend(messageId: String): Boolean = (call { it.cancelSend(messageId) } != null).also { refresh() }

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

    /** Sends a file as it is (read from disk while it is encrypted; up to 2 GiB). */
    suspend fun sendFile(group: String, file: java.io.File, options: MediaOptions = plainFile()): Boolean {
        val mime = withContext(io) { java.nio.file.Files.probeContentType(file.toPath()) } ?: "application/octet-stream"
        val ok = call { it.sendFilePath(group, file.path, file.name, mime, options) } != null
        pumpUploads()
        refresh()
        return ok
    }

    /** Sends file contents with what the app knows (picture size, preview picture...). */
    suspend fun sendMedia(group: String, bytes: ByteArray, name: String, mime: String, options: MediaOptions = plainFile()): Boolean {
        val ok = call { it.sendMedia(group, bytes, name, mime, options) } != null
        pumpUploads()
        refresh()
        return ok
    }

    /** For platforms that hand over file contents (Android content URIs). */
    suspend fun sendBytes(group: String, bytes: ByteArray, name: String, mime: String): Boolean = sendMedia(group, bytes, name, mime)

    /** The reference of a file message (received, or sent by this device). */
    fun fileOf(msgId: String): Attachment? =
        _state.value.files[msgId] ?: _state.value.messages.firstOrNull { it.id == msgId }?.file

    /** Decrypted contents of a file, for platforms that write via streams. */
    suspend fun fileBytes(msgId: String): ByteArray? {
        val f = fileOf(msgId)?.takeIf { it.id.isNotEmpty() } ?: return null
        return call { it.download(f) }
    }

    /** Save as: downloads, checks and decrypts a file into `dest` (or copies it if already here). */
    suspend fun saveFile(msgId: String, dest: java.io.File): Boolean {
        _state.value.downloaded[msgId]?.let { have ->
            withContext(io) { java.io.File(have).copyTo(dest, overwrite = true) }
            return true
        }
        val f = fileOf(msgId)?.takeIf { it.id.isNotEmpty() } ?: return false
        val ok = call { it.downloadTo(f, dest.path) } != null
        if (ok) _state.update { it.copy(downloaded = it.downloaded + (msgId to dest.path)) }
        updateTransfers()
        return ok
    }

    suspend fun loadFeatures() {
        val f = call { it.features() } ?: return
        _state.update { it.copy(features = f) }
    }

    suspend fun setFeature(key: String, on: Boolean, option: String? = null) {
        call { if (on) it.applyFeature(key, option) else it.releaseFeature(key) }
        loadFeatures()
    }

    suspend fun recoveryPhrase(korean: Boolean): String? = call { it.newRecoveryPhrase(24u, korean, null) }?.words

    suspend fun inviteLink(group: String): String? = call { it.createInviteLink(group, 24L * 3600, 10u) }

    suspend fun joinLink(link: String): Boolean = call { it.joinInviteLink(link.trim()) } != null

    suspend fun setUsername(name: String): String? = call { it.setUsername(name, true) }

    fun clearMessages() = _state.update { it.copy(error = null, notice = null) }

    companion object {
        /** A file without details. */
        fun plainFile() = MediaOptions(viewOnce = false, voice = false, width = null, height = null, durationMs = null, thumbnail = null)

        /** A picture with its size and preview. */
        fun picture(width: Int, height: Int, thumbnail: ByteArray?) =
            MediaOptions(viewOnce = false, voice = false, width = width.toUInt(), height = height.toUInt(), durationMs = null, thumbnail = thumbnail)

        /** A received file name made safe for this device's disk (no folders, no hidden files). */
        fun safeName(name: String): String =
            name.replace(Regex("[^\\p{L}\\p{N}._ -]"), "_").trimStart('.', ' ').take(100).ifEmpty { "file" }
    }
}
