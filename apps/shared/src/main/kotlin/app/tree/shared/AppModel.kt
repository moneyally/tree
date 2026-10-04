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
import uniffi.tree_ffi.LinkState
import uniffi.tree_ffi.Member
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.TreeEvent
import uniffi.tree_ffi.TreeException
import uniffi.tree_ffi.TreeLink
import uniffi.tree_ffi.TreeSession

/** One chat as the list shows it. */
data class Chat(
    val id: String,
    val title: String,
    val status: String,
    val requestFrom: String?,
    val unread: Int,
    val pinned: Boolean = false,
    val archived: Boolean = false,
    val muted: Boolean = false,
    /** End of a timed mute (unix seconds); null while muted until unmuted. */
    val mutedUntil: Long? = null,
    val markedUnread: Boolean = false,
    /** Unsent text kept for this chat (user.drafts). */
    val draft: String? = null,
    /**
     * Stranger labels for the other person of a 1:1 chat or the sender of a
     * request (`not_contact`, `no_common_group`, `name_unverified`); empty
     * while user.stranger_labels is released.
     */
    val labels: List<String> = emptyList(),
)

/**
 * A device link in progress on this device. On the new device `text` is
 * what it shows (QR code content); on both, `code` is what the person
 * compares before confirming.
 */
data class LinkUi(
    val text: String? = null,
    val state: String = "waiting",
    val code: String? = null,
    val reason: String? = null,
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
    /** Own messages still in the outbox and not failed: sync sends them. */
    val sending: Boolean = false,
    /** The list shows the archived chats instead of the main list. */
    val showArchived: Boolean = false,
    /** Notifications shown in this session (muted chats and silent messages never notify). */
    val notified: Int = 0,
    /** This account's username link (user.username_link), also shown as a QR code. */
    val usernameLink: String? = null,
    /** A device link in progress (either side), and this account's devices. */
    val link: LinkUi? = null,
    val devices: List<String> = emptyList(),
    /** Pins, polls, scheduled messages, reminders of the open chat (RichChats.kt). */
    val rich: RichUi = RichUi(),
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
    internal val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    var session: TreeSession? = null
        private set
    private var profilePath: String? = null
    private var loop: Job? = null

    /** The platform shows a notification: chat title and text (null: a file). */
    var notifier: ((String, String?) -> Unit)? = null


    internal suspend fun <T> call(block: (TreeSession) -> T): T? {
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
        is TreeException.InvalidOption -> "INVALID_OPTION: ${e.reason}"
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
                if (pending || outbox) syncNow() else tick()
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
        refresh()
        checkReminders()
    }

    /**
     * Notifies for a new message unless the chat is open, muted, or the
     * message was sent silently (the client decides: `shouldNotify`).
     */
    private suspend fun maybeNotify(group: String, silent: Boolean, text: String?) {
        if (group == _state.value.open) return
        if (call { it.shouldNotify(group, silent) } != true) return
        _state.update { it.copy(notified = it.notified + 1) }
        val title = _state.value.chats.firstOrNull { it.id == group }?.title ?: group.take(8)
        // The text only if the user wants it in notifications.
        val content = call { s -> s.features().any { it.key == "user.notification_content" && it.applied } } == true
        notifier?.invoke(title, if (content) text else null)
    }

    private suspend fun onEvent(e: TreeEvent) {
        when (e) {
            is TreeEvent.Text -> maybeNotify(e.group, e.silent, e.text)
            is TreeEvent.File -> {
                _state.update { it.copy(files = it.files + (e.file.msgId to e.file)) }
                maybeNotify(e.group, false, null)
            }
            // An admin carries out a leave request (quiet or not: the
            // others' devices decide whether a line is shown).
            // Never automatic: which account a device belongs to comes from
            // other members' rosters (PROTOCOL.md 8.11).
            is TreeEvent.RemoveDeviceRequested -> _state.update { it.copy(notice = Strings.t("remove_device_asked")) }
            is TreeEvent.LeaveRequested -> call { s ->
                if (s.group(e.group).admins.contains(s.memberId())) s.remove(e.group, listOf(e.member))
            }
            is TreeEvent.Typing -> if (e.group == _state.value.open) {
                _state.update { it.copy(typing = if (e.on) it.typing + e.from else it.typing - e.from) }
            }
            is TreeEvent.GroupSafetyNotice -> _state.update { it.copy(notice = Strings.t("group_notice")) }
            is TreeEvent.KeyChanged -> _state.update { it.copy(notice = Strings.t("key_changed")) }
            is TreeEvent.SendFailed -> _state.update { it.copy(notice = Strings.t("send_failed")) }
            is TreeEvent.Poll -> maybeNotify(e.group, false, e.question)
            else -> {}
        }
    }

    suspend fun refresh() {
        val chats = call { s ->
            // In list order: pinned first, then by last activity.
            s.chatList().map { c ->
                val g = c.group
                val info = s.group(g)
                val others = s.members(g).filter { it.id != s.memberId() }
                val names = others.mapNotNull { it.name }
                // Labels for the person behind a request or a 1:1 chat.
                val person = info.requestFrom ?: others.singleOrNull()?.account
                val labels = person?.let { s.strangerLabels(it) }?.let { l ->
                    listOfNotNull(
                        "not_contact".takeIf { l.notContact },
                        "no_common_group".takeIf { l.noCommonGroup },
                        "name_unverified".takeIf { l.nameUnverified },
                    )
                } ?: emptyList()
                Chat(
                    g, info.name ?: names.joinToString(", ").ifEmpty { g.take(8) }, info.status, info.requestFrom,
                    c.unread.toInt(), c.pinned, c.archived, c.muted, c.mutedUntil, c.markedUnread, c.draft, labels,
                )
            }
        } ?: return
        val open = _state.value.open
        val messages = if (open != null) call { it.history(open, 200u) } ?: emptyList() else emptyList()
        // Opening a chat reads it (a receipt if user.read_receipts is applied).
        if (open != null && chats.any { it.id == open && (it.unread > 0 || it.markedUnread) }) {
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
                chats = chats.map { c -> if (c.id == open) c.copy(unread = 0, markedUnread = false) else c },
                messages = messages, names = names, members = members, chatFeatures = chatFeatures,
                screenshotBlocked = blocked, folders = folders, readMine = readMine, sending = sending,
            )
        }
        loadRich()
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

    /**
     * Chats the list shows under the selected folder, in list order (pinned
     * first): the main list, or only the archived chats while
     * [UiState.showArchived].
     */
    fun visibleChats(s: UiState): List<Chat> {
        val list = s.chats.filter { it.archived == s.showArchived }
        val f = s.folder ?: return list
        val ids = s.folders.firstOrNull { it.name == f }?.chats?.toSet() ?: return list
        return list.filter { it.id in ids }
    }

    /** Switches between the main list and the archived chats. */
    fun showArchived(on: Boolean) = _state.update { it.copy(showArchived = on) }

    /** Mutes for `seconds` (one of [muteChoices]; null = until unmuted). */
    suspend fun mute(group: String, seconds: Long?): Boolean = (call { it.muteFor(group, seconds); true } == true).also { refresh() }

    suspend fun unmute(group: String): Boolean = (call { it.mute(group, false) } != null).also { refresh() }

    /** The mute durations to offer: label (`1h`, `8h`, `1w`, `forever`) and seconds. */
    fun muteChoices(): List<Pair<String, Long?>> = uniffi.tree_ffi.muteChoices().map { it.label to it.seconds }

    suspend fun archive(group: String, on: Boolean): Boolean = (call { it.archiveChat(group, on) } != null).also { refresh() }

    /** At most five pinned chats; a sixth is refused (the reason is in `error`). */
    suspend fun pin(group: String, on: Boolean): Boolean = (call { it.pinChat(group, on) } != null).also { refresh() }

    suspend fun movePin(group: String, to: Int): Boolean = (call { it.movePinnedChat(group, to.toUInt()) } != null).also { refresh() }

    suspend fun markUnread(group: String, on: Boolean): Boolean = (call { it.markUnread(group, on) } != null).also { refresh() }

    /** Keeps the unsent text of a chat (restored when it opens; cleared on send). */
    suspend fun saveDraft(group: String, text: String) {
        call { it.setDraft(group, text) }
        _state.update { st -> st.copy(chats = st.chats.map { c -> if (c.id == group) c.copy(draft = text.ifBlank { null }) else c }) }
    }

    /** Leaves a chat; `quiet`: the others' apps show no "left" line. */
    suspend fun leave(group: String, quiet: Boolean): Boolean = (call { it.leave(group, quiet) } != null).also { refresh() }

    suspend fun loadUsernameLink() {
        val l = call { it.usernameLink() }
        _state.update { it.copy(usernameLink = l) }
    }

    /** A new username link; the old one stops working. */
    suspend fun resetUsernameLink(): String? = call { it.resetUsernameLink() }.also { loadUsernameLink() }

    /** Scanned QR code or pasted username link: adds the person as a contact. */
    suspend fun addByLink(link: String): String? = call { it.addContactByLink(link.trim()) }

    suspend fun typing(group: String, on: Boolean) {
        call { it.setTyping(group, on) }
    }

    suspend fun createFolder(name: String): Boolean = (call { it.createFolder(name) } != null).also { refresh() }

    suspend fun fileChat(folder: String, group: String): Boolean = (call { it.fileChat(folder, group, true) } != null).also { refresh() }

    suspend fun newChat(): String? = call { it.createGroup() }?.also { refresh(); openChat(it) }

    suspend fun invite(group: String, who: String): Boolean = (call { it.invite(group, who.trim()) }?.accepted == true).also { refresh() }

    /** `silent`: the others' apps do not notify for this message. */
    suspend fun send(group: String, text: String, silent: Boolean = false): Boolean {
        if (text.isBlank()) return false
        return (call { it.sendTextWith(group, text, false, emptyList(), false, null, silent) } != null).also { refresh() }
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

    /**
     * Admins: apply or release a chat setting for everyone in the group.
     * `option`: one of the feature's `choices` (e.g. `1d` for
     * chat.disappearing); null = the feature's default.
     */
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

    /**
     * Applies (with `option`, one of the feature's `choices` or another
     * value of its format; null = the default) or releases a user setting.
     * Returns false if refused (the reason is in `error`).
     */
    suspend fun setFeature(key: String, on: Boolean, option: String? = null): Boolean {
        val ok = call { if (on) it.applyFeature(key, option) else it.releaseFeature(key) } != null
        loadFeatures()
        if (key == "user.username_link") loadUsernameLink()
        if (key == "user.stranger_labels" || key == "user.drafts") refresh()
        return ok
    }

    /** "Release pending until <date>" for a release that takes effect later, else null. */
    fun pendingNote(f: Feature): String? = f.releasePendingUntil?.let { at ->
        val day = java.time.Instant.ofEpochSecond(at).atZone(java.time.ZoneId.systemDefault()).toLocalDate()
        "${Strings.t("release_pending")}: $day"
    }

    suspend fun recoveryPhrase(korean: Boolean): String? = call { it.newRecoveryPhrase(24u, korean, null) }?.words

    suspend fun inviteLink(group: String): String? = call { it.createInviteLink(group, 24L * 3600, 10u) }

    suspend fun joinLink(link: String): Boolean = call { it.joinInviteLink(link.trim()) } != null

    /** Findable by others only while `user.discoverable` is applied. */
    suspend fun setUsername(name: String): String? = call { it.setUsername(name) }

    // --- device linking (both devices show a code; the person confirms on both) ---

    private var newDevice: TreeLink? = null

    private fun show(l: LinkState, text: String? = _state.value.link?.text) =
        _state.update { it.copy(link = LinkUi(text, l.state, l.code, l.reason)) }

    private suspend fun <T> linkCall(block: () -> T): T? = try {
        withContext(io) { block() }
    } catch (e: TreeException) {
        _state.update { it.copy(error = describe(e)) }
        null
    }

    /** New device: makes the profile and returns the link to show. */
    suspend fun startLinkNewDevice(path: String, passphrase: String, name: String, server: String): String? {
        val l = linkCall { uniffi.tree_ffi.startLinkNewDevice(path, passphrase, name, server) } ?: return null
        newDevice = l
        profilePath = path
        val text = linkCall { l.link() } ?: return null
        _state.update { it.copy(link = LinkUi(text)) }
        return text
    }

    /** New device: checks for progress; signs in once linked. */
    suspend fun pollNewDevice(): String? {
        val l = newDevice ?: return null
        val st = linkCall { l.poll() } ?: return null
        show(st)
        if (st.state == "linked") {
            val s = linkCall { l.finish() } ?: return st.state
            newDevice = null
            session = s
            _state.update { it.copy(signedIn = true, name = s.name(), account = s.accountId(), link = null, error = null) }
            refresh()
        }
        if (st.state == "cancelled") newDevice = null
        return st.state
    }

    /** New device: the person compared the codes. */
    suspend fun confirmNewDevice(matches: Boolean): String? {
        val l = newDevice ?: return null
        val st = linkCall { l.confirm(matches) } ?: return null
        show(st)
        if (st.state == "cancelled") newDevice = null
        return st.state
    }

    /** Existing device: answers a new device's link (scanned or pasted). */
    suspend fun scanLink(text: String): String? = call { it.scanLink(text.trim()) }?.also { show(it, null) }?.state

    /** Existing device: checks for progress (the code appears, then "linked"). */
    suspend fun linkStatus(): String? {
        val st = call { it.linkStatus() } ?: return null
        show(st, null)
        if (st.state == "linked") loadDevices()
        return st.state
    }

    /** Existing device: the person compared the codes. */
    suspend fun confirmLink(matches: Boolean): String? {
        val st = call { it.confirmLink(matches) } ?: return null
        show(st, null)
        if (st.state == "linked") loadDevices()
        return st.state
    }

    /** Polls whichever side is linking until it is linked or cancelled. */
    fun watchLink(onLinked: () -> Unit = {}) {
        scope.launch {
            while (isActive) {
                val st = if (newDevice != null) pollNewDevice() else if (session != null) linkStatus() else null
                if (st == "linked") onLinked()
                if (st == null || st == "linked" || st == "cancelled") break
                kotlinx.coroutines.delay(1000)
            }
        }
    }

    fun closeLink() = _state.update { it.copy(link = null) }

    suspend fun loadDevices() {
        val d = call { it.devices() } ?: return
        _state.update { it.copy(devices = d) }
    }

    /** Removes another device of this account from its chats and the server. */
    suspend fun removeDevice(deviceId: String): Boolean = (call { it.removeDevice(deviceId) } != null).also { loadDevices(); refresh() }

    fun clearMessages() = _state.update { it.copy(error = null, notice = null) }
}
