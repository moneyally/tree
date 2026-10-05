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
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.withLock
import app.tree.shared.qr.CodeKind
import app.tree.shared.qr.QrCode
import app.tree.shared.qr.QrMatrix
import app.tree.shared.qr.TreeCodes
import uniffi.tree_ffi.Attachment
import uniffi.tree_ffi.Feature
import uniffi.tree_ffi.LinkState
import uniffi.tree_ffi.MediaOptions
import uniffi.tree_ffi.Member
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.NetworkKind
import uniffi.tree_ffi.Transfer
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
    /** A private channel (end-to-end; only admins post). */
    val channel: Boolean = false,
    /** The newest message, for the list's second line and time. */
    val last: Message? = null,
    /** Members other than this device's account, and their names. */
    val others: Int = 0,
    /** The other person's account in a 1:1 chat. */
    val peer: String? = null,
)

/** A person as the contacts screen shows them. */
data class ContactRow(
    val account: String,
    val name: String,
    val verified: Boolean,
    val blocked: Boolean,
    /** A 1:1 chat with them, if any. */
    val chat: String? = null,
)

/**
 * A device link in progress on this device. On the new device `text` is
 * what it shows and `qr` its QR code (the same text, exactly); on both,
 * `code` is what the person compares before confirming.
 */
data class LinkUi(
    val text: String? = null,
    val state: String = "waiting",
    val code: String? = null,
    val reason: String? = null,
    val qr: QrMatrix? = null,
)

/** What became of a scanned or pasted code ([AppModel.useScanned]). */
enum class ScanOutcome { ACCEPTED, NOT_TREE, WRONG_KIND, FAILED }

/**
 * When a member was last around (unix seconds; null: unknown). `exact`: they
 * said so themselves (user.last_seen on both sides); otherwise it is only
 * their latest message, shown vaguely.
 */
data class Seen(val at: Long?, val exact: Boolean)

/** A member typing: its name and when the indicator lapses if no "stopped" arrives. */
data class Typer(val name: String, val until: Long)

/** The names of who is typing in [group] now (expired ones left out). */
fun UiState.typersIn(group: String, now: Long = System.currentTimeMillis()): List<String> =
    typingIn[group]?.values?.filter { it.until > now }?.map { it.name }.orEmpty()

data class UiState(
    val signedIn: Boolean = false,
    val name: String = "",
    val account: String = "",
    val chats: List<Chat> = emptyList(),
    /** People this account knows (contacts screen). */
    val contacts: List<ContactRow> = emptyList(),
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
    /** Open chat: when each other member was last around (member id). */
    val seen: Map<String, Seen> = emptyMap(),
    /** Who is typing in every chat (chat -> member -> name and until when), for the chat list. */
    val typingIn: Map<String, Map<String, Typer>> = emptyMap(),
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
    /** The list shows the archived chats instead of the main list. */
    val showArchived: Boolean = false,
    /** Notifications shown in this session (muted chats and silent messages never notify). */
    val notified: Int = 0,
    /** This account's username link (user.username_link), also shown as a QR code. */
    val usernameLink: String? = null,
    /** The QR code of [usernameLink] (the link text, exactly). */
    val usernameQr: QrMatrix? = null,
    /** A device link in progress (either side), and this account's devices. */
    val link: LinkUi? = null,
    val devices: List<String> = emptyList(),
    /** Pins, polls, scheduled messages, reminders of the open chat (RichChats.kt). */
    val rich: RichUi = RichUi(),
    /** Topics, roles, admin log, join requests, moderation, communities (Groups.kt). */
    val groups: GroupsUi = GroupsUi(),
    /** Public groups and channels: NOT end-to-end encrypted (PublicSpaces.kt). */
    val pub: PublicUi = PublicUi(),
    /** The open chat as a private channel (PublicSpaces.kt). */
    val channel: ChannelUi = ChannelUi(),
    /** The bot factory and directory (Bots.kt). */
    val bots: BotsUi = BotsUi(),
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
    internal val io: CoroutineDispatcher = Dispatchers.IO,
) {
    internal val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    var session: TreeSession? = null
        private set
    private var profilePath: String? = null
    private var loop: Job? = null

    /** The platform shows a notification: chat title and text (null: a file). */
    var notifier: ((String, String?) -> Unit)? = null
    /** Where files that download by themselves (`user.auto_download`) go; set by the platform. */
    var downloadDir: java.io.File? = null


    /** When the public spaces were last synced (PublicSpaces.kt). */
    internal var lastPublicSync = 0L

    /** Stickers, GIFs, locations, events, video notes, photos, per-chat profiles. */
    val rich = RichChats(this)

    /** App lock (PIN, biometric), search, push wake-ups, notifications (DeviceSafety.kt). */
    val device = DeviceSafety(this)

    /** @gardenerbot, the in-app helper for bots and sticker packs. */
    val gardener = Gardener(this)

    internal fun showError(e: TreeException) = _state.update { it.copy(error = describe(e)) }

    internal fun countNotification() = _state.update { it.copy(notified = it.notified + 1) }

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
        is TreeException.WrongPin -> "${Strings.t("wrong_pin")} (${Strings.t("attempts_left")}: ${e.attemptsLeft})"
        is TreeException.PinUnavailable -> Strings.t("pin_unavailable")
        is TreeException.Server -> "${e.code} (${e.status})"
        is TreeException.Feature -> e.code
        is TreeException.InvalidOption -> "INVALID_OPTION: ${e.reason}"
        is TreeException.Network -> e.reason
        is TreeException.Usage -> e.reason
        is TreeException.Other -> e.reason
    }

    /** The server's proof-of-work bits: a new bot costs the same as a signup (Bots.kt). */
    internal var botPowBits: UInt = 20u

    suspend fun createAccount(path: String, passphrase: String, name: String, server: String, powBits: UInt = 20u): Boolean {
        botPowBits = powBits
        return signIn(path) { TreeSession.create(path, passphrase, name, server, powBits) }
    }

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

    internal suspend fun signIn(path: String, make: () -> TreeSession): Boolean {
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
    private var lastAnnounce = 0L

    /** The app is in front (the platform sets it); only then is "seen" announced. */
    @Volatile var foreground = true

    /**
     * The app is in front: tell the chats (user.last_seen; the core sends
     * nothing while it is released). At most every two minutes.
     */
    suspend fun announceSeen() {
        val now = System.currentTimeMillis()
        if (session == null || !foreground || now - lastAnnounce < 120_000) return
        lastAnnounce = now
        val st = _state.value
        for (c in st.chats) {
            if (c.status == "accepted" && !c.channel && c.id != st.notes) call { it.announceSeen(c.id) }
        }
    }

    /** True while the receiving loop runs. */
    val receiving: Boolean get() = loop?.isActive == true

    /** Starts receiving unless it already runs (the signed-in screens call it). */
    fun ensureSyncLoop() {
        if (loop?.isActive != true && session != null) startSyncLoop()
    }

    fun startSyncLoop() {
        loop?.cancel()
        loop = scope.launch {
            var quiet = 0
            // What arrived while the app was closed shows at once, not after the first long poll.
            try { syncNow() } catch (e: kotlinx.coroutines.CancellationException) { throw e } catch (e: Exception) { System.err.println("tree: first sync: $e") }
            while (isActive && session != null) {
                try {
                    val outbox = _state.value.sending
                    // null: the long poll failed (network, server): sync anyway
                    // after a pause, so one bad poll never stops receiving.
                    val pending = call { it.wait(if (outbox) 5u else 25u) }
                    if (pending == null) delay(3_000)
                    // Every few quiet rounds a full sync too, in case a wake-up was missed.
                    if (pending != false || outbox || ++quiet >= 4) { quiet = 0; syncNow() } else tick()
                } catch (e: kotlinx.coroutines.CancellationException) {
                    throw e
                } catch (e: Exception) {
                    // A bug in handling one event must not end receiving for good.
                    System.err.println("tree: sync loop: $e")
                    delay(3_000)
                }
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
        syncPublic()
        refresh()
        checkReminders()
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
        checkReminders()
    }

    /**
     * Notifies for a new message unless the chat is open, muted, or the
     * message was sent silently (the client decides: `shouldNotify`).
     */
    private suspend fun maybeNotify(group: String, silent: Boolean, text: String?) = device.notify(group, silent, text)

    private suspend fun onEvent(e: TreeEvent) {
        when (e) {
            is TreeEvent.Text -> {
                // A message ends its sender's "typing".
                _state.update {
                    val inChat = it.typingIn[e.group].orEmpty() - e.from
                    it.copy(typing = it.typing - e.from, typingIn = if (inChat.isEmpty()) it.typingIn - e.group else it.typingIn + (e.group to inChat))
                }
                maybeNotify(e.group, e.silent, e.text)
            }
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
            is TreeEvent.Typing -> {
                val name = if (e.on) {
                    _state.value.names[e.from] ?: call { s -> s.members(e.group).firstOrNull { it.id == e.from }?.name } ?: Strings.t("someone")
                } else ""
                _state.update {
                    val inChat = it.typingIn[e.group].orEmpty()
                    val now = if (e.on) inChat + (e.from to Typer(name, System.currentTimeMillis() + TYPING_MS)) else inChat - e.from
                    it.copy(
                        typing = if (e.group != it.open) it.typing else if (e.on) it.typing + e.from else it.typing - e.from,
                        typingIn = if (now.isEmpty()) it.typingIn - e.group else it.typingIn + (e.group to now),
                    )
                }
            }
            is TreeEvent.GroupSafetyNotice -> _state.update { it.copy(notice = Strings.t("group_notice")) }
            is TreeEvent.KeyChanged -> _state.update { it.copy(notice = Strings.t("key_changed")) }
            is TreeEvent.SendFailed -> _state.update { it.copy(notice = Strings.t("send_failed")) }
            is TreeEvent.Poll -> maybeNotify(e.group, false, e.question)
            is TreeEvent.Sticker -> maybeNotify(e.group, false, e.emoji)
            is TreeEvent.Location -> maybeNotify(e.group, false, Strings.t("location"))
            is TreeEvent.ChatEvent -> maybeNotify(e.group, false, e.title)
            // Another device of this account changed settings (self group).
            is TreeEvent.SettingsSynced -> loadFeatures()
            // Wave 3 (Groups.kt).
            is TreeEvent.Welcome -> _state.update { it.copy(notice = Strings.t("welcome_notice") + ": " + e.text) }
            is TreeEvent.HistoryShared -> _state.update { it.copy(notice = Strings.t("history_received")) }
            is TreeEvent.JoinRequest -> _state.update { it.copy(notice = Strings.t("join_request_notice")) }
            is TreeEvent.SlowModeHidden -> _state.update { it.copy(notice = Strings.t("slow_mode_hidden")) }
            // Wave 5: a bot answered a button press (Bots.kt).
            is TreeEvent.CallbackAnswer -> onBotAnswer(e.text)
            else -> {}
        }
    }

    suspend fun refresh() {
        val notesId = call { it.notesChat() }
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
                val last = s.history(g, 1u).lastOrNull()
                val peerAccount = others.mapNotNull { it.account }.distinct().singleOrNull()?.takeIf { others.size <= 3 && info.name == null }
                Chat(
                    g, if (g == notesId) Strings.t("notes") else info.name ?: names.distinct().joinToString(", ").ifEmpty { g.take(8) }, info.status, info.requestFrom,
                    c.unread.toInt(), c.pinned, c.archived, c.muted, c.mutedUntil, c.markedUnread, c.draft, labels, info.channel,
                    last = last, others = others.size, peer = peerAccount,
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
        // When each member was last around: their "seen" (user.last_seen, both
        // sides) or, failing that, their latest message here.
        val seen = if (open != null) members.filter { it.id != me }.associate { m ->
            val announced = call { it.lastSeen(open, m.id) }
            val wrote = messages.lastOrNull { it.sender == m.id }?.receivedAt
            m.id to Seen(maxOf(announced ?: 0, wrote ?: 0).takeIf { t -> t > 0 }, exact = announced != null && announced >= (wrote ?: 0))
        } else emptyMap()
        val blocked = open != null && (call { it.screenshotBlocked(open) } ?: false)
        val sending = call { s -> s.outbox().any { it.state != "failed" } } ?: false
        _state.update {
            it.copy(
                chats = chats.map { c -> if (c.id == open) c.copy(unread = 0, markedUnread = false) else c },
                messages = messages, names = names, members = members, chatFeatures = chatFeatures, seen = seen,
                screenshotBlocked = blocked, folders = folders, readMine = readMine, sending = sending,
                notes = notesId ?: it.notes,
            )
        }
        loadRich()
        rich.refresh(open, messages)
        loadGroups()
        loadChannel()
        loadPublic()
    }

    /**
     * The contacts screen: every known account with the name its devices
     * announced in shared chats, and the 1:1 chat with it if there is one.
     */
    suspend fun loadContacts() {
        val rows = call { s ->
            val me = s.memberId()
            val nameOf = mutableMapOf<String, String>()
            val oneToOne = mutableMapOf<String, String>()
            for (g in s.groups()) {
                val ms = s.members(g).filter { it.id != me }
                for (m in ms) {
                    val a = m.account ?: continue
                    m.name?.let { nameOf.putIfAbsent(a, it) }
                }
                val accounts = ms.mapNotNull { it.account }.distinct()
                if (accounts.size == 1 && s.group(g).name == null) oneToOne.putIfAbsent(accounts[0], g)
            }
            s.contacts().filter { it.accepted || it.verified }.map { c ->
                ContactRow(c.account, nameOf[c.account] ?: c.account.take(8), c.verified, c.blocked, oneToOne[c.account])
            }.sortedBy { it.name.lowercase() }
        } ?: return
        _state.update { it.copy(contacts = rows) }
    }

    /** Opens the 1:1 chat with an account, starting one if needed. */
    suspend fun chatWith(account: String): String? {
        _state.value.contacts.firstOrNull { it.account == account }?.chat?.let { openChat(it); return it }
        val g = call { it.createGroup() } ?: return null
        call { it.invite(g, account) }
        refresh()
        openChat(g)
        loadContacts()
        return g
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
        // The notes chat has its own row above the list.
        val list = s.chats.filter { it.archived == s.showArchived && it.id != s.notes }
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
        _state.update { it.copy(usernameLink = l, usernameQr = l?.let(QrCode::encode)) }
    }

    /** A new username link; the old one stops working. */
    suspend fun resetUsernameLink(): String? = call { it.resetUsernameLink() }.also { loadUsernameLink() }

    /**
     * Scanned QR code or pasted username link: adds the person as a contact and
     * pins the devices the server names for the account now (a key-package
     * claim), so their chats are not requests. A device only claimed later in
     * a group's member list never counts as the contact (F-021).
     */
    suspend fun addByLink(link: String): String? =
        call { it.addContactByLink(link.trim()) }?.also { account -> call { it.confirmContact(account) } }

    /**
     * A code the camera read or the person pasted, on a screen that expects
     * [want] (a device link or a username link). Only Tree's two link
     * kinds are acted on; anything else is never opened (NOT_TREE), and a
     * Tree code of the other kind is refused (WRONG_KIND) so that scanning
     * on the wrong screen does nothing unexpected. A device link starts the
     * link (the code appears on both devices; nothing links before both are
     * confirmed); a username link adds the person.
     */
    suspend fun useScanned(raw: String, want: CodeKind): ScanOutcome {
        val code = TreeCodes.parse(raw)
        return when {
            code.kind == CodeKind.NOT_TREE -> ScanOutcome.NOT_TREE
            code.kind != want -> ScanOutcome.WRONG_KIND
            code.kind == CodeKind.DEVICE_LINK ->
                if (scanLink(code.text) != null) ScanOutcome.ACCEPTED.also { watchLink() } else ScanOutcome.FAILED
            code.kind == CodeKind.SAFETY -> {
                // Only for the contact whose code was asked for; the core compares in constant time.
                val acc = safetyTarget ?: return ScanOutcome.FAILED
                val bytes = TreeCodes.safetyPayload(code) ?: return ScanOutcome.FAILED
                if (call { it.verify(acc, bytes) } != null) {
                    _state.update { it.copy(notice = Strings.t("safety_matched")) }
                    loadContacts()
                    ScanOutcome.ACCEPTED
                } else ScanOutcome.FAILED
            }
            else -> if (addByLink(code.text) != null) {
                _state.update { it.copy(notice = Strings.t("qr_friend_added")) }
                ScanOutcome.ACCEPTED
            } else ScanOutcome.FAILED
        }
    }

    /** The contact a safety QR scan is for (set before the scanner opens). */
    var safetyTarget: String? = null

    /** My safety QR for [account] (show it; they scan it). */
    suspend fun safetyQr(account: String): Pair<String, QrMatrix?>? =
        call { it.safetyQr(account) }?.let { TreeCodes.safetyText(it) }?.let { it to QrCode.encode(it) }

    // --- contacts and security ---

    suspend fun block(account: String): Boolean = (call { it.block(account) } != null).also { loadContacts(); refresh() }

    suspend fun unblock(account: String): Boolean = (call { it.unblock(account) } != null).also { loadContacts(); refresh() }

    /** My own screenshot block for one chat (on top of the chat's setting). */
    suspend fun setScreenshotBlock(group: String, on: Boolean): Boolean =
        (call { it.setScreenshotBlock(group, on) } != null).also { refresh() }

    /** After a suspected compromise: new keys in every chat now. How many chats. */
    suspend fun refreshAllKeys(): Int? = call { it.refreshAll() }?.size

    suspend fun recoveryStatus(): uniffi.tree_ffi.Recovery? = call { it.recoveryStatus() }

    /** Turns recovery off (pending for a while unless the current phrase is given). */
    suspend fun releaseRecovery(current: String?): uniffi.tree_ffi.Recovery? = call { it.releaseRecovery(current?.trim()?.takeIf { p -> p.isNotEmpty() }) }

    suspend fun releaseUsername(): Boolean = (call { it.releaseUsername() } != null).also { loadUsernameLink() }

    suspend fun typing(group: String, on: Boolean) {
        call { it.setTyping(group, on) }
    }

    suspend fun createFolder(name: String): Boolean = (call { it.createFolder(name) } != null).also { refresh() }

    suspend fun fileChat(folder: String, group: String, add: Boolean = true): Boolean = (call { it.fileChat(folder, group, add) } != null).also { refresh() }

    suspend fun deleteFolder(name: String): Boolean = (call { it.deleteFolder(name) } != null).also { refresh() }

    suspend fun newChat(): String? = call { it.createGroup() }?.also { refresh(); openChat(it) }

    suspend fun invite(group: String, who: String): Boolean = (call { it.invite(group, who.trim()) }?.accepted == true).also { refresh() }

    /**
     * Sends a text. `silent`: the others' apps do not notify. `formatted`:
     * Tree markup (**bold** ...). `mentions`: member ids named with @;
     * `all`: @all. `replyTo`: the message it answers.
     */
    suspend fun send(
        group: String, text: String, silent: Boolean = false, formatted: Boolean = false,
        mentions: List<String> = emptyList(), all: Boolean = false, replyTo: String? = null,
    ): Boolean {
        if (text.isBlank()) return false
        return (call { it.sendMessage(group, text, formatted, mentions, all, silent, replyTo) } != null).also { refresh() }
    }

    /** A text answering message [replyTo] (quoted above it). */
    suspend fun reply(group: String, text: String, replyTo: String): Boolean = send(group, text, replyTo = replyTo)

    /** A failed message (status "failed"): try again now. True if it went out. */
    /** Names a group (admins). */
    suspend fun renameGroup(group: String, name: String?): Boolean =
        (call { it.setGroupName(group, name?.takeIf { n -> n.isNotBlank() }) }?.accepted == true).also { refresh() }

    /** Adds (or with `remove` takes back) an emoji reaction (chat.reactions). */
    suspend fun react(group: String, id: String, emoji: String, remove: Boolean = false): Boolean =
        (call { it.react(group, id, emoji, remove) } != null).also { refresh() }

    /** Edits an own text message (chat.edit, within the window). */
    suspend fun edit(group: String, id: String, text: String): Boolean =
        (call { it.edit(group, id, text) } != null).also { refresh() }

    /** Deletes an own message for everyone (chat.delete_for_all, within the window). */
    suspend fun deleteForAll(group: String, id: String): Boolean =
        (call { it.deleteForAll(group, id) } != null).also { refresh() }

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
        _state.update {
            val old = it.link
            val qr = if (text == null) null else if (old?.text == text && old.qr != null) old.qr else QrCode.encode(text)
            it.copy(link = LinkUi(text, l.state, l.code, l.reason, qr))
        }

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
        _state.update { it.copy(link = LinkUi(text, qr = QrCode.encode(text))) }
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
    suspend fun scanLink(text: String): String? =
        linkLock.withLock { call { it.scanLink(text.trim()) }?.also { show(it, null) }?.state }

    /**
     * Existing device: each link call and the screen state it leads to
     * happen together, so a background poll never sees the link gone
     * (ended by the person's own answer) before the screen says so.
     */
    private val linkLock = kotlinx.coroutines.sync.Mutex()

    /** Existing device: checks for progress (the code appears, then "linked"). */
    suspend fun linkStatus(): String? = linkLock.withLock {
        val s = session ?: return@withLock null
        val st = try {
            withContext(io) { s.linkStatus() }
        } catch (e: TreeException) {
            // The person's own answer already ended the link (a poll that
            // waited behind it finds no link open): nothing went wrong.
            _state.value.link?.state?.takeIf { it in ENDED }?.let { return@withLock it }
            _state.update { it.copy(error = describe(e)) }
            return@withLock null
        }
        show(st, null)
        if (st.state == "linked") loadDevices()
        st.state
    }

    /** Existing device: the person compared the codes. */
    suspend fun confirmLink(matches: Boolean): String? = linkLock.withLock {
        val st = call { it.confirmLink(matches) } ?: return@withLock null
        show(st, null)
        if (st.state == "linked") loadDevices()
        st.state
    }

    /** Polls whichever side is linking until it is linked or cancelled. */
    fun watchLink(onLinked: () -> Unit = {}) {
        linkWatch?.cancel()
        linkWatch = scope.launch {
            while (isActive) {
                if (newDevice == null && _state.value.link?.state in ENDED) break
                val st = if (newDevice != null) pollNewDevice() else if (session != null) linkStatus() else null
                if (st == "linked") onLinked()
                if (st == null || st == "linked" || st == "cancelled") break
                kotlinx.coroutines.delay(1000)
            }
        }
    }

    private var linkWatch: Job? = null

    /**
     * Hides the link and stops watching it. Nothing is confirmed by this: a
     * link nobody confirmed links nothing and expires on the server.
     */
    fun closeLink() {
        linkWatch?.cancel()
        linkWatch = null
        _state.update { it.copy(link = null) }
    }

    suspend fun loadDevices() {
        val d = call { it.devices() } ?: return
        _state.update { it.copy(devices = d) }
    }

    /** Removes another device of this account from its chats and the server. */
    suspend fun removeDevice(deviceId: String): Boolean = (call { it.removeDevice(deviceId) } != null).also { loadDevices(); refresh() }

    /** Shows a short message to the person (the app shows notices for a few seconds). */
    fun notice(text: String) = _state.update { it.copy(notice = text) }

    fun clearMessages() = _state.update { it.copy(error = null, notice = null) }

    companion object {
        private val ENDED = setOf("linked", "cancelled")

        /** A typing indicator lapses after this long without news (a lost "stopped"). */
        const val TYPING_MS = 6_000L

        /** The line a scanning screen shows for [o] (null: nothing to say). */
        fun scanMessage(o: ScanOutcome, want: CodeKind): String? = when (o) {
            ScanOutcome.NOT_TREE -> Strings.t("qr_not_tree")
            ScanOutcome.WRONG_KIND -> Strings.t(when (want) { CodeKind.DEVICE_LINK -> "qr_wrong_device"; CodeKind.SAFETY -> "qr_wrong_safety"; else -> "qr_wrong_friend" })
            else -> null
        }

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
