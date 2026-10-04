package app.tree.shared

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import uniffi.tree_ffi.ChatEventInfo
import uniffi.tree_ffi.ChatProfileInfo
import uniffi.tree_ffi.GifResult
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.NewStickerItem
import uniffi.tree_ffi.Pack
import uniffi.tree_ffi.PhotoData
import uniffi.tree_ffi.PinnedMessage
import uniffi.tree_ffi.Place
import uniffi.tree_ffi.PollInfo
import uniffi.tree_ffi.Relays
import uniffi.tree_ffi.ReminderInfo
import uniffi.tree_ffi.ScheduledMessage
import uniffi.tree_ffi.StickerRefInfo
import uniffi.tree_ffi.StorageCleanReport

// Wave 2 part A: pins, polls, scheduled messages, reminders, forwarding,
// export, storage clean-up. State in UiState.rich ([RichUi]).

/**
 * Rich chats (wave 2 part A) for the open chat: pins, polls, scheduled
 * messages, reminders, and what the chat's settings allow (forwarding,
 * export). Kept apart from [UiState]'s other fields so the shared model
 * changes in one place.
 */
data class RichUi(
    /** Pinned messages of the open chat, newest first (chat.pins). */
    val pins: List<PinnedMessage> = emptyList(),
    /** This user may pin here (an admin, or either person in a 1:1). */
    val mayPin: Boolean = false,
    /** Polls of the open chat by message id, with their tally. */
    val polls: Map<String, PollInfo> = emptyMap(),
    /** Messages waiting on this device for their time (this chat). */
    val scheduled: List<ScheduledMessage> = emptyList(),
    /** Reminders not due yet (all chats). */
    val reminders: List<ReminderInfo> = emptyList(),
    /** chat.forwarding: false hides forward, save and copy. */
    val forwardingAllowed: Boolean = true,
    /** chat.export. */
    val exportAllowed: Boolean = true,
)

/** Reloads [RichUi] for the open chat ([AppModel.refresh] calls this). */
suspend fun AppModel.loadRich() {
    val open = state.value.open
    val reminders = call { it.reminders() } ?: emptyList()
    if (open == null) {
        _state.update { it.copy(rich = RichUi(reminders = reminders)) }
        return
    }
    val rich = call { s ->
        val polls = state.value.messages.filter { it.kind == "poll" }
            .mapNotNull { m -> s.poll(open, m.id)?.let { m.id to it } }.toMap()
        RichUi(
            pins = s.pins(open),
            mayPin = s.mayPin(open),
            polls = polls,
            scheduled = s.scheduled(open),
            reminders = reminders,
            forwardingAllowed = s.forwardingAllowed(open),
            exportAllowed = s.exportAllowed(open),
        )
    } ?: return
    _state.update { it.copy(rich = rich) }
}

/** Pin expiries to offer: label (`24h`, `7d`, `30d`, `forever`) and seconds (null: until unpinned). */
fun AppModel.pinChoices(): List<Pair<String, Long?>> = uniffi.tree_ffi.pinChoices().map { it.label to it.seconds }

suspend fun AppModel.pinMessage(group: String, id: String, seconds: Long?): Boolean =
    (call { it.pinMessage(group, id, seconds) } != null).also { refresh() }

suspend fun AppModel.unpinMessage(group: String, id: String): Boolean =
    (call { it.unpinMessage(group, id) } != null).also { refresh() }

/** A poll with 2 to 10 options; `closeIn` seconds (null: until its creator closes it). */
suspend fun AppModel.createPoll(
    group: String, question: String, options: List<String>,
    multi: Boolean = false, anonymous: Boolean = false, closeIn: Long? = null,
): String? = call { it.createPoll(group, question, options.filter { o -> o.isNotBlank() }, multi, anonymous, closeIn) }.also { refresh() }

/** This user's whole vote (option indexes); empty takes it back. */
suspend fun AppModel.vote(group: String, poll: String, choices: List<Int>): Boolean =
    (call { it.vote(group, poll, choices.map { c -> c.toUInt() }) } != null).also { refresh() }

suspend fun AppModel.closePoll(group: String, poll: String): Boolean =
    (call { it.closePoll(group, poll) } != null).also { refresh() }

/**
 * Sends `text` at `at` (unix seconds) from this device. The server never
 * holds it: the app must be running then, or the next sync sends it.
 */
suspend fun AppModel.schedule(group: String, text: String, at: Long, silent: Boolean = false): String? =
    call { it.scheduleText(group, text, at, silent) }.also { refresh() }

suspend fun AppModel.editScheduled(id: String, text: String?, at: Long?): Boolean =
    (call { it.editScheduled(id, text, at) } != null).also { refresh() }

suspend fun AppModel.cancelScheduled(id: String): Boolean =
    (call { it.cancelScheduled(id) } != null).also { refresh() }

/** Forwards a text or file to another chat, shown there as forwarded (no original sender). */
suspend fun AppModel.forward(from: String, id: String, to: String): String? =
    call { it.forward(from, id, to) }.also { refresh() }

/** "Remind me about this message" at `at` (unix seconds); local only. */
suspend fun AppModel.remindMe(group: String, id: String, at: Long): String? =
    call { it.remindMe(group, id, at) }.also { refresh() }

suspend fun AppModel.cancelReminder(id: String): Boolean = (call { it.cancelReminder(id) } != null).also { refresh() }

/**
 * Every round of the sync loop without news: scheduled messages that came
 * due go out, and due reminders are shown.
 */
suspend fun AppModel.tick() {
    val sent = call { it.sendDueScheduled() } ?: emptyList()
    if (sent.isNotEmpty()) refresh()
    checkReminders()
}

/** Reminders that came due: each is shown once as a local notification. */
suspend fun AppModel.checkReminders(): List<ReminderInfo> {
    val due = call { it.dueReminders() } ?: return emptyList()
    for (r in due) {
        val title = Strings.t("reminder") + ": " + (state.value.chats.firstOrNull { it.id == r.group }?.title ?: r.group.take(8))
        notifier?.invoke(title, r.text)
    }
    return due
}

/** Writes the chat to `<pathPrefix>.txt` and `.json` (chat.export); the two paths. */
suspend fun AppModel.exportChat(group: String, pathPrefix: String): List<String>? = call { it.exportChatTo(group, pathPrefix) }

/** Opens a received file into the media folder `dir`; its path (user.storage_clean cleans these). */
suspend fun AppModel.openFile(msgId: String, dir: String): String? {
    val f = state.value.files[msgId] ?: return null
    return call { it.downloadToCache(f, dir) }
}

/** Deletes downloaded media older than the user.storage_clean period now. */
suspend fun AppModel.cleanStorage(): StorageCleanReport? = call { it.cleanStorage() }

// Wave 2 part B: stickers, GIFs, locations, events, video notes, photos,
// per-chat profiles. State in AppModel.rich ([RichChats.state]).

/** What the rich-chat parts of the screens show (the open chat and this device). */
data class RichState(
    /** Relays the server offers; the GIF button is hidden without `gif`. */
    val relays: Relays = Relays(gif = false, map = false),
    /** Sticker and custom emoji packs installed on this device. */
    val packs: List<Pack> = emptyList(),
    /** Open chat: sticker messages (message id -> pack and item). */
    val stickers: Map<String, StickerRefInfo> = emptyMap(),
    /** Open chat: location cards (message id -> place). */
    val places: Map<String, Place> = emptyMap(),
    /** Open chat: event cards with their tally (message id -> event). */
    val events: Map<String, ChatEventInfo> = emptyMap(),
    /** Open chat: members' photos (member id -> photo). */
    val photos: Map<String, PhotoData> = emptyMap(),
    /** Chat list: the other person's photo of each 1:1 chat (chat id -> photo). */
    val chatPhotos: Map<String, PhotoData> = emptyMap(),
    /** This user's own photo, and its name / photo for the open chat only. */
    val myPhoto: PhotoData? = null,
    val chatProfile: ChatProfileInfo? = null,
    /** The last GIF search. */
    val gifs: List<GifResult> = emptyList(),
    /** Live locations this device is sharing (message id). */
    val sharing: Set<String> = emptySet(),
)

/**
 * Stickers and custom emoji, GIFs through the relay, locations, events,
 * video notes, profile photos and per-chat profiles (Wave 2 part B), on
 * top of [AppModel]. Everything goes through the Rust client; this only
 * keeps what the screens show.
 */
class RichChats(private val model: AppModel) {
    private val _state = MutableStateFlow(RichState())
    val state: StateFlow<RichState> = _state.asStateFlow()

    private suspend fun <T> call(block: (uniffi.tree_ffi.TreeSession) -> T): T? = model.call(block)

    /** Reloads what the open chat shows (called by [AppModel.refresh]). */
    suspend fun refresh(open: String?, messages: List<Message>) {
        val relays = call { it.relayStatus() } ?: Relays(gif = false, map = false)
        val packs = call { it.stickerPacks() } ?: emptyList()
        val me = model.session?.memberId()
        var stickers = emptyMap<String, StickerRefInfo>()
        var places = emptyMap<String, Place>()
        var events = emptyMap<String, ChatEventInfo>()
        var photos = emptyMap<String, PhotoData>()
        var profile: ChatProfileInfo? = null
        if (open != null) {
            stickers = messages.filter { it.kind == "sticker" }.mapNotNull { m -> call { it.stickerOf(open, m.id) }?.let { m.id to it } }.toMap()
            places = messages.filter { it.kind == "location" }.mapNotNull { m -> call { it.location(open, m.id) }?.let { m.id to it } }.toMap()
            events = messages.filter { it.kind == "event" }.mapNotNull { m -> call { it.chatEvent(open, m.id) }?.let { m.id to it } }.toMap()
            photos = model.state.value.members.mapNotNull { m -> call { it.memberPhoto(open, m.id) }?.let { m.id to it } }.toMap()
            profile = call { it.chatProfile(open) }
        }
        val chatPhotos = model.state.value.chats.mapNotNull { c ->
            val other = call { s -> s.members(c.id).filter { it.id != me } }?.singleOrNull() ?: return@mapNotNull null
            call { it.memberPhoto(c.id, other.id) }?.let { c.id to it }
        }.toMap()
        val mine = call { it.profilePhoto() }
        _state.update {
            it.copy(
                relays = relays, packs = packs, stickers = stickers, places = places, events = events,
                photos = photos, chatPhotos = chatPhotos, myPhoto = mine, chatProfile = profile,
                sharing = it.sharing.filter { id -> places[id]?.live != false }.toSet(),
            )
        }
    }

    private suspend fun done(ok: Boolean): Boolean = ok.also { model.refresh() }

    /** Whether the open chat shows the GIF button: the server has a relay and the chat allows GIFs. */
    fun gifAvailable(state: UiState): Boolean =
        _state.value.relays.gif && state.chatFeatures.any { it.key == "chat.gifs" && it.applied }

    /** Whether a chat setting is applied in the open chat (hides the matching button). */
    fun allowed(state: UiState, key: String): Boolean = state.chatFeatures.any { it.key == key && it.applied }

    // --- stickers and custom emoji ---

    /** Uploads a pack (images as encrypted attachments) and returns its link to share. */
    suspend fun createPack(title: String, items: List<NewStickerItem>, emojiPack: Boolean = false): String? =
        call { it.createStickerPack(title, items, emojiPack) }?.link.also { model.refresh() }

    suspend fun installPack(link: String): Boolean = done(call { it.installStickerPack(link.trim()) } != null)

    suspend fun removePack(id: String): Boolean = done(call { it.removeStickerPack(id) } != null)

    suspend fun stickerImage(pack: String, index: Int): ByteArray? = call { it.stickerImage(pack, index.toUInt()) }

    suspend fun sendSticker(group: String, pack: String, index: Int): Boolean =
        done(call { it.sendSticker(group, pack, index.toUInt()) } != null)

    /** Reacts with a custom emoji from an installed pack. */
    suspend fun reactSticker(group: String, message: String, pack: String, index: Int, remove: Boolean = false): Boolean =
        done(call { it.reactSticker(group, message, pack, index.toUInt(), remove) } != null)

    // --- GIFs (only when [gifAvailable]) ---

    suspend fun searchGifs(query: String): List<GifResult> {
        val r = call { it.gifSearch(query, 20u) } ?: emptyList()
        _state.update { it.copy(gifs = r) }
        return r
    }

    suspend fun gifPreview(gif: GifResult): ByteArray? = call { it.gifMedia(gif.preview ?: gif.media) }

    /** The sender's device fetches the GIF through the relay and sends it as an encrypted file. */
    suspend fun sendGif(group: String, gif: GifResult): Boolean = done(call { it.sendGif(group, gif) } != null)

    // --- location ---

    suspend fun sendLocation(group: String, lat: Double, lon: Double, accuracy: Int? = null, label: String? = null): Boolean =
        done(call { it.sendLocation(group, lat, lon, accuracy?.toUInt(), label?.ifBlank { null }) } != null)

    /** Live location for `seconds` (one of [liveChoices]); returns its id for [updateLive]. */
    suspend fun startLive(group: String, lat: Double, lon: Double, seconds: Long): String? =
        call { it.startLiveLocation(group, lat, lon, null, seconds.toUInt()) }?.also { id ->
            _state.update { it.copy(sharing = it.sharing + id) }
            model.refresh()
        }

    /** New coordinates from the platform; sent at most every 30 s (later ones wait for the sync). */
    suspend fun updateLive(group: String, id: String, lat: Double, lon: Double): Boolean =
        call { it.updateLiveLocation(group, id, lat, lon, null) } ?: false

    suspend fun stopLive(group: String, id: String): Boolean {
        val ok = call { it.stopLiveLocation(group, id) } != null
        _state.update { it.copy(sharing = it.sharing - id) }
        return done(ok)
    }

    /** The map tile (zoom 15) around a place, through the server's map relay; null without one. */
    suspend fun mapTile(lat: Double, lon: Double, zoom: Int = 15): ByteArray? {
        if (!_state.value.relays.map) return null
        val n = 1 shl zoom
        val x = ((lon + 180.0) / 360.0 * n).toInt().coerceIn(0, n - 1)
        val r = Math.toRadians(lat)
        val y = ((1.0 - Math.log(Math.tan(r) + 1.0 / Math.cos(r)) / Math.PI) / 2.0 * n).toInt().coerceIn(0, n - 1)
        return call { it.mapTile(zoom.toUInt(), x.toUInt(), y.toUInt()) }
    }

    fun liveChoices(): List<Long> = uniffi.tree_ffi.liveLocationChoices().map { it.toLong() }

    /** "12:34" left of a live location, or null when it is not live. */
    fun countdown(p: Place, nowSecs: Long = System.currentTimeMillis() / 1000): String? {
        val until = p.liveUntil ?: return null
        if (!p.live || until <= nowSecs) return null
        val left = until - nowSecs
        return if (left >= 3600) "%d:%02d:%02d".format(left / 3600, (left % 3600) / 60, left % 60) else "%d:%02d".format(left / 60, left % 60)
    }

    // --- events ---

    suspend fun createEvent(group: String, title: String, startsAt: Long, place: String? = null, description: String? = null): String? =
        call { it.createEvent(group, title, startsAt, null, place?.ifBlank { null }, description?.ifBlank { null }) }.also { model.refresh() }

    /** `going`, `maybe` or `not`. */
    suspend fun rsvp(group: String, id: String, answer: String): Boolean = done(call { it.rsvp(group, id, answer) } != null)

    suspend fun cancelEvent(group: String, id: String): Boolean = done(call { it.cancelEvent(group, id) } != null)

    // --- video notes ---

    /** A short square video (at most a minute) sent as a round video note. */
    suspend fun sendVideoNote(group: String, bytes: ByteArray, mime: String, durationMs: Long): Boolean =
        done(call { it.sendVideoNote(group, bytes, mime, durationMs.toULong()) } != null)

    // --- profile photo and per-chat profile ---

    suspend fun setPhoto(bytes: ByteArray, mime: String): Boolean = done(call { it.setProfilePhoto(bytes, mime) } != null)

    suspend fun removePhoto(): Boolean = done(call { it.removeProfilePhoto() } != null)

    /** A name shown in this chat only (needs user.per_chat_profile; the chat may forbid it). */
    suspend fun setChatName(group: String, name: String): Boolean =
        done(call { it.setChatProfile(group, name.ifBlank { null }, null) } != null)

    suspend fun clearChatProfile(group: String): Boolean = done(call { it.clearChatProfile(group) } != null)
}
