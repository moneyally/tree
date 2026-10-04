package app.tree.shared

import kotlinx.coroutines.flow.update
import uniffi.tree_ffi.PinnedMessage
import uniffi.tree_ffi.PollInfo
import uniffi.tree_ffi.ReminderInfo
import uniffi.tree_ffi.ScheduledMessage
import uniffi.tree_ffi.StorageCleanReport

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
