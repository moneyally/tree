package app.tree.shared

import kotlinx.coroutines.flow.update
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.PublicPostInfo
import uniffi.tree_ffi.PublicSpaceInfo

// Wave 4: public groups and channels (NOT end-to-end encrypted: every
// object says isPublic and the screens show the "Public" badge), and
// private channels (end-to-end). State in UiState.pub ([PublicUi]) and
// UiState.channel ([ChannelUi]); the behaviour and every check are in
// tree_client (public.rs, channel.rs) and on the server.

/** Public spaces: the subscribed ones, the directory, and the one open. */
data class PublicUi(
    /** Subscribed spaces as kept on this device, with unread counts. */
    val spaces: List<PublicSpaceInfo> = emptyList(),
    /** Directory results (chat.public_listing) or a space found by @handle. */
    val found: List<PublicSpaceInfo> = emptyList(),
    val open: PublicSpaceInfo? = null,
    /** The open space's posts (oldest first) and comments per post. */
    val posts: List<PublicPostInfo> = emptyList(),
    val comments: Map<String, List<PublicPostInfo>> = emptyMap(),
)

/** The open chat as a private channel (end-to-end). */
data class ChannelUi(
    val isChannel: Boolean = false,
    val mayPost: Boolean = true,
    val mayComment: Boolean = false,
    val signatures: Boolean = true,
    /** Post id -> its comments. */
    val comments: Map<String, List<Message>> = emptyMap(),
)

/** The "Public" badge text; shown wherever public content appears. */
fun publicBadge(): String = Strings.t("public_badge")

/** What the list and headers show for a space: badge, kind and name. */
fun publicTitle(s: PublicSpaceInfo): String =
    "[${publicBadge()}] " + (if (s.kind == "channel") Strings.t("public_channel") else Strings.t("public_group")) + " · " + s.name

/** The author line of a public post: the channel's name while signatures are off. */
fun publicAuthor(p: PublicPostInfo, space: PublicSpaceInfo?): String =
    when {
        p.mine -> Strings.t("me")
        p.authorName != null -> p.authorName!!
        p.author != null -> p.author!!.take(8)
        else -> space?.name ?: Strings.t("public_channel")
    }

/** Reloads [PublicUi] from this device (no network); [AppModel.refresh] calls it. */
suspend fun AppModel.loadPublic() {
    val openId = state.value.pub.open?.id
    val spaces = call { it.publicCached() } ?: return
    val open = openId?.let { id -> spaces.firstOrNull { it.id == id } ?: state.value.pub.open }
    val posts = if (open != null) call { it.publicPosts(open.id, 200u) } ?: emptyList() else emptyList()
    val comments = if (open != null && open.kind == "channel") {
        posts.filter { it.comments > 0u }.associate { p -> p.id to (call { it.publicComments(open.id, p.id) } ?: emptyList()) }
    } else emptyMap()
    _state.update { it.copy(pub = it.pub.copy(spaces = spaces, open = open, posts = posts, comments = comments)) }
}

/** Fetches what changed in the subscribed spaces (at most every 20 s unless forced). */
suspend fun AppModel.syncPublic(force: Boolean = false) {
    val now = System.currentTimeMillis()
    if (!force && now - lastPublicSync < 20_000) return
    lastPublicSync = now
    call { it.publicSyncAll() }
    loadPublic()
}

/** Searches the directory; a query starting with @ also looks the exact handle up. */
suspend fun AppModel.searchPublic(query: String) {
    val q = query.trim()
    val listed = call { it.publicDirectory(q.removePrefix("@")) } ?: emptyList()
    val exact = if (q.length >= 5) call { it.publicFind(q) } else null
    val found = (listOfNotNull(exact) + listed).distinctBy { it.id }
    _state.update { it.copy(pub = it.pub.copy(found = found)) }
}

/** Creates a public group or channel ("group" / "channel"); opens it. */
suspend fun AppModel.createPublic(kind: String, name: String, handle: String, description: String): String? {
    val s = call { it.publicCreate(kind, name.trim(), handle.trim(), description.trim()) } ?: return null
    openPublic(s.id)
    return s.id
}

/** Opens a public space (subscribed or not: public content can be read). */
suspend fun AppModel.openPublic(id: String?) {
    if (id == null) {
        _state.update { it.copy(pub = it.pub.copy(open = null, posts = emptyList(), comments = emptyMap())) }
        return
    }
    val s = call { it.publicSpace(id) } ?: return
    _state.update { it.copy(open = null, pub = it.pub.copy(open = s)) }
    if (s.role != null) {
        call { it.publicSync(id) }
        call { it.publicMarkRead(id) }
        loadPublic()
    } else {
        // Not subscribed: nothing is kept on this device; shown from the
        // server's newest page.
        val posts = call { it.publicPeek(id) } ?: emptyList()
        _state.update { it.copy(pub = it.pub.copy(posts = posts)) }
    }
}

suspend fun AppModel.joinPublic(id: String): Boolean =
    (call { it.publicJoin(id) } != null).also { openPublic(id); loadPublic() }

suspend fun AppModel.leavePublic(id: String): Boolean =
    (call { it.publicLeave(id) } != null).also { openPublic(null); loadPublic() }

/** Posts in the open space (a channel: admins), or comments with [replyTo]. */
suspend fun AppModel.postPublic(text: String, replyTo: String? = null): Boolean {
    val s = state.value.pub.open ?: return false
    if (text.isBlank()) return false
    return (call { it.publicPost(s.id, text, replyTo) } != null).also { call { it.publicMarkRead(s.id) }; loadPublic() }
}

suspend fun AppModel.editPublic(post: String, text: String): Boolean {
    val s = state.value.pub.open ?: return false
    return (call { it.publicEdit(s.id, post, text) } != null).also { loadPublic() }
}

suspend fun AppModel.deletePublic(post: String): Boolean {
    val s = state.value.pub.open ?: return false
    return (call { it.publicDelete(s.id, post) } != null).also { loadPublic() }
}

suspend fun AppModel.reportPublic(post: String, reason: String): Boolean =
    (call { it.publicReport(post, reason) } != null).also {
        if (it) _state.update { s -> s.copy(notice = Strings.t("public_reported")) }
    }

/** An admin applies or releases a space setting (chat.public_listing, channel.comments, ...). */
suspend fun AppModel.setPublicFeature(key: String, on: Boolean, option: String? = null): Boolean {
    val s = state.value.pub.open ?: return false
    val n = call { it.publicSetFeature(s.id, key, on, option) } ?: return false
    _state.update { it.copy(pub = it.pub.copy(open = n)) }
    call { it.publicSync(s.id) }
    loadPublic()
    return true
}

suspend fun AppModel.setPublicNotify(on: Boolean): Boolean {
    val s = state.value.pub.open ?: return false
    val n = call { it.publicSetNotify(s.id, on) } ?: return false
    _state.update { it.copy(pub = it.pub.copy(open = n)) }
    loadPublic()
    return true
}

suspend fun AppModel.publicBan(account: String, ban: Boolean): Boolean {
    val s = state.value.pub.open ?: return false
    val n = call { it.publicBan(s.id, account.trim(), ban) } ?: return false
    _state.update { it.copy(pub = it.pub.copy(open = n)) }
    return true
}

suspend fun AppModel.publicSetAdmin(account: String, admin: Boolean): Boolean {
    val s = state.value.pub.open ?: return false
    val n = call { it.publicSetAdmin(s.id, account.trim(), admin) } ?: return false
    _state.update { it.copy(pub = it.pub.copy(open = n)) }
    return true
}

suspend fun AppModel.loadPublicComments(post: String) {
    val s = state.value.pub.open ?: return
    val c = call { it.publicLoadComments(s.id, post) } ?: return
    _state.update { it.copy(pub = it.pub.copy(comments = it.pub.comments + (post to c))) }
}

// --- private channels (end-to-end) ---

/** A new private channel (only admins post, up to 1,000 members); opens it. */
suspend fun AppModel.createChannel(name: String): String? =
    call { it.createChannel(name.trim()) }?.also { refresh(); openChat(it) }

/** Reloads [ChannelUi] for the open chat. */
suspend fun AppModel.loadChannel() {
    val open = state.value.open
    val c = if (open == null) ChannelUi() else call { s ->
        if (!s.isChannel(open)) return@call ChannelUi()
        val posts = state.value.messages.filter { it.replyTo == null && it.kind == "text" }
        ChannelUi(
            isChannel = true,
            mayPost = s.mayPost(open),
            mayComment = s.mayComment(open),
            signatures = s.showsSignatures(open),
            comments = posts.associate { p -> p.id to s.comments(open, p.id) }.filterValues { it.isNotEmpty() },
        )
    } ?: return
    _state.update { it.copy(channel = c) }
}

suspend fun AppModel.commentOn(group: String, post: String, text: String): Boolean {
    if (text.isBlank()) return false
    return (call { it.comment(group, post, text) } != null).also { refresh() }
}

/** The name shown for a message in a channel: null shows the channel's name. */
suspend fun AppModel.channelAuthor(group: String, id: String): String? = call { it.authorShown(group, id) }
