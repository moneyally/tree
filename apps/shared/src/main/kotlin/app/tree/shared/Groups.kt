package app.tree.shared

import kotlinx.coroutines.flow.update
import uniffi.tree_ffi.AdminLogItem
import uniffi.tree_ffi.CommunityChatInfo
import uniffi.tree_ffi.JoinRequestInfo
import uniffi.tree_ffi.Message
import uniffi.tree_ffi.RestrictedMember
import uniffi.tree_ffi.RoleInfo
import uniffi.tree_ffi.TopicInfo

// Wave 3: groups and communities. State in UiState.groups ([GroupsUi]); the
// behaviour (and every check) is in tree_client.

/** One community this device is in, with its chats. */
data class CommunityUi(val id: String, val name: String, val chats: List<CommunityChatInfo>, val admin: Boolean)

/**
 * The open chat's group features: topics (and the one shown), roles, the
 * admin log, join requests, restrictions, slow mode, the welcome text and
 * history sharing; plus the communities for the sidebar.
 */
data class GroupsUi(
    /** chat.topics: the topics with their unread counts (empty while released). */
    val topics: List<TopicInfo> = emptyList(),
    /** The topic shown (null: the main chat) and its messages. */
    val topic: String? = null,
    val topicMessages: List<Message> = emptyList(),
    val mayCreateTopics: Boolean = false,
    val mayManageTopics: Boolean = false,
    /** chat.roles: the roles of the group, and what this device may do. */
    val roles: List<RoleInfo> = emptyList(),
    val mayDelete: Boolean = false,
    val mayAdd: Boolean = true,
    val admin: Boolean = false,
    /** chat.admin_log (admins only). */
    val adminLog: List<AdminLogItem> = emptyList(),
    /** chat.join_approval: invite-link joins waiting on this device. */
    val joinRequests: List<JoinRequestInfo> = emptyList(),
    /** chat.restrict: restricted members, and until when this device is. */
    val restricted: List<RestrictedMember> = emptyList(),
    val restrictedUntil: Long? = null,
    /** chat.slow_mode: the interval and how long this device still waits. */
    val slowMode: Long? = null,
    val slowWait: Long? = null,
    /** chat.welcome. */
    val welcome: String? = null,
    /** chat.history_share: messages new members get; show the notice while set. */
    val historyShare: Int? = null,
    /** Who becomes admin if this device (the only admin) leaves. */
    val successor: String? = null,
    val communities: List<CommunityUi> = emptyList(),
)

/** Reloads [GroupsUi] ([AppModel.refresh] calls this). */
suspend fun AppModel.loadGroups() {
    val open = state.value.open
    val keepTopic = state.value.groups.topic
    val g = call { s ->
        val communities = s.communities().map { id ->
            val info = s.group(id)
            CommunityUi(id, info.name ?: id.take(8), s.communityChats(id), info.admins.contains(s.memberId()))
        }
        if (open == null || s.isCommunity(open)) return@call GroupsUi(communities = communities)
        val admin = s.group(open).admins.contains(s.memberId())
        val topics = s.topics(open)
        val topic = keepTopic?.takeIf { t -> topics.any { it.id == t } }
        GroupsUi(
            topics = topics,
            topic = topic,
            topicMessages = if (topic != null) s.topicHistory(open, topic, 200u) else emptyList(),
            mayCreateTopics = s.mayCreateTopics(open),
            mayManageTopics = s.mayManageTopics(open),
            roles = s.roles(open),
            mayDelete = s.may(open, "delete"),
            mayAdd = s.mayAdd(open),
            admin = admin,
            adminLog = if (admin) s.adminLog(open) else emptyList(),
            joinRequests = if (admin) s.joinRequests(open) else emptyList(),
            restricted = s.restrictedMembers(open),
            restrictedUntil = s.restrictedUntil(open),
            slowMode = s.slowMode(open),
            slowWait = s.slowModeWait(open),
            welcome = s.welcomeText(open),
            historyShare = s.historyShare(open)?.toInt(),
            successor = s.successor(open),
            communities = communities,
        )
    } ?: return
    _state.update { it.copy(groups = g) }
}

/** Shows a topic (null: the main chat); its unread count goes to zero. */
suspend fun AppModel.openTopic(topic: String?) {
    val open = state.value.open ?: return
    if (topic != null) call { it.markTopicRead(open, topic) }
    _state.update { it.copy(groups = it.groups.copy(topic = topic)) }
    loadGroups()
}

suspend fun AppModel.createTopic(group: String, name: String): String? =
    call { it.createTopic(group, name.trim()) }.also { refresh() }

suspend fun AppModel.renameTopic(group: String, id: String, name: String): Boolean =
    (call { it.renameTopic(group, id, name.trim()) } != null).also { refresh() }

suspend fun AppModel.closeTopic(group: String, id: String, closed: Boolean): Boolean =
    (call { it.closeTopic(group, id, closed) } != null).also { refresh() }

/** Sends in the topic shown (or the main chat). */
suspend fun AppModel.sendInTopic(group: String, text: String): Boolean {
    if (text.isBlank()) return false
    val topic = state.value.groups.topic ?: return send(group, text)
    return (call { it.sendTextInTopic(group, topic, text) } != null).also { refresh() }
}

/** What a role may allow, for the roles editor. */
fun AppModel.rolePermissions(): List<String> = uniffi.tree_ffi.rolePermissions()

suspend fun AppModel.createRole(group: String, name: String, color: String, perms: List<String>): String? =
    call { it.createRole(group, name.trim(), color.trim(), perms) }.also { refresh() }

suspend fun AppModel.updateRole(group: String, id: String, name: String, color: String, perms: List<String>): Boolean =
    (call { it.updateRole(group, id, name.trim(), color.trim(), perms) } != null).also { refresh() }

suspend fun AppModel.deleteRole(group: String, id: String): Boolean =
    (call { it.deleteRole(group, id) } != null).also { refresh() }

suspend fun AppModel.assignRole(group: String, member: String, role: String, on: Boolean): Boolean =
    (call { it.assignRole(group, member, role, on) } != null).also { refresh() }

/** Restricts a member for `seconds` (null lifts it). */
suspend fun AppModel.restrict(group: String, member: String, seconds: Long?): Boolean {
    val until = seconds?.let { System.currentTimeMillis() / 1000 + it }
    return (call { it.restrictMember(group, member, until) } != null).also { refresh() }
}

/** Restriction lengths the apps offer: label and seconds. */
fun AppModel.restrictChoices(): List<Pair<String, Long>> =
    listOf("1h" to 3600L, "1d" to 86400L, "1w" to 7 * 86400L)

suspend fun AppModel.deleteAsModerator(group: String, id: String): Boolean =
    (call { it.deleteAsModerator(group, id) } != null).also { refresh() }

/** The welcome text for new members (null or blank: none). */
suspend fun AppModel.setWelcome(group: String, text: String?): Boolean =
    if (text.isNullOrBlank()) setChatFeature(group, "chat.welcome", false)
    else setChatFeature(group, "chat.welcome", true, text.trim())

suspend fun AppModel.approveJoin(group: String, account: String): Boolean =
    (call { it.approveJoin(group, account) }?.accepted == true).also { refresh() }

suspend fun AppModel.declineJoin(group: String, account: String): Boolean =
    (call { it.declineJoin(group, account) } != null).also { refresh() }

suspend fun AppModel.createCommunity(name: String): String? =
    call { it.createCommunity(name.trim()) }.also { refresh() }

suspend fun AppModel.addCommunityChat(community: String, group: String): Boolean =
    (call { it.addCommunityChat(community, group) } != null).also { refresh() }

suspend fun AppModel.removeCommunityChat(community: String, group: String): Boolean =
    (call { it.removeCommunityChat(community, group) } != null).also { refresh() }

/** Asks the community's admins to add this device to one of its chats. */
suspend fun AppModel.joinCommunityChat(community: String, group: String): Boolean =
    (call { it.joinCommunityChat(community, group) } != null).also {
        if (it) _state.update { s -> s.copy(notice = Strings.t("community_join_asked")) }
        refresh()
    }

/** Texts for a log entry: "<actor> <action> <target>". */
fun AppModel.describeLog(e: AdminLogItem, names: Map<String, String>): String {
    val who = names[e.actor]?.ifEmpty { Strings.t("me") } ?: e.actor.take(6)
    val target = e.target?.let { names[it]?.ifEmpty { Strings.t("me") } ?: it.take(12) }
    return listOfNotNull(who, Strings.t("log_" + e.action), target, e.detail).joinToString(" ")
}
