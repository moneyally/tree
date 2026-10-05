package app.tree.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountCircle
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.rounded.AccountCircle
import androidx.compose.material.icons.rounded.ChatBubble
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.outlined.PersonOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.UiState
import app.tree.shared.qr.CodeKind
import kotlinx.coroutines.delay

/** Where the person is: one of the main tabs, or an inner screen on top. */
sealed class Route {
    data object Home : Route()
    data class Chat(val id: String) : Route()
    data class ChatInfo(val id: String) : Route()
    data class Settings(val page: String) : Route()
    data class Scan(val kind: CodeKind) : Route()
    data object NewGroup : Route()
    data class ChatSearch(val id: String) : Route()
    data class Safety(val chat: String, val account: String) : Route()
    data class GroupAdmin(val chat: String, val page: String) : Route()
    data class Comments(val chat: String, val post: String) : Route()
    data object Public : Route()
    data class PublicSpace(val id: String) : Route()
    data object Bots : Route()
}

enum class Tab(val ko: String, val en: String, val on: ImageVector, val off: ImageVector) {
    CHATS("대화", "Chats", Icons.Rounded.ChatBubble, Icons.Outlined.ChatBubbleOutline),
    CONTACTS("연락처", "Contacts", Icons.Rounded.Person, Icons.Outlined.PersonOutline),
    SETTINGS("설정", "Settings", Icons.Rounded.Settings, Icons.Outlined.Settings),
    PROFILE("프로필", "Profile", Icons.Rounded.AccountCircle, Icons.Outlined.AccountCircle),
}

/** The screen stack; the app's back button pops it. */
class TreeNav {
    val stack = mutableStateListOf<Route>(Route.Home)
    var tab by mutableStateOf(Tab.CHATS)
    /** A message to scroll to when its chat shows next (from search). */
    var focusMessage by mutableStateOf<String?>(null)
    val top: Route get() = stack.last()
    val canPop: Boolean get() = stack.size > 1
    fun push(r: Route) { stack.add(r) }
    fun pop() { if (canPop) stack.removeAt(stack.lastIndex) }
    fun home() { while (canPop) pop() }
}

/** The whole app: onboarding until signed in, then the tabs and inner screens. */
@Composable
fun TreeUi(model: AppModel, platform: TreePlatform, nav: TreeNav, dark: Boolean? = null) {
    val state by model.state.collectAsState()
    TreeTheme(dark = dark ?: androidx.compose.foundation.isSystemInDarkTheme(), font = platform.font) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Box(Modifier.fillMaxSize()) {
                if (!state.signedIn) Onboarding(model, platform) else Signed(model, platform, nav, state)
                Toast(model, state)
            }
        }
    }
}

@Composable
private fun Signed(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState) {
    // Receiving runs whenever a profile is open. Started here, not by the
    // sign-in screen: that screen's own coroutines end as it closes.
    LaunchedEffect(Unit) { model.ensureSyncLoop() }
    // "Seen" for the others (user.last_seen), now and while the app stays open.
    LaunchedEffect(Unit) { while (true) { model.announceSeen(); kotlinx.coroutines.delay(150_000) } }
    // A device link in progress takes the whole screen until it ends.
    state.link?.let { LinkScreen(model, it, newDevice = false); return }
    val top = nav.top
    // The chat screen keeps the model's open chat in step with the stack.
    LaunchedEffect(top) {
        val want = (top as? Route.Chat)?.id ?: (top as? Route.ChatInfo)?.id ?: (top as? Route.ChatSearch)?.id ?: (top as? Route.GroupAdmin)?.chat ?: (top as? Route.Comments)?.chat
        if (state.open != want) model.openChat(want)
        if (top is Route.Home && nav.tab == Tab.CONTACTS) model.loadContacts()
    }
    if (!platform.isPhone && (top is Route.Home || top is Route.Chat)) {
        // Computer: the list on the left, the chat on the right.
        Row(Modifier.fillMaxSize()) {
            Box(Modifier.width(400.dp).fillMaxHeight()) { HomeTabs(model, platform, nav, state) }
            VerticalDivider(color = extra.divider)
            Box(Modifier.weight(1f).fillMaxHeight()) {
                val chat = (top as? Route.Chat)?.let { r -> state.chats.firstOrNull { it.id == r.id } }
                if (chat != null) ChatScreen(model, platform, nav, state, chat)
                else EmptyState(Icons.Outlined.ChatBubbleOutline, t("대화를 골라 주세요", "Pick a chat"), t("왼쪽에서 대화를 고르면 여기에 열립니다.", "Choose a chat on the left to open it here."), Modifier.fillMaxSize().padding(top = 120.dp))
            }
        }
        return
    }
    when (top) {
        is Route.Home -> HomeTabs(model, platform, nav, state)
        is Route.Chat -> state.chats.firstOrNull { it.id == top.id }?.let { ChatScreen(model, platform, nav, state, it) }
            ?: LaunchedEffect(top) { nav.pop() }
        is Route.ChatInfo -> state.chats.firstOrNull { it.id == top.id }?.let { ChatInfoScreen(model, platform, nav, state, it) }
            ?: LaunchedEffect(top) { nav.pop() }
        is Route.Settings -> SettingsPage(model, platform, nav, state, top.page)
        is Route.Scan -> platform.Scanner(top.kind) { nav.pop() }
        is Route.Comments -> state.chats.firstOrNull { it.id == top.chat }?.let { CommentsScreen(model, nav, state, it, top.post) }
            ?: LaunchedEffect(top) { nav.pop() }
        is Route.Public -> PublicScreen(model, nav, state)
        is Route.PublicSpace -> PublicSpaceScreen(model, nav, state, top.id)
        is Route.Bots -> BotsScreen(model, nav, state, platform)
        is Route.NewGroup -> NewGroupScreen(model, nav, state)
        is Route.GroupAdmin -> state.chats.firstOrNull { it.id == top.chat }?.let { GroupAdminScreen(model, nav, state, it, top.page) }
            ?: LaunchedEffect(top) { nav.pop() }
        is Route.Safety -> SafetyScreen(model, platform, nav, state, top.account, state.chats.firstOrNull { it.id == top.chat }?.title ?: "")
        is Route.ChatSearch -> state.chats.firstOrNull { it.id == top.id }?.let { ChatSearchScreen(model, nav, state, it) }
            ?: LaunchedEffect(top) { nav.pop() }
    }
}

@Composable
private fun HomeTabs(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState) {
    Box(Modifier.fillMaxSize().statusBarsPadding()) {
        when (nav.tab) {
            Tab.CHATS -> ChatListScreen(model, platform, nav, state)
            Tab.CONTACTS -> ContactsScreen(model, platform, nav, state)
            Tab.SETTINGS -> SettingsHome(model, platform, nav, state)
            Tab.PROFILE -> ProfileScreen(model, platform, nav, state)
        }
        FloatingTabBar(nav, state, Modifier.align(Alignment.BottomCenter))
    }
}

/** The floating rounded tab bar at the bottom. */
@Composable
private fun FloatingTabBar(nav: TreeNav, state: UiState, modifier: Modifier) {
    val unread = state.chats.count { (it.unread > 0 || it.markedUnread) && !it.muted && !it.archived }
    Row(
        modifier.navigationBarsPadding().padding(horizontal = 22.dp, vertical = 12.dp).fillMaxWidth().height(66.dp)
            .shadow(14.dp, RoundedCornerShape(33.dp)).clip(RoundedCornerShape(33.dp)).background(extra.navBar)
            .padding(horizontal = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceEvenly,
    ) {
        Tab.entries.forEach { tab ->
            val selected = nav.tab == tab
            Column(
                Modifier.weight(1f).height(54.dp).clip(RoundedCornerShape(27.dp))
                    .background(if (selected) MaterialTheme.colorScheme.primary.copy(alpha = 0.16f) else androidx.compose.ui.graphics.Color.Transparent)
                    .clickable { nav.tab = tab; nav.home() },
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Box {
                    Icon(
                        if (selected) tab.on else tab.off, contentDescription = t(tab.ko, tab.en),
                        tint = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier.size(25.dp),
                    )
                    if (tab == Tab.CHATS && unread > 0) {
                        Box(Modifier.align(Alignment.TopEnd).padding(start = 18.dp).size(17.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary), contentAlignment = Alignment.Center) {
                            Text(if (unread > 99) "99" else unread.toString(), color = MaterialTheme.colorScheme.onPrimary, style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
                Spacer(Modifier.height(2.dp))
                Text(
                    t(tab.ko, tab.en), style = MaterialTheme.typography.labelMedium,
                    color = if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                )
            }
        }
    }
}

/** Errors and notices slide in at the top for a few seconds instead of a dialog. */
@Composable
private fun Toast(model: AppModel, state: UiState) {
    val msg = state.error ?: state.notice
    LaunchedEffect(msg) { if (msg != null) { delay(3500); model.clearMessages() } }
    AnimatedVisibility(
        visible = msg != null,
        enter = slideInVertically { -it } + fadeIn(),
        exit = slideOutVertically { -it } + fadeOut(),
        modifier = Modifier.fillMaxWidth().statusBarsPadding().padding(12.dp),
    ) {
        Box(
            Modifier.fillMaxWidth().clip(RoundedCornerShape(18.dp))
                .background(if (state.error != null) extra.danger.copy(alpha = 0.92f) else MaterialTheme.colorScheme.surfaceContainerHigh)
                .clickable { model.clearMessages() }.padding(horizontal = 18.dp, vertical = 14.dp),
        ) {
            Text(
                friendlyError(msg ?: ""),
                color = if (state.error != null) androidx.compose.ui.graphics.Color.White else MaterialTheme.colorScheme.onSurface,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

/** Error codes from the core in words people understand. */
fun friendlyError(code: String): String = when {
    code.startsWith("LOCKED_BY_CHAT") -> t("이 대화방 설정 때문에 할 수 없어요.", "This chat's settings don't allow that.")
    code.startsWith("LOCKED_BY_SERVER") -> t("지금은 서버에서 막아 둔 기능이에요.", "The server has this switched off right now.")
    code.startsWith("LOCKED_ALWAYS") || code.startsWith("RELEASED_ALWAYS") -> t("보안상 바꿀 수 없는 설정이에요.", "This setting can't be changed, for safety.")
    code.startsWith("RATE_LIMITED") -> t("너무 빨라요. 잠시 후 다시 해 주세요.", "Too fast. Try again in a moment.")
    code.contains("error sending request") || code.contains("connect") -> t("서버에 연결할 수 없어요. 인터넷 연결을 확인해 주세요.", "Can't reach the server. Check your connection.")
    else -> code
}
