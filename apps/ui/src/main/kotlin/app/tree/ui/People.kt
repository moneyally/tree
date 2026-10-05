package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.automirrored.rounded.Logout
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.ChatBubble
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.AlternateEmail
import androidx.compose.material.icons.rounded.Archive
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.ExitToApp
import androidx.compose.material.icons.rounded.GroupAdd
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.NotificationsOff
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.PersonAdd
import androidx.compose.material.icons.rounded.PhotoCamera
import androidx.compose.material.icons.rounded.PushPin
import androidx.compose.material.icons.rounded.QrCode2
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.VerifiedUser
import androidx.compose.material.icons.outlined.PersonOutline
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.tree.shared.AppModel
import app.tree.shared.Chat
import app.tree.shared.UiState
import app.tree.shared.qr.CodeKind
import kotlinx.coroutines.launch

/** Profile tab: big picture and name, quick actions, username and my QR. */
@Composable
fun ProfileScreen(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState) {
    val scope = rememberCoroutineScope()
    val username by produceState<String?>(null, state.usernameLink) { value = runCatching { model.session?.username() }.getOrNull() }
    var editName by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.loadUsernameLink() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 120.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 6.dp)) {
            androidx.compose.material3.IconButton(onClick = { nav.push(Route.Scan(CodeKind.USERNAME)) }) { Icon(Icons.Rounded.QrCodeScanner, t("QR 찍기", "Scan QR")) }
        }
        Avatar(state.name, state.account, 112.dp, image = rememberPhoto(platform, "me", model.rich.state.collectAsState().value.myPhoto?.bytes, 384))
        Spacer(Modifier.height(14.dp))
        Text(state.name, style = MaterialTheme.typography.headlineMedium)
        Text(username?.let { "@$it" } ?: t("아이디 없음", "No username yet"), color = extra.muted, style = MaterialTheme.typography.bodyLarge)
        Spacer(Modifier.height(22.dp))
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            ActionCard(Icons.Rounded.PhotoCamera, t("사진 설정", "Set photo"), Modifier.weight(1f)) { platform.pickImage { b, m -> scope.launch { if (model.rich.setPhoto(b, m)) model.notice(t("사진을 바꿨어요", "Photo updated")) } } }
            ActionCard(Icons.Rounded.Edit, t("정보 수정", "Edit info"), Modifier.weight(1f)) { nav.push(Route.Settings("account")) }
            ActionCard(Icons.Rounded.Settings, t("설정", "Settings"), Modifier.weight(1f)) { nav.tab = Tab.SETTINGS }
        }
        Spacer(Modifier.height(6.dp))
        CardGroup {
            InfoLine(username?.let { "@$it" } ?: t("아이디를 정해 보세요", "Pick a username"), t("아이디", "Username"), Icons.Rounded.AlternateEmail) { nav.push(Route.Settings("account")) }
            RowDivider(20.dp)
            InfoLine(state.account.take(12) + "…", t("계정 ID · 누르면 복사", "Account ID · tap to copy"), Icons.Rounded.ContentCopy) { platform.copy(state.account); model.notice(t("복사했어요", "Copied")) }
        }
        CardGroup(title = t("내 QR 코드", "My QR code")) {
            val qr = state.usernameQr
            Column(Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(12.dp)) {
                if (qr != null && state.usernameLink != null) {
                    Box(Modifier.clip(RoundedCornerShape(20.dp)).background(Color.White).padding(14.dp)) { QrView(qr, 200.dp) }
                    Text(t("친구가 이 QR을 찍으면 나를 추가할 수 있어요.", "Friends can scan this to add you."), color = extra.muted, style = MaterialTheme.typography.bodySmall, textAlign = TextAlign.Center)
                    Row {
                        QuietButton(t("링크 복사", "Copy link"), { platform.copy(state.usernameLink!!); model.notice(t("복사했어요", "Copied")) })
                        QuietButton(t("새로 만들기", "Reset"), { scope.launch { model.resetUsernameLink() } }, color = extra.muted)
                    }
                } else {
                    Text(
                        if (username == null) t("아이디를 먼저 정하면 내 QR을 만들 수 있어요.", "Set a username first to get your QR code.")
                        else t("QR을 만들면 친구가 찍어서 나를 추가할 수 있어요.", "Make a QR code so friends can add you."),
                        color = extra.muted, textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyMedium,
                    )
                    if (username != null) PillButton(t("내 QR 만들기", "Make my QR"), { scope.launch { model.resetUsernameLink() } }, icon = Icons.Rounded.QrCode2)
                }
            }
        }
    }
}

@Composable
private fun ActionCard(icon: ImageVector, label: String, modifier: Modifier, onClick: () -> Unit) {
    Column(
        modifier.clip(RoundedCornerShape(20.dp)).background(extra.card).clickable(onClick = onClick).padding(vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Icon(icon, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(26.dp))
        Text(label, style = MaterialTheme.typography.labelLarge)
    }
}

@Composable
private fun InfoLine(value: String, label: String, icon: ImageVector, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 20.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(value, style = MaterialTheme.typography.bodyLarge)
            Text(label, style = MaterialTheme.typography.bodySmall, color = extra.muted)
        }
        Icon(icon, null, tint = extra.muted, modifier = Modifier.size(20.dp))
    }
}

/** Contacts tab: search, add by QR or username, everyone known. */
@Composable
fun ContactsScreen(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState) {
    val scope = rememberCoroutineScope()
    var query by remember { mutableStateOf("") }
    var byName by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.loadContacts() }
    val list = state.contacts.filter { query.isBlank() || it.name.contains(query, ignoreCase = true) || it.account.startsWith(query) }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 120.dp)) {
        item { BigHeader(t("연락처", "Contacts")) }
        item { SearchField(query, { query = it }, t("연락처 검색", "Search contacts")) }
        item {
            CardGroup {
                SettingsRow(t("QR로 친구 추가", "Add friend by QR"), null, Icons.Rounded.QrCodeScanner, TreeColors.TileBlue, onClick = { nav.push(Route.Scan(CodeKind.USERNAME)) }, trailing = null)
                RowDivider()
                SettingsRow(t("아이디로 찾기", "Find by username"), null, Icons.Rounded.PersonAdd, TreeColors.TileGreen, onClick = { byName = true }, trailing = null)
            }
        }
        if (list.isEmpty()) {
            item { EmptyState(Icons.Outlined.PersonOutline, t("아직 연락처가 없어요", "No contacts yet"), t("QR이나 아이디로 친구를 추가해 보세요.", "Add friends by QR code or username.")) }
        } else {
            item { Text(t("내 연락처", "My contacts"), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall, modifier = Modifier.padding(start = 22.dp, top = 14.dp, bottom = 4.dp)) }
            items(list, key = { it.account }) { c ->
                Row(
                    Modifier.fillMaxWidth().clickable { scope.launch { model.chatWith(c.account)?.let { nav.push(Route.Chat(it)) } } }.padding(horizontal = 18.dp, vertical = 9.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Avatar(c.name, c.account, 50.dp)
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(c.name, style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            if (c.verified) { Spacer(Modifier.width(6.dp)); Icon(Icons.Rounded.VerifiedUser, t("안전 번호 확인됨", "Verified"), tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(16.dp)) }
                        }
                        Text(if (c.blocked) t("차단함", "Blocked") else if (c.verified) t("안전 번호 확인됨", "Safety number verified") else t("확인 안 됨", "Not verified"),
                            style = MaterialTheme.typography.bodySmall, color = if (c.blocked) extra.danger else extra.muted)
                    }
                }
            }
        }
    }
    if (byName) FindByName(model, nav) { byName = false }
}

@Composable
private fun FindByName(model: AppModel, nav: TreeNav, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(t("아이디로 찾기", "Find by username")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(name, { name = it }, placeholder = { Text("@username") }, singleLine = true, shape = RoundedCornerShape(14.dp))
                Text(t("상대가 ‘아이디로 찾기 허용’을 켠 경우에만 찾을 수 있어요.", "Works only if they allow being found by username."), style = MaterialTheme.typography.bodySmall, color = extra.muted)
            }
        },
        confirmButton = {
            TextButton(onClick = {
                scope.launch {
                    val g = model.newChat() ?: return@launch
                    if (model.invite(g, "@" + name.trim().removePrefix("@"))) { onClose(); nav.push(Route.Chat(g)) }
                }
            }, enabled = name.isNotBlank()) { Text(t("대화 시작", "Start chat"), fontWeight = FontWeight.SemiBold) }
        },
        dismissButton = { TextButton(onClick = onClose) { Text(t("취소", "Cancel")) } },
    )
}

/** Chat info: who is in it, safety number, notifications, the chat's own settings, leaving. */
@Composable
fun ChatInfoScreen(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState, chat: Chat) {
    val scope = rememberCoroutineScope()
    var safety by remember { mutableStateOf<String?>(null) }
    var invite by remember { mutableStateOf(false) }
    var rename by remember { mutableStateOf(false) }
    var link by remember { mutableStateOf<String?>(null) }
    val me = model.session?.memberId()
    val others = state.members.filter { it.id != me }
    val admin = state.members.firstOrNull { it.id == me }?.admin == true
    val media by model.rich.state.collectAsState()
    var tab by remember(chat.id) { mutableStateOf(if (chat.others > 1 || chat.channel) InfoTab.MEMBERS else InfoTab.MEDIA) }
    var leaving by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().verticalScroll(rememberScrollState()).padding(bottom = 30.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            androidx.compose.material3.IconButton(onClick = { nav.pop() }) { Icon(Icons.AutoMirrored.Rounded.ArrowBack, t("뒤로", "Back")) }
            Spacer(Modifier.weight(1f))
            if (admin && chat.others > 1) androidx.compose.material3.IconButton(onClick = { rename = true }) { Icon(Icons.Rounded.Edit, t("이름 바꾸기", "Rename")) }
        }
        Avatar(chat.title, chat.peer ?: chat.id, 110.dp, image = rememberPhoto(platform, chat.id, media.chatPhotos[chat.id]?.bytes, 384))
        Spacer(Modifier.height(14.dp))
        Text(chat.title, style = MaterialTheme.typography.headlineMedium, textAlign = TextAlign.Center, modifier = Modifier.padding(horizontal = 24.dp))
        Text(
            when {
                chat.channel -> t("채널 · 구독자 ${chat.others + 1}명", "Channel · ${chat.others + 1} subscribers")
                chat.others > 1 -> t("멤버 ${chat.others + 1}명", "${chat.others + 1} members") +
                    state.seen.values.count { Format.online(it) }.let { n -> if (n > 0) t(", 온라인 ${n}명", ", $n online") else "" }
                else -> Format.seenLabel(state.seen.values.singleOrNull())
            },
            color = extra.muted, style = MaterialTheme.typography.bodyMedium,
        )
        Spacer(Modifier.height(20.dp))
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            InfoAction(Icons.Rounded.ChatBubble, t("메시지", "Message"), Modifier.weight(1f)) { nav.pop() }
            InfoAction(if (chat.muted) Icons.Rounded.Notifications else Icons.Rounded.NotificationsOff, if (chat.muted) t("알림 켜기", "Unmute") else t("알림 끄기", "Mute"), Modifier.weight(1f)) { scope.launch { if (chat.muted) model.unmute(chat.id) else model.mute(chat.id, null) } }
            InfoAction(Icons.AutoMirrored.Rounded.Logout, t("나가기", "Leave"), Modifier.weight(1f)) { leaving = true }
        }
        CardGroup {
            others.mapNotNull { it.account }.distinct().singleOrNull()?.takeIf { chat.others <= 1 }?.let { acc ->
                SettingsRow(t("안전 번호 확인", "Verify safety number"), t("직접 만나서 숫자를 맞춰 보세요", "Compare the numbers in person"), Icons.Rounded.Shield, TreeColors.TileGreen, onClick = { scope.launch { safety = model.safetyNumber(acc) } })
            }
            if (admin && chat.others > 1) {
                SettingsRow(t("초대 링크 만들기", "Make invite link"), t("24시간 동안 10명까지", "24 hours, up to 10 people"), Icons.Rounded.Link, TreeColors.TileIndigo, onClick = { scope.launch { link = model.inviteLink(chat.id) } }, trailing = null)
            }
            SettingsRow(if (chat.pinned) t("목록 위 고정 해제", "Unpin from top") else t("목록 위에 고정", "Pin to top"), null, Icons.Rounded.PushPin, TreeColors.TileAmber, onClick = { scope.launch { model.pin(chat.id, !chat.pinned) } }, trailing = null)
        }
        Spacer(Modifier.height(14.dp))
        val tabs = InfoTab.entries.filter { it != InfoTab.MEMBERS || chat.others > 1 || chat.channel }
        Row(
            Modifier.clip(RoundedCornerShape(24.dp)).background(extra.card).padding(4.dp),
            horizontalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            tabs.forEach { tb ->
                val on = tb == tab
                Text(
                    t(tb.ko, tb.en), style = MaterialTheme.typography.titleSmall,
                    color = if (on) MaterialTheme.colorScheme.primary else extra.muted,
                    modifier = Modifier.clip(RoundedCornerShape(20.dp))
                        .background(if (on) MaterialTheme.colorScheme.primary.copy(alpha = 0.16f) else androidx.compose.ui.graphics.Color.Transparent)
                        .clickable { tab = tb }.padding(horizontal = 16.dp, vertical = 8.dp),
                )
            }
        }
        CardGroup {
            when (tab) {
                InfoTab.MEMBERS -> {
                    if (state.groups.mayAdd) {
                        SettingsRow(t("멤버 초대", "Add members"), null, Icons.Rounded.GroupAdd, TreeColors.TileBlue, onClick = { invite = true }, trailing = null)
                        RowDivider(76.dp)
                    }
                    state.members.forEachIndexed { i, m ->
                        val name = if (m.id == me) state.name else (m.name ?: m.id.take(6))
                        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 9.dp), verticalAlignment = Alignment.CenterVertically) {
                            Avatar(name, m.account ?: m.id, 46.dp, image = rememberPhoto(platform, "m:" + m.id, media.photos[m.id]?.bytes, 128))
                            Spacer(Modifier.width(14.dp))
                            Column(Modifier.weight(1f)) {
                                Text(name + if (m.id == me) t(" (나)", " (you)") else "", style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                val seen = state.seen[m.id]
                                val live = m.id == me || Format.online(seen)
                                Text(
                                    when {
                                        m.bot != null -> t("봇", "Bot")
                                        m.restrictedUntil != null -> t("발언 제한 중", "Restricted")
                                        m.id == me -> t("온라인", "online")
                                        else -> Format.seenLabel(seen)
                                    },
                                    style = MaterialTheme.typography.bodySmall, color = if (live && m.bot == null) MaterialTheme.colorScheme.primary else extra.muted,
                                )
                            }
                            val role = m.roles.firstOrNull()
                            when {
                                role != null -> PillTag(role.name, runCatching { androidx.compose.ui.graphics.Color(("FF" + role.color.removePrefix("#")).toLong(16)) }.getOrDefault(MaterialTheme.colorScheme.primary))
                                m.admin -> PillTag(t("관리자", "Admin"), MaterialTheme.colorScheme.primary)
                            }
                        }
                        if (i < state.members.lastIndex) RowDivider(76.dp)
                    }
                }
                InfoTab.MEDIA -> MediaGrid(platform, state.messages.filter { (it.file ?: state.files[it.id])?.mime?.startsWith("image/") == true && !it.deleted }, state)
                InfoTab.FILES -> {
                    val files = state.messages.filter { it.kind == "file" && !it.deleted && (it.file ?: state.files[it.id])?.mime?.startsWith("image/") != true }
                    if (files.isEmpty()) InfoEmpty(t("주고받은 파일이 없어요", "No files yet"))
                    files.asReversed().forEach { m ->
                        val f = m.file ?: state.files[m.id]
                        SettingsRow(f?.name ?: t("파일", "File"), listOfNotNull(f?.let { Format.size(it.size.toLong()) }, Format.listTime(m.receivedAt)).joinToString(" · "), Icons.Rounded.Description, TreeColors.TileSky,
                            onClick = { f?.let { platform.saveAs(m.id, it.name) } }, trailing = null)
                    }
                }
                InfoTab.LINKS -> {
                    val re = Regex("https?://[^\\s]+")
                    val links = state.messages.filter { !it.deleted && it.kind == "text" }.flatMap { m -> re.findAll(m.text ?: "").map { it.value to m }.toList() }
                    if (links.isEmpty()) InfoEmpty(t("주고받은 링크가 없어요", "No links yet"))
                    links.asReversed().forEach { (url, m) ->
                        SettingsRow(url, Format.listTime(m.receivedAt), Icons.Rounded.Link, TreeColors.TileIndigo, onClick = { platform.copy(url); model.notice(t("링크를 복사했어요", "Link copied")) }, trailing = null)
                    }
                }
            }
        }
        if (admin && state.chatFeatures.isNotEmpty()) {
            var open by remember { mutableStateOf(false) }
            CardGroup {
                SettingsRow(t("대화방 설정", "Chat settings"), t("관리자만 바꿀 수 있어요 · 사라지는 메시지, 캡처 막기 등", "Admins only · disappearing messages, screenshot block and more"),
                    Icons.Rounded.Tune, TreeColors.TileGrey, onClick = { open = !open },
                    trailing = { Icon(if (open) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore, null, tint = extra.muted) })
                if (open) state.chatFeatures.filter { it.lockedBy == null }.forEach { f ->
                    val name = chatFeatureName(f.key) ?: return@forEach
                    RowDivider()
                    SwitchRow(name, null, f.applied) { on -> scope.launch { model.setChatFeature(chat.id, f.key, on) } }
                }
            }
        }
    }
    if (leaving) {
        AlertDialog(
            onDismissRequest = { leaving = false },
            title = { Text(t("대화방을 나갈까요?", "Leave this chat?")) },
            text = { Text(t("조용히 나가면 다른 사람에게 나갔다는 줄이 보이지 않아요.", "Leaving quietly shows no \"left\" line to the others."), color = extra.muted) },
            confirmButton = { TextButton(onClick = { leaving = false; scope.launch { if (model.leave(chat.id, false)) nav.home() } }) { Text(t("나가기", "Leave"), color = extra.danger, fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { leaving = false; scope.launch { if (model.leave(chat.id, true)) nav.home() } }) { Text(t("조용히 나가기", "Leave quietly")) } },
        )
    }
    safety?.let { s ->
        AlertDialog(
            onDismissRequest = { safety = null },
            title = { Text(t("안전 번호", "Safety number")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(t("상대 기기에 보이는 숫자와 같으면 ‘확인’을 누르세요.", "If the other device shows the same numbers, tap Verify."), color = extra.muted)
                    Box(Modifier.clip(RoundedCornerShape(14.dp)).background(extra.card).padding(16.dp)) {
                        Text(s.chunked(5).chunked(4).joinToString("\n") { it.joinToString("  ") }, fontFamily = FontFamily.Monospace, fontSize = 17.sp, lineHeight = 26.sp)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { val acc = others.mapNotNull { it.account }.firstOrNull(); safety = null; if (acc != null) scope.launch { model.markVerified(acc) } }) { Text(t("확인", "Verify"), fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { safety = null }) { Text(t("닫기", "Close")) } },
        )
    }
    link?.let { l ->
        AlertDialog(
            onDismissRequest = { link = null },
            title = { Text(t("초대 링크", "Invite link")) },
            text = { Text(l, style = MaterialTheme.typography.bodySmall) },
            confirmButton = { TextButton(onClick = { platform.copy(l); link = null; model.notice(t("복사했어요", "Copied")) }) { Text(t("복사", "Copy"), fontWeight = FontWeight.SemiBold) } },
        )
    }
    if (invite) InviteDialog(model, chat.id) { invite = false }
    if (rename) {
        var name by remember { mutableStateOf(chat.title) }
        AlertDialog(
            onDismissRequest = { rename = false },
            title = { Text(t("대화방 이름", "Chat name")) },
            text = { OutlinedTextField(name, { name = it }, singleLine = true, shape = RoundedCornerShape(14.dp)) },
            confirmButton = { TextButton(onClick = { rename = false; scope.launch { model.renameGroup(chat.id, name) } }) { Text(t("저장", "Save"), fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { rename = false }) { Text(t("취소", "Cancel")) } },
        )
    }
}

private enum class InfoTab(val ko: String, val en: String) { MEMBERS("멤버", "Members"), MEDIA("미디어", "Media"), FILES("파일", "Files"), LINKS("링크", "Links") }

@Composable
private fun PillTag(text: String, color: androidx.compose.ui.graphics.Color) {
    Text(text, color = color, style = MaterialTheme.typography.labelLarge, maxLines = 1,
        modifier = Modifier.clip(RoundedCornerShape(14.dp)).background(color.copy(alpha = 0.16f)).padding(horizontal = 10.dp, vertical = 4.dp))
}

@Composable
private fun InfoEmpty(text: String) {
    Text(text, color = extra.muted, textAlign = TextAlign.Center, modifier = Modifier.fillMaxWidth().padding(28.dp))
}

/** Pictures of the chat, three to a row, from their previews (through the shared cache). */
@Composable
private fun MediaGrid(platform: TreePlatform, pics: List<uniffi.tree_ffi.Message>, state: UiState) {
    if (pics.isEmpty()) { InfoEmpty(t("주고받은 사진이 없어요", "No photos yet")); return }
    Column(Modifier.padding(4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        pics.asReversed().chunked(3).forEach { row ->
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                row.forEach { m ->
                    val f = m.file ?: state.files[m.id]
                    val img by rememberImage(platform, "thumb:" + m.id, 320) { f?.thumbnail }
                    Box(Modifier.weight(1f).aspectRatio(1f).clip(RoundedCornerShape(10.dp)).background(extra.divider).clickable { f?.let { platform.saveAs(m.id, it.name) } }) {
                        img?.let { androidx.compose.foundation.Image(it, f?.name, Modifier.fillMaxSize(), contentScale = androidx.compose.ui.layout.ContentScale.Crop) }
                    }
                }
                repeat(3 - row.size) { Spacer(Modifier.weight(1f)) }
            }
        }
    }
}

private fun chatFeatureName(key: String): String? = when (key) {
    "chat.disappearing" -> t("사라지는 메시지", "Disappearing messages")
    "chat.media" -> t("사진·영상·파일", "Photos, videos, files")
    "chat.voice" -> t("음성 메시지", "Voice messages")
    "chat.reactions" -> t("반응", "Reactions")
    "chat.edit" -> t("메시지 수정", "Edit messages")
    "chat.delete_for_all" -> t("모두에게서 삭제", "Delete for everyone")
    "chat.screenshot_block" -> t("화면 캡처 막기", "Block screenshots")
    "chat.view_once" -> t("한 번 보기", "View once")
    "chat.formatting" -> t("글자 서식", "Text formatting")
    "chat.mention_all" -> t("@모두 멘션", "@all mentions")
    "chat.invite_link" -> t("초대 링크", "Invite links")
    "chat.pins" -> t("메시지 고정", "Pinned messages")
    "chat.polls" -> t("투표", "Polls")
    "chat.forwarding" -> t("전달·저장 허용", "Forwarding and saving")
    "chat.export" -> t("대화 내보내기", "Export chat")
    "chat.stickers" -> t("스티커", "Stickers")
    "chat.gifs" -> "GIF"
    "chat.location" -> t("위치 보내기", "Location")
    "chat.events" -> t("일정", "Events")
    "chat.video_notes" -> t("영상 메시지", "Video messages")
    "chat.topics" -> t("주제", "Topics")
    "chat.roles" -> t("역할", "Roles")
    "chat.admin_log" -> t("관리 기록", "Admin log")
    "chat.welcome" -> t("환영 메시지", "Welcome message")
    "chat.history_share" -> t("새 멤버에게 최근 대화 공유", "Share recent history with new members")
    "chat.join_approval" -> t("가입 승인", "Approve joins")
    "chat.slow_mode" -> t("느린 모드", "Slow mode")
    "chat.restrict" -> t("멤버 발언 제한", "Restrict members")
    "chat.member_adds" -> t("멤버도 초대 가능", "Members can add people")
    "chat.bots" -> t("봇 허용", "Allow bots")
    "chat.allow_per_chat_profiles" -> t("방마다 다른 프로필", "Per-chat profiles")
    "chat.owner_succession" -> t("방장 자동 승계", "Owner succession")
    "chat.public_listing" -> t("공개 목록에 표시", "Listed publicly")
    else -> null
}

@Composable
private fun InfoAction(icon: ImageVector, label: String, modifier: Modifier, onClick: () -> Unit) {
    Column(
        modifier.clip(RoundedCornerShape(18.dp)).background(extra.card).clickable(onClick = onClick).padding(vertical = 14.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(5.dp),
    ) {
        Icon(icon, null, tint = MaterialTheme.colorScheme.primary)
        Text(label, style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
private fun InviteDialog(model: AppModel, group: String, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var who by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text(t("멤버 초대", "Add members")) },
        text = { OutlinedTextField(who, { who = it }, placeholder = { Text(t("@아이디 또는 계정 ID", "@username or account ID")) }, singleLine = true, shape = RoundedCornerShape(14.dp)) },
        confirmButton = { TextButton(onClick = { scope.launch { if (model.invite(group, who)) onClose() } }, enabled = who.isNotBlank()) { Text(t("초대", "Add"), fontWeight = FontWeight.SemiBold) } },
        dismissButton = { TextButton(onClick = onClose) { Text(t("취소", "Cancel")) } },
    )
}

/** A new group: its name and the first people, then it opens. */
@Composable
fun NewGroupScreen(model: AppModel, nav: TreeNav, state: UiState) {
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    var who by remember { mutableStateOf("") }
    val people = remember { mutableStateListOf<String>() }
    var busy by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { model.loadContacts() }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
        BackHeader(t("새 그룹", "New group"), { nav.pop() })
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(name, { name = it }, label = { Text(t("그룹 이름", "Group name")) }, singleLine = true, shape = RoundedCornerShape(16.dp), modifier = Modifier.fillMaxWidth())
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(who, { who = it }, label = { Text(t("@아이디로 추가", "Add by @username")) }, singleLine = true, shape = RoundedCornerShape(16.dp), modifier = Modifier.weight(1f))
                TextButton(onClick = { if (who.isNotBlank()) { people.add(who.trim()); who = "" } }) { Text(t("추가", "Add")) }
            }
            if (state.contacts.isNotEmpty()) Text(t("연락처에서 고르기", "From your contacts"), color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.titleSmall)
            state.contacts.forEach { c ->
                val picked = c.account in people
                Row(Modifier.fillMaxWidth().clip(RoundedCornerShape(14.dp)).clickable { if (picked) people.remove(c.account) else people.add(c.account) }.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Avatar(c.name, c.account, 40.dp)
                    Spacer(Modifier.width(12.dp))
                    Text(c.name, modifier = Modifier.weight(1f))
                    if (picked) Icon(Icons.Rounded.VerifiedUser, null, tint = MaterialTheme.colorScheme.primary)
                }
            }
            people.filter { p -> state.contacts.none { it.account == p } }.forEach { p -> Text("• $p", color = extra.muted) }
        }
        Box(Modifier.padding(16.dp)) {
            PillButton(t("그룹 만들기", "Create group"), enabled = !busy && people.isNotEmpty(), onClick = {
                busy = true
                scope.launch {
                    val g = model.newChat()
                    if (g != null) {
                        if (name.isNotBlank()) model.renameGroup(g, name)
                        people.forEach { model.invite(g, it) }
                        nav.pop(); nav.push(Route.Chat(g))
                    }
                    busy = false
                }
            })
        }
    }
}
