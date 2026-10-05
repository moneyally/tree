package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.AccountCircle
import androidx.compose.material.icons.rounded.Badge
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.ChatBubble
import androidx.compose.material.icons.rounded.CleaningServices
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Devices
import androidx.compose.material.icons.rounded.DoneAll
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.Folder
import androidx.compose.material.icons.rounded.GroupAdd
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Keyboard
import androidx.compose.material.icons.rounded.Label
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.MailOutline
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.Pageview
import androidx.compose.material.icons.rounded.Person
import androidx.compose.material.icons.rounded.Photo
import androidx.compose.material.icons.rounded.Policy
import androidx.compose.material.icons.rounded.QrCode2
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material.icons.rounded.Screenshot
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.SmartToy
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Edit
import androidx.compose.material.icons.rounded.Laptop
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.Lang
import app.tree.shared.Strings
import app.tree.shared.UiState
import app.tree.shared.cleanStorage
import app.tree.shared.qr.CodeKind
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Feature

/** What each user setting is called and what it does, in plain words. */
private data class Meta(val ko: String, val en: String, val koDesc: String, val enDesc: String, val icon: ImageVector, val tile: Color)

private val META = mapOf(
    "user.read_receipts" to Meta("읽음 표시", "Read receipts", "끄면 나도 상대가 읽었는지 볼 수 없어요", "Off: neither side sees reads", Icons.Rounded.DoneAll, TreeColors.TileBlue),
    "user.typing" to Meta("입력 중 표시", "Typing indicator", "글을 쓰는 중이라는 표시를 주고받아요", "Share that you are typing", Icons.Rounded.Keyboard, TreeColors.TileSky),
    "user.last_seen" to Meta("마지막 접속 표시", "Last seen", "끄면 나도 상대의 접속 시간을 볼 수 없어요", "Off: neither side sees it", Icons.Rounded.Schedule, TreeColors.TileIndigo),
    "user.link_preview" to Meta("링크 미리보기", "Link previews", "보내는 내 기기에서만 만들어요. 받는 쪽은 사이트에 접속하지 않아요", "Made by the sender only", Icons.Rounded.Link, TreeColors.TileTeal),
    "user.message_requests" to Meta("메시지 요청함", "Message requests", "모르는 사람의 대화는 요청함에 먼저 들어와요", "Strangers land in requests first", Icons.Rounded.MailOutline, TreeColors.TileAmber),
    "user.stranger_block" to Meta("모르는 사람 막기", "Block strangers", "모르는 사람의 대화를 아예 받지 않아요", "Refuse chats from strangers", Icons.Rounded.Block, TreeColors.TileRed),
    "user.stranger_labels" to Meta("낯선 상대 표시", "Stranger labels", "‘연락처 아님’ 같은 경고를 보여줘요", "Warn about people you don't know", Icons.Rounded.Label, TreeColors.TileOrange),
    "user.group_add" to Meta("나를 그룹에 넣을 수 있는 사람", "Who can add me to groups", "연락처만 / 아무도", "Contacts / nobody", Icons.Rounded.GroupAdd, TreeColors.TileGreen),
    "user.group_safety_notice" to Meta("모르는 그룹 안내", "Unknown group notice", "모르는 그룹에 들어가면 주의할 점을 보여줘요", "Safety tips in unknown groups", Icons.Rounded.Policy, TreeColors.TileViolet),
    "user.discoverable" to Meta("아이디로 찾기 허용", "Findable by username", "끄면 아무도 내 @아이디로 나를 찾을 수 없어요", "Off: nobody finds you by @name", Icons.Rounded.Search, TreeColors.TileBlue),
    "user.app_lock" to Meta("앱 잠금", "App lock", "앱을 나가면 다시 잠금을 풀어야 열려요", "Lock when you leave the app", Icons.Rounded.Lock, TreeColors.TileGreen),
    "user.app_switcher_blur" to Meta("앱 전환 화면 가리기", "Hide in app switcher", "최근 앱 목록에서 대화 내용을 가려요", "Hide content in recent apps", Icons.Rounded.Visibility, TreeColors.TileGrey),
    "user.incognito_keyboard" to Meta("키보드 학습 막기", "Incognito keyboard", "키보드가 내가 쓴 글을 배우지 않게 요청해요", "Ask the keyboard not to learn", Icons.Rounded.Keyboard, TreeColors.TileGrey),
    "user.pc_screen_security" to Meta("PC 화면 보호", "Computer screen protection", "PC에서 화면 캡처·녹화에 대화가 찍히지 않게 해요", "Keep chats out of screen captures", Icons.Rounded.Screenshot, TreeColors.TileGrey),
    "user.notification_content" to Meta("알림에 내용 보이기", "Show text in notifications", "끄면 알림에 이름만 보여요", "Off: names only", Icons.Rounded.Notifications, TreeColors.TileRed),
    "user.auto_download" to Meta("자동 다운로드", "Auto-download", "연락처가 보낸 파일만, 고른 네트워크에서 받아요", "Contacts' files on chosen networks", Icons.Rounded.Download, TreeColors.TileBlue),
    "user.storage_clean" to Meta("저장 공간 자동 정리", "Auto clean storage", "오래 된 받은 파일을 기기에서 지워요", "Delete old downloads from this device", Icons.Rounded.CleaningServices, TreeColors.TileOrange),
    "user.search_index" to Meta("기기 안 검색", "On-device search", "검색 색인은 이 기기 안에만 있어요", "The index stays on this device", Icons.Rounded.Pageview, TreeColors.TileTeal),
    "user.drafts" to Meta("임시 저장", "Drafts", "보내지 않은 글을 대화마다 남겨둬요", "Keep unsent text per chat", Icons.Rounded.Edit, TreeColors.TileAmber),
    "user.folders" to Meta("대화 폴더", "Chat folders", "대화를 폴더별로 정리해요", "Sort chats into folders", Icons.Rounded.Folder, TreeColors.TileBlue),
    "user.default_folders" to Meta("기본 폴더", "Default folders", "안 읽음 · 1:1 · 그룹 폴더", "Unread · 1:1 · Groups", Icons.Rounded.Folder, TreeColors.TileSky),
    "user.quiet_folder" to Meta("조용한 대화 폴더", "Quiet folder", "알림 끈 대화를 따로 모아요", "Muted chats in one place", Icons.Rounded.Folder, TreeColors.TileGrey),
    "user.profile_photo_visibility" to Meta("프로필 사진 공개 범위", "Profile photo visibility", "대화 상대 / 연락처 / 아무도", "Chats / contacts / nobody", Icons.Rounded.Photo, TreeColors.TilePink),
    "user.username_link" to Meta("아이디 링크·QR", "Username link & QR", "링크나 QR로 친구를 추가할 수 있어요", "Let people add you by link or QR", Icons.Rounded.QrCode2, TreeColors.TileIndigo),
    "user.peek" to Meta("안 읽고 보기", "Peek", "읽음 표시 없이 미리 볼 수 있어요", "Preview without a read receipt", Icons.Rounded.Visibility, TreeColors.TileViolet),
    "user.note_to_self" to Meta("나에게 메모", "Note to self", "나만 보는 대화방", "A chat only you see", Icons.Rounded.Edit, TreeColors.TileGreen),
)

private val PAGES = mapOf(
    "privacy" to listOf("user.read_receipts", "user.last_seen", "user.typing", "user.discoverable", "user.group_add", "user.message_requests", "user.stranger_block", "user.stranger_labels", "user.group_safety_notice", "user.profile_photo_visibility", "user.username_link"),
    "security" to listOf("user.app_lock", "user.app_switcher_blur", "user.incognito_keyboard", "user.pc_screen_security"),
    "notifications" to listOf("user.notification_content"),
    "chats" to listOf("user.link_preview", "user.drafts", "user.peek", "user.note_to_self", "user.search_index"),
    "data" to listOf("user.auto_download", "user.storage_clean"),
    "folders" to listOf("user.folders", "user.default_folders", "user.quiet_folder"),
)

private fun title(p: String) = when (p) {
    "privacy" -> t("개인정보", "Privacy")
    "security" -> t("보안", "Security")
    "notifications" -> t("알림", "Notifications")
    "chats" -> t("대화 설정", "Chat settings")
    "data" -> t("데이터 및 저장공간", "Data and storage")
    "folders" -> t("대화 폴더", "Chat folders")
    "devices" -> t("기기", "Devices")
    "account" -> t("내 계정", "My account")
    "language" -> t("언어", "Language")
    "advanced" -> t("고급: 모든 설정", "Advanced: all settings")
    else -> p
}

@Composable
fun SettingsHome(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState) {
    LaunchedEffect(Unit) { model.loadFeatures() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 110.dp)) {
        BigHeader(t("설정", "Settings"))
        CardGroup(title = t("계정", "Account")) {
            Row(Modifier.fillMaxWidth().clickable { nav.tab = Tab.PROFILE }.padding(horizontal = 18.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                Avatar(state.name, state.account, 48.dp)
                Spacer(Modifier.width(14.dp))
                Column(Modifier.weight(1f)) {
                    Text(state.name, style = MaterialTheme.typography.titleMedium)
                    Text(t("프로필, 아이디, 내 QR", "Profile, username, my QR"), style = MaterialTheme.typography.bodySmall, color = extra.muted)
                }
                Chevron()
            }
        }
        CardGroup {
            SettingsRow(t("내 계정", "My account"), t("아이디, 복구 문구, 계정 삭제", "Username, recovery phrase, delete"), Icons.Rounded.Person, TreeColors.TileBlue, onClick = { nav.push(Route.Settings("account")) })
            SettingsRow(t("대화 설정", "Chat settings"), t("링크 미리보기, 임시 저장, 검색", "Link previews, drafts, search"), Icons.Rounded.ChatBubble, TreeColors.TileAmber, onClick = { nav.push(Route.Settings("chats")) })
            SettingsRow(t("개인정보", "Privacy"), t("읽음 표시, 마지막 접속, 아이디 찾기", "Read receipts, last seen, finding you"), Icons.Rounded.Key, TreeColors.TileGreen, onClick = { nav.push(Route.Settings("privacy")) })
            SettingsRow(t("보안", "Security"), t("앱 잠금, 화면 보호, 키보드", "App lock, screen protection, keyboard"), Icons.Rounded.Shield, TreeColors.TileTeal, onClick = { nav.push(Route.Settings("security")) })
            SettingsRow(t("알림", "Notifications"), t("알림에 보일 내용", "What notifications show"), Icons.Rounded.Notifications, TreeColors.TileRed, onClick = { nav.push(Route.Settings("notifications")) })
            SettingsRow(t("데이터 및 저장공간", "Data and storage"), t("미디어 자동 다운로드, 정리", "Auto-download, clean-up"), Icons.Rounded.Storage, TreeColors.TileIndigo, onClick = { nav.push(Route.Settings("data")) })
            SettingsRow(t("대화 폴더", "Chat folders"), t("대화를 폴더별로 정리", "Sort chats into folders"), Icons.Rounded.Folder, TreeColors.TileSky, onClick = { nav.push(Route.Settings("folders")) })
            SettingsRow(t("기기", "Devices"), t("연결된 기기 관리, 기기 연결", "Linked devices, link a device"), Icons.Rounded.Laptop, TreeColors.TileTeal, onClick = { nav.push(Route.Settings("devices")) })
            SettingsRow(t("언어", "Language"), if (Strings.lang == Lang.KO) "한국어" else "English", Icons.Rounded.Language, TreeColors.TileViolet, onClick = { nav.push(Route.Settings("language")) })
        }
        CardGroup {
            platform.extraScreens.forEach { (key, label) ->
                SettingsRow(label, null, if (key == "bots") Icons.Rounded.SmartToy else Icons.Rounded.Public, if (key == "bots") TreeColors.TileBlue else TreeColors.TileOrange, onClick = { nav.push(Route.Extra(key)) })
            }
            SettingsRow(t("고급: 모든 설정", "Advanced: all settings"), t("모든 기능의 적용/해제", "Apply/release every feature"), Icons.Rounded.Tune, TreeColors.TileGrey, onClick = { nav.push(Route.Settings("advanced")) })
        }
        Caption(t("Tree는 대화 내용을 서버에 남기지 않아요. 모든 비공개 대화는 끝단 암호화돼요.", "Tree keeps no chat content on its server. Every private chat is end-to-end encrypted."))
    }
}

@Composable
fun SettingsPage(model: AppModel, platform: TreePlatform, nav: TreeNav, state: UiState, page: String) {
    val scope = rememberCoroutineScope()
    LaunchedEffect(page) { model.loadFeatures(); if (page == "devices") model.loadDevices() }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
        BackHeader(title(page), { nav.pop() })
        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(bottom = 30.dp)) {
            when (page) {
                "account" -> AccountPage(model, nav, state)
                "devices" -> DevicesPage(model, nav, state)
                "language" -> LanguagePage(model)
                "advanced" -> CardGroup {
                    state.features.filter { it.key.startsWith("user.") }.forEach { f -> FeatureRow(model, f) }
                }
                "security" -> {
                    CardGroup { PAGES.getValue(page).forEach { k -> state.features.firstOrNull { it.key == k }?.let { FeatureRow(model, it) } } }
                    platform.AppLockSettings()
                    Caption(t("앱 잠금을 켜면 앱을 나갈 때 대화가 잠기고, 기기 잠금 문장·PIN·지문으로만 다시 열려요.", "With app lock on, leaving the app locks your chats until you unlock again."))
                }
                else -> CardGroup {
                    PAGES[page]?.forEach { k -> state.features.firstOrNull { it.key == k }?.let { FeatureRow(model, it) } }
                }
            }
            if (page == "data") {
                CardGroup {
                    SettingsRow(t("지금 정리하기", "Clean up now"), t("오래된 받은 파일을 지워요", "Delete old downloads"), Icons.Rounded.CleaningServices, TreeColors.TileOrange, onClick = {
                        scope.launch { model.cleanStorage()?.let { model.notice(t("정리했어요", "Cleaned up")) } }
                    })
                }
            }
        }
    }
}

/** One feature as a switch, with its options as a menu and its lock reason when locked. */
@Composable
private fun FeatureRow(model: AppModel, f: Feature) {
    val scope = rememberCoroutineScope()
    val m = META[f.key]
    var options by remember { mutableStateOf(false) }
    val name = m?.let { t(it.ko, it.en) } ?: f.key
    val desc = f.releasePendingUntil?.let { model.pendingNote(f) }
        ?: (if (f.applied && f.option != null) optionLabel(f.option!!) + " · " else "") + (m?.let { t(it.koDesc, it.enDesc) } ?: "")
    Box {
        SwitchRow(
            name, desc, f.applied, m?.icon, m?.tile ?: TreeColors.TileGrey,
            locked = f.lockedBy?.let { lockText(it) },
        ) { on -> if (on && f.choices.isNotEmpty()) options = true else scope.launch { model.setFeature(f.key, on) } }
        DropdownMenu(options, { options = false }) {
            f.choices.forEach { c ->
                DropdownMenuItem({ Text(optionLabel(c)) }, onClick = { options = false; scope.launch { model.setFeature(f.key, true, c) } })
            }
        }
    }
    if (f.applied && f.choices.isNotEmpty() && f.lockedBy == null) {
        Row(Modifier.padding(start = 70.dp, bottom = 6.dp)) { QuietButton(t("옵션 바꾸기", "Change option"), { options = true }) }
    }
}

private fun lockText(by: String) = when {
    by.startsWith("always") -> t("보안상 항상 켜져 있어요", "Always on, for safety")
    by == "server" -> t("서버에서 꺼 둔 기능이에요", "Switched off by the server")
    by == "chat" -> t("이 대화방 설정이 정해요", "Set by the chat")
    else -> by
}

private fun optionLabel(o: String) = when (o) {
    "contacts" -> t("연락처만", "Contacts only")
    "nobody" -> t("아무도", "Nobody")
    "chats" -> t("대화 상대", "My chats")
    "wifi" -> t("와이파이", "Wi-Fi")
    "never" -> t("안 함", "Never")
    "passphrase" -> t("잠금 문장", "Passphrase")
    "pin" -> "PIN"
    "bio" -> t("지문·얼굴", "Biometric")
    else -> o.replace("wifi+mobile", t("와이파이+모바일", "Wi-Fi+mobile")).replace("wifi", t("와이파이", "Wi-Fi"))
}

@Composable
private fun AccountPage(model: AppModel, nav: TreeNav, state: UiState) {
    val scope = rememberCoroutineScope()
    var phrase by remember { mutableStateOf<String?>(null) }
    var confirmDelete by remember { mutableStateOf(false) }
    var username by remember { mutableStateOf("") }
    CardGroup(title = t("아이디", "Username")) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(username, { username = it }, placeholder = { Text("@username") }, singleLine = true, shape = RoundedCornerShape(14.dp), modifier = Modifier.weight(1f))
            TextButton(onClick = { scope.launch { model.setUsername(username.trim().removePrefix("@"))?.let { model.notice(t("아이디를 정했어요: @$it", "Username set: @$it")) } } }, enabled = username.isNotBlank()) { Text(t("저장", "Save")) }
        }
        Text(
            t("아이디는 서버에 해시로만 저장돼요. 다만 흔한 아이디는 추측될 수 있어요.", "Stored on the server as a hash only; common names can still be guessed."),
            style = MaterialTheme.typography.bodySmall, color = extra.muted, modifier = Modifier.padding(horizontal = 20.dp, vertical = 6.dp),
        )
    }
    CardGroup(title = t("복구", "Recovery")) {
        SettingsRow(t("복구 문구 만들기", "Make a recovery phrase"), t("기기를 모두 잃어도 계정을 되찾는 24단어", "24 words to get your account back"), Icons.Rounded.Key, TreeColors.TileAmber, onClick = {
            scope.launch { phrase = model.recoveryPhrase(Strings.lang == Lang.KO) }
        })
    }
    CardGroup(title = t("계정 정보", "Account info")) {
        SettingsRow(t("계정 ID", "Account ID"), state.account, Icons.Rounded.Badge, TreeColors.TileGrey)
    }
    CardGroup {
        SettingsRow(t("계정 삭제", "Delete account"), t("모든 기기와 서버에서 지워요. 되돌릴 수 없어요.", "Removes it everywhere. Cannot be undone."), Icons.Rounded.Delete, TreeColors.TileRed, titleColor = extra.danger, onClick = { confirmDelete = true })
    }
    phrase?.let { words ->
        AlertDialog(
            onDismissRequest = { phrase = null },
            title = { Text(t("복구 문구", "Recovery phrase")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(t("종이에 순서대로 적어 안전한 곳에 두세요. 이 화면은 다시 볼 수 없고, 누구에게도 보여주면 안 돼요.", "Write these down in order and keep them safe. They won't be shown again; never show them to anyone."), color = extra.warning)
                    Box(Modifier.clip(RoundedCornerShape(14.dp)).background(extra.card).padding(14.dp)) {
                        Text(words.split(" ").mapIndexed { i, w -> "${i + 1}. $w" }.chunked(3).joinToString("\n") { it.joinToString("   ") }, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { phrase = null }) { Text(t("다 적었어요", "I wrote them down"), fontWeight = FontWeight.SemiBold) } },
        )
    }
    if (confirmDelete) {
        AlertDialog(
            onDismissRequest = { confirmDelete = false },
            title = { Text(t("정말 계정을 지울까요?", "Delete your account?")) },
            text = { Text(t("모든 대화와 연결된 기기가 사라지고 되돌릴 수 없어요.", "All chats and linked devices go away. This cannot be undone.")) },
            confirmButton = { TextButton(onClick = { confirmDelete = false; scope.launch { model.deleteAccount() } }) { Text(t("삭제", "Delete"), color = extra.danger, fontWeight = FontWeight.SemiBold) } },
            dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text(t("취소", "Cancel")) } },
        )
    }
}

@Composable
private fun DevicesPage(model: AppModel, nav: TreeNav, state: UiState) {
    val scope = rememberCoroutineScope()
    Column(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp).clip(RoundedCornerShape(22.dp)).background(extra.card).padding(22.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Box(Modifier.size(84.dp).clip(RoundedCornerShape(24.dp)).background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
            Icon(Icons.Rounded.Devices, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(44.dp))
        }
        Text(
            t("새 기기(PC·다른 폰)에서 Tree를 열고 ‘이미 쓰는 기기가 있어요’를 누르면 QR이 나와요. 그 QR을 찍으세요.", "Open Tree on the new computer or phone and choose \"I already use Tree\". Scan the QR code it shows."),
            textAlign = TextAlign.Center, style = MaterialTheme.typography.bodyMedium,
        )
        PillButton(t("기기 연결 (QR 찍기)", "Link a device (scan QR)"), { nav.push(Route.Scan(CodeKind.DEVICE_LINK)) }, icon = Icons.Rounded.QrCodeScanner)
    }
    CardGroup(title = t("이 계정의 기기", "Devices on this account")) {
        state.devices.forEachIndexed { i, d ->
            SettingsRow(
                if (i == 0) t("이 기기", "This device") else t("연결된 기기", "Linked device"), d.take(10) + "…",
                if (i == 0) Icons.Rounded.Devices else Icons.Rounded.Laptop, if (i == 0) TreeColors.TileGreen else TreeColors.TileSky,
                trailing = if (i > 0) ({ TextButton(onClick = { scope.launch { model.removeDevice(d) } }) { Text(t("연결 해제", "Unlink"), color = extra.danger) } }) else null,
            )
            if (i < state.devices.lastIndex) RowDivider()
        }
    }
    Caption(t("기기를 연결할 땐 두 기기에 같은 6자리 숫자가 나와야 해요. 누가 숫자를 불러 달라고 하면 사기예요.", "Linking always shows the same six digits on both devices. Anyone asking for them is a scammer."))
}

@Composable
private fun LanguagePage(model: AppModel) {
    val scope = rememberCoroutineScope()
    CardGroup {
        listOf(Lang.KO to "한국어", Lang.EN to "English").forEach { (l, label) ->
            SettingsRow(label, null, trailing = { if (Strings.lang == l) Icon(Icons.Rounded.DoneAll, null, tint = MaterialTheme.colorScheme.primary) }, onClick = {
                Strings.lang = l
                scope.launch { model.refresh() }
            })
        }
    }
}
