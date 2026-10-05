package app.tree.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Devices
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.QrCode2
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VisibilityOff
import androidx.compose.material.icons.rounded.Groups
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.tree.shared.AppModel
import app.tree.shared.LinkUi
import app.tree.shared.qr.QrMatrix
import kotlinx.coroutines.launch
import java.io.File

private enum class Step { WELCOME, CREATE, LINK, RECOVERY }

/** First run (welcome, account, recovery) or unlocking an existing profile. */
@Composable
fun Onboarding(model: AppModel, platform: TreePlatform) {
    val exists = remember { File(platform.profilePath).exists() }
    if (exists) { Unlock(model, platform); return }
    var step by remember { mutableStateOf(Step.WELCOME) }
    val link = model.state.collectAsState().value.link
    if (link != null) { LinkScreen(model, link, newDevice = true); return }
    when (step) {
        Step.WELCOME -> Welcome(onCreate = { step = Step.CREATE }, onLink = { step = Step.LINK })
        Step.CREATE -> CreateAccount(model, platform, onBack = { step = Step.WELCOME }, link = false)
        Step.LINK -> CreateAccount(model, platform, onBack = { step = Step.WELCOME }, link = true)
        Step.RECOVERY -> {}
    }
}

@Composable
private fun Welcome(onCreate: () -> Unit, onLink: () -> Unit) {
    Column(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(72.dp))
        Logo(112.dp)
        Spacer(Modifier.height(28.dp))
        Text("Tree", style = MaterialTheme.typography.headlineLarge, fontSize = 40.sp)
        Spacer(Modifier.height(10.dp))
        Text(
            t("서버도 내 대화를 볼 수 없는 메신저", "The messenger even its server can't read"),
            style = MaterialTheme.typography.bodyLarge, color = extra.muted, textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(40.dp))
        Column(Modifier.widthIn(max = 420.dp), verticalArrangement = Arrangement.spacedBy(18.dp)) {
            Point(Icons.Rounded.Lock, t("모든 대화를 끝단 암호화", "Every private chat end-to-end encrypted"), t("내 기기와 상대 기기만 읽을 수 있어요.", "Only your devices and theirs can read it."))
            Point(Icons.Rounded.VisibilityOff, t("전화번호가 필요 없어요", "No phone number needed"), t("이름과 기기 잠금 문장만으로 시작해요.", "Start with a name and a device passphrase."))
            Point(Icons.Rounded.Shield, t("광고 없음, 추적 없음", "No ads, no tracking"), t("대화를 팔지 않아요.", "Your chats are not for sale."))
        }
        Spacer(Modifier.height(44.dp))
        Column(Modifier.widthIn(max = 420.dp)) {
            PillButton(t("시작하기", "Get started"), onCreate)
            Spacer(Modifier.height(10.dp))
            OutlinedButton(onClick = onLink, modifier = Modifier.fillMaxWidth().height(54.dp), shape = RoundedCornerShape(27.dp)) {
                Icon(Icons.Rounded.QrCode2, contentDescription = null, modifier = Modifier.size(20.dp))
                Spacer(Modifier.size(10.dp))
                Text(t("이미 쓰는 기기가 있어요 · QR로 연결", "I already use Tree · link with QR"), style = MaterialTheme.typography.labelLarge)
            }
        }
        Spacer(Modifier.height(32.dp))
    }
}

@Composable
private fun Point(icon: ImageVector, title: String, text: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(44.dp).clip(RoundedCornerShape(14.dp)).background(MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
            Icon(icon, contentDescription = null, tint = MaterialTheme.colorScheme.primary)
        }
        Spacer(Modifier.size(16.dp))
        Column {
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(text, style = MaterialTheme.typography.bodySmall, color = extra.muted)
        }
    }
}

/** The Tree mark: a rounded green tile with three leaves. */
@Composable
fun Logo(size: Dp) {
    Box(
        Modifier.size(size).clip(RoundedCornerShape(size * 0.3f)).background(MaterialTheme.colorScheme.primary),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(size * 0.6f)) {
            val w = this.size.width
            val leaf = Color.White
            drawCircle(leaf, radius = w * 0.2f, center = Offset(w * 0.5f, w * 0.28f))
            drawCircle(leaf, radius = w * 0.17f, center = Offset(w * 0.3f, w * 0.5f))
            drawCircle(leaf, radius = w * 0.17f, center = Offset(w * 0.7f, w * 0.5f))
            drawRect(leaf, topLeft = Offset(w * 0.455f, w * 0.45f), size = Size(w * 0.09f, w * 0.48f))
        }
    }
}

@Composable
private fun fieldColors() = OutlinedTextFieldDefaults.colors(
    focusedContainerColor = extra.card, unfocusedContainerColor = extra.card,
    unfocusedBorderColor = Color.Transparent, focusedBorderColor = MaterialTheme.colorScheme.primary,
)

/** Name, device passphrase and (under 고급) the server; then create, or start a link to an existing account. */
@Composable
private fun CreateAccount(model: AppModel, platform: TreePlatform, onBack: () -> Unit, link: Boolean) {
    val scope = rememberCoroutineScope()
    var name by remember { mutableStateOf("") }
    var pass by remember { mutableStateOf("") }
    var server by remember { mutableStateOf(platform.defaultServer) }
    var advanced by remember { mutableStateOf(platform.defaultServer.isBlank()) }
    var busy by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding()) {
        BackHeader(if (link) t("기존 계정에 연결", "Link to my account") else t("새 계정", "New account"), onBack)
        Column(
            Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(horizontal = 24.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                if (link) t("이 기기에 QR 코드가 나타나요. 이미 쓰는 기기에서 그 QR을 찍으면 연결돼요.", "This device will show a QR code. Scan it with a device you already use.")
                else t("상대에게 보일 이름과, 이 기기를 잠글 문장을 정해 주세요.", "Choose the name others see, and a passphrase that locks this device."),
                style = MaterialTheme.typography.bodyMedium, color = extra.muted,
            )
            OutlinedTextField(name, { name = it }, placeholder = { Text(t("이름", "Name")) }, singleLine = true, shape = RoundedCornerShape(16.dp), colors = fieldColors(), modifier = Modifier.fillMaxWidth())
            OutlinedTextField(
                pass, { pass = it }, placeholder = { Text(t("기기 잠금 문장", "Device passphrase")) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                shape = RoundedCornerShape(16.dp), colors = fieldColors(), modifier = Modifier.fillMaxWidth(),
            )
            Text(
                t("이 문장은 이 기기 안의 대화를 잠가요. 서버로 보내지지 않고, 잊으면 이 기기의 대화를 열 수 없어요.", "It locks the chats on this device. It never leaves the device; if you forget it, this device's chats stay locked."),
                style = MaterialTheme.typography.bodySmall, color = extra.muted,
            )
            if (advanced) {
                OutlinedTextField(server, { server = it }, placeholder = { Text(t("서버 주소", "Server address")) }, singleLine = true, shape = RoundedCornerShape(16.dp), colors = fieldColors(), modifier = Modifier.fillMaxWidth())
            } else {
                QuietButton(t("고급: 서버 바꾸기", "Advanced: change server"), { advanced = true }, color = extra.muted)
            }
        }
        Column(Modifier.padding(24.dp)) {
            if (busy) Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
            else PillButton(
                if (link) t("QR 코드 만들기", "Show QR code") else t("계정 만들기", "Create account"),
                enabled = name.isNotBlank() && pass.length >= 6 && server.isNotBlank(),
                onClick = {
                    busy = true
                    scope.launch {
                        if (link) {
                            if (model.startLinkNewDevice(platform.profilePath, pass, name.trim(), server.trim()) != null) model.watchLink { model.startSyncLoop() }
                        } else if (model.createAccount(platform.profilePath, pass, name.trim(), server.trim())) {
                            model.startSyncLoop()
                        }
                        busy = false
                    }
                },
            )
            if (pass.isNotEmpty() && pass.length < 6) {
                Text(t("6자 이상으로 정해 주세요.", "Use at least 6 characters."), style = MaterialTheme.typography.bodySmall, color = extra.warning, modifier = Modifier.padding(top = 8.dp))
            }
        }
    }
}

@Composable
private fun Unlock(model: AppModel, platform: TreePlatform) {
    val scope = rememberCoroutineScope()
    var pass by remember { mutableStateOf("") }
    Column(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().imePadding().verticalScroll(rememberScrollState()).padding(horizontal = 28.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Spacer(Modifier.height(96.dp))
        Logo(84.dp)
        Spacer(Modifier.height(20.dp))
        Text(t("다시 오셨네요", "Welcome back"), style = MaterialTheme.typography.headlineMedium)
        Text(t("기기 잠금 문장으로 대화를 열어요", "Open your chats with the device passphrase"), color = extra.muted, style = MaterialTheme.typography.bodyMedium)
        Spacer(Modifier.height(32.dp))
        Column(Modifier.widthIn(max = 420.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            OutlinedTextField(
                pass, { pass = it }, placeholder = { Text(t("기기 잠금 문장", "Device passphrase")) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                shape = RoundedCornerShape(16.dp), colors = fieldColors(), modifier = Modifier.fillMaxWidth(),
            )
            PillButton(t("열기", "Open"), enabled = pass.isNotEmpty(), onClick = {
                scope.launch { if (model.openProfile(platform.profilePath, pass)) model.startSyncLoop() }
            })
            platform.UnlockOptions { model.startSyncLoop() }
        }
    }
}

/** The steps of a device link on either side: QR (new device), then the six digits. */
@Composable
fun LinkScreen(model: AppModel, link: LinkUi, newDevice: Boolean) {
    val scope = rememberCoroutineScope()
    Column(
        Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding().verticalScroll(rememberScrollState()).padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(16.dp))
        when (link.state) {
            "waiting" -> {
                if (newDevice && link.text != null) {
                    Text(t("이미 쓰는 기기에서 이 QR을 찍어 주세요", "Scan this with a device you already use"), style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                    Text(t("설정 › 기기 › 기기 연결", "Settings › Devices › Link a device"), color = extra.muted)
                    link.qr?.let { Box(Modifier.clip(RoundedCornerShape(24.dp)).background(Color.White).padding(16.dp)) { QrView(it, 260.dp) } }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.size(10.dp))
                    Text(t("다른 기기를 기다리는 중…", "Waiting for the other device…"), color = extra.muted)
                }
            }
            "code" -> {
                Icon(Icons.Rounded.Devices, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(56.dp))
                Text(t("두 기기의 숫자가 같나요?", "Do both devices show the same digits?"), style = MaterialTheme.typography.titleLarge, textAlign = TextAlign.Center)
                CodeDigits(link.code)
                Box(Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(extra.warning.copy(alpha = 0.14f)).padding(14.dp)) {
                    Text(
                        t("두 기기를 지금 내 손에 들고 있을 때만 확인을 누르세요. 누가 전화나 메시지로 숫자를 불러 달라고 하면 사기예요.", "Confirm only while you hold both devices yourself. Anyone asking you to read the digits out is a scam."),
                        style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold,
                    )
                }
                PillButton(t("숫자가 같아요", "The digits match"), onClick = { scope.launch { if (newDevice) model.confirmNewDevice(true) else model.confirmLink(true) } })
                QuietButton(t("달라요 / 내가 시작하지 않았어요", "Different / I didn't start this"), { scope.launch { if (newDevice) model.confirmNewDevice(false) else model.confirmLink(false) } }, color = extra.danger)
            }
            "confirmed" -> {
                CodeDigits(link.code)
                Text(t("다른 기기에서도 확인을 눌러 주세요", "Now confirm on the other device too"), textAlign = TextAlign.Center)
                CircularProgressIndicator()
            }
            "linked" -> {
                Icon(Icons.Rounded.Devices, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(64.dp))
                Text(t("연결됐어요", "Linked"), style = MaterialTheme.typography.headlineMedium)
                PillButton(t("확인", "Done"), onClick = model::closeLink)
            }
            else -> {
                Text(t("연결되지 않았어요", "Not linked"), style = MaterialTheme.typography.headlineMedium)
                link.reason?.let { Text(it, color = extra.muted, textAlign = TextAlign.Center) }
                PillButton(t("닫기", "Close"), onClick = model::closeLink)
            }
        }
        if (link.state == "waiting") QuietButton(t("취소", "Cancel"), model::closeLink, color = extra.muted)
    }
}

@Composable
private fun CodeDigits(code: String?) {
    Box(Modifier.clip(RoundedCornerShape(20.dp)).background(extra.card).padding(horizontal = 28.dp, vertical = 18.dp)) {
        Text(code ?: "", fontSize = 46.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, letterSpacing = 6.sp)
    }
}

/** A QR code drawn module by module, dark on white whatever the theme. */
@Composable
fun QrView(m: QrMatrix, size: Dp) {
    Canvas(Modifier.size(size).background(Color.White)) {
        val cell = this.size.minDimension / m.size
        for (y in 0 until m.size) for (x in 0 until m.size) {
            if (m[x, y]) drawRect(Color(0xFF111214), Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
        }
    }
}
