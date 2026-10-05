package app.tree.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Laptop
import androidx.compose.material.icons.rounded.PersonAdd
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.ScanOutcome
import app.tree.shared.qr.CodeKind
import kotlinx.coroutines.launch

/**
 * Where there is no camera: the code's text is pasted instead of scanned.
 * The same checks run as for a scan (only a Tree code of the kind asked).
 */
@Composable
fun PasteScanner(model: AppModel, kind: CodeKind, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<String?>(null) }
    val device = kind == CodeKind.DEVICE_LINK
    Column(Modifier.fillMaxSize().statusBarsPadding().navigationBarsPadding()) {
        BackHeader(when (kind) { CodeKind.DEVICE_LINK -> t("기기 연결", "Link a device"); CodeKind.SAFETY -> t("안전 번호 확인", "Verify safety number"); else -> t("친구 추가", "Add a friend") }, onClose)
        Column(
            Modifier.fillMaxWidth().padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Icon(if (device) Icons.Rounded.Laptop else Icons.Rounded.PersonAdd, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 20.dp))
            Text(
                when (kind) {
                    CodeKind.DEVICE_LINK -> t("새 기기 화면의 QR 아래에 있는 글자를 복사해서 붙여 넣으세요.", "Copy the text under the QR code on the new device and paste it here.")
                    CodeKind.SAFETY -> t("상대 화면의 안전 번호 QR 아래 글자를 붙여 넣으세요.", "Paste the text under the safety number QR on their screen.")
                    else -> t("친구에게 받은 링크를 붙여 넣으세요.", "Paste the link your friend sent you.")
                },
                textAlign = TextAlign.Center, color = extra.muted,
            )
            OutlinedTextField(
                text, { text = it; message = null }, singleLine = true, shape = RoundedCornerShape(16.dp),
                placeholder = { Text("tree://…") }, modifier = Modifier.fillMaxWidth(),
            )
            message?.let { Text(it, color = extra.danger, style = MaterialTheme.typography.bodySmall) }
            Spacer(Modifier.height(4.dp))
            PillButton(t("확인", "Continue"), enabled = text.isNotBlank(), onClick = {
                scope.launch {
                    val o = model.useScanned(text.trim(), kind)
                    message = AppModel.scanMessage(o, kind) ?: if (o == ScanOutcome.FAILED) t("연결하지 못했어요. 코드를 다시 확인해 주세요.", "That didn't work. Check the code.") else null
                    if (o == ScanOutcome.ACCEPTED) onClose()
                }
            })
        }
    }
}
