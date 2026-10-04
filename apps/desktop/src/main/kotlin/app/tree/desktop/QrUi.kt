package app.tree.desktop

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import app.tree.shared.AppModel
import app.tree.shared.LinkUi
import app.tree.shared.ScanOutcome
import app.tree.shared.Strings
import app.tree.shared.qr.CodeKind
import app.tree.shared.qr.QrMatrix
import kotlinx.coroutines.launch

/**
 * A QR code drawn module by module (black on white, quiet zone included in
 * the matrix), whatever the theme, so every camera reads it.
 */
@Composable
fun QrImage(m: QrMatrix, size: Dp) {
    Canvas(Modifier.size(size).background(Color.White)) {
        val cell = this.size.minDimension / m.size
        for (y in 0 until m.size) for (x in 0 until m.size) {
            // A hair larger than the cell, so no seams show between modules.
            if (m[x, y]) drawRect(Color.Black, Offset(x * cell, y * cell), Size(cell + 0.5f, cell + 0.5f))
        }
    }
}

/** The QR code with its text below and a copy button. */
@Composable
fun QrWithText(m: QrMatrix?, text: String, size: Dp = 320.dp) {
    val clipboard = LocalClipboardManager.current
    var copied by remember(text) { mutableStateOf(false) }
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(8.dp)) {
        m?.let { QrImage(it, size) }
        SelectionContainer { Text(text, style = MaterialTheme.typography.bodySmall, modifier = Modifier.width(size)) }
        TextButton(onClick = { clipboard.setText(AnnotatedString(text)); copied = true }) {
            Text(Strings.t(if (copied) "qr_copied" else "qr_copy"))
        }
    }
}

/**
 * A device link in progress: the QR code to show (new device), then the
 * six digits to compare, large, with one clear "match" and one
 * "different / I did not start this". Nothing links until both devices
 * confirm (PROTOCOL.md 8.11).
 */
@Composable
fun LinkPanel(model: AppModel, newDevice: Boolean) {
    val state by model.state.collectAsState()
    val link = state.link ?: return
    LinkSteps(model, link, newDevice)
}

@Composable
private fun LinkSteps(model: AppModel, link: LinkUi, newDevice: Boolean) {
    val scope = rememberCoroutineScope()
    Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
        when (link.state) {
            "waiting" -> {
                link.text?.let {
                    Text(Strings.t("qr_show_new"), textAlign = TextAlign.Center)
                    QrWithText(link.qr, it)
                }
                Text(Strings.t("link_wait"), style = MaterialTheme.typography.bodySmall)
            }
            "code" -> {
                Text(Strings.t("code_title"), style = MaterialTheme.typography.titleMedium)
                BigCode(link.code)
                Text(Strings.t("code_hold_both"), textAlign = TextAlign.Center, fontWeight = FontWeight.Bold)
                Button(
                    onClick = { scope.launch { if (newDevice) model.confirmNewDevice(true) else model.confirmLink(true) } },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                ) { Text(Strings.t("code_match"), fontSize = 18.sp) }
                OutlinedButton(
                    onClick = { scope.launch { if (newDevice) model.confirmNewDevice(false) else model.confirmLink(false) } },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(Strings.t("code_differ")) }
            }
            "confirmed" -> {
                BigCode(link.code)
                Text(Strings.t("code_other_too"), textAlign = TextAlign.Center)
                Text(Strings.t("link_wait"), style = MaterialTheme.typography.bodySmall)
            }
            "linked" -> Text(Strings.t("link_done"), style = MaterialTheme.typography.titleLarge)
            else -> Text(Strings.t("link_cancelled") + (link.reason?.let { ": $it" } ?: ""), style = MaterialTheme.typography.titleMedium)
        }
    }
}

/** The six digits, as large as the screen allows ("123 456"). */
@Composable
fun BigCode(code: String?) {
    Text(
        code ?: "",
        fontSize = 56.sp, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, letterSpacing = 4.sp,
        modifier = Modifier.padding(vertical = 8.dp),
    )
}

/**
 * Settings, existing device: link a new device. A computer has no camera
 * API the app can rely on, so the new device's link text is pasted. Once
 * accepted, the code steps open in a dialog that stays until the link is
 * done or cancelled.
 */
@Composable
fun LinkNewDevicePaste(model: AppModel) {
    val scope = rememberCoroutineScope()
    val state by model.state.collectAsState()
    var text by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<String?>(null) }
    Text(Strings.t("qr_desktop_paste"), style = MaterialTheme.typography.bodySmall)
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(text, { text = it; message = null }, label = { Text(Strings.t("link_scan")) }, singleLine = true)
        TextButton(onClick = {
            scope.launch {
                val o = model.useScanned(text, CodeKind.DEVICE_LINK)
                message = AppModel.scanMessage(o, CodeKind.DEVICE_LINK)
                if (o == ScanOutcome.ACCEPTED) text = ""
            }
        }) { Text("→") }
    }
    message?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    state.link?.let { link ->
        AlertDialog(
            onDismissRequest = {},
            confirmButton = {
                // While the digits are shown the person answers with one of the two buttons.
                if (link.state != "code" && link.state != "confirmed") TextButton(onClick = model::closeLink) { Text(Strings.t("qr_close")) }
            },
            text = { LinkSteps(model, link, newDevice = false) },
        )
    }
}

/** Settings: my username link as a QR code (dialog), with the text and a copy button. */
@Composable
fun UsernameQrButton(model: AppModel) {
    val state by model.state.collectAsState()
    val link = state.usernameLink ?: return
    var open by remember { mutableStateOf(false) }
    TextButton(onClick = { open = true }) { Text(Strings.t("qr_my_code")) }
    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            confirmButton = { TextButton(onClick = { open = false }) { Text(Strings.t("qr_close")) } },
            text = { QrWithText(state.usernameQr, link, 280.dp) },
        )
    }
}
