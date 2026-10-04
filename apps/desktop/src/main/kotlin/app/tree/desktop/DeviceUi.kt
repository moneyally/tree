package app.tree.desktop

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.DeviceProtection
import app.tree.shared.Strings
import app.tree.shared.UiState
import kotlinx.coroutines.launch

/**
 * What a user setting does on a computer, shown under its switch, so the
 * settings screen never pretends: the keyboard and app-switcher switches
 * act on phones only, and screen-capture protection says whether this
 * system offers it.
 */
@Composable
fun platformNote(key: String): String? {
    val active by DesktopProtection.active.collectAsState()
    return when (key) {
        "user.incognito_keyboard" -> Strings.t("note_incognito_desktop")
        "user.app_switcher_blur" -> Strings.t("note_blur_desktop")
        "user.pc_screen_security" -> Strings.t(
            when {
                !DesktopProtection.guard.available -> "capture_none"
                active -> "capture_active"
                else -> "capture_off"
            },
        )
        else -> null
    }
}

/** Search over the history on this computer (`user.search_index`). */
@Composable
fun SearchBox(model: AppModel) {
    val scope = rememberCoroutineScope()
    val found by model.device.search.collectAsState()
    var q by remember { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(q, { q = it }, label = { Text(Strings.t("search")) }, singleLine = true, modifier = Modifier.width(170.dp))
        TextButton(onClick = { scope.launch { model.device.search(q) } }) { Text("⌕") }
    }
    if (found.query.isNotEmpty()) {
        if (found.results.isEmpty()) Text(Strings.t("search_none"), style = MaterialTheme.typography.bodySmall)
        found.results.take(20).forEach { m ->
            Text(
                (m.text ?: "").take(60),
                Modifier.fillMaxWidth().clickable { scope.launch { model.openChat(m.group); model.device.clearSearch() } }.padding(4.dp),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

/** The lock screen's PIN field, while PIN unlock is on for this profile. */
@Composable
fun PinUnlockRow(model: AppModel, path: String, onOpen: suspend () -> Unit) {
    val scope = rememberCoroutineScope()
    var pin by remember { mutableStateOf("") }
    var st by remember { mutableStateOf(model.device.pinState(path)) }
    if (!st.enabled) return
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(pin, { v -> pin = v.filter { it.isDigit() } }, label = { Text(Strings.t("pin")) }, singleLine = true,
            visualTransformation = PasswordVisualTransformation())
        TextButton(onClick = {
            scope.launch {
                val ok = model.device.openWithPin(path, pin, null)
                pin = ""
                st = model.device.pinState(path)
                if (ok) onOpen()
            }
        }) { Text(Strings.t("pin_unlock")) }
    }
    Text("${Strings.t("attempts_left")}: ${st.attemptsLeft}", style = MaterialTheme.typography.bodySmall)
}

/** Settings: the app lock's PIN (computers have no biometric unlock in this app). */
@Composable
fun AppLockPanel(model: AppModel, state: UiState, path: String) {
    val scope = rememberCoroutineScope()
    var pass by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var st by remember { mutableStateOf(model.device.pinState(path)) }
    Column {
        Text(Strings.t("app_lock"), style = MaterialTheme.typography.titleSmall)
        Text(Strings.t("pin_note"), style = MaterialTheme.typography.bodySmall)
        if (st.enabled && DeviceProtection.lockMethod(state.features) == "pin") {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("${Strings.t("pin_on")} (${Strings.t("attempts_left")}: ${st.attemptsLeft})")
                TextButton(onClick = { scope.launch { model.device.disablePin(path); st = model.device.pinState(path) } }) {
                    Text(Strings.t("pin_disable"))
                }
            }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(pass, { pass = it }, label = { Text(Strings.t("passphrase")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.width(220.dp))
                OutlinedTextField(pin, { v -> pin = v.filter { it.isDigit() } }, label = { Text(Strings.t("pin")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), modifier = Modifier.width(160.dp))
                Button(onClick = {
                    scope.launch {
                        model.device.enablePin(path, pass, pin, null)
                        pass = ""
                        pin = ""
                        st = model.device.pinState(path)
                    }
                }) { Text(Strings.t("pin_enable")) }
            }
        }
    }
}
