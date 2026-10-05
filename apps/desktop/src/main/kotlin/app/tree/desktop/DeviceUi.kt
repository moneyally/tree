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
