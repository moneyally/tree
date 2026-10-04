package app.tree.android

import android.app.Activity
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.DeviceProtection
import app.tree.shared.Strings
import app.tree.shared.UiState
import kotlinx.coroutines.launch

/** Lock screen extras: PIN field and biometric button, when set up for this profile. */
@Composable
fun UnlockOptions(model: AppModel, profile: String, onOpen: () -> Unit) {
    val scope = rememberCoroutineScope()
    val activity = LocalContext.current as Activity
    var pin by remember { mutableStateOf("") }
    var st by remember { mutableStateOf(model.device.pinState(profile)) }
    if (st.enabled) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(pin, { v -> pin = v.filter { it.isDigit() } }, label = { Text(Strings.t("pin")) }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                modifier = Modifier.weight(1f))
            TextButton(onClick = {
                scope.launch {
                    val secret = if (st.deviceSecret) DeviceSecret.get(profile, create = false) else null
                    val ok = model.device.openWithPin(profile, pin, secret)
                    secret?.fill(0)
                    pin = ""
                    st = model.device.pinState(profile)
                    if (ok) onOpen()
                }
            }) { Text(Strings.t("pin_unlock")) }
        }
        Text("${Strings.t("attempts_left")}: ${st.attemptsLeft}", style = MaterialTheme.typography.bodySmall)
    }
    if (BiometricUnlock.enrolled(profile) && BiometricUnlock.available(activity)) {
        TextButton(onClick = {
            BiometricUnlock.unlock(activity, profile) { key ->
                if (key != null) scope.launch { if (model.device.openWithPlatformKey(profile, key)) onOpen() }
            }
        }) { Text(Strings.t("bio_unlock")) }
    }
}

/** Settings: how the app unlocks after the app lock (PIN with its limits, biometric). */
@Composable
fun AppLockSettings(model: AppModel, state: UiState, profile: String) {
    val scope = rememberCoroutineScope()
    val activity = LocalContext.current as Activity
    var pass by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var st by remember { mutableStateOf(model.device.pinState(profile)) }
    var bio by remember { mutableStateOf(BiometricUnlock.enrolled(profile)) }
    val method = DeviceProtection.lockMethod(state.features)
    Column {
        Text(Strings.t("app_lock"), style = MaterialTheme.typography.titleSmall)
        Text(Strings.t("pin_note"), style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(pass, { pass = it }, label = { Text(Strings.t("passphrase")) }, singleLine = true,
            visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
        if (st.enabled && method == "pin") {
            Text("${Strings.t("pin_on")} (${Strings.t("attempts_left")}: ${st.attemptsLeft})")
            TextButton(onClick = {
                scope.launch { model.device.disablePin(profile); DeviceSecret.forget(profile); st = model.device.pinState(profile) }
            }) { Text(Strings.t("pin_disable")) }
        } else {
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(pin, { v -> pin = v.filter { it.isDigit() } }, label = { Text(Strings.t("pin")) }, singleLine = true,
                    visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                    modifier = Modifier.weight(1f))
                Button(onClick = {
                    scope.launch {
                        // A secret from the keystore goes into the PIN's key derivation.
                        val secret = DeviceSecret.get(profile, create = true)
                        model.device.enablePin(profile, pass, pin, secret)
                        secret?.fill(0)
                        pin = ""
                        st = model.device.pinState(profile)
                    }
                }) { Text(Strings.t("pin_enable")) }
            }
        }
        Text(Strings.t("bio_note"), style = MaterialTheme.typography.bodySmall)
        when {
            !BiometricUnlock.available(activity) -> Text(Strings.t("bio_unavailable"), style = MaterialTheme.typography.bodySmall)
            bio && method == "bio" -> TextButton(onClick = {
                BiometricUnlock.disable(profile)
                bio = false
                scope.launch { model.setFeature("user.app_lock", true, "passphrase") }
            }) { Text(Strings.t("pin_disable")) }
            else -> TextButton(onClick = {
                scope.launch {
                    val key = model.device.keyForPlatformWrap(profile, pass) ?: return@launch
                    BiometricUnlock.enroll(activity, profile, key) { ok ->
                        bio = ok
                        if (ok) scope.launch { model.setFeature("user.app_lock", true, "bio") }
                    }
                }
            }) { Text(Strings.t("bio_enable")) }
        }
        val push = Push.endpoint(activity)
        Text(Strings.t(if (push != null) "push_on" else "push_none"), style = MaterialTheme.typography.bodySmall)
    }
}

/** Search over the history on this phone (`user.search_index`). */
@Composable
fun SearchBar(model: AppModel) {
    val scope = rememberCoroutineScope()
    val found by model.device.search.collectAsState()
    var q by remember { mutableStateOf("") }
    Row(verticalAlignment = Alignment.CenterVertically) {
        OutlinedTextField(q, { q = it }, label = { Text(Strings.t("search")) }, singleLine = true, modifier = Modifier.weight(1f))
        TextButton(onClick = { scope.launch { model.device.search(q) } }) { Text("⌕") }
    }
    if (found.query.isNotEmpty()) {
        if (found.results.isEmpty()) Text(Strings.t("search_none"), style = MaterialTheme.typography.bodySmall)
        found.results.take(20).forEach { m ->
            Text((m.text ?: "").take(80), Modifier.fillMaxWidth().clickable { scope.launch { model.openChat(m.group); model.device.clearSearch() } }.padding(8.dp))
        }
    }
}
