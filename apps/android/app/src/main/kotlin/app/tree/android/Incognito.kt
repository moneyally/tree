package app.tree.android

import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputMethodRequest

/**
 * `user.incognito_keyboard`: while `enabled`, every text field inside
 * `content` asks the keyboard not to learn from what is typed (the
 * system's "no personalized learning" input flag). It is a request to the
 * keyboard app: a keyboard that ignores the flag still sees the text.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun IncognitoKeyboard(enabled: Boolean, content: @Composable () -> Unit) {
    InterceptPlatformTextInput(
        interceptor = { request, next ->
            val r = if (!enabled) request else object : PlatformTextInputMethodRequest {
                override fun createInputConnection(outAttributes: EditorInfo): InputConnection =
                    request.createInputConnection(outAttributes).also {
                        outAttributes.imeOptions = outAttributes.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                    }
            }
            next.startInputMethod(r)
        },
        content = content,
    )
}
