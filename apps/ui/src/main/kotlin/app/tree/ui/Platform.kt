package app.tree.ui

import androidx.compose.runtime.Composable
import app.tree.shared.qr.CodeKind

/**
 * What differs between the phone and the computer. The screens are the
 * same; these pieces are provided by each app.
 */
interface TreePlatform {
    /** Phone layout (bottom bar) or computer layout (side rail, two panes). */
    val isPhone: Boolean

    /** The encrypted profile file of this device. */
    val profilePath: String

    /** The server the app uses unless the person changes it under 고급. */
    val defaultServer: String

    /** The camera scanner (phone) or a paste field (computer) for a Tree code. */
    @Composable
    fun Scanner(kind: CodeKind, onClose: () -> Unit)

    /** Extra ways to open the profile (PIN, biometric) under the passphrase field. */
    @Composable
    fun UnlockOptions(onOpen: () -> Unit) {}

    /** App lock settings this platform supports (PIN, biometric). */
    @Composable
    fun AppLockSettings() {}

    /** Lets the person pick a file and sends it to `group`. */
    fun pickAndSend(group: String, kind: AttachKind)

    /** Lets the person pick a picture; gives its bytes and type. */
    fun pickImage(onPicked: (ByteArray, String) -> Unit)

    /** This device can tell where it is (asks for permission first). */
    val hasLocation: Boolean get() = false

    /** Where the device is now: latitude, longitude, accuracy in metres; null if unknown or refused. */
    fun currentLocation(onResult: (Triple<Double, Double, Int?>?) -> Unit) { onResult(null) }

    /** Lets the person choose where to save a received file. */
    fun saveAs(msgId: String, name: String)

    /**
     * A picture (JPEG/PNG/WebP) as something Compose can draw, scaled down to
     * at most [maxPx] on its longer side (0: as it is); null if unreadable.
     */
    fun decodeImage(bytes: ByteArray, maxPx: Int = 0): androidx.compose.ui.graphics.ImageBitmap?

    /** Copies text to the clipboard. */
    fun copy(text: String)

    /** Screens only this platform has (bot factory, public spaces...), by key; null if none. */
    @Composable
    fun Extra(key: String, onBack: () -> Unit) {}

    /** The app's font (bundled Pretendard); null: the system's. */
    val font: androidx.compose.ui.text.font.FontFamily? get() = null

    /** Which keys [Extra] can show. */
    val extraScreens: List<Pair<String, String>> get() = emptyList()
}

/** PHOTO_ONCE: a picture the receiver can open once (chat.view_once). */
enum class AttachKind { PHOTO, PHOTO_ONCE, FILE }

/** Short Korean / English text by the app's language. */
fun t(ko: String, en: String): String = if (app.tree.shared.Strings.lang == app.tree.shared.Lang.KO) ko else en
