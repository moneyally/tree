package app.tree.desktop

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.qr.CodeKind
import app.tree.ui.AttachKind
import app.tree.ui.BackHeader
import app.tree.ui.PasteScanner
import app.tree.ui.TreePlatform
import app.tree.ui.t
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.awt.FileDialog
import java.awt.Frame
import java.awt.Toolkit
import java.awt.datatransfer.StringSelection
import java.io.File

/** The computer's side of the shared screens: file dialogs, paste instead of camera, PIN lock. */
class DesktopPlatform(private val model: AppModel, private val scope: CoroutineScope) : TreePlatform {
    override val isPhone = false
    override val profilePath: String = profilePath()
    override val defaultServer: String = System.getenv("TREE_URL") ?: System.getProperty("tree.server") ?: "https://"

    @Composable
    override fun Scanner(kind: CodeKind, onClose: () -> Unit) = PasteScanner(model, kind, onClose)

    @Composable
    override fun UnlockOptions(onOpen: () -> Unit) {
        PinUnlockRow(model, profilePath) { onOpen() }
    }

    @Composable
    override fun AppLockSettings() {
        val state by model.state.collectAsState()
        Box(Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) { AppLockPanel(model, state, profilePath) }
    }

    private fun open(title: String): File? {
        val d = FileDialog(null as Frame?, title, FileDialog.LOAD)
        d.isVisible = true
        return d.file?.let { File(d.directory, it) }
    }

    override fun pickAndSend(group: String, kind: AttachKind) {
        val f = open(if (kind == AttachKind.FILE) t("파일 보내기", "Send file") else t("사진 보내기", "Send photo")) ?: return
        scope.launch {
            val picture = if (kind != AttachKind.FILE) DesktopMedia.load(f) else null
            val once = kind == AttachKind.PHOTO_ONCE
            if (picture == null) {
                // Not a picture this computer can read: a view-once one is not sent as a plain file.
                if (once) { model.notice(t("사진만 한 번 보기로 보낼 수 있어요", "Only pictures can be view-once")); return@launch }
                model.sendFile(group, f)
            } else {
                // Re-encoded, so the original's metadata (place, camera) stays on this computer.
                val jpeg = DesktopMedia.jpeg(picture)
                model.sendMedia(group, jpeg, f.nameWithoutExtension + ".jpg", "image/jpeg",
                    AppModel.picture(picture.width, picture.height, if (once) null else DesktopMedia.thumbnail(picture)).copy(viewOnce = once))
            }
        }
    }

    override fun pickImage(onPicked: (ByteArray, String) -> Unit) {
        val f = open(t("사진 고르기", "Choose a photo")) ?: return
        val picture = DesktopMedia.load(f) ?: return
        onPicked(DesktopMedia.jpeg(picture), "image/jpeg")
    }

    override fun saveAs(msgId: String, name: String) {
        val d = FileDialog(null as Frame?, t("다른 이름으로 저장", "Save as"), FileDialog.SAVE)
        d.file = name
        d.isVisible = true
        if (d.file != null) scope.launch { model.saveFile(msgId, File(d.directory, d.file)) }
    }

    override fun decodeImage(bytes: ByteArray, maxPx: Int): ImageBitmap? = runCatching {
        val img = org.jetbrains.skia.Image.makeFromEncoded(bytes)
        val longer = maxOf(img.width, img.height)
        if (maxPx <= 0 || longer <= maxPx) return@runCatching img.toComposeImageBitmap()
        // Scaled down once here, so the cache holds what is drawn, not the original.
        val s = maxPx.toFloat() / longer
        val w = (img.width * s).toInt().coerceAtLeast(1)
        val h = (img.height * s).toInt().coerceAtLeast(1)
        val surface = org.jetbrains.skia.Surface.makeRasterN32Premul(w, h)
        surface.canvas.drawImageRect(img, org.jetbrains.skia.Rect.makeWH(img.width.toFloat(), img.height.toFloat()), org.jetbrains.skia.Rect.makeWH(w.toFloat(), h.toFloat()), org.jetbrains.skia.SamplingMode.LINEAR, null, true)
        surface.makeImageSnapshot().toComposeImageBitmap().also { img.close(); surface.close() }
    }.getOrNull()

    override fun copy(text: String) {
        runCatching { Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(text), null) }
    }

    override val font = Fonts.pretendard

    override val canRecord: Boolean get() = DesktopAudio.available
    override fun startRecording(onStarted: (Boolean) -> Unit) = onStarted(DesktopAudio.start())
    override fun stopRecording(cancel: Boolean): ByteArray? = DesktopAudio.stop(cancel)
    override fun play(wav: ByteArray, onDone: () -> Unit) = DesktopAudio.play(wav, onDone)
    override fun stopPlaying() = DesktopAudio.stopPlaying()

    override val extraScreens = listOf(
        "bots" to t("봇 만들기", "Bot factory"),
        "public" to t("공개 공간", "Public spaces"),
    )

    @Composable
    override fun Extra(key: String, onBack: () -> Unit) {
        val state by model.state.collectAsState()
        Column(Modifier.fillMaxSize()) {
            BackHeader(extraScreens.firstOrNull { it.first == key }?.second ?: "", onBack)
            Box(Modifier.padding(horizontal = 16.dp)) {
                when (key) {
                    "bots" -> BotsScreen(model, state)
                    "public" -> PublicScreen(model, state)
                }
            }
        }
    }
}

/** The bundled font, from the classpath (apps/ui/res). */
object Fonts {
    val pretendard: androidx.compose.ui.text.font.FontFamily by lazy {
        fun f(name: String, w: androidx.compose.ui.text.font.FontWeight) = androidx.compose.ui.text.platform.Font("font/pretendard_$name.otf", w)
        androidx.compose.ui.text.font.FontFamily(
            f("regular", androidx.compose.ui.text.font.FontWeight.Normal),
            f("medium", androidx.compose.ui.text.font.FontWeight.Medium),
            f("semibold", androidx.compose.ui.text.font.FontWeight.SemiBold),
            f("bold", androidx.compose.ui.text.font.FontWeight.Bold),
        )
    }
}
