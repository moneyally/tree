package app.tree.android

import android.content.ClipData
import android.content.ClipboardManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import app.tree.shared.AppModel
import app.tree.shared.qr.CodeKind
import app.tree.ui.AttachKind
import app.tree.ui.TreePlatform
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

/**
 * The phone's side of the shared screens: the camera scanner, system file
 * pickers, PIN and biometric unlock. The pickers are registered by
 * [Launchers], which the activity puts in its content once.
 */
class AndroidPlatform(private val activity: ComponentActivity, private val model: AppModel, override val profilePath: String) : TreePlatform {
    override val isPhone = true
    override val defaultServer: String = BuildConfig.TREE_SERVER

    /** The bundled font (apps/ui/res/font). */
    override val font = androidx.compose.ui.text.font.FontFamily(
        androidx.compose.ui.text.font.Font(R.font.pretendard_regular, androidx.compose.ui.text.font.FontWeight.Normal),
        androidx.compose.ui.text.font.Font(R.font.pretendard_medium, androidx.compose.ui.text.font.FontWeight.Medium),
        androidx.compose.ui.text.font.Font(R.font.pretendard_semibold, androidx.compose.ui.text.font.FontWeight.SemiBold),
        androidx.compose.ui.text.font.Font(R.font.pretendard_bold, androidx.compose.ui.text.font.FontWeight.Bold),
    )

    private var pickPhoto: ((String) -> Unit)? = null
    private var pickFile: ((String) -> Unit)? = null
    private var createDoc: ((String) -> Unit)? = null
    private var pendingGroup: String? = null
    private var pendingKind: AttachKind = AttachKind.FILE
    private var pendingImage: ((ByteArray, String) -> Unit)? = null
    private var pendingSave: String? = null

    /** Registers the system pickers; call once inside the activity's content. */
    @Composable
    fun Launchers() {
        val open = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri -> if (uri != null) picked(uri) }
        val save = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            val id = pendingSave
            pendingSave = null
            if (uri != null && id != null) activity.lifecycleScopeLaunch {
                val bytes = model.fileBytes(id) ?: return@lifecycleScopeLaunch
                withContext(Dispatchers.IO) { activity.contentResolver.openOutputStream(uri)?.use { it.write(bytes) } }
                model.notice(app.tree.ui.t("저장했어요", "Saved"))
            }
        }
        SideEffect {
            pickPhoto = { open.launch("image/*") }
            pickFile = { open.launch("*/*") }
            createDoc = { name -> save.launch(name) }
        }
    }

    private fun picked(uri: Uri) {
        val image = pendingImage
        val group = pendingGroup
        val kind = pendingKind
        pendingImage = null
        pendingGroup = null
        activity.lifecycleScopeLaunch {
            val r = activity.contentResolver
            val name = withContext(Dispatchers.IO) { displayName(uri) } ?: "file"
            val mime = r.getType(uri) ?: "application/octet-stream"
            val bytes = withContext(Dispatchers.IO) { r.openInputStream(uri)?.use { it.readBytes() } } ?: return@lifecycleScopeLaunch
            when {
                image != null -> withContext(Dispatchers.Default) { reencode(bytes, 1024) }?.let { (jpeg, _) -> image(jpeg, "image/jpeg") }
                group == null -> {}
                kind == AttachKind.PHOTO && mime.startsWith("image/") -> {
                    // Re-encoded here, so the original's metadata (place, camera) stays on the phone.
                    val out = withContext(Dispatchers.Default) { reencode(bytes, 2560) }
                    if (out == null) model.sendBytes(group, bytes, name, mime)
                    else {
                        val (jpeg, bmp) = out
                        val thumb = withContext(Dispatchers.Default) { thumbnail(bmp) }
                        model.sendMedia(group, jpeg, name.substringBeforeLast('.') + ".jpg", "image/jpeg", AppModel.picture(bmp.width, bmp.height, thumb))
                        bmp.recycle()
                    }
                }
                else -> model.sendBytes(group, bytes, name, mime)
            }
        }
    }

    private fun displayName(uri: Uri): String? =
        activity.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }

    /** The picture at most [maxSide] px, as a fresh JPEG without metadata; the bitmap is the caller's to recycle. */
    private fun reencode(bytes: ByteArray, maxSide: Int): Pair<ByteArray, Bitmap>? {
        val bmp = decode(bytes, maxSide) ?: return null
        val out = ByteArrayOutputStream()
        bmp.compress(Bitmap.CompressFormat.JPEG, 86, out)
        return out.toByteArray() to bmp
    }

    /** The preview sent with a picture: at most 320 px and 32 KiB. */
    private fun thumbnail(bmp: Bitmap): ByteArray {
        var side = 320
        while (true) {
            val scale = side.toFloat() / maxOf(bmp.width, bmp.height)
            val small = if (scale < 1f) Bitmap.createScaledBitmap(bmp, (bmp.width * scale).toInt().coerceAtLeast(1), (bmp.height * scale).toInt().coerceAtLeast(1), true) else bmp
            for (q in listOf(70, 50, 30)) {
                val out = ByteArrayOutputStream()
                small.compress(Bitmap.CompressFormat.JPEG, q, out)
                if (out.size() <= 32 * 1024) {
                    if (small !== bmp) small.recycle()
                    return out.toByteArray()
                }
            }
            if (small !== bmp) small.recycle()
            side /= 2
        }
    }

    /** Decodes with the largest power-of-two step that keeps [maxSide], then scales the rest. */
    private fun decode(bytes: ByteArray, maxSide: Int): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        var sample = 1
        if (maxSide > 0) while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= maxSide) sample *= 2
        val bmp = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample }) ?: return null
        val longer = maxOf(bmp.width, bmp.height)
        if (maxSide <= 0 || longer <= maxSide) return bmp
        val s = maxSide.toFloat() / longer
        val scaled = Bitmap.createScaledBitmap(bmp, (bmp.width * s).toInt().coerceAtLeast(1), (bmp.height * s).toInt().coerceAtLeast(1), true)
        if (scaled !== bmp) bmp.recycle()
        return scaled
    }

    @Composable
    override fun Scanner(kind: CodeKind, onClose: () -> Unit) = ScanScreen(model, kind, onClose)

    @Composable
    override fun UnlockOptions(onOpen: () -> Unit) = app.tree.android.UnlockOptions(model, profilePath, onOpen)

    @Composable
    override fun AppLockSettings() {
        val state by model.state.collectAsState()
        Box(Modifier.padding(horizontal = 20.dp, vertical = 8.dp)) { app.tree.android.AppLockSettings(model, state, profilePath) }
    }

    override fun pickAndSend(group: String, kind: AttachKind) {
        pendingGroup = group
        pendingKind = kind
        (if (kind == AttachKind.PHOTO) pickPhoto else pickFile)?.invoke("")
    }

    override fun pickImage(onPicked: (ByteArray, String) -> Unit) {
        pendingGroup = null
        pendingImage = onPicked
        pickPhoto?.invoke("")
    }

    override fun saveAs(msgId: String, name: String) {
        pendingSave = msgId
        createDoc?.invoke(name)
    }

    override fun decodeImage(bytes: ByteArray, maxPx: Int): ImageBitmap? =
        runCatching { decode(bytes, maxPx)?.asImageBitmap() }.getOrNull()

    override fun copy(text: String) {
        activity.getSystemService(ClipboardManager::class.java)?.setPrimaryClip(ClipData.newPlainText("Tree", text))
    }
}

private fun ComponentActivity.lifecycleScopeLaunch(block: suspend kotlinx.coroutines.CoroutineScope.() -> Unit) {
    lifecycleScope.launch(block = block)
}
