package app.tree.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.automirrored.rounded.Undo
import androidx.compose.material.icons.rounded.BlurOn
import androidx.compose.material.icons.rounded.Brush
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.Crop
import androidx.compose.material.icons.rounded.RotateRight
import androidx.compose.material.icons.rounded.TextFields
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.media.Box as PicBox
import app.tree.shared.media.EditOp
import app.tree.shared.media.MediaEdit
import app.tree.shared.media.Pt
import app.tree.shared.media.Raster
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private enum class Tool { DRAW, TEXT, BLUR, CROP }

private val INKS = listOf(0xFFFFFFFF, 0xFFE53935, 0xFFFDD835, 0xFF3FCB8E, 0xFF3B82F6, 0xFF111111).map { it.toInt() }

/** The picture as sent: JPEG without metadata, its size and a preview (at most 320 px, 32 KiB). */
private fun export(platform: TreePlatform, r: Raster): Triple<ByteArray, Int, ByteArray?>? {
    val jpeg = platform.encodeJpeg(r, 0.88f) ?: return null
    var side = 320
    var thumb: ByteArray? = null
    while (thumb == null && side >= 40) {
        val (w, h) = MediaEdit.fit(r.width, r.height, side)
        val small = MediaEdit.scaleDown(r, w, h)
        for (q in listOf(0.7f, 0.5f, 0.3f)) {
            val b = platform.encodeJpeg(small, q) ?: break
            if (b.size <= 32 * 1024) { thumb = b; break }
        }
        side /= 2
    }
    return Triple(jpeg, 0, thumb)
}

/**
 * Edits a picture before it is sent: draw, text, cover (mosaic), crop,
 * rotate, undo. The original stays on this device; only the result is sent,
 * as a fresh JPEG without the camera's metadata. `once`: a view-once photo
 * (sent without a preview).
 */
@Composable
fun PhotoEditor(model: AppModel, platform: TreePlatform, group: String, original: Raster, name: String, viewOnceAllowed: Boolean, startOnce: Boolean, onClose: () -> Unit) {
    val scope = rememberCoroutineScope()
    val ops = remember { mutableStateListOf<EditOp>() }
    var tool by remember { mutableStateOf(Tool.DRAW) }
    var ink by remember { mutableStateOf(INKS[1]) }
    var once by remember { mutableStateOf(startOnce) }
    var view by remember { mutableStateOf(IntSize(1, 1)) }
    var drag by remember { mutableStateOf<List<Offset>>(emptyList()) }
    var textAt by remember { mutableStateOf<Pt?>(null) }
    var sending by remember { mutableStateOf(false) }
    val edited = remember(ops.toList()) { MediaEdit.apply(original, ops, platform.textPainter) }
    val bitmap = remember(edited) { platform.rasterBitmap(edited) }
    val scale = minOf(view.width.toFloat() / edited.width, view.height.toFloat() / edited.height)
    val ox = (view.width - edited.width * scale) / 2
    val oy = (view.height - edited.height * scale) / 2
    fun toPicture(p: Offset) = Pt((p.x - ox) / scale, (p.y - oy) / scale)

    Column(Modifier.fillMaxSize().background(Color.Black).statusBarsPadding().navigationBarsPadding()) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 4.dp, vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            IconButton(onClick = onClose) { Icon(Icons.Rounded.Close, t("취소", "Cancel"), tint = Color.White) }
            Spacer(Modifier.weight(1f))
            IconButton(onClick = { if (ops.isNotEmpty()) ops.removeAt(ops.lastIndex) }, enabled = ops.isNotEmpty()) {
                Icon(Icons.AutoMirrored.Rounded.Undo, t("되돌리기", "Undo"), tint = if (ops.isNotEmpty()) Color.White else Color.White.copy(alpha = 0.3f))
            }
            IconButton(onClick = { ops += EditOp.Rotate(1) }) { Icon(Icons.Rounded.RotateRight, t("돌리기", "Rotate"), tint = Color.White) }
        }
        Box(
            Modifier.weight(1f).fillMaxWidth().onSizeChanged { view = it }
                .pointerInput(tool, ink, edited) {
                    if (tool == Tool.TEXT) detectTapGestures { p -> textAt = toPicture(p) }
                    else detectDragGestures(
                        onDragStart = { p -> drag = listOf(p) },
                        onDrag = { change, _ -> drag = drag + change.position },
                        onDragEnd = {
                            val pts = drag.map(::toPicture)
                            drag = emptyList()
                            if (pts.size >= 2) ops += when (tool) {
                                Tool.CROP -> EditOp.Crop(PicBox.of(pts.first(), pts.last()))
                                Tool.BLUR -> EditOp.Blur(PicBox.of(pts.first(), pts.last()))
                                else -> EditOp.Stroke(pts, ink, maxOf(4f, edited.width / 120f))
                            }
                        },
                    )
                },
            contentAlignment = Alignment.Center,
        ) {
            bitmap?.let { Image(it, null, Modifier.fillMaxSize(), contentScale = ContentScale.Fit) }
            // What is being drawn right now, before it becomes an operation.
            Canvas(Modifier.fillMaxSize()) {
                if (drag.size >= 2) {
                    if (tool == Tool.DRAW) {
                        for (i in 1 until drag.size) drawLine(Color(ink), drag[i - 1], drag[i], strokeWidth = maxOf(4f, edited.width / 120f) * scale)
                    } else {
                        val a = drag.first(); val b = drag.last()
                        drawRect(Color.White, Offset(minOf(a.x, b.x), minOf(a.y, b.y)), androidx.compose.ui.geometry.Size(kotlin.math.abs(b.x - a.x), kotlin.math.abs(b.y - a.y)), style = Stroke(2.dp.toPx()))
                    }
                }
            }
        }
        if (tool == Tool.DRAW || tool == Tool.TEXT) Row(Modifier.fillMaxWidth().padding(vertical = 8.dp), horizontalArrangement = Arrangement.Center) {
            INKS.forEach { c ->
                Box(Modifier.padding(horizontal = 6.dp).size(28.dp).clip(CircleShape).background(Color(c))
                    .let { if (c == ink) it.border(3.dp, Color.White, CircleShape) else it.border(1.dp, Color.White.copy(alpha = 0.4f), CircleShape) }
                    .clickable { ink = c })
            }
        }
        Row(Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            ToolButton(Icons.Rounded.Brush, t("그리기", "Draw"), tool == Tool.DRAW) { tool = Tool.DRAW }
            ToolButton(Icons.Rounded.TextFields, t("글자", "Text"), tool == Tool.TEXT) { tool = Tool.TEXT }
            ToolButton(Icons.Rounded.BlurOn, t("가리기", "Cover"), tool == Tool.BLUR) { tool = Tool.BLUR }
            ToolButton(Icons.Rounded.Crop, t("자르기", "Crop"), tool == Tool.CROP) { tool = Tool.CROP }
            if (viewOnceAllowed) ToolButton(Icons.Rounded.Visibility, t("한 번 보기", "View once"), once) { once = !once }
            Spacer(Modifier.weight(1f))
            Box(
                Modifier.size(52.dp).clip(CircleShape).background(MaterialTheme.colorScheme.primary).clickable(enabled = !sending) {
                    sending = true
                    scope.launch {
                        val out = withContext(Dispatchers.Default) { export(platform, edited) }
                        if (out != null) {
                            val (jpeg, _, thumb) = out
                            model.sendMedia(group, jpeg, "$name.jpg", "image/jpeg",
                                AppModel.picture(edited.width, edited.height, if (once) null else thumb).copy(viewOnce = once))
                        }
                        onClose()
                    }
                },
                contentAlignment = Alignment.Center,
            ) { Icon(Icons.AutoMirrored.Rounded.Send, t("보내기", "Send"), tint = MaterialTheme.colorScheme.onPrimary) }
        }
    }
    textAt?.let { at ->
        var text by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { textAt = null },
            title = { Text(t("글자 넣기", "Add text")) },
            text = { OutlinedTextField(text, { text = it.take(80) }, singleLine = true, shape = RoundedCornerShape(14.dp)) },
            confirmButton = {
                TextButton(onClick = {
                    if (text.isNotBlank()) ops += EditOp.Text(text, at.x.toInt(), at.y.toInt(), maxOf(18f, edited.height / 14f), ink)
                    textAt = null
                }) { Text(t("넣기", "Add"), fontWeight = FontWeight.SemiBold) }
            },
            dismissButton = { TextButton(onClick = { textAt = null }) { Text(t("취소", "Cancel")) } },
        )
    }
}

@Composable
private fun ToolButton(icon: ImageVector, label: String, on: Boolean, onClick: () -> Unit) {
    Column(
        Modifier.clip(RoundedCornerShape(12.dp)).clickable(onClick = onClick).padding(horizontal = 8.dp, vertical = 6.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(icon, label, tint = if (on) MaterialTheme.colorScheme.primary else Color.White)
        Spacer(Modifier.height(2.dp))
        Text(label, color = if (on) MaterialTheme.colorScheme.primary else Color.White, style = MaterialTheme.typography.labelSmall)
    }
}
