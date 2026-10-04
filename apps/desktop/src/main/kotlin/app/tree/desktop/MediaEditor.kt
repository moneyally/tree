package app.tree.desktop

import app.tree.shared.Strings
import app.tree.shared.media.Box
import app.tree.shared.media.EditOp
import app.tree.shared.media.JpegMeta
import app.tree.shared.media.MediaEdit
import app.tree.shared.media.Pt
import app.tree.shared.media.Raster
import app.tree.shared.media.TextPainter
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.toComposeImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.dp
import java.awt.Color
import java.awt.Font
import java.awt.RenderingHints
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.File
import javax.imageio.IIOImage
import javax.imageio.ImageIO
import javax.imageio.ImageWriteParam

/** Desktop side of the editor: AWT pictures <-> [Raster], text, JPEG export. */
object DesktopMedia {
    fun toRaster(img: BufferedImage): Raster {
        val r = Raster(img.width, img.height)
        img.getRGB(0, 0, img.width, img.height, r.pixels, 0, img.width)
        return r
    }

    fun toImage(r: Raster): BufferedImage {
        val img = BufferedImage(r.width, r.height, BufferedImage.TYPE_INT_ARGB)
        img.setRGB(0, 0, r.width, r.height, r.pixels, 0, r.width)
        return img
    }

    /** Text with Java2D (antialiased, bold sans serif, a dark outline). */
    val text = TextPainter { target, op ->
        val img = toImage(target)
        val g = img.createGraphics()
        g.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        g.font = Font(Font.SANS_SERIF, Font.BOLD, maxOf(1, op.size.toInt()))
        val base = op.y + g.fontMetrics.ascent
        g.color = Color(0, 0, 0, 160)
        for ((dx, dy) in listOf(-1 to 0, 1 to 0, 0 to -1, 0 to 1)) g.drawString(op.text, op.x + dx, base + dy)
        g.color = Color(op.argb, true)
        g.drawString(op.text, op.x, base)
        g.dispose()
        img.getRGB(0, 0, img.width, img.height, target.pixels, 0, img.width)
    }

    fun load(file: File): Raster? = ImageIO.read(file)?.let(::toRaster)

    /**
     * JPEG of the picture. Java's encoder writes no EXIF; [JpegMeta.strip]
     * removes any metadata segment anyway, so nothing about the camera,
     * place or time leaves the device.
     */
    fun jpeg(r: Raster, quality: Float = 0.9f): ByteArray {
        val rgb = BufferedImage(r.width, r.height, BufferedImage.TYPE_INT_RGB)
        val g = rgb.createGraphics()
        g.color = Color.WHITE
        g.fillRect(0, 0, r.width, r.height)
        g.drawImage(toImage(r), 0, 0, null)
        g.dispose()
        val out = ByteArrayOutputStream()
        val writer = ImageIO.getImageWritersByFormatName("jpeg").next()
        ImageIO.createImageOutputStream(out).use { ios ->
            writer.output = ios
            val p = writer.defaultWriteParam
            p.compressionMode = ImageWriteParam.MODE_EXPLICIT
            p.compressionQuality = quality
            writer.write(null, IIOImage(rgb, null, null), p)
        }
        writer.dispose()
        return JpegMeta.strip(out.toByteArray()) ?: error("encoder wrote a broken JPEG")
    }

    /** Preview picture for the message: at most 320 px, at most 32 KiB. */
    fun thumbnail(r: Raster): ByteArray {
        var side = 320
        while (true) {
            val (w, h) = MediaEdit.fit(r.width, r.height, side)
            for (q in listOf(0.7f, 0.5f, 0.3f)) {
                val b = jpeg(MediaEdit.scaleDown(r, w, h), q)
                if (b.size <= 32 * 1024) return b
            }
            side /= 2
        }
    }

    /** A picture file as it is sent without editing: re-encoded, so its metadata is gone. */
    fun cleanCopy(file: File): ByteArray? = load(file)?.let { jpeg(it) }
}

/** Editing tools. */
private enum class Tool { CROP, DRAW, TEXT, BLUR }

/**
 * The editor screen: the picture with the operations so far, tools, undo,
 * send. Sends `jpeg`, the picture size and a preview picture.
 */
@Composable
fun EditorDialog(original: Raster, onSend: (ByteArray, Int, Int, ByteArray) -> Unit, onCancel: () -> Unit) {
    val ops = remember { mutableStateListOf<EditOp>() }
    var tool by remember { mutableStateOf(Tool.DRAW) }
    var caption by remember { mutableStateOf("") }
    var view by remember { mutableStateOf(IntSize(1, 1)) }
    var drag by remember { mutableStateOf<List<Pt>>(emptyList()) }
    val edited = remember(ops.toList()) { MediaEdit.apply(original, ops, DesktopMedia.text) }
    val bitmap = remember(edited) { DesktopMedia.toImage(edited).toComposeImageBitmap() }
    // From the view (picture fitted inside it) to picture pixels.
    fun toPicture(x: Float, y: Float): Pt {
        val s = minOf(view.width.toFloat() / edited.width, view.height.toFloat() / edited.height)
        val ox = (view.width - edited.width * s) / 2
        val oy = (view.height - edited.height * s) / 2
        return Pt((x - ox) / s, (y - oy) / s)
    }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(Strings.t("edit")) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    for ((t, k) in listOf(Tool.CROP to "crop", Tool.DRAW to "draw", Tool.TEXT to "text", Tool.BLUR to "blur")) {
                        FilterChip(selected = tool == t, onClick = { tool = t }, label = { Text(Strings.t(k)) })
                    }
                    TextButton(onClick = { ops += EditOp.Rotate(1) }) { Text(Strings.t("rotate")) }
                    TextButton(onClick = { if (ops.isNotEmpty()) ops.removeAt(ops.size - 1) }) { Text(Strings.t("undo")) }
                }
                if (tool == Tool.TEXT) OutlinedTextField(caption, { caption = it }, label = { Text(Strings.t("text")) }, singleLine = true)
                Image(
                    bitmap, null,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.width(640.dp).height(420.dp)
                        .onSizeChanged { view = it }
                        .pointerInput(tool, caption, edited) {
                            if (tool == Tool.TEXT) {
                                detectTapGestures { p ->
                                    val at = toPicture(p.x, p.y)
                                    if (caption.isNotBlank()) {
                                        ops += EditOp.Text(caption, at.x.toInt(), at.y.toInt(), maxOf(16f, edited.height / 14f), 0xFFFFFFFF.toInt())
                                    }
                                }
                            } else {
                                detectDragGestures(
                                    onDragStart = { p -> drag = listOf(toPicture(p.x, p.y)) },
                                    onDrag = { change, _ -> drag = drag + toPicture(change.position.x, change.position.y) },
                                    onDragEnd = {
                                        val pts = drag
                                        drag = emptyList()
                                        if (pts.size >= 2) {
                                            val box = Box.of(pts.first(), pts.last())
                                            ops += when (tool) {
                                                Tool.CROP -> EditOp.Crop(box)
                                                Tool.BLUR -> EditOp.Blur(box)
                                                else -> EditOp.Stroke(pts, 0xFFE53935.toInt(), maxOf(3f, edited.width / 150f))
                                            }
                                        }
                                    },
                                )
                            }
                        },
                )
                Text(Strings.t("original_stays"), modifier = Modifier.fillMaxWidth().padding(top = 4.dp))
            }
        },
        confirmButton = {
            TextButton(onClick = { onSend(DesktopMedia.jpeg(edited), edited.width, edited.height, DesktopMedia.thumbnail(edited)) }) {
                Text(Strings.t("send"))
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text(Strings.t("cancel_send")) } },
    )
}
