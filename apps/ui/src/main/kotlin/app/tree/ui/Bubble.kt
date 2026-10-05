package app.tree.ui

import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Outline
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathOperation
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp

/**
 * A message bubble. Every bubble keeps a strip of [tail] on the sender's
 * side so a run lines up; the last one of a run draws a small curved tail
 * there, out of its bottom corner. Corners between bubbles of one run are
 * tighter ([joined]) so the run reads as one block.
 */
class BubbleShape(
    private val mine: Boolean,
    private val first: Boolean,
    private val last: Boolean,
    private val radius: Dp = 18.dp,
    private val joined: Dp = 6.dp,
    val tail: Dp = 7.dp,
) : Shape {
    override fun createOutline(size: Size, layoutDirection: LayoutDirection, density: Density): Outline {
        val r = with(density) { radius.toPx() }
        val j = with(density) { joined.toPx() }
        val t = with(density) { tail.toPx() }
        val w = size.width
        val h = size.height
        val left = if (mine) 0f else t
        val right = if (mine) w - t else w
        fun c(v: Float) = CornerRadius(v.coerceAtMost(minOf(right - left, h) / 2), v.coerceAtMost(minOf(right - left, h) / 2))
        // The corners on the sender's side are tight inside a run and sharp under the tail.
        val sideTop = if (first) r else j
        val sideBottom = if (last) 0f else j
        val body = Path().apply {
            addRoundRect(
                if (mine) RoundRect(left, 0f, right, h, topLeftCornerRadius = c(r), topRightCornerRadius = c(sideTop), bottomRightCornerRadius = c(sideBottom), bottomLeftCornerRadius = c(r))
                else RoundRect(left, 0f, right, h, topLeftCornerRadius = c(sideTop), topRightCornerRadius = c(r), bottomRightCornerRadius = c(r), bottomLeftCornerRadius = c(sideBottom)),
            )
        }
        if (!last) return Outline.Generic(body)
        val rise = minOf(h * 0.6f, t * 2.4f)
        val tailPath = Path().apply {
            if (mine) {
                moveTo(right, h - rise)
                cubicTo(right, h - rise * 0.35f, right + t * 0.45f, h - 1f, w, h)
                lineTo(right - t, h)
            } else {
                moveTo(left, h - rise)
                cubicTo(left, h - rise * 0.35f, left - t * 0.45f, h - 1f, 0f, h)
                lineTo(left + t, h)
            }
            close()
        }
        return Outline.Generic(Path().apply { op(body, tailPath, PathOperation.Union) })
    }
}
