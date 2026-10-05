package app.tree.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Delete
import androidx.compose.material.icons.rounded.Pause
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import app.tree.shared.AppModel
import app.tree.shared.media.Wav
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import uniffi.tree_ffi.Message

private fun mmss(ms: Long): String { val s = ms / 1000; return "%d:%02d".format(s / 60, s % 60) }

/** A voice note in a bubble: play / pause, its loudness bars, its length. */
@Composable
fun VoiceContent(model: AppModel, platform: TreePlatform, m: Message, mine: Boolean, textColor: Color) {
    val scope = rememberCoroutineScope()
    var playing by remember(m.id) { mutableStateOf(false) }
    var bars by remember(m.id) { mutableStateOf<List<Float>?>(null) }
    var wav by remember(m.id) { mutableStateOf<ByteArray?>(null) }
    val length = m.file?.durationMs?.toLong() ?: 0L
    DisposableEffect(m.id) { onDispose { if (playing) platform.stopPlaying() } }
    // Until the note is fetched: even bars from its id, so they do not jump.
    val shown = bars ?: remember(m.id) { val r = java.util.Random(m.id.hashCode().toLong()); List(28) { 0.2f + r.nextFloat() * 0.5f } }
    val accent = if (mine) textColor else MaterialTheme.colorScheme.primary
    Row(Modifier.padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(42.dp).clip(CircleShape).background(accent).clickable {
                if (playing) { platform.stopPlaying(); playing = false; return@clickable }
                scope.launch {
                    val bytes = wav ?: model.fileBytes(m.id)?.also { b -> wav = b; Wav.decode(b)?.let { (pcm, _) -> bars = Wav.levels(pcm, 28) } }
                    if (bytes == null) { model.notice(t("재생할 수 없어요", "Can't play this")); return@launch }
                    playing = true
                    platform.play(bytes) { playing = false }
                }
            },
            contentAlignment = Alignment.Center,
        ) {
            Icon(if (playing) Icons.Rounded.Pause else Icons.Rounded.PlayArrow, if (playing) t("멈춤", "Pause") else t("재생", "Play"),
                tint = if (mine) extra.bubbleMine else MaterialTheme.colorScheme.onPrimary)
        }
        Spacer(Modifier.width(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(2.dp), verticalAlignment = Alignment.CenterVertically) {
            shown.forEach { lv -> Box(Modifier.width(3.dp).height((4 + 22 * lv).dp).clip(RoundedCornerShape(2.dp)).background(accent.copy(alpha = if (bars != null) 0.9f else 0.45f))) }
        }
        Spacer(Modifier.width(10.dp))
        Text(mmss(length), color = extra.bubbleMeta, style = MaterialTheme.typography.labelMedium)
    }
}

/** The composer while recording: a red dot, the time, cancel, and the send button stays. */
@Composable
fun RecordingBar(startedAt: Long, onCancel: () -> Unit) {
    var now by remember { mutableStateOf(System.currentTimeMillis()) }
    LaunchedEffect(startedAt) { while (true) { now = System.currentTimeMillis(); delay(200) } }
    val blink = (now / 500) % 2 == 0L
    Row(Modifier.fillMaxWidth().height(48.dp), verticalAlignment = Alignment.CenterVertically) {
        IconButton(onClick = onCancel) { Icon(Icons.Rounded.Delete, t("녹음 취소", "Cancel"), tint = extra.danger) }
        Box(Modifier.size(10.dp).clip(CircleShape).background(if (blink) extra.danger else extra.danger.copy(alpha = 0.3f)))
        Spacer(Modifier.width(8.dp))
        Text(mmss(now - startedAt), style = MaterialTheme.typography.titleSmall)
        Spacer(Modifier.width(10.dp))
        Text(t("녹음 중", "Recording"), color = extra.muted, style = MaterialTheme.typography.bodyMedium)
    }
}
