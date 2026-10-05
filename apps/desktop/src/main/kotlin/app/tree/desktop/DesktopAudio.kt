package app.tree.desktop

import app.tree.shared.media.Wav
import java.io.ByteArrayOutputStream
import javax.sound.sampled.AudioFormat
import javax.sound.sampled.AudioSystem
import javax.sound.sampled.SourceDataLine
import javax.sound.sampled.TargetDataLine

/** Voice notes on a computer: the default microphone and speakers, 16 kHz mono (Java Sound). */
object DesktopAudio {
    private val format = AudioFormat(Wav.RATE.toFloat(), 16, 1, true, false)
    @Volatile private var line: TargetDataLine? = null
    private var buffer = ByteArrayOutputStream()
    private var reader: Thread? = null
    @Volatile private var playing: SourceDataLine? = null
    private var player: Thread? = null

    val available: Boolean get() = runCatching { AudioSystem.isLineSupported(javax.sound.sampled.DataLine.Info(TargetDataLine::class.java, format)) }.getOrDefault(false)

    fun start(): Boolean {
        if (line != null) return true
        val l = runCatching { AudioSystem.getTargetDataLine(format).also { it.open(format); it.start() } }.getOrNull() ?: return false
        buffer = ByteArrayOutputStream()
        line = l
        val max = Wav.RATE * 2 * Wav.MAX_SECONDS
        reader = Thread {
            val chunk = ByteArray(3200)
            while (line === l) {
                val n = l.read(chunk, 0, chunk.size)
                if (n > 0) synchronized(this) { if (buffer.size() < max) buffer.write(chunk, 0, n) }
            }
        }.apply { isDaemon = true; start() }
        return true
    }

    fun stop(cancel: Boolean): ByteArray? {
        val l = line ?: return null
        line = null
        l.stop(); l.close()
        reader?.join(500)
        val pcm = synchronized(this) { buffer.toByteArray() }
        buffer = ByteArrayOutputStream()
        // Under half a second is a mis-tap.
        return if (cancel || pcm.size < Wav.RATE) null else Wav.encode(pcm)
    }

    fun play(wav: ByteArray, onDone: () -> Unit) {
        stopPlaying()
        val (pcm, rate) = Wav.decode(wav) ?: return onDone()
        val f = AudioFormat(rate.toFloat(), 16, 1, true, false)
        val out = runCatching { AudioSystem.getSourceDataLine(f).also { it.open(f); it.start() } }.getOrNull() ?: return onDone()
        playing = out
        player = Thread {
            var at = 0
            while (playing === out && at < pcm.size) {
                val n = minOf(3200, pcm.size - at)
                out.write(pcm, at, n)
                at += n
            }
            if (playing === out) out.drain()
            out.close()
            if (playing === out) playing = null
            onDone()
        }.apply { isDaemon = true; start() }
    }

    fun stopPlaying() {
        val p = playing ?: return
        playing = null
        p.stop(); p.flush()
    }
}
