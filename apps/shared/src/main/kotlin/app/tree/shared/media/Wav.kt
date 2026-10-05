package app.tree.shared.media

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Voice messages as plain WAV: 16 kHz, mono, 16-bit. Every device plays it
 * without a codec; about 32 KB a second, so the apps keep notes short
 * ([MAX_SECONDS]). Recording and playback are the platforms'; this only
 * wraps and reads the samples.
 */
object Wav {
    const val RATE = 16_000
    const val MAX_SECONDS = 300

    /** A WAV file around little-endian 16-bit mono samples. */
    fun encode(pcm: ByteArray, rate: Int = RATE): ByteArray {
        val out = ByteArrayOutputStream(44 + pcm.size)
        val h = ByteBuffer.allocate(44).order(ByteOrder.LITTLE_ENDIAN)
        h.put("RIFF".toByteArray()).putInt(36 + pcm.size).put("WAVE".toByteArray())
        h.put("fmt ".toByteArray()).putInt(16).putShort(1).putShort(1).putInt(rate).putInt(rate * 2).putShort(2).putShort(16)
        h.put("data".toByteArray()).putInt(pcm.size)
        out.write(h.array())
        out.write(pcm)
        return out.toByteArray()
    }

    /** The samples and their rate, if this is a 16-bit mono PCM WAV; null otherwise. */
    fun decode(wav: ByteArray): Pair<ByteArray, Int>? {
        if (wav.size < 44 || String(wav, 0, 4) != "RIFF" || String(wav, 8, 4) != "WAVE") return null
        val b = ByteBuffer.wrap(wav).order(ByteOrder.LITTLE_ENDIAN)
        var at = 12
        var rate = 0
        var ok = false
        while (at + 8 <= wav.size) {
            val id = String(wav, at, 4)
            val len = b.getInt(at + 4)
            if (len < 0 || at + 8 + len > wav.size) return null
            when (id) {
                "fmt " -> {
                    if (len < 16) return null
                    val format = b.getShort(at + 8).toInt()
                    val channels = b.getShort(at + 10).toInt()
                    rate = b.getInt(at + 12)
                    val bits = b.getShort(at + 22).toInt()
                    ok = format == 1 && channels == 1 && bits == 16 && rate in 8_000..48_000
                }
                "data" -> return if (ok) wav.copyOfRange(at + 8, at + 8 + len) to rate else null
            }
            at += 8 + len + (len and 1)
        }
        return null
    }

    /** Length in milliseconds of 16-bit mono samples. */
    fun durationMs(pcm: ByteArray, rate: Int = RATE): Long = pcm.size / 2 * 1000L / rate

    /** [bars] loudness levels 0..1 across the note, for the bubble's waveform. */
    fun levels(pcm: ByteArray, bars: Int): List<Float> {
        val samples = pcm.size / 2
        if (samples == 0 || bars <= 0) return List(bars) { 0f }
        val b = ByteBuffer.wrap(pcm).order(ByteOrder.LITTLE_ENDIAN)
        val per = maxOf(1, samples / bars)
        val raw = List(bars) { i ->
            var peak = 0
            val from = i * per
            for (s in from until minOf(samples, from + per)) peak = maxOf(peak, kotlin.math.abs(b.getShort(s * 2).toInt()))
            peak.toFloat()
        }
        val top = raw.maxOrNull()?.takeIf { it > 0f } ?: return raw.map { 0f }
        return raw.map { (it / top).coerceIn(0.08f, 1f) }
    }
}
