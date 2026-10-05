package app.tree.android

import android.annotation.SuppressLint
import android.media.AudioAttributes
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.AudioTrack
import android.media.MediaRecorder
import app.tree.shared.media.Wav
import java.io.ByteArrayOutputStream

/**
 * Voice notes on the phone: raw 16 kHz mono samples from the microphone,
 * played back from memory. No file ever holds the decrypted note.
 */
object AndroidAudio {
    @Volatile private var rec: AudioRecord? = null
    private var buffer = ByteArrayOutputStream()
    private var reader: Thread? = null
    @Volatile private var track: AudioTrack? = null

    @SuppressLint("MissingPermission")
    fun start(): Boolean {
        if (rec != null) return true
        val min = AudioRecord.getMinBufferSize(Wav.RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT)
        if (min <= 0) return false
        val r = runCatching { AudioRecord(MediaRecorder.AudioSource.MIC, Wav.RATE, AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT, min * 4) }.getOrNull() ?: return false
        if (r.state != AudioRecord.STATE_INITIALIZED) { r.release(); return false }
        r.startRecording()
        buffer = ByteArrayOutputStream()
        rec = r
        val max = Wav.RATE * 2 * Wav.MAX_SECONDS
        reader = Thread {
            val chunk = ByteArray(min)
            while (rec === r) {
                val n = r.read(chunk, 0, chunk.size)
                if (n > 0) synchronized(this) { if (buffer.size() < max) buffer.write(chunk, 0, n) }
            }
        }.apply { isDaemon = true; start() }
        return true
    }

    fun stop(cancel: Boolean): ByteArray? {
        val r = rec ?: return null
        rec = null
        runCatching { r.stop() }
        reader?.join(500)
        r.release()
        val pcm = synchronized(this) { buffer.toByteArray() }
        buffer = ByteArrayOutputStream()
        return if (cancel || pcm.size < Wav.RATE) null else Wav.encode(pcm)
    }

    fun play(wav: ByteArray, onDone: () -> Unit) {
        stopPlaying()
        val (pcm, rate) = Wav.decode(wav) ?: return onDone()
        val t = runCatching {
            AudioTrack.Builder()
                .setAudioAttributes(AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_MEDIA).setContentType(AudioAttributes.CONTENT_TYPE_SPEECH).build())
                .setAudioFormat(AudioFormat.Builder().setSampleRate(rate).setEncoding(AudioFormat.ENCODING_PCM_16BIT).setChannelMask(AudioFormat.CHANNEL_OUT_MONO).build())
                .setTransferMode(AudioTrack.MODE_STATIC).setBufferSizeInBytes(pcm.size).build()
        }.getOrNull() ?: return onDone()
        t.write(pcm, 0, pcm.size)
        track = t
        t.notificationMarkerPosition = pcm.size / 2
        t.setPlaybackPositionUpdateListener(object : AudioTrack.OnPlaybackPositionUpdateListener {
            override fun onMarkerReached(a: AudioTrack) { if (track === a) { track = null; a.release() }; onDone() }
            override fun onPeriodicNotification(a: AudioTrack) {}
        })
        t.play()
    }

    fun stopPlaying() {
        val t = track ?: return
        track = null
        runCatching { t.stop() }
        t.release()
    }
}
