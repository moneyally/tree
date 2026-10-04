package app.tree.desktop

import app.tree.shared.AppModel
import app.tree.shared.media.MediaEdit
import app.tree.shared.media.Raster
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import uniffi.tree_ffi.NetworkKind
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Media through the screens' model against a real server (scripts/desktop_test.sh). */
class MediaModelTest {
    private val url = System.getenv("TREE_URL")!!
    private val dir = Files.createTempDirectory("tree-desktop-media").toString()

    @Test
    fun editedPictureThumbnailAutoDownloadProgressAndSaveAs() = runBlocking {
        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        assertTrue(alice.createAccount("$dir/alice.db", "alice pass", "alice", url, 8u))
        assertTrue(bob.createAccount("$dir/bob.db", "bob pass", "bob", url, 8u))
        val g = assertNotNull(alice.newChat())
        assertTrue(alice.invite(g, bob.state.value.account))
        bob.syncNow()
        bob.accept(g) // alice becomes bob's contact
        alice.syncNow()
        bob.downloadDir = File(dir, "bob-downloads")
        bob.setNetwork(NetworkKind.WIFI)

        // An edited picture: JPEG without metadata, its size and preview in the message.
        val edited = MediaEdit.rotate(Raster(300, 200, IntArray(300 * 200) { i -> 0xFF000000.toInt() or (i * 2654435 and 0xFFFFFF) }), 1)
        val jpeg = DesktopMedia.jpeg(edited)
        val thumb = DesktopMedia.thumbnail(edited)
        assertTrue(alice.sendMedia(g, jpeg, "sea.jpg", "image/jpeg", AppModel.picture(edited.width, edited.height, thumb)))
        bob.syncNow()
        val (msgId, file) = bob.state.value.files.entries.single()
        assertEquals(200u to 300u, file.width to file.height)
        assertContentEquals(thumb, file.thumbnail)
        // From a contact on Wi-Fi and small: it downloaded by itself.
        val got = assertNotNull(bob.state.value.downloaded[msgId])
        assertContentEquals(jpeg, File(got).readBytes())

        // A larger file in slices: progress shows between slices, then it is sent.
        val big = ByteArray(3 * 1024 * 1024 + 5000) { (it * 31).toByte() }
        val s = alice.session!!
        s.setUploadSlice((1024 * 1024).toULong())
        val sent = s.sendMedia(g, big, "big.bin", "application/octet-stream", AppModel.plainFile())
        assertTrue(s.uploading())
        alice.updateTransfers()
        val t = assertNotNull(alice.state.value.transfers[sent.msgId])
        assertTrue(t.upload && t.done > 0u && t.done < t.total, "$t")
        alice.pumpUploads()
        assertTrue(alice.state.value.transfers.isEmpty())
        alice.openChat(g)
        assertEquals("sent", alice.state.value.messages.last().status)
        assertTrue(alice.fileOf(sent.msgId)!!.id.isNotEmpty(), "own history knows the id")

        // bob: over 20 MiB? no, but 3 MiB on Wi-Fi does download; save as copies it.
        bob.syncNow()
        val dest = File(dir, "saved.bin")
        assertTrue(bob.saveFile(sent.msgId, dest))
        assertContentEquals(big, dest.readBytes())
        // Mobile network and the default option (Wi-Fi only): nothing by itself.
        bob.setNetwork(NetworkKind.MOBILE)
        assertTrue(alice.sendMedia(g, ByteArray(10) { 1 }, "small.bin", "application/octet-stream"))
        bob.syncNow()
        val last = bob.state.value.files.keys.first { it != msgId && it != sent.msgId }
        assertTrue(last !in bob.state.value.downloaded)
        alice.stop(); bob.stop()
    }
}
