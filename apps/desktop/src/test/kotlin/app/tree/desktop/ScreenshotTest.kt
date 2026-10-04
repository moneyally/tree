package app.tree.desktop

import app.tree.shared.*

import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.use
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.jetbrains.skia.EncodedImageFormat
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertTrue

/** Renders the real screens off-screen into PNG files (no display needed). */
class ScreenshotTest {
    private val url = System.getenv("TREE_URL")!!
    private val out = File(System.getenv("TREE_SHOTS") ?: "build/screenshots").apply { mkdirs() }

    private fun shot(name: String, model: AppModel) {
        ImageComposeScene(width = 900, height = 600) { App(model) }.use { scene ->
            scene.render() // first frame
            val img = scene.render(1_000_000_000L)
            val png = img.encodeToData(EncodedImageFormat.PNG)!!.bytes
            File(out, "$name.png").writeBytes(png)
            assertTrue(png.size > 1000, name)
        }
    }

    @Test
    fun screens() = runBlocking {
        Strings.lang = Lang.KO
        val dir = Files.createTempDirectory("tree-shots").toString()
        val signIn = AppModel(this, Dispatchers.IO)
        shot("01-sign-in", signIn)

        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        alice.createAccount("$dir/a.db", "pw", "앨리스", url, 8u)
        bob.createAccount("$dir/b.db", "pw", "밥", url, 8u)
        val g = alice.newChat()!!
        alice.invite(g, bob.state.value.account)
        bob.syncNow()
        bob.accept(g)
        alice.syncNow()
        alice.send(g, "안녕, 트리에서 보내는 첫 메시지")
        bob.syncNow()
        bob.send(g, "잘 받았어!")
        alice.syncNow()
        alice.openChat(g)
        shot("02-chat", alice)

        // Linking a computer: its QR code, then the digits on both devices.
        val desk = AppModel(this, Dispatchers.IO)
        val text = desk.startLinkNewDevice("$dir/desk.db", "pw", "앨리스", url)!!
        shot("03-link-qr", desk)
        alice.useScanned(text, app.tree.shared.qr.CodeKind.DEVICE_LINK)
        desk.pollNewDevice()
        shot("04-link-code", desk)
        desk.confirmNewDevice(false)
        alice.closeLink()
        alice.stop(); bob.stop()
    }
}
