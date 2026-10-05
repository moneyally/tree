package app.tree.desktop

import app.tree.shared.*

import androidx.compose.ui.ImageComposeScene
import androidx.compose.ui.unit.Density
import androidx.compose.ui.use
import app.tree.ui.Route
import app.tree.ui.Tab
import app.tree.ui.TreeNav
import app.tree.ui.TreePlatform
import app.tree.ui.TreeUi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.jetbrains.skia.EncodedImageFormat
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * Renders the real screens, on a real local server, off-screen into PNG
 * files (no display needed): phone size and computer size, dark and light.
 */
class ScreenshotTest {
    private val url = System.getenv("TREE_URL")!!
    private val out = File(System.getenv("TREE_SHOTS") ?: "build/screenshots").apply { mkdirs() }

    /** The computer's platform shown in the phone layout. */
    private class Phone(d: DesktopPlatform) : TreePlatform by d {
        override val isPhone = true
    }

    private fun shot(name: String, model: AppModel, platform: TreePlatform, nav: TreeNav, dark: Boolean, phone: Boolean = true) {
        val (w, h, d) = if (phone) Triple(412 * 2, 900 * 2, 2f) else Triple(1180, 760, 1f)
        ImageComposeScene(width = w, height = h, density = Density(d)) { TreeUi(model, platform, nav, dark) }.use { scene ->
            scene.render(0)
            // Pictures decode off the main thread; give them a moment, then draw again.
            Thread.sleep(400)
            scene.render(500_000_000L)
            Thread.sleep(200)
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
        val scope = CoroutineScope(Dispatchers.IO)
        fun phone(m: AppModel) = Phone(DesktopPlatform(m, scope))

        val fresh = AppModel(this, Dispatchers.IO)
        shot("01-welcome", fresh, phone(fresh), TreeNav(), dark = true)

        val alice = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        val carol = AppModel(this, Dispatchers.IO)
        alice.createAccount("$dir/a.db", "pw", "정원", url, 8u)
        bob.createAccount("$dir/b.db", "pw", "민준", url, 8u)
        carol.createAccount("$dir/c.db", "pw", "서연", url, 8u)

        // A 1:1 chat.
        val dm = alice.newChat()!!
        alice.invite(dm, bob.state.value.account)
        bob.syncNow(); bob.accept(dm); alice.syncNow()
        alice.send(dm, "내일 몇 시에 볼까?")
        bob.syncNow()
        bob.send(dm, "3시 어때? 역 앞 카페에서 👍")

        // Carol is a contact too (only contacts may add someone to a group, user.group_add).
        val dc = alice.newChat()!!
        alice.invite(dc, carol.state.value.account)
        carol.syncNow(); carol.accept(dc); alice.syncNow()
        carol.send(dc, "사진 보내줄게요")

        // A group of three.
        val g = alice.newChat()!!
        alice.renameGroup(g, "주말 등산 모임 🌲")
        alice.invite(g, bob.state.value.account)
        alice.invite(g, carol.state.value.account)
        bob.syncNow(); bob.accept(g)
        carol.syncNow(); carol.accept(g)
        alice.syncNow()
        alice.send(g, "이번 주 토요일 북한산 어때요?")
        bob.syncNow(); carol.syncNow()
        bob.send(g, "좋아요! 몇 시 출발이에요?")
        bob.send(g, "저는 9시 전엔 힘들어요")
        carol.syncNow()
        carol.send(g, "🔥🔥")
        carol.send(g, "저도 갈게요. 김밥 싸 갈게요")
        alice.syncNow()
        alice.openChat(g)
        val first = alice.state.value.messages.first { it.text?.startsWith("이번 주") == true }
        alice.pinMessage(g, first.id, null)
        bob.syncNow()
        bob.openChat(g)
        val bobsQuestion = bob.state.value.messages.first { it.text?.startsWith("좋아요") == true }
        bob.react(g, first.id, "👍")
        carol.syncNow(); carol.react(g, first.id, "👍")
        alice.syncNow()
        alice.reply(g, "10시에 구파발역 2번 출구에서 만나요", bobsQuestion.id)
        alice.send(g, "날씨 좋대요 ☀️ 물 꼭 챙기세요")
        bob.syncNow(); carol.syncNow()
        bob.send(g, "넵 ㅎㅎ")
        // Notes to self.
        alice.openNotes()
        alice.send(alice.state.value.notes!!, "등산화 끈 바꾸기")
        alice.openChat(null)
        // Unread in the list, and someone typing in the group.
        alice.syncNow()
        carol.typing(g, true)
        bob.typing(dm, true)
        alice.syncNow()
        alice.loadContacts()

        val pa = phone(alice)
        shot("02-chats-dark", alice, pa, TreeNav(), dark = true)
        shot("03-chats-light", alice, pa, TreeNav(), dark = false)

        alice.openChat(g)
        alice.syncNow()
        val chatNav = TreeNav().apply { push(Route.Chat(g)) }
        shot("04-group-dark", alice, pa, chatNav, dark = true)
        shot("05-group-light", alice, pa, chatNav, dark = false)
        shot("06-group-info-dark", alice, pa, TreeNav().apply { push(Route.ChatInfo(g)) }, dark = true)

        alice.openChat(dm)
        shot("07-dm-dark", alice, pa, TreeNav().apply { push(Route.Chat(dm)) }, dark = true)
        alice.openChat(null)

        shot("08-settings-dark", alice, pa, TreeNav().apply { tab = Tab.SETTINGS }, dark = true)
        shot("09-profile-dark", alice, pa, TreeNav().apply { tab = Tab.PROFILE }, dark = true)
        shot("10-contacts-dark", alice, pa, TreeNav().apply { tab = Tab.CONTACTS }, dark = true)
        shot("11-privacy-dark", alice, pa, TreeNav().apply { tab = Tab.SETTINGS; push(Route.Settings("privacy")) }, dark = true)

        alice.openChat(g)
        shot("12-desktop-light", alice, DesktopPlatform(alice, scope), TreeNav().apply { push(Route.Chat(g)) }, dark = false, phone = false)
        shot("13-desktop-dark", alice, DesktopPlatform(alice, scope), TreeNav().apply { push(Route.Chat(g)) }, dark = true, phone = false)

        // Linking a computer: its QR code, then the digits.
        val desk = AppModel(this, Dispatchers.IO)
        val text = desk.startLinkNewDevice("$dir/desk.db", "pw", "정원", url)!!
        shot("14-link-qr", desk, phone(desk), TreeNav(), dark = true)
        alice.useScanned(text, app.tree.shared.qr.CodeKind.DEVICE_LINK)
        desk.pollNewDevice()
        shot("15-link-code", desk, phone(desk), TreeNav(), dark = true)
        desk.confirmNewDevice(false)
        alice.closeLink()
        alice.stop(); bob.stop(); carol.stop()
    }
}
