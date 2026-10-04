package app.tree.desktop

import app.tree.shared.*

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import uniffi.tree_ffi.Feature
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Device-level switches (Wave 1 items 7-10): the window and keyboard
 * decisions both platforms apply, and through a real server the PIN app
 * lock with its attempt limit, the search index, notifications and
 * settings sync between two linked devices (scripts/desktop_test.sh).
 */
class DeviceProtectionTest {
    private val url = System.getenv("TREE_URL")!!
    private val dir = Files.createTempDirectory("tree-device").toString()

    private fun f(key: String, on: Boolean, option: String? = null) =
        Feature(key, on, option, null, emptyList(), null)

    private fun state(vararg fs: Feature, blocked: Boolean = false) = UiState(features = fs.toList(), screenshotBlocked = blocked)

    @Test
    fun appSwitcherBlurAndScreenshotBlockAreSeparateOnAndroid() {
        val blur = f("user.app_switcher_blur", true)
        val noBlur = f("user.app_switcher_blur", false)
        // API 33+: blur only hides the recents snapshot; screenshots stay allowed.
        assertEquals(AndroidWindow(secure = false, hideFromRecents = true), DeviceProtection.androidWindow(state(blur), false, 34))
        assertEquals(AndroidWindow(secure = false, hideFromRecents = true), DeviceProtection.androidWindow(state(blur), true, 34))
        assertEquals(AndroidWindow(secure = false, hideFromRecents = false), DeviceProtection.androidWindow(state(noBlur), true, 34))
        // Older Android: the secure flag only while in the background.
        assertEquals(AndroidWindow(secure = false, hideFromRecents = false), DeviceProtection.androidWindow(state(blur), false, 30))
        assertEquals(AndroidWindow(secure = true, hideFromRecents = false), DeviceProtection.androidWindow(state(blur), true, 30))
        assertEquals(AndroidWindow(secure = false, hideFromRecents = false), DeviceProtection.androidWindow(state(noBlur), true, 30))
        // A chat that blocks screenshots: secure while it is open, whatever the blur says.
        assertEquals(AndroidWindow(secure = true, hideFromRecents = false), DeviceProtection.androidWindow(state(noBlur, blocked = true), false, 34))
        assertEquals(AndroidWindow(secure = true, hideFromRecents = true), DeviceProtection.androidWindow(state(blur, blocked = true), false, 34))
        assertEquals(AndroidWindow(secure = true, hideFromRecents = false), DeviceProtection.androidWindow(state(noBlur, blocked = true), false, 28))
    }

    @Test
    fun keyboardCaptureAndLockDecisions() {
        assertTrue(DeviceProtection.incognitoKeyboard(state(f("user.incognito_keyboard", true))))
        assertFalse(DeviceProtection.incognitoKeyboard(state(f("user.incognito_keyboard", false))))
        assertTrue(DeviceProtection.desktopCaptureExcluded(state(f("user.pc_screen_security", true))))
        assertFalse(DeviceProtection.desktopCaptureExcluded(state(f("user.pc_screen_security", false))))
        assertTrue(DeviceProtection.desktopCaptureExcluded(state(f("user.pc_screen_security", false), blocked = true)), "a chat that blocks screenshots")
        assertNull(DeviceProtection.lockMethod(listOf(f("user.app_lock", false, "pin"))))
        assertEquals("passphrase", DeviceProtection.lockMethod(listOf(f("user.app_lock", true))))
        assertEquals("pin", DeviceProtection.lockMethod(listOf(f("user.app_lock", true, "pin"))))
        // This test machine offers no capture exclusion: the settings row says so.
        if (!System.getProperty("os.name").lowercase().startsWith("win")) {
            assertFalse(DesktopProtection.guard.available)
            assertFalse(DesktopProtection.active.value, "never claims protection it does not have")
        }
    }

    @Test
    fun pinAppLockWithAttemptLimit() = runBlocking {
        val path = "$dir/pin.db"
        val m = AppModel(this, Dispatchers.IO)
        assertTrue(m.createAccount(path, "pin pass", "dana", url, 8u))
        assertFalse(m.device.pinState(path).enabled)
        assertFalse(m.device.enablePin(path, "wrong pass", "246810", null), "the passphrase is checked")
        m.clearMessages()
        assertTrue(m.device.enablePin(path, "pin pass", "246810", null))
        assertEquals("pin", DeviceProtection.lockMethod(m.state.value.features))
        assertEquals(10u, m.device.pinState(path).attemptsLeft)
        assertTrue(m.lockIfEnabled())
        assertFalse(m.state.value.signedIn)
        assertFalse(m.device.openWithPin(path, "000000", null))
        assertTrue(m.state.value.error!!.contains("9"), m.state.value.error)
        m.clearMessages()
        assertTrue(m.device.openWithPin(path, "246810", null))
        assertEquals(10u, m.device.pinState(path).attemptsLeft, "a right PIN resets the count")
        assertTrue(m.lockIfEnabled())
        repeat(10) { assertFalse(m.device.openWithPin(path, "111111", null)) }
        assertFalse(m.device.pinState(path).enabled, "ten wrong PINs: PIN unlock is gone")
        assertFalse(m.device.openWithPin(path, "246810", null))
        assertEquals(Strings.t("pin_unavailable"), m.state.value.error)
        assertTrue(m.openProfile(path, "pin pass"), "the passphrase still opens it")
        // PIN off again: back to the passphrase.
        assertTrue(m.device.enablePin(path, "pin pass", "246810", null))
        assertTrue(m.device.disablePin(path))
        assertFalse(m.device.pinState(path).enabled)
        assertEquals("passphrase", DeviceProtection.lockMethod(m.state.value.features))
        m.stop()
    }

    @Test
    fun searchNotificationsAndSettingsSync() = runBlocking {
        val phone = AppModel(this, Dispatchers.IO)
        val bob = AppModel(this, Dispatchers.IO)
        assertTrue(phone.createAccount("$dir/s-phone.db", "phone pass", "erin", url, 8u))
        assertTrue(bob.createAccount("$dir/s-bob.db", "bob pass", "bob", url, 8u))
        val shown = mutableListOf<Pair<String, String?>>()
        phone.notifier = { title, text -> shown += title to text }
        val g = assertNotNull(bob.newChat())
        assertTrue(bob.invite(g, phone.state.value.account))
        phone.syncNow()
        phone.accept(g)
        bob.syncNow()

        // Notifications: a stranger's request never shows text; then the name only (default).
        assertTrue(bob.send(g, "first message"))
        phone.syncNow()
        assertEquals(null, shown.last().second)
        assertTrue(phone.setFeature("user.notification_content", true))
        assertTrue(bob.send(g, "with text now"))
        phone.syncNow()
        assertEquals("with text now", shown.last().second)
        // This chat blocks screenshots (the user's own block): no text on the lock screen.
        phone.session!!.setScreenshotBlock(g, true)
        assertTrue(bob.send(g, "secret plans"))
        phone.syncNow()
        assertEquals(null, shown.last().second)
        phone.session!!.setScreenshotBlock(g, false)
        // Silent: nothing.
        val before = shown.size
        assertTrue(bob.send(g, "shh", silent = true))
        phone.syncNow()
        assertEquals(before, shown.size)

        // Search over the encrypted history; release deletes the index.
        assertEquals(listOf("secret plans"), phone.device.search("plan").map { it.text })
        assertEquals(g, phone.device.search("secret").single().group)
        assertTrue(phone.setFeature("user.search_index", false))
        assertTrue(phone.device.search("plan").isEmpty())
        assertNotNull(phone.state.value.error)
        phone.clearMessages()
        assertTrue(phone.setFeature("user.search_index", true))
        assertEquals(listOf("secret plans"), phone.device.search("PLANS").map { it.text })

        // A second device of the same account; settings follow through the self group.
        val desk = AppModel(this, Dispatchers.IO)
        val text = assertNotNull(desk.startLinkNewDevice("$dir/s-desk.db", "desk pass", "erin", url))
        assertEquals("waiting", phone.scanLink(text))
        assertEquals("code", desk.pollNewDevice())
        assertEquals("code", phone.linkStatus())
        assertEquals("confirmed", desk.confirmNewDevice(true))
        assertEquals("linked", phone.confirmLink(true))
        assertEquals("linked", desk.pollNewDevice())
        desk.syncNow()
        phone.syncNow()
        desk.syncNow()
        assertTrue(desk.state.value.chats.none { it.id == desk.session!!.selfGroup() }, "the self group is never a chat")
        assertTrue(phone.setFeature("user.pc_screen_security", false))
        assertTrue(phone.setFeature("user.incognito_keyboard", false))
        desk.syncNow()
        val f = desk.state.value.features
        assertFalse(DeviceProtection.desktopCaptureExcluded(desk.state.value))
        assertFalse(f.single { it.key == "user.incognito_keyboard" }.applied)
        assertTrue(desk.setFeature("user.pc_screen_security", true))
        phone.syncNow()
        assertTrue(DeviceProtection.desktopCaptureExcluded(phone.state.value))
        phone.stop(); bob.stop(); desk.stop()
    }
}
