package app.tree.desktop

import app.tree.shared.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Folders, pinned order, scheduling, reminders and export, on a real server. */
class OrganizeTest {
    private val url = System.getenv("TREE_URL")!!

    @Test
    fun organize() = runBlocking {
        val dir = Files.createTempDirectory("tree-org").toString()
        val a = AppModel(this, Dispatchers.IO)
        val b = AppModel(this, Dispatchers.IO)
        a.createAccount("$dir/a.db", "pw", "A", url, 8u)
        b.createAccount("$dir/b.db", "pw", "B", url, 8u)
        val g1 = a.newChat()!!; a.invite(g1, b.state.value.account); b.syncNow(); b.accept(g1)
        val g2 = a.newChat()!!; a.renameGroup(g2, "둘")

        assertTrue(a.createFolder("회사"))
        assertTrue(a.fileChat("회사", g1))
        assertEquals(listOf(g1), a.state.value.folders.first { it.name == "회사" }.chats)
        assertTrue(a.fileChat("회사", g1, add = false))
        assertTrue(a.state.value.folders.first { it.name == "회사" }.chats.isEmpty())
        assertTrue(a.deleteFolder("회사"))
        assertFalse(a.state.value.folders.any { it.name == "회사" })

        a.pin(g1, true); a.pin(g2, true)
        val before = a.state.value.chats.filter { it.pinned }.map { it.id }
        assertTrue(a.movePin(before[1], 0))
        assertEquals(before.reversed(), a.state.value.chats.filter { it.pinned }.map { it.id })

        a.openChat(g1)
        val sid = a.schedule(g1, "내일 아침에 보내", System.currentTimeMillis() / 1000 + 86400)
        assertNotNull(sid)
        assertEquals(1, a.state.value.rich.scheduled.size)
        assertTrue(a.cancelScheduled(sid))
        assertTrue(a.state.value.rich.scheduled.isEmpty())

        a.send(g1, "이거 나중에 다시 보기")
        val mid = a.state.value.messages.last().id
        assertNotNull(a.remindMe(g1, mid, System.currentTimeMillis() / 1000 + 3600))
        assertTrue(a.state.value.rich.reminders.any { it.messageId == mid })

        val files = a.exportChat(g1, File(dir, "export").path)
        assertNotNull(files)
        assertTrue(files.isNotEmpty() && files.all { File(it).exists() })
        assertTrue(File(files.first()).readText().contains("이거 나중에 다시 보기"))
        a.stop(); b.stop()
    }
}
