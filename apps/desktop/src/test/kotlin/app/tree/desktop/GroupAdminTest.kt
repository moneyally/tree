package app.tree.desktop

import app.tree.shared.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** What the group admin screens do, on a real server. */
class GroupAdminTest {
    private val url = System.getenv("TREE_URL")!!

    @Test
    fun adminActions() = runBlocking {
        val dir = Files.createTempDirectory("tree-admin").toString()
        val a = AppModel(this, Dispatchers.IO)
        val b = AppModel(this, Dispatchers.IO)
        val c = AppModel(this, Dispatchers.IO)
        a.createAccount("$dir/a.db", "pw", "A", url, 8u)
        b.createAccount("$dir/b.db", "pw", "B", url, 8u)
        c.createAccount("$dir/c.db", "pw", "C", url, 8u)
        // Contacts first (only contacts may add someone to a group).
        for (o in listOf(b, c)) {
            val d = a.newChat()!!; a.invite(d, o.state.value.account); o.syncNow(); o.accept(d); a.syncNow()
        }
        val g = a.newChat()!!
        a.renameGroup(g, "G")
        a.invite(g, b.state.value.account); a.invite(g, c.state.value.account)
        b.syncNow(); c.syncNow(); a.syncNow()
        a.openChat(g)
        val members = a.state.value.members
        val bm = members.first { it.name == "B" }.id
        val cm = members.first { it.name == "C" }.id

        // Admin, role, restriction, welcome.
        assertTrue(a.makeAdmin(g, bm, true))
        assertTrue(a.state.value.members.first { it.id == bm }.admin)
        val role = a.createRole(g, "운영진", "#3B82F6", listOf("pin"))
        assertNotNull(role)
        assertTrue(a.assignRole(g, cm, role, true))
        assertEquals("운영진", a.state.value.members.first { it.id == cm }.roles.single().name)
        assertTrue(a.restrict(g, cm, 3600))
        assertTrue(a.state.value.groups.restricted.any { it.member == cm })
        assertTrue(a.setWelcome(g, "어서 와요"))
        assertEquals("어서 와요", a.state.value.groups.welcome)
        assertTrue(a.state.value.groups.adminLog.isNotEmpty())

        // Topics: on, one made, messages go into it.
        assertTrue(a.setChatFeature(g, "chat.topics", true))
        val topic = a.createTopic(g, "공지")
        assertNotNull(topic)
        a.openTopic(topic)
        assertTrue(a.sendInTopic(g, "토픽 안 메시지"))
        assertTrue(a.state.value.groups.topicMessages.any { it.text == "토픽 안 메시지" })
        a.openTopic(null)

        // Invite links revoked; a member removed.
        assertNotNull(a.inviteLink(g))
        assertTrue(a.revokeInviteLinks(g))
        assertTrue(a.removeMember(g, cm))
        assertFalse(a.state.value.members.any { it.id == cm })
        a.stop(); b.stop(); c.stop()
    }
}
