import java.nio.file.Files
import uniffi.tree_ffi.TreeException
import uniffi.tree_ffi.TreeEvent
import uniffi.tree_ffi.TreeSession

fun main() {
    val url = System.getenv("TREE_URL")
    val dir = Files.createTempDirectory("tree-kt").toString()
    val bits = 12u
    val alice = TreeSession.create("$dir/alice.db", "alice pass", "alice", url, bits)
    val bob = TreeSession.create("$dir/bob.db", "bob pass", "bob", url, bits)
    bob.addContact(alice.accountId())

    val g = alice.createGroup()
    check(alice.invite(g, bob.accountId()).accepted)
    check(bob.sync(0u).any { it is TreeEvent.Joined }) { "bob joined" }
    alice.sync(0u)

    alice.sendText(g, "안녕, Kotlin에서 보냄")
    val got = bob.sync(0u).filterIsInstance<TreeEvent.Text>().last()
    check(got.text == "안녕, Kotlin에서 보냄") { got.text }
    println("bob got: ${got.text}")

    bob.sendText(g, "잘 받았어")
    check(alice.sync(0u).filterIsInstance<TreeEvent.Text>().last().text == "잘 받았어")
    check(alice.safetyNumber(bob.accountId()) == bob.safetyNumber(alice.accountId()))

    try {
        TreeSession.open("$dir/bob.db", "wrong")
        error("wrong passphrase opened the profile")
    } catch (e: TreeException.WrongKey) {
        println("wrong passphrase refused")
    }
    try {
        alice.setChatFeature(g, "chat.e2e", false, null)
        error("released end-to-end encryption")
    } catch (e: TreeException) {
        println("chat.e2e cannot be released: $e")
    }
    println("Kotlin/JVM demo: all checks passed")
}
