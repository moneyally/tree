// Two Tree devices chat through a real server via the Swift bindings (the
// iOS app's path). Run with scripts/ffi_swift_demo.sh (Linux or macOS).
import Foundation

let url = ProcessInfo.processInfo.environment["TREE_URL"]!
let dir = NSTemporaryDirectory() + "tree-swift-\(UUID().uuidString)"
try! FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

func check(_ ok: Bool, _ what: String) {
    if !ok { print("FAILED: \(what)"); exit(1) }
}

do {
    let alice = try TreeSession.create(path: "\(dir)/alice.db", passphrase: "alice pass", name: "alice", server: url, powBits: 12)
    let bob = try TreeSession.create(path: "\(dir)/bob.db", passphrase: "bob pass", name: "bob", server: url, powBits: 12)
    try bob.addContact(account: alice.accountId())

    let g = try alice.createGroup()
    check(try alice.invite(group: g, accountOrUsername: bob.accountId()).accepted, "invite")
    let joined = try bob.sync(wait: 0).contains { if case .joined = $0 { return true } else { return false } }
    check(joined, "bob joined")
    _ = try alice.sync(wait: 0)

    _ = try alice.sendText(group: g, text: "안녕, Swift에서 보냄")
    let texts = try bob.sync(wait: 0).compactMap { e -> String? in
        if case let .text(_, _, _, _, text, _, _, _) = e { return text } else { return nil }
    }
    check(texts.last == "안녕, Swift에서 보냄", "bob got the text: \(texts)")
    print("bob got: \(texts.last!)")

    check(try alice.safetyNumber(account: bob.accountId()) == bob.safetyNumber(account: alice.accountId()), "safety numbers")

    do {
        _ = try TreeSession.open(path: "\(dir)/bob.db", passphrase: "wrong")
        check(false, "wrong passphrase opened the profile")
    } catch TreeError.WrongKey {
        print("wrong passphrase refused")
    }
    do {
        _ = try alice.setChatFeature(group: g, key: "chat.e2e", apply: false, option: nil)
        check(false, "released end-to-end encryption")
    } catch let TreeError.Feature(code) {
        print("chat.e2e cannot be released: \(code)")
    }
    print("Swift demo: all checks passed")
} catch {
    print("FAILED: \(error)")
    exit(1)
}
