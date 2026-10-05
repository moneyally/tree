package app.tree.shared.qr

/**
 * What a scanned or pasted text is. The scanner accepts exactly three kinds
 * of text and nothing else (APP_PROTOCOL.md 6.5): a device link
 * `tree://link/<194 base64url characters>`, a username link
 * `tree://u/<22 base64url characters>` and a safety number
 * `tree://safety/<87 base64url characters>`. Anything else (web addresses, other
 * schemes, other Tree links) is "not a Tree code" and is never opened.
 */
enum class CodeKind { DEVICE_LINK, USERNAME, SAFETY, NOT_TREE }

data class TreeCode(val kind: CodeKind, val text: String)

object TreeCodes {
    const val DEVICE_PREFIX = "tree://link/"
    const val USERNAME_PREFIX = "tree://u/"
    /** b64u(145 bytes): version 2 invitation (PROTOCOL.md 8.11). */
    const val DEVICE_LEN = 194
    /** b64u(16 bytes): the username link token (PROTOCOL.md 8.4). */
    const val USERNAME_LEN = 22
    const val SAFETY_PREFIX = "tree://safety/"
    /** b64u(65 bytes): version and both fingerprints (`safety_qr`). */
    const val SAFETY_LEN = 87

    /** The safety QR text for the core's payload. */
    fun safetyText(payload: ByteArray): String =
        SAFETY_PREFIX + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(payload)

    /** The payload of a safety code (from [parse]), for `verify`. */
    fun safetyPayload(code: TreeCode): ByteArray? =
        if (code.kind != CodeKind.SAFETY) null
        else runCatching { java.util.Base64.getUrlDecoder().decode(code.text.removePrefix(SAFETY_PREFIX)) }.getOrNull()

    private val b64u = Regex("[A-Za-z0-9_-]+")

    /** Leading and trailing white space is dropped (as the Rust parsers do); nothing else is changed. */
    fun parse(raw: String): TreeCode {
        val t = raw.trim()
        fun body(prefix: String, len: Int): String? =
            if (t.startsWith(prefix)) t.substring(prefix.length).takeIf { it.length == len && b64u.matches(it) } else null
        body(DEVICE_PREFIX, DEVICE_LEN)?.let { return TreeCode(CodeKind.DEVICE_LINK, t) }
        body(USERNAME_PREFIX, USERNAME_LEN)?.let { return TreeCode(CodeKind.USERNAME, t) }
        body(SAFETY_PREFIX, SAFETY_LEN)?.let { return TreeCode(CodeKind.SAFETY, t) }
        return TreeCode(CodeKind.NOT_TREE, t)
    }
}
