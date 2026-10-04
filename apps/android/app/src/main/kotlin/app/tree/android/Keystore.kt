package app.tree.android

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import app.tree.shared.Strings
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Keys of the system keystore (hardware-backed where the phone has it),
 * through the platform API only: AES-256-GCM keys that never leave it.
 */
private object Keys {
    fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun key(alias: String, spec: () -> KeyGenParameterSpec, create: Boolean): SecretKey? {
        val ks = store()
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        if (!create) return null
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(spec())
        return g.generateKey()
    }

    fun delete(alias: String) = runCatching { store().deleteEntry(alias) }

    fun spec(alias: String) = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)

    /** iv (12 bytes) | ciphertext */
    fun seal(c: Cipher, plain: ByteArray): ByteArray = c.iv + c.doFinal(plain)
}

/**
 * The PIN's device secret: 32 random bytes kept encrypted by a keystore key
 * (`<profile>.pinsecret`). It goes into the PIN's key derivation, so a copy
 * of the profile files is not enough to guess the PIN offline.
 */
object DeviceSecret {
    private const val ALIAS = "tree.pin.secret"

    fun get(profile: String, create: Boolean): ByteArray? = runCatching {
        val f = File("$profile.pinsecret")
        val key = Keys.key(ALIAS, { Keys.spec(ALIAS).build() }, create) ?: return null
        if (f.exists()) {
            val b = f.readBytes()
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, b, 0, 12))
            c.doFinal(b, 12, b.size - 12)
        } else if (create) {
            val s = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key)
            f.writeBytes(Keys.seal(c, s))
            s
        } else null
    }.getOrNull()

    fun forget(profile: String) {
        File("$profile.pinsecret").delete()
        Keys.delete(ALIAS)
    }
}

/**
 * Biometric unlock (`user.app_lock` = `bio`): the database key, encrypted by
 * a keystore key that works only right after a strong biometric check and
 * is invalidated when a new fingerprint or face is enrolled
 * (`<profile>.bio`). Needs Android 11 (API 30) and an enrolled strong
 * biometric; otherwise [available] is false and the app says so.
 */
object BiometricUnlock {
    private const val ALIAS = "tree.bio"

    fun available(a: Activity): Boolean {
        if (Build.VERSION.SDK_INT < 30) return false
        val bm = a.getSystemService(BiometricManager::class.java) ?: return false
        return bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun enrolled(profile: String): Boolean = File("$profile.bio").exists()

    private fun prompt(a: Activity, cipher: Cipher, done: (Cipher?) -> Unit) {
        if (Build.VERSION.SDK_INT < 30) return done(null)
        val p = BiometricPrompt.Builder(a)
            .setTitle(Strings.t("bio_prompt"))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButton(Strings.t("cancel_action"), a.mainExecutor) { _, _ -> done(null) }
            .build()
        p.authenticate(BiometricPrompt.CryptoObject(cipher), CancellationSignal(), a.mainExecutor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = done(result.cryptoObject?.cipher)
            override fun onAuthenticationError(code: Int, msg: CharSequence) = done(null)
        })
    }

    /** Wraps `dbKey` after a biometric check; the array is wiped either way. */
    fun enroll(a: Activity, profile: String, dbKey: ByteArray, done: (Boolean) -> Unit) {
        if (Build.VERSION.SDK_INT < 30 || !available(a)) {
            dbKey.fill(0)
            return done(false)
        }
        runCatching {
            Keys.delete(ALIAS)
            val key = Keys.key(ALIAS, {
                Keys.spec(ALIAS)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .setInvalidatedByBiometricEnrollment(true)
                    .build()
            }, true)!!
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key)
            prompt(a, c) { ok ->
                val r = ok?.let { runCatching { File("$profile.bio").writeBytes(Keys.seal(it, dbKey)) }.isSuccess } ?: false
                dbKey.fill(0)
                done(r)
            }
        }.onFailure {
            dbKey.fill(0)
            done(false)
        }
    }

    /** The database key after a biometric check, or null (refused, invalidated, not set up). */
    fun unlock(a: Activity, profile: String, done: (ByteArray?) -> Unit) {
        runCatching {
            val b = File("$profile.bio").readBytes()
            val key = Keys.key(ALIAS, { Keys.spec(ALIAS).build() }, false) ?: return done(null)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, b, 0, 12))
            prompt(a, c) { ok -> done(ok?.let { runCatching { it.doFinal(b, 12, b.size - 12) }.getOrNull() }) }
        }.onFailure {
            // A new fingerprint invalidated the key: back to the passphrase.
            disable(profile)
            done(null)
        }
    }

    fun disable(profile: String) {
        File("$profile.bio").delete()
        Keys.delete(ALIAS)
    }
}
