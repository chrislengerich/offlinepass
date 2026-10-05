package com.linuxpass.app.vault

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * A tiny encrypter for the few strings the app must keep but must never store
 * plainly: the sync repo's personal access token, the one credential that
 * would open the whole repository to whoever reads the device.
 *
 * The key lives in the AndroidKeyStore, the hardware-backed keychain the
 * system never exports: an attacker with root and the app's files can read the
 * ciphertext below but cannot decrypt it, because the key never left the
 * secure element. The secret itself (a raw PAT, up to a few hundred bytes)
 * rides in [SecretStore.KEYS] as an AES/GCM blob - authenticated, so a byte
 * flipped in storage fails the tag instead of decrypting into garbage.
 *
 * The store is deliberately not "encrypted SharedPreferences" from a library:
 * a PAT is one value, and wrapping one value in a whole keystore library is a
 * dependency to keep patched for no benefit over the few lines here.
 */
class SecretStore(context: Context) {

    private val prefs = context.applicationContext.getSharedPreferences(KEYS, Context.MODE_PRIVATE)

    /**
     * Encrypts [value] under the AndroidKeyStore key and stores it as [key],
     * Base64 of the IV-prefixed ciphertext. Re-encrypts on every write so the
     * key never accumulates for a value that has changed.
     */
    fun save(key: String, value: String) {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, androidKey())
        val blob = cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        prefs.edit().putString(key, Base64.encodeToString(blob, Base64.NO_WRAP)).apply()
    }

    /**
     * Decrypts the value stored under [key], or null when absent or when the
     * stored blob no longer decrypts (key invalidated, or storage tampered
     * with). A failed read is "no credential" to every caller: nothing is
     * worse than a half-unwrapped token.
     */
    fun read(key: String): String? {
        val encoded = prefs.getString(key, null) ?: return null
        val blob = runCatching { Base64.decode(encoded, Base64.NO_WRAP) }.getOrNull() ?: run {
            Log.w(TAG, "Secret $key is not valid Base64; treating as absent")
            return null
        }
        val tag = blob.copyOfRange(0, GCM_IV_LENGTH)
        val ciphertext = blob.copyOfRange(GCM_IV_LENGTH, blob.size)
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, androidKey(), GCMParameterSpec(TAG_BITS, tag))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        }.getOrElse {
            Log.w(TAG, "Could not decrypt secret $key (${it.message}); treating as absent")
            null
        }
    }

    /** Drops the stored blob, e.g. when the owner rotates the token. */
    fun delete(key: String) {
        prefs.edit().remove(key).apply()
    }

    fun contains(key: String): Boolean = prefs.contains(key)

    /** The AndroidKeyStore secret, created once per app install. */
    private fun androidKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private const val TAG = "SecretStore"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "linuxpass_secrets"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_IV_LENGTH = 12
        private const val TAG_BITS = 128

        /** The preference filename; also the externally-known storage name. */
        const val KEYS = "linuxpass_secret_keys"

        /** The repo credential this store keeps. */
        /** The camera's repo token: read and write, because it pushes. */
        const val KEY_REPO_PAT = "sync_repo_pat"

        /**
         * The viewer's repo token: read only. A device that only ever pulls
         * footage is not handed a credential that could rewrite the repo.
         */
        const val KEY_VIEWER_PAT = "sync_viewer_pat"
    }
}