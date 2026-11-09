package com.offlinepass.app.vault

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.MGF1ParameterSpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

/**
 * The device-local sealed cache behind the experimental "encrypt individual items while in use"
 * toggle. The GPG-encrypted envelope in the repo stays the only synced
 * representation; this cache is never committed anywhere.
 *
 * At rest in app-private storage:
 *  - PLAINTEXT: the metadata the search/list UI already shows — names,
 *    usernames, emails, URLs, modify times, uuids — plus the envelope's
 *    public bookkeeping (rev, deviceId, paired paste devices, tombstones;
 *    all non-secret by design — the pairing record is a public key).
 *  - SEALED: each item's secrets ({password, note, totpUri}) AES-256-GCM'd
 *    under ONE random cache key (KEK); the KEK itself is RSA-OAEP-wrapped
 *    to the SCREENLOCK keystore key. The wrap uses the certificate's public
 *    key (plain JCE — no keystore op, no auth: saves re-seal freely); the
 *    KEK unwrap runs through the keystore private key, which requires the
 *    device screen lock and opens a 60s validity window per successful
 *    prompt.
 *
 * Flow: the locked app renders the manifest directly; tapping an entry
 * prompts once and unseals that item; a save/edit promotes to a full
 * session by unsealing everything (silent while the auth window is open —
 * the keystore auth timestamp is global across time-based keys, so the
 * reveal prompt and the commit-signing prompt share one window). A seal
 * stale against the vault file forces the legacy GPG unlock, which re-seals.
 */
object SealedVault {

    private const val TAG = "SealedVault"
    private const val KEY_ALIAS = "offlinepass-seal-rsa"
    private const val FILE_NAME = "sealed/sealed.json"
    private const val FORMAT_VERSION = 1
    private const val ITEM_AAD_PREFIX = "offlinepass-seal-item-v1:"
    /** Bump when the keystore key spec changes: the alias is deleted and
     *  regenerated (the old cache becomes unwrappable → the GPG re-seal
     *  path rebuilds everything). v3: MGF1-SHA1 + hybrid KEK format. */
    private const val KEY_SPEC_VERSION = 3

    /** One manifest row: everything the locked list/search shows. */
    data class ManifestEntry(
        val uuid: String,
        val name: String,
        val username: String,
        val email: String,
        val urls: List<String>,
        val modifyTime: Long
    ) {
        /** Pre-auth search: all words must hit name/username/email/urls.
         *  (Notes are sealed — they only match in a full session.) */
        fun matches(query: String): Boolean {
            val words = query.lowercase().split(" ").filter { it.isNotBlank() }
            if (words.isEmpty()) return true
            val haystack = listOf(name, username, email, urls.joinToString(" "))
                .joinToString(" ").lowercase()
            return words.all { it in haystack }
        }
    }

    private lateinit var appContext: Context
    private val sealMutex = Mutex()
    private val scope = SupervisorJob().let { job ->
        kotlinx.coroutines.CoroutineScope(job + Dispatchers.IO)
    }

    fun init(context: Context) {
        if (::appContext.isInitialized) return
        appContext = context.applicationContext
    }

    /** Test-only: the singleton outlives Robolectric tests — reset to
     *  pristine defaults for [context] and wipe the on-disk cache. */
    internal fun resetForTest(context: Context) {
        appContext = context.applicationContext
        cacheFile().delete()
    }

    private fun cacheFile(): File = File(appContext.filesDir, FILE_NAME)

    private fun specs() =
        appContext.getSharedPreferences("sealed_vault", Context.MODE_PRIVATE)

    /** Raised when the cache was sealed by a DIFFERENT keystore key (spec
     *  regeneration) — only the GPG re-seal path can rebuild it. */
    internal class SealedKeyMismatchException : Exception()

    internal fun isKeyMismatch(e: Exception): Boolean {
        var c: Throwable? = e
        while (c != null) {
            if (c is SealedKeyMismatchException) return true
            c = c.cause
        }
        return false
    }

    private fun keyIdOf(kp: KeyPair): String = sha256Hex(kp.public.encoded)

    // -- injectable CEK crypto (Robolectric tests replace the keystore) ------

    /** Wraps a CEK. Production: RSA-OAEP to the keystore cert's public key
     *  (public-key math outside the keystore — no user auth needed). */
    internal var wrapCekHook: ((cek: ByteArray) -> ByteArray)? = null

    /** Unwraps a CEK. Production: the keystore private key — THE gated
     *  operation. Throws [android.security.keystore.UserNotAuthenticatedException]
     *  when the validity window is closed. */
    internal var unwrapCekHook: ((wrapped: ByteArray) -> ByteArray)? = null

    private fun wrapFn(kp: KeyPair?): (ByteArray) -> ByteArray =
        wrapCekHook ?: { cek -> rsaWrap(cek, kp!!.public) }

    private fun unwrapFn(kp: KeyPair?): (ByteArray) -> ByteArray =
        unwrapCekHook ?: { w -> rsaUnwrap(w, kp!!.private) }

    // -- keystore key ---------------------------------------------------------

    /**
     * Loads — or lazily generates — the screenlock-gated RSA keypair.
     * Returns null when the device has no screen lock (keystore refuses
     * auth-required keys) or generation fails; callers degrade to the
     * legacy GPG-unlock flow. A permanently invalidated key (screen lock
     * removed) is deleted here so the NEXT seal regenerates a fresh one;
     * old CEKs become unwrappable, which the staleness flow absorbs.
     */
    private fun ensureKeyPair(): KeyPair? {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val entry = try {
                ks.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
            } catch (e: Exception) {
                // Unrecoverable/invalidated → drop and regenerate below.
                runCatching { ks.deleteEntry(KEY_ALIAS) }
                null
            }
            if (entry != null) {
                if (specs().getInt("keySpecVersion", 0) != KEY_SPEC_VERSION) {
                    // Generated with an older spec — regenerate fresh.
                    ks.deleteEntry(KEY_ALIAS)
                    specs().edit().remove("keySpecVersion").apply()
                } else {
                    return KeyPair(entry.certificate.publicKey, entry.privateKey)
                }
            }
            val gen = java.security.KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS, KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(2048)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                // OAEP hash (SHA-256) AND the MGF1 digest (SHA-1 — what the
                // OAEPWithSHA-256AndMGF1Padding transformation actually uses
                // on this keystore, see INCOMPATIBLE_MGF_DIGEST) must both
                // be allowed by the key.
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA1)
                .setUserAuthenticationRequired(true)
                // New biometric enrollments must not brick the cache.
                .setInvalidatedByBiometricEnrollment(false)
                .apply {
                    // The LEGACY validity-duration setting — the exact
                    // combination the app's SSH key + screenlock gate use
                    // successfully on this ROM. (The modern
                    // setUserAuthenticationParameters(STRONG|CREDENTIAL) +
                    // setAllowedAuthenticators prompt authenticated fine but
                    // did NOT open this key's window here.) Legacy = any
                    // biometric or lockscreen credential, 60s window.
                    setUserAuthenticationValidityDurationSeconds(60)
                }
                .build()
            gen.initialize(spec)
            val kp = gen.generateKeyPair()
            specs().edit().putInt("keySpecVersion", KEY_SPEC_VERSION).apply()
            return kp
        } catch (e: Exception) {
            Log.w(TAG, "seal key unavailable (${e.javaClass.simpleName}: ${e.message})")
            null
        }
    }

    /** RSA-OAEP(SHA-256, MGF1-SHA256). The explicit MGF1 digest is required:
     *  the JCE default MGF1-SHA1 would NOT match the keystore side, which
     *  applies its configured digest to MGF1 as well. */
    private fun rsaWrap(cek: ByteArray, publicKey: java.security.PublicKey): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec())
        return cipher.doFinal(cek)
    }

    private fun rsaUnwrap(wrapped: ByteArray, privateKey: java.security.PrivateKey): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec())
        return cipher.doFinal(wrapped)
    }

    private fun oaepSpec() = OAEPParameterSpec(
        "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)

    private fun aesSeal(cek: ByteArray, plain: ByteArray, aad: ByteArray):
            Pair<ByteArray, ByteArray> {
        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        return iv to cipher.doFinal(plain)
    }

    private fun aesUnseal(cek: ByteArray, iv: ByteArray, ct: ByteArray, aad: ByteArray):
            ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(cek, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        return cipher.doFinal(ct)
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it) }

    // -- seal (write) ----------------------------------------------------------

    /**
     * Rebuilds the sealed cache from the current in-memory session. Best-
     * effort and asynchronous (IO scope, mutex-serialized): callers never
     * block and failures only log — the cache is a convenience, the repo's
     * GPG envelope is the source of truth.
     */
    fun seal(items: List<ProtonItem>, env: Envelope, vaultFile: File) {
        if (!::appContext.isInitialized) return
        scope.launch {
            sealMutex.withLock {
                try {
                    sealNow(items, env, vaultFile)
                } catch (e: Exception) {
                    Log.w(TAG, "seal failed: ${e.javaClass.simpleName}: ${e.message}")
                }
            }
        }
    }

    private fun sealNow(items: List<ProtonItem>, env: Envelope, vaultFile: File) {
        val kp = ensureKeyPair()
        if (kp == null && wrapCekHook == null) return
        val wrap = wrapFn(kp)
        // Hybrid: ONE random cache key (KEK) RSA-wrapped to the screenlock
        // keystore key; every item's secrets AES-GCM'd under the KEK (plain
        // JCE — deterministic on all devices). Only the KEK unwrap is the
        // gated keystore operation.
        val kek = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val vaultSha = sha256Hex(vaultFile.takeIf { it.exists() }?.readBytes() ?: ByteArray(0))
        val arr = JSONArray()
        for (item in items) {
            val aad = (ITEM_AAD_PREFIX + item.itemUuid).toByteArray()
            val secrets = JSONObject()
                .put("password", item.password)
                .put("note", item.note)
                .put("totpUri", item.totpUri)
            val (iv, ct) = aesSeal(kek, secrets.toString().toByteArray(), aad)
            arr.put(itemJson(item)
                .put("iv", Base64.getEncoder().encodeToString(iv))
                .put("ct", Base64.getEncoder().encodeToString(ct)))
        }
        val out = JSONObject()
            .put("v", FORMAT_VERSION)
            .put("vaultSha256", vaultSha)
            .put("items", arr)
            .put("kek", Base64.getEncoder().encodeToString(wrap(kek)))
        if (kp != null) out.put("keyId", keyIdOf(kp))
        // Envelope PUBLIC bookkeeping (non-secret: pairing records are
        // public keys, tombstones are uuids) — lets a save/edit promote
        // to a full session without GPG.
        out.put("meta", JSONObject()
            .put("rev", env.rev)
            .put("deviceId", env.deviceId)
            .put("deletedItemUuids", JSONArray().apply { env.deletedItemUuids.forEach { put(it) } })
            .put("devices", JSONArray().apply { env.devices.forEach { put(it.toJsonObject()) } })
            .put("removedDeviceIds", JSONArray().apply { env.removedDeviceIds.forEach { put(it) } })
            .put("extraFields", JSONObject().apply {
                env.extraFields.forEach { (k, v) ->
                    when (v) {
                        is JSONObject, is JSONArray, JSONObject.NULL -> put(k, v)
                        null -> put(k, JSONObject.NULL)
                        else -> put(k, v.toString())
                    }
                }
            }))
        // Atomic write: tmp + rename; the tmp never survives a failure.
        val target = cacheFile()
        target.parentFile?.mkdirs()
        val tmp = File(target.parentFile, target.name + ".tmp")
        try {
            tmp.writeText(out.toString())
            if (!tmp.renameTo(target)) {
                target.delete()
                if (!tmp.renameTo(target)) throw IOException("rename failed")
            }
            Log.i(TAG, "sealed ${items.size} entries (vault sha ${vaultSha.take(8)})")
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    private fun itemJson(item: ProtonItem): JSONObject = JSONObject()
        .put("uuid", item.itemUuid)
        .put("name", item.displayName)
        .put("username", item.username)
        .put("email", item.email)
        .put("urls", JSONArray(item.urls))
        .put("modifyTime", item.modifyTime)

    // -- read: the pre-auth surface ---------------------------------------------

    private fun readCache(): JSONObject? = runCatching {
        val f = cacheFile()
        if (!f.exists()) return null
        JSONObject(f.readText())
    }.getOrNull()

    fun hasCache(): Boolean = readCache() != null

    fun wipe() {
        cacheFile().delete()
    }

    /** The cache is fresh when it was sealed against the CURRENT vault file
     *  bytes. Stale ⇒ unsealing would resurrect outdated secrets — flows
     *  must fall back to the GPG unlock (which re-seals on success). */
    fun isFresh(vaultFile: File): Boolean {
        val cache = readCache() ?: return false
        val actual = sha256Hex(vaultFile.takeIf { it.exists() }?.readBytes() ?: ByteArray(0))
        return cache.optString("vaultSha256", "") == actual
    }

    fun manifest(): List<ManifestEntry> {
        val cache = readCache() ?: return emptyList()
        return cache.optJSONArray("items")?.let { arr ->
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.optJSONObject(i) ?: return@mapNotNull null
                ManifestEntry(
                    uuid = o.optString("uuid"),
                    name = o.optString("name"),
                    username = o.optString("username"),
                    email = o.optString("email"),
                    urls = o.optJSONArray("urls")
                        ?.let { a -> (0 until a.length()).map { a.getString(it) } }
                        ?: emptyList(),
                    modifyTime = o.optLong("modifyTime", 0)
                )
            }
        } ?: emptyList()
    }

    /** Pre-auth search over the manifest (locked list backing). */
    fun searchManifest(query: String): List<String> =
        manifest().filter { it.matches(query) }.map { it.uuid }

    /** Locked-mode list backing: ProtonItem stubs with the manifest
     *  metadata filled in and every secret field empty. */
    fun manifestItems(): List<ProtonItem> = manifest().map { e ->
        ProtonItem(
            name = e.name, username = e.username, email = e.email,
            urls = e.urls, modifyTime = e.modifyTime, itemUuid = e.uuid)
    }

    fun pairedDevices(): List<DeviceRecord> =
        readCache()?.optJSONObject("meta")?.optJSONArray("devices")
            ?.let { a ->
                (0 until a.length()).mapNotNull { i ->
                    DeviceRecord.fromJson(a.optJSONObject(i) ?: return@mapNotNull null)
                }
            } ?: emptyList()

    // -- unseal: the screenlock-gated operations ---------------------------------

    /**
     * Unseals ONE item (the click-through reveal). Requires the keystore
     * auth window — the UI runs the screen-lock prompt right before.
     * Returns null when the uuid is unknown or its blob fails to open.
     */
    suspend fun reveal(uuid: String): ProtonItem? = withContext(Dispatchers.IO) {
        try {
            unsealInternal(listOf(uuid)).firstOrNull()
        } catch (e: Exception) {
            if (isAuthError(e)) throw e
            Log.w(TAG, "reveal failed for $uuid: ${e.message}")
            null
        }
    }

    /** Unseals every item (the promote-to-full-session operation). */
    suspend fun unsealAll(): List<ProtonItem> = withContext(Dispatchers.IO) {
        unsealInternal(manifest().map { it.uuid })
    }

    private fun unsealInternal(uuids: List<String>): List<ProtonItem> {
        val cache = readCache() ?: return emptyList()
        val kp = if (unwrapCekHook == null) ensureKeyPair() else null
        if (kp == null && unwrapCekHook == null) return emptyList()
        val unwrap = unwrapFn(kp)
        // Sealed by a different key generation, or the pre-KEK format?
        // Only the GPG re-seal rebuilds.
        val cacheKeyId = cache.optString("keyId", "")
        if (unwrapCekHook == null &&
            (cacheKeyId.isEmpty() || cacheKeyId != keyIdOf(kp!!)))
            throw SealedKeyMismatchException()
        val kekWrapped = cache.optString("kek", "")
        if (kekWrapped.isEmpty()) throw SealedKeyMismatchException()
        // THE gated keystore operation — once per unseal batch.
        val kek = unwrap(Base64.getDecoder().decode(kekWrapped))
        val stubs = manifestItems().associateBy { it.itemUuid }
        val byUuid = cache.optJSONArray("items")?.let { arr ->
            (0 until arr.length()).mapNotNull { i -> arr.optJSONObject(i) }
                .associateBy { it.optString("uuid") }
        } ?: emptyMap()
        val out = mutableListOf<ProtonItem>()
        for (uuid in uuids) {
            val o = byUuid[uuid] ?: continue
            try {
                val aad = (ITEM_AAD_PREFIX + uuid).toByteArray()
                val secrets = JSONObject(String(aesUnseal(
                    kek,
                    Base64.getDecoder().decode(o.getString("iv")),
                    Base64.getDecoder().decode(o.getString("ct")),
                    aad)))
                stubs[uuid]?.copy(
                    password = secrets.optString("password"),
                    note = secrets.optString("note"),
                    totpUri = secrets.optString("totpUri"))?.let { out += it }
            } catch (e: Exception) {
                // Auth failures MUST propagate (the caller prompts + retries);
                // per-item data failures only skip the entry.
                if (isAuthError(e)) throw e
                Log.w(TAG, "unseal failed for $uuid: ${e.message}")
            }
        }
        return out
    }

    internal fun isAuthError(e: Exception): Boolean {
        var c: Throwable? = e
        while (c != null) {
            if (c is android.security.keystore.UserNotAuthenticatedException ||
                c is android.security.KeyStoreException ||
                c is java.security.UnrecoverableKeyException) return true
            c = c.cause
        }
        return false
    }

    /** Rebuilds the loaded envelope (public metadata + unsealed items) —
     *  what a promoted session carries. Call after [unsealAll]. */
    fun toEnvelope(items: List<ProtonItem>): Envelope {
        val meta = readCache()?.optJSONObject("meta") ?: JSONObject()
        return Envelope(
            rev = meta.optLong("rev", 0),
            deviceId = meta.optString("deviceId"),
            items = items.toMutableList(),
            deletedItemUuids = meta.optJSONArray("deletedItemUuids")
                ?.let { a -> (0 until a.length()).map { a.getString(it) }.toMutableSet() }
                ?: mutableSetOf(),
            devices = meta.optJSONArray("devices")
                ?.let { a ->
                    (0 until a.length()).mapNotNull { i ->
                        DeviceRecord.fromJson(a.optJSONObject(i) ?: return@mapNotNull null)
                    }.toMutableList()
                } ?: mutableListOf(),
            removedDeviceIds = meta.optJSONArray("removedDeviceIds")
                ?.let { a -> (0 until a.length()).map { a.getString(it) }.toMutableSet() }
                ?: mutableSetOf()
        )
    }
}
