package com.offlinepass.app.vault

import android.content.Context
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
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/**
 * The device-local sealed cache behind the "encrypt individual items while in use"
 * toggle. The GPG-encrypted envelope in the repo stays the only synced
 * representation; this cache is never committed anywhere.
 *
 * At rest in app-private storage (FORMAT v2):
 *  - PLAINTEXT: the metadata the search/list UI already shows — names,
 *    usernames, emails, URLs, modify times, uuids — plus the envelope's
 *    public bookkeeping (rev, deviceId, paired paste devices, tombstones;
 *    all non-secret by design — the pairing record is a public key).
 *  - SEALED: each item's secrets ({password, note, totpUri}) are
 *    AES-256-GCM'd DIRECTLY under a SCREENLOCK-GATED AndroidKeyStore AES
 *    key (one keystore op per item; the IV is keystore-generated). NO KEK,
 *    NO RSA wrap, NO wrapped symmetric key at rest — one layer, and the
 *    TEE performs the per-item crypto. The unseal requires the device
 *    screen lock and opens a 60s validity window per successful prompt.
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
    private const val KEY_ALIAS = "offlinepass-seal-aes"
    private const val FILE_NAME = "sealed/sealed.json"
    private const val FORMAT_VERSION = 2
    private const val ITEM_AAD_PREFIX = "offlinepass-seal-item-v1:"
    /** Bump when the keystore key spec changes: the alias is deleted and
     *  regenerated (the old cache becomes un-decryptable → the GPG re-seal
     *  path rebuilds everything). v1: the direct AES-GCM per-item format
     *  (the KEK/RSA hybrid is retired). */
    private const val KEY_SPEC_VERSION = 1

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
        cryptoHook = null
        cacheFile().delete()
    }

    private fun cacheFile(): File = File(appContext.filesDir, FILE_NAME)

    private fun specs() =
        appContext.getSharedPreferences("sealed_vault", Context.MODE_PRIVATE)

    /** Raised when the cache was sealed by a DIFFERENT keystore key (spec
     *  regeneration) or carries a retired format — only the GPG re-seal
     *  path can rebuild it. */
    internal class SealedKeyMismatchException : Exception()

    internal fun isKeyMismatch(e: Exception): Boolean {
        var c: Throwable? = e
        while (c != null) {
            if (c is SealedKeyMismatchException) return true
            c = c.cause
        }
        return false
    }

    // -- injectable per-item crypto (Robolectric tests replace the keystore) --

    /** The per-item crypto: the production impl = the screenlock-gated
     *  AndroidKeyStore AES-GCM key (the keystore generates the IVs).
     *  Tests inject a software AES with a throwaway key. */
    interface SealCrypto {
        fun seal(plain: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray>
        fun unseal(iv: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray
    }

    internal var cryptoHook: SealCrypto? = null

    /** Production: the keystore AES-GCM cipher. Both directions are
     *  auth-gated (the per-op window covers the whole batch). */
    private class KeystoreSealCrypto(private val key: javax.crypto.SecretKey) : SealCrypto {
        override fun seal(plain: ByteArray, aad: ByteArray): Pair<ByteArray, ByteArray> {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.ENCRYPT_MODE, key)
            c.updateAAD(aad)
            val ct = c.doFinal(plain)
            return (c.iv) to ct
        }

        override fun unseal(iv: ByteArray, ct: ByteArray, aad: ByteArray): ByteArray {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            c.updateAAD(aad)
            return c.doFinal(ct)
        }
    }

    /**
     * Loads — or lazily generates — the screenlock-gated AES-256-GCM key.
     * Returns null when the device has no screen lock (keystore refuses
     * auth-required keys) or generation fails; callers degrade to the
     * legacy GPG-unlock flow. A permanently invalidated key (screen lock
     * removed) is deleted here so the NEXT seal regenerates a fresh one;
     * the old cache becomes un-decryptable, which the staleness flow
     * absorbs.
     */
    /** The blocking variant: the save's re-seal = AWAITED (the post-save
     *  re-stub must not race the cache write — a tap right after the save
     *  would read the stale cache and demand the card per item). The same
     *  mutex, the same call — just awaited by the caller. */
    suspend fun sealNowAwait(items: List<ProtonItem>, env: Envelope, vaultFile: File) =
        withContext(Dispatchers.IO) {
            sealMutex.withLock { sealNow(items, env, vaultFile) }
        }

    private fun ensureAesKey(): javax.crypto.SecretKey? {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val entry = try {
                ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry
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
                    return entry.secretKey
                }
            }
            val gen = javax.crypto.KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                // New biometric enrollments must not brick the cache.
                .setInvalidatedByBiometricEnrollment(false)
                .apply {
                    // The LEGACY validity-duration setting — the exact
                    // combination the app's SSH key + screenlock gate use
                    // successfully on this ROM. Legacy = any biometric or
                    // lockscreen credential, 60s window (one prompt covers
                    // the whole unseal batch).
                    setUserAuthenticationValidityDurationSeconds(60)
                }
                .build()
            gen.init(spec)
            val key = gen.generateKey()
            specs().edit().putInt("keySpecVersion", KEY_SPEC_VERSION).apply()
            key
        } catch (e: Exception) {
            Log.w(TAG, "seal key unavailable (${e.javaClass.simpleName}: ${e.message})")
            null
        }
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
                    // The file channel: the ROM's logd is broken — the seal's
                    // outcome must be visible to the log pull.
                    runCatching {
                        java.io.File(appContext.filesDir, "debug-sync.log").appendText(
                            "[${System.currentTimeMillis()}] seal: sealed " +
                                "${items.size} items\n")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "seal failed: ${e.javaClass.simpleName}: ${e.message}")
                    runCatching {
                        java.io.File(appContext.filesDir, "debug-sync.log").appendText(
                            "[${System.currentTimeMillis()}] seal FAILED: " +
                                "${e.javaClass.simpleName}: ${e.message}\n")
                    }
                }
            }
        }
    }

    private fun sealNow(items: List<ProtonItem>, env: Envelope, vaultFile: File) {
        val crypto = cryptoHook ?: (ensureAesKey()?.let { KeystoreSealCrypto(it) })
            ?: return
        val vaultSha = sha256Hex(vaultFile.takeIf { it.exists() }?.readBytes() ?: ByteArray(0))
        val arr = JSONArray()
        for (item in items) {
            val aad = (ITEM_AAD_PREFIX + item.itemUuid).toByteArray()
            val secrets = JSONObject()
                .put("password", item.password)
                .put("note", item.note)
                .put("totpUri", item.totpUri)
            val (iv, ct) = crypto.seal(secrets.toString().toByteArray(), aad)
            arr.put(itemJson(item)
                .put("iv", Base64.getEncoder().encodeToString(iv))
                .put("ct", Base64.getEncoder().encodeToString(ct)))
        }
        val out = JSONObject()
            .put("v", FORMAT_VERSION)
            .put("vaultSha256", vaultSha)
            .put("items", arr)
            .put("meta", metaJson(env))
        atomicWriteCache(out)
        Log.i(TAG, "sealed ${items.size} entries (vault sha ${vaultSha.take(8)})")
    }

    /** Envelope PUBLIC bookkeeping (non-secret: pairing records are public
     *  keys, tombstones are uuids) — lets a save/edit promote to a full
     *  session without GPG. */
    private fun metaJson(env: Envelope): JSONObject = JSONObject()
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
        })

    /** Atomic write: tmp + rename; the tmp never survives a failure. */
    private fun atomicWriteCache(out: JSONObject) {
        val target = cacheFile()
        target.parentFile?.mkdirs()
        val tmp = File(target.parentFile, target.name + ".tmp")
        try {
            tmp.writeText(out.toString())
            if (!tmp.renameTo(target)) {
                target.delete()
                if (!tmp.renameTo(target)) throw IOException("rename failed")
            }
        } finally {
            if (tmp.exists()) tmp.delete()
        }
    }

    /** THE INCREMENTAL SEAL (the save's tail): only the AFFECTED item's
     *  blob is re-sealed — the other entries reuse their blobs (the AAD
     *  binds the uuid; the keystore key is unchanged), never-seen items
     *  get fresh blobs, removed items' rows drop, and the bookkeeping
     *  (rev, vaultSha, the manifest rows) refreshes. The repo commit has
     *  ALREADY landed when this runs: the cache is derived — a kill here
     *  leaves it stale-but-reconstructable by the repo decrypt. */
    suspend fun syncAfterSaveAwait(env: Envelope, vaultFile: File, editedUuid: String?) =
        withContext(Dispatchers.IO) {
            sealMutex.withLock {
                try {
                    syncNow(env, vaultFile, editedUuid)
                    runCatching {
                        java.io.File(appContext.filesDir, "debug-sync.log").appendText(
                            "[${System.currentTimeMillis()}] seal: incremental " +
                                "(edited=${editedUuid ?: "-"}, ${env.items.size} items)\n")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "incremental seal failed: ${e.javaClass.simpleName}: ${e.message}")
                    runCatching {
                        java.io.File(appContext.filesDir, "debug-sync.log").appendText(
                            "[${System.currentTimeMillis()}] incremental seal FAILED: " +
                                "${e.javaClass.simpleName}: ${e.message}\n")
                    }
                }
            }
        }

    private fun syncNow(env: Envelope, vaultFile: File, editedUuid: String?) {
        val crypto = cryptoHook ?: (ensureAesKey()?.let { KeystoreSealCrypto(it) }) ?: return
        // No cache (or a retired format) → nothing to increment: the next
        // unlock's GPG fallback re-seals from scratch.
        val cache = readCache() ?: return
        if (cache.optInt("v", 1) != FORMAT_VERSION) return
        val vaultSha = sha256Hex(vaultFile.takeIf { it.exists() }?.readBytes() ?: ByteArray(0))
        val existing = cache.optJSONArray("items")?.let { arr ->
            (0 until arr.length()).mapNotNull { i -> arr.optJSONObject(i) }
                .associateBy { it.optString("uuid") }
        } ?: emptyMap()
        val desired = env.items.associateBy { it.itemUuid }
        val arr = JSONArray()
        for (item in env.items) {
            val prev = existing[item.itemUuid]
            if (prev != null && item.itemUuid != editedUuid) {
                // REUSE the blob (the secrets unchanged); the metadata row
                // still refreshes (the name/username ride the envelope).
                arr.put(itemJson(item)
                    .put("iv", prev.getString("iv"))
                    .put("ct", prev.getString("ct")))
            } else {
                val aad = (ITEM_AAD_PREFIX + item.itemUuid).toByteArray()
                val secrets = JSONObject()
                    .put("password", item.password)
                    .put("note", item.note)
                    .put("totpUri", item.totpUri)
                val (iv, ct) = crypto.seal(secrets.toString().toByteArray(), aad)
                arr.put(itemJson(item)
                    .put("iv", Base64.getEncoder().encodeToString(iv))
                    .put("ct", Base64.getEncoder().encodeToString(ct)))
            }
        }
        // The tombstoned/gone items' rows drop (the cache = the mirror).
        val out = JSONObject()
            .put("v", FORMAT_VERSION)
            .put("vaultSha256", vaultSha)
            .put("items", arr)
            .put("meta", metaJson(env))
        atomicWriteCache(out)
        Log.i(TAG, "incremental seal: ${env.items.size} items " +
            "(edited=${editedUuid ?: "-"}, new=${desired.count { existing[it.key] == null }})")
    }

    private fun itemJson(item: ProtonItem): JSONObject = JSONObject()
        .put("uuid", item.itemUuid)
        .put("name", item.name)
        .put("username", item.username)
        .put("email", item.email)
        .put("urls", JSONArray().apply { item.urls.forEach { put(it) } })
        .put("modifyTime", item.modifyTime)

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
        // v1 caches (the retired KEK/RSA format) = stale: only the GPG
        // re-seal rebuilds.
        if (cache.optInt("v", 1) != FORMAT_VERSION) throw SealedKeyMismatchException()
        val crypto = cryptoHook ?: (ensureAesKey()?.let { KeystoreSealCrypto(it) })
            ?: return emptyList()
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
                val secrets = JSONObject(String(crypto.unseal(
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

    private fun readCache(): JSONObject? {
        val f = cacheFile()
        if (!f.exists()) return null
        return runCatching { JSONObject(f.readText()) }.getOrNull()
    }

    fun hasCache(): Boolean = readCache() != null

    fun wipe() {
        cacheFile().delete()
    }
}
