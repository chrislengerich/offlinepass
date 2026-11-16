package com.offlinepass.app.vault

import android.content.Context
import android.app.PendingIntent
import android.content.Intent
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.offlinepass.app.crypto.OpenPgpClient
import com.offlinepass.app.crypto.OpenPgpOps
import com.offlinepass.app.crypto.PgpSshBridge
import com.offlinepass.app.crypto.SshKeyManager
import com.offlinepass.app.crypto.YubiKeySshIdentity
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The app's vault orchestration: config + lock state + the one decrypted
 * item list while unlocked. Ties together OpenKeyChain (crypto), JGit
 * (sync, when a remote is configured) and the vault file on disk.
 *
 * State machine: NoConfig -> Locked -> Unlocked; save() re-encrypts and
 * pushes (or just writes, in local-only mode). OpenKeyChain's user
 * interaction is surfaced to the UI as [Interaction] results; the UI
 * launches the PendingIntent and calls the same op again.
 */
object VaultSession {

    sealed class State {
        object NoConfig : State()
        object Locked : State()
        data class Unlocked(val items: List<ProtonItem>) : State()
    }

    sealed class Result {
        object Success : Result()
        data class Interaction(val pendingIntent: android.app.PendingIntent) : Result()
        data class Error(val message: String) : Result()
        /** Sealed cache stale/missing → the UI must run the GPG unlock. */
        data class NeedsKeyDecrypt(val reason: String) : Result()
        /** One entry unsealed from the sealed cache (locked-mode reveal). */
        data class Revealed(val item: ProtonItem) : Result()
    }

    data class Config(
        val remoteUrl: String?,
        val recipientEmails: List<String>,
        val deviceId: String
    )

    private const val TAG = "VaultSession"
    private val PICK_SENTINEL = "pick-recipient@offlinepass.local"
    private lateinit var appContext: Context

    var state by mutableStateOf<State>(State.Locked)
        private set
    var busy by mutableStateOf<String?>(null)
        private set

    /**
     * Set by the UI layer: launches the OpenKeyChain interaction
     * PendingIntent and returns its RESULT intent (which carries the call
     * UUIDs for OpenKeyChain's crypto-input cache). Every interaction loop
     * below depends on this to converge.
     */
    var interactionHandler: (suspend (PendingIntent) -> Intent?)? = null

    /**
     * Builds the OpenPGP client used by the save path. Production: the real
     * OpenKeyChain IPC client. Tests override this to stub OpenKeyChain
     * (device-only) and exercise the save transaction on the JVM.
     */
    internal var openPgpClientFactory: (Context) -> OpenPgpOps = { OpenPgpClient(it) }

    /** Commit signing modes: OpenKeyChain's signing key (default — software
     *  keys or security keys behind the OKK interaction) or the SCREENLOCK
     *  keystore key (per-device, per-operation screen-lock auth, no OKK
     *  interaction at all). */
    const val SIGNING_OPENKEYCHAIN = "openkeychain"
    const val SIGNING_SCREENLOCK = "screenlock"
    const val SIGNING_YUBIKEY = "yubikey"

    fun commitSigningMode(): String =
        prefs().getString("commitSigningMode", null) ?: SIGNING_OPENKEYCHAIN

    fun setCommitSigningMode(mode: String) {
        prefs().edit().putString("commitSigningMode", mode).apply()
    }

    /** UI hook for the screenlock signature: receives the exact bytes to
     *  sign, runs the BiometricPrompt interaction, returns the signature
     *  (or null on decline). Set by MainActivity; hops to Main itself. */
    var keystoreSignerHook: (suspend (ByteArray) -> ByteArray?)? = null

    /** SSH sync identities: the SCREENLOCK keystore key or the YUBIKEY's
     *  OpenPGP auth subkey (via OpenKeyChain — the key already enrolled in
     *  GitHub). Whichever was enrolled last wins; both are exclusive of
     *  the HTTPS/PAT path. */
    const val SSH_SYNC_SCREENLOCK = "screenlock"
    const val SSH_SYNC_YUBIKEY = "yubikey"

    fun sshSyncMode(): String =
        prefs().getString("sshSyncMode", null) ?: SSH_SYNC_SCREENLOCK

    fun setSshSyncMode(mode: String) {
        prefs().edit().putString("sshSyncMode", mode).apply()
    }

    fun yubikeySshLine(): String? = prefs().getString("yubikeySshLine", null)
    fun yubikeyAuthSubkeyId(): Long? = prefs().getString("yubikeyAuthSubkeyId", null)
        // The stored value is UNSIGNED 64-bit hex; ids with the high bit set
        // (very common) are negative as signed Longs — base-10 parsing or
        // toLongOrNull(16) would return null for exactly the ids real keys
        // have. (This was the root cause of the silent "Auth cancelled".)
        ?.let { runCatching { java.lang.Long.parseUnsignedLong(it, 16) }.getOrNull() }

    /** Persists the YubiKey SSH enrollment (public line + auth subkey id)
     *  and activates the YubiKey SSH sync mode. */
    fun clearYubikeySsh() {
        prefs().edit()
            .remove("yubikeySshLine")
            .remove("yubikeyAuthSubkeyId")
            .putString("sshSyncMode", SSH_SYNC_SCREENLOCK)
            .apply()
    }

    fun setYubikeySsh(sshLine: String, subkeyIdHex: String) {
        prefs().edit()
            .putString("yubikeySshLine", sshLine)
            .putString("yubikeyAuthSubkeyId", subkeyIdHex)
            .putString("sshSyncMode", SSH_SYNC_YUBIKEY)
            .apply()
    }

    /** Provides the JSch identity for the ACTIVE ssh sync mode: the
     *  screenlock keystore key, or the YubiKey auth subkey via
     *  OpenKeyChain (its interaction — the YubiKey touch — is the gate).
     *  Set by MainActivity; returns null when the mode isn't enrolled. */
    var sshIdentityProvider: () -> com.jcraft.jsch.Identity? = { null }

    /** Why the SSH identity is unavailable (set by [buildSshIdentity]) —
     *  the transport surfaces this INSTEAD of the generic "not enrolled"
     *  error when set. */
    @Volatile var sshIdentityUnavailable: String? = null

    /** The app-level YubiKey PIN cache with the screenlock gate's 60s
     *  validity model: within a sync, the commit signature and the SSH
     *  auth share ONE prompt (the card resets its PIN state per connection
     *  anyway; the cache only spares the user the second dialog). The
     *  cached value is stored ONLY on success — [yubikeyPinRemember] —
     *  a wrong PIN is never kept. The expired/wrong value is zeroed. */
    private var cachedYubikeyPin: CharArray? = null
    private var cachedYubikeyPinAt = 0L

    /** The YubiKey OpenPGP user PIN: the 60s-valid cache, or a fresh
     *  prompt. Null = the user cancelled. */
    suspend fun yubikeyPin(): CharArray? {
        cachedYubikeyPin?.takeIf {
            System.currentTimeMillis() - cachedYubikeyPinAt < 60_000
        }?.let { return it }
        cachedYubikeyPin?.fill('0')
        cachedYubikeyPin = null
        return openPgpPinPrompt?.invoke()
    }

    /** Caches [pin] (on a successful sign only). */
    fun yubikeyPinRemember(pin: CharArray) {
        cachedYubikeyPin?.fill('0')
        cachedYubikeyPin = pin
        cachedYubikeyPinAt = System.currentTimeMillis()
    }

    // -- The device identity + the repo's key-material registry --------------
    //
    // Layout (the repo = the offline keyring):
    //   meta/devices.json               — the device name → public-key mapping
    //     [{name, authKey, cert?}]  (the identity rides in the key line's comment)
    //   keys/auth/authorized-keys       — the transport lines (authorized_keys format)
    //   keys/sign/<keyid>.pub.asc       — the commit-signing certs (the card's full cert)
    //   keys/encrypt/<keyid>.pub.asc    — the envelope recipients
    //
    // The LEGACY layout (the flat keys/<keyid>.public.asc,
    // keys/keystore-signer.pub, keys/signer-<id>.asc) is migrated once,
    // on the first save after this feature lands: the files MOVE to the
    // new locations (git history preserves the originals) and
    // meta/devices.json is created.

    /** The user-editable device name (defaults to the model); stamped into
     *  the registry. */
    fun deviceName(): String =
        prefs().getString("deviceName", null) ?: android.os.Build.MODEL
    fun setDeviceName(n: String) {
        prefs().edit().putString("deviceName", n.trim()).apply()
    }

    /** The minimal registry entry: the device NAME mapped to its public
     *  key. The device identity rides in the key line's own comment
     *  ("… offlinepass-screenlock device=<id>"), so there is exactly one
     *  place the identity lives. */
    data class DeviceRegistryEntry(
        val name: String,
        val authKey: String?,      // the OpenSSH line (inline)
        val cert: String?          // the cert path (relative to the repo root)
    )

    private fun metaDevicesFile(): File = File(gitRoot(), "meta/devices.json")
    private fun keysAuthDir(): File = File(gitRoot(), "keys/auth")
    private fun keysSignDir(): File = File(gitRoot(), "keys/sign")
    private fun keysEncryptDir(): File = File(gitRoot(), "keys/encrypt")
    private fun authorizedKeysFile(): File = File(keysAuthDir(), "authorized-keys")

    fun readDeviceRegistry(): List<DeviceRegistryEntry> {
        val f = metaDevicesFile()
        if (!f.exists()) return emptyList()
        return runCatching {
            val arr = org.json.JSONObject(f.readText()).getJSONArray("devices")
            (0 until arr.length()).mapNotNull { i ->
                val o = arr.getJSONObject(i)
                DeviceRegistryEntry(
                    o.optString("name", ""),
                    o.optString("authKey", "").ifEmpty { null },
                    o.optString("cert", "").ifEmpty { null })
            }
        }.getOrDefault(emptyList())
    }

    private fun writeDeviceRegistry(entries: List<DeviceRegistryEntry>) {
        val f = metaDevicesFile()
        f.parentFile?.mkdirs()
        val root = org.json.JSONObject()
        val arr = org.json.JSONArray()
        for (e in entries) {
            val o = org.json.JSONObject()
            o.put("name", e.name)
            if (e.authKey != null) o.put("authKey", e.authKey)
            if (e.cert != null) o.put("cert", e.cert)
            arr.put(o)
        }
        root.put("devices", arr)
        f.writeText(root.toString(2) + "\n")
    }

    /** This device's screenlock enrollment per the REGISTRY (what other
     *  devices see). The local capability check is KeystoreSigner.hasKey(). */
    fun screenlockRegisteredForThisDevice(): Boolean =
        readDeviceRegistry().any {
            it.authKey?.contains("offlinepass-screenlock device=${deviceId()}") == true
        }

    /** Append-only: adds THIS device's screenlock entry when absent (a
     *  second device appends — never overwrites another device's entry). */
    private fun appendScreenlockRegistryEntry(includeAuth: Boolean) {
        val line = com.offlinepass.app.crypto.KeystoreSigner
            .publicKeySshLine("offlinepass-screenlock device=${deviceId()}") ?: return
        val entries = readDeviceRegistry().toMutableList()
        if (entries.none {
                it.authKey?.contains("offlinepass-screenlock device=${deviceId()}") == true
            }) {
            entries += DeviceRegistryEntry(deviceName(), line, null)
            writeDeviceRegistry(entries)
        }
        val f = authorizedKeysFile()
        f.parentFile?.mkdirs()
        if (!f.exists() || f.readLines().none { it.substringBefore(" ") == line.substringBefore(" ") && it.substringAfter(" ", "").substringBefore(" ") == line.substringAfter(" ", "") }) {
            f.appendText(line + "\n")
        }
    }

    /** Ensures a transport line is present in keys/auth/authorized-keys. */
    private fun appendAuthorizedKey(line: String) {
        val f = authorizedKeysFile()
        f.parentFile?.mkdirs()
        val existing = if (f.exists()) f.readLines() else emptyList()
        if (existing.none { it.substringBefore(" ").substringBefore(" ") == line.substringBefore(" ") }) {
            f.appendText(line + "\n")
        }
    }

    /** Best-effort repo materialization, called pre-commit in syncNow:
     *  the legacy layout migrates once, the card's cert lands in
     *  keys/sign/, this device's lines join keys/auth/. Failures are
     *  non-fatal (the next save retries). */
    suspend fun updateRepoKeyMaterial(client: OpenPgpOps) {
        runCatching { migrateLegacyKeyLayout() }
        runCatching {
            val subkeyId = yubikeyAuthSubkeyId()
            if (subkeyId != null) {
                // The card's full GPG cert — what a fresh device's OKK needs.
                when (val fk = client.fetchPublicKeyArmored(subkeyId, null)) {
                    is OpenPgpClient.PublicKey.Success -> {
                        val f = File(keysSignDir(), "%016X.pub.asc".format(subkeyId))
                        if (!f.exists() || f.readText() != fk.armored) {
                            f.parentFile?.mkdirs()
                            f.writeText(fk.armored.trimEnd() + "\n")
                        }
                    }
                    else -> {} // OKK interaction/failure: the next save retries
                }
                yubikeySshLine()?.let { appendAuthorizedKey(it.trimEnd()) }
                val entries = readDeviceRegistry().toMutableList()
                val certPath = "keys/sign/%016X.pub.asc".format(subkeyId)
                if (entries.none { it.cert == certPath }) {
                    entries += DeviceRegistryEntry(
                        deviceName() + " (card)", yubikeySshLine()?.trimEnd(), certPath)
                    writeDeviceRegistry(entries)
                }
            }
            if ((commitSigningMode() == SIGNING_SCREENLOCK ||
                        sshSyncMode() == SSH_SYNC_SCREENLOCK) &&
                com.offlinepass.app.crypto.KeystoreSigner.hasKey()
            ) {
                appendScreenlockRegistryEntry(includeAuth = sshSyncMode() == SSH_SYNC_SCREENLOCK)
            }
        }
    }

    /** The repo's public-key material OKK could import (the sign/encrypt
     *  certs present on disk). */
    fun repoKeyMaterialFiles(): List<File> {
        val out = mutableListOf<File>()
        keysSignDir().listFiles { f -> f.name.endsWith(".pub.asc") }?.forEach { out += it }
        keysEncryptDir().listFiles { f -> f.name.endsWith(".pub.asc") }?.forEach { out += it }
        return out
    }

    /** Stages the repo's key material (one concatenated .asc in Downloads)
     *  and opens OpenKeyChain's import screen — the file hand-off, since
     *  the OpenPGP remote API cannot mutate OKK's keyring. */
    fun openOkkImportFromRepo(activity: android.app.Activity): String {
        if (android.os.Build.VERSION.SDK_INT < 29) {
            return "The OKK bootstrap needs Android 10+."
        }
        val files = repoKeyMaterialFiles()
        if (files.isEmpty()) return "The repo carries no public key material yet."
        val content = files.joinToString("\n") { it.readText().trimEnd() } + "\n"
        val values = android.content.ContentValues().apply {
            put(android.provider.MediaStore.Downloads.DISPLAY_NAME, "offlinepass-keys.asc")
            put(android.provider.MediaStore.Downloads.MIME_TYPE, "application/pgp-keys")
        }
        val uri = activity.contentResolver.insert(
            android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: return "Could not stage the key material (the Downloads insert failed)."
        activity.contentResolver.openOutputStream(uri)?.use { out ->
            out.write(content.toByteArray())
        } ?: return "Could not write the staged keys."
        val intent = android.content.Intent(android.content.Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/pgp-keys")
            .addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
        return try {
            activity.startActivity(intent)
            "OpenKeyChain's import opened — confirm the keys there."
        } catch (e: Exception) {
            "OpenKeyChain's import could not be opened: ${e.message} " +
                "(the staged file is in Downloads: offlinepass-keys.asc)"
        }
    }

    // Test hooks (the singleton + the private layout ops).
    internal fun migrateLegacyKeyLayoutForTest() = migrateLegacyKeyLayout()
    internal fun writeDeviceRegistryForTest(entries: List<DeviceRegistryEntry>) =
        writeDeviceRegistry(entries)

    /** The one-time migration of the LEGACY flat layout into the subfolders
     *  + meta. The files MOVE (git history preserves the originals):
     *  keys/<id>.public.asc → keys/encrypt/<id>.pub.asc,
     *  keys/signer-<id>.asc → keys/sign/<id>.pub.asc,
     *  keys/keystore-signer.pub → keys/sign/ (the legacy screenlock PEM —
     *  kept for the record; the live entry derives from the key itself). */
    private fun migrateLegacyKeyLayout() {
        if (prefs().getBoolean("keyMaterialMigrated", false)) return
        val legacy = File(gitRoot(), "keys")
        if (legacy.exists()) {
            for (f in legacy.listFiles()?.filter { it.isFile } ?: emptyList()) {
                val name = f.name
                val target: File? = when {
                    name.endsWith(".public.asc") -> File(
                        keysEncryptDir(), name.removeSuffix(".public.asc") + ".pub.asc")
                    name.startsWith("signer-") && name.endsWith(".asc") -> File(
                        keysSignDir(), name.removePrefix("signer-")
                            .removeSuffix(".asc") + ".pub.asc")
                    name == "keystore-signer.pub" -> File(keysSignDir(), name)
                    else -> null
                }
                if (target != null) {
                    target.parentFile?.mkdirs()
                    f.renameTo(target)
                }
            }
            // recipients.txt (the informational ledger) moves into encrypt/.
            val ledger = File(legacy, "recipients.txt")
            if (ledger.exists()) ledger.renameTo(File(keysEncryptDir(), "recipients.txt"))
        }
        prefs().edit().putBoolean("keyMaterialMigrated", true).apply()
    }

    /** The migration's surgical step: remove THIS device's screenlock
     *  entry from meta and its line from the transport registry; the
     *  card's entries survive (the card is a physical key, not a
     *  device). */
    private fun removeThisDeviceFromRegistry() {
        val mine = readDeviceRegistry().filter {
            it.authKey?.contains("offlinepass-screenlock device=${deviceId()}") != true
        }
        writeDeviceRegistry(mine)
        val f = authorizedKeysFile()
        if (f.exists()) {
            val kept = f.readLines().filter { l ->
                l.isBlank() || !l.contains("offlinepass-screenlock device=${deviceId()}")
            }
            if (kept.size != f.readLines().size) {
                f.writeText(kept.joinToString("", postfix = "\n"))
            }
        }
    }

    /** Post-load signing-role resolution: the screenlock stays the local
     *  signer when its key is enrolled (first-class); otherwise the
     *  security key (the YubiKey enrollment); otherwise whatever is
     *  configured (the OpenKeyChain default). NEVER enrolls the
     *  screenlock here — bootstrap pulls are security-key-only. */
    fun resolveCommitSigningModeAfterLoad() {
        if (com.offlinepass.app.crypto.KeystoreSigner.hasKey()) return
        if (yubikeyAuthSubkeyId() != null && yubikeySshLine() != null) {
            setCommitSigningMode(SIGNING_YUBIKEY)
        }
    }

    /** Removes the screenlock key from every role: the commit signing and
     *  the SSH sync mode move to the security key (the YubiKey
     *  enrollment); with no YubiKey enrolled, signing falls back to
     *  OpenKeyChain and the SSH mode stays (with an explanation). The
     *  keystore key itself is DELETED. The envelope's OpenPGP recipients
     *  are unaffected (the screenlock key was never one). Returns a
     *  user-facing summary. */
    fun migrateOffScreenlock(): String {
        val yubiEnrolled = yubikeyAuthSubkeyId() != null && yubikeySshLine() != null
        val parts = mutableListOf<String>()
        if (sshSyncMode() == SSH_SYNC_SCREENLOCK) {
            if (yubiEnrolled) {
                setSshSyncMode(SSH_SYNC_YUBIKEY)
                parts += "SSH auth now uses the YubiKey."
            } else {
                parts += "SSH auth stays on the screenlock key " +
                    "(enroll the YubiKey first to move it)."
            }
        }
        if (commitSigningMode() == SIGNING_SCREENLOCK) {
            if (yubiEnrolled) {
                setCommitSigningMode(SIGNING_YUBIKEY)
                parts += "Commit signing now uses the YubiKey."
            } else {
                setCommitSigningMode(SIGNING_OPENKEYCHAIN)
                parts += "Commit signing now uses OpenKeyChain."
            }
        }
        removeThisDeviceFromRegistry()
        com.offlinepass.app.crypto.KeystoreSigner.removeKey()
        parts += "The screenlock key was deleted."
        return parts.joinToString(" ")
    }

    /** The YubiKey commit signer per the YUBIKEY signing mode: the
     *  enrolled S subkey (the SSH enrollment's subkey id — the SIGNATURE
     *  slot) signs each commit, PIN + touch. Null = not usable; the
     *  unavailability reason lands in [sshIdentityUnavailable]. */
    fun yubikeyCommitSignerOrNull(): org.eclipse.jgit.lib.Signer? {
        val keyId = yubikeyAuthSubkeyId()
        if (keyId == null) {
            sshIdentityUnavailable =
                "Enroll the YubiKey SSH key first (Setup → Choose key)."
            return null
        }
        if (!com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(appContext)) {
            sshIdentityUnavailable =
                "The YubiKey is not attached (or USB access was not granted) " +
                    "— plug it in and retry."
            return null
        }
        sshIdentityUnavailable = null
        return com.offlinepass.app.crypto.YubiKitCommitSigner(
            appContext, keyId,
            prompt = { yubikeyPin() },
            rememberPin = { yubikeyPinRemember(it) })
    }

    /** The commit signer for sync-time commits (the pre-sync commit and
     *  the merge commit) per the active signing mode. */
    fun syncCommitSigner(client: OpenPgpClient): org.eclipse.jgit.lib.Signer? {
        return when (commitSigningMode()) {
            SIGNING_SCREENLOCK -> keystoreSignerHook
                ?.let { com.offlinepass.app.crypto.KeystoreCommitSigner(it) }
            SIGNING_YUBIKEY -> yubikeyCommitSignerOrNull()
            else -> signingKeyId()?.let { OpenKeyChainSigner(client, it) }
        }
    }

    /** The PIN-caching signer wrapper: prompts once per session and caches
     *  the PIN ONLY after a successful sign — a wrong PIN must re-prompt
     *  (with the card's attempts-remaining message), never poison the
     *  cache and fail every retry in silence. */
    internal fun pinCachingSigner(
        prompt: suspend () -> CharArray?,
        sign: suspend (CharArray, ByteArray) -> ByteArray,
    ): suspend (ByteArray) -> ByteArray {
        var cached: CharArray? = null
        return { payload ->
            val pin = cached ?: prompt() ?: throw java.io.IOException("OpenPGP PIN cancelled")
            val sig = sign(pin, payload)
            cached = pin
            sig
        }
    }

    /** Builds the active SSH identity for a sync/load, or null when the
     *  chosen mode isn't fully usable. YubiKey mode = the YubiKit card
     *  path ONLY (the SIGNATURE slot, no OpenKeyChain): when the key is
     *  not attached/permitted, the build FAILS FAST with a clear message —
     *  the OKK card-sign fallback is a measured dead end
     *  (UNSUPPORTED_ACTION) and silently confusing. */
    fun buildSshIdentity(): com.jcraft.jsch.Identity? {
        sshIdentityUnavailable = null
        return when (sshSyncMode()) {
            SSH_SYNC_YUBIKEY -> {
                val line = yubikeySshLine() ?: return null
                val subkeyId = yubikeyAuthSubkeyId() ?: return null
                val context = appContext
                if (!com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(context)) {
                    sshIdentityUnavailable = "The YubiKey is not attached (or USB access was " +
                        "not granted) — plug it in and retry."
                    return null
                }
                val yubiKitSigner: (suspend (payload: ByteArray) -> ByteArray) =
                    pinCachingSigner(
                        prompt = { yubikeyPin() },
                        sign = { pin, payload ->
                            val sig = com.offlinepass.app.crypto.YubiKitSshAuth
                                .sign(context, pin, payload)
                            yubikeyPinRemember(pin)
                            sig
                        })
                com.offlinepass.app.crypto.YubiKeySshIdentity(
                    client = null, authSubkeyId = subkeyId, publicKeyLine = line,
                    interaction = { null }, yubiKitSigner = yubiKitSigner)
            }
            else -> null // screenlock mode uses the Keystore identity directly
        }
    }

    /** UI hook for the screenlock auth that precedes SSH-key syncs (the
     *  key's 60s validity window opens on a successful interaction). Set
     *  by MainActivity; must run on Main. */
    var syncAuthGate: (suspend () -> Boolean)? = null

    /** UI hook for the screen-lock prompt that opens the SEAL key's 60s
     *  validity window (biometric/credential; runs on Main). One successful
     *  prompt unlocks ALL time-based keystore keys for the window, so the
     *  reveal unseal and a following commit-signing prompt share it. */
    var sealGate: (suspend (title: String, subtitle: String) -> Boolean)? = null

    /** UI hook: the OpenPGP applet's USER PIN for YubiKit card signing.
     *  Shows a dialog, returns the PIN (or null on cancel); the PIN is
     *  never stored — it is used once and dropped. */
    var openPgpPinPrompt: (suspend () -> CharArray?)? = null

    /** The auth subkey id picked in OpenKeyChain (reactive — the Setup
     *  enrollment dialog prepopulates its field from this). */
    var pickedAuthSubkeyId by mutableStateOf<Long?>(null)

    /** The OpenSSH line built from the picked key's material (reactive —
     *  the enrollment dialog prepopulates its field from this). */
    var yubikeySshLineDraft by mutableStateOf<String?>(null)

    /** Last successful screenlock gate (for the key's validity window). */
    private var lastSshGateSuccessAt: Long = 0L

    /** Runs the screenlock gate unless it already succeeded within the
     *  key's validity window (prevents the double prompt from
     *  connectRemote → syncNow). Returns null when satisfied. */
    private suspend fun sshGateIfNeeded(): String? {
        if (System.currentTimeMillis() - lastSshGateSuccessAt < 55_000) return null
        val gate = syncAuthGate ?: return "Sync auth gate unavailable"
        busy = "Screen lock…"
        val ok = try { gate() } catch (e: Exception) { false }
        busy = null
        if (!ok) return "Screen lock declined"
        lastSshGateSuccessAt = System.currentTimeMillis()
        return null
    }

    /** Logs a sync/save failure to files/debug-sync.log (this ROM suppresses
     *  Log.w stack traces) and returns the enriched error message with the
     *  captured SSH session diagnostics (GitHub's actual rejection reason). */
    private fun logSyncFailure(where: String, e: Exception): String {
        val diag = com.offlinepass.app.crypto.KeystoreSshSessionFactory.lastSessionDiagnostics
        val stack = Log.getStackTraceString(e)
        runCatching {
            val f = File(appContext.filesDir, "debug-sync.log")
            if (f.length() > 256_000) f.writeText("")
            f.appendText("[${System.currentTimeMillis()}] $where: " +
                "${e.javaClass.simpleName}: ${e.message}\n$stack\ndiag: $diag\n\n")
        }
        Log.w(TAG, "$where failed: ${e.message} | diag: $diag", e)
        return if (diag.isNotBlank()) "${e.javaClass.simpleName}: ${e.message} — $diag"
        else "${e.javaClass.simpleName}: ${e.message}"
    }

    /** UI hook confirming the FIRST push to an empty remote (the remote
     *  main branch gets created by the push). Set by MainActivity. */
    var firstPushGate: (suspend () -> Boolean)? = null

    /** Human-readable sync state, shown above the Sync-now button. */
    var syncStatus by mutableStateOf<String?>(null)
        private set

    /** Remote outcome of the most recent save(): "synced" (pushed),
     * "pending" (saved locally, offline — background sync will retry), or
     * "none" (local-only mode). Read by the UI for save toasts. */
    var lastSaveRemoteState by mutableStateOf("none")
        private set

    /** A commit exists locally that the remote hasn't seen. */
    private var pendingPush = false
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Envelope revision of the currently-open vault; bumped on each save. */
    private var rev: Long = 0

    /** The envelope as loaded (tombstones + unknown fields preserved through saves). */
    private var loadedEnvelope: Envelope? = null

    fun init(context: Context) {
        if (::appContext.isInitialized) return
        appContext = context.applicationContext
        // A local vault file = the vault exists → Locked (unlock screen).
        // No local vault → the setup/import screen (no unlock shown).
        state = if (File(vaultFilePath()).exists()) State.Locked else State.NoConfig
        registerConnectivityWatch()
    }

    /** Test-only: the singleton holds memory across Robolectric tests —
     * reset it to pristine defaults for [context] (no connectivity watch). */
    internal fun resetForTest(context: Context) {
        appContext = context.applicationContext
        rev = 0
        loadedEnvelope = null
        state = if (File(vaultFilePath()).exists()) State.Locked else State.NoConfig
        pendingPush = false
        lastSaveRemoteState = "none"
        syncStatus = null
        busy = null
    }

    /** Background sync: when connectivity returns and a push is pending,
     * attempt one sync. */
    fun registerConnectivityWatch() {
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE)
            as? android.net.ConnectivityManager ?: return
        val request = android.net.NetworkRequest.Builder()
            .addCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        cm.registerNetworkCallback(request, object : android.net.ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: android.net.Network) {
                if (pendingPush) {
                    Log.i(TAG, "connectivity back — background sync")
                    pendingPush = false
                    appScope.launch { syncNow() }
                }
            }
        })
    }

    // -- config -------------------------------------------------------------

    private fun prefs() = appContext.getSharedPreferences("vault_config", Context.MODE_PRIVATE)

    fun config(): Config? {
        val prefs = prefs()
        val remote = prefs.getString("remoteUrl", null)
        val emails = prefs.getString("recipientEmails", null)?.split(",")?.filter { it.isNotBlank() }
        val ids = prefs.getString("recipientKeyIds", null)?.split(",")?.mapNotNull { it.toLongOrNull() }
        if (remote == null && emails == null && ids == null) return null
        return Config(remote, emails ?: emptyList(), deviceId())
    }

    fun recipientKeyIds(): List<Long> =
        prefs().getString("recipientKeyIds", null)
            ?.split(",")?.mapNotNull { it.toLongOrNull() } ?: emptyList()

    fun setRecipientKeyIds(ids: List<Long>) {
        prefs().edit().putString("recipientKeyIds", ids.joinToString(",")).apply()
    }

    var lastPickedKeyIds: List<Long> = emptyList()
        private set

    // -- signing identity ----------------------------------------------------

    fun signingKeyId(): Long? = prefs().getString("signingKeyId", null)?.toLongOrNull()
    fun signingKeyUserId(): String? = prefs().getString("signingKeyUserId", null)

    /**
     * Runs OpenKeychain's sign-key picker (GET_SIGN_KEY_ID) and persists the
     * picked key as the app's signing identity. Interaction surfaces for the
     * UI loop.
     */
    suspend fun pickSigningKey(): Result {
        val client = OpenPgpClient(appContext)
        var reqData: Intent? = null
        var guard = 0
        while (guard++ < 2) {
            when (val sk = client.pickSignKey(reqData)) {
                is OpenPgpClient.SignKey.Picked -> {
                    prefs().edit()
                        .putString("signingKeyId", sk.keyId.toString())
                        .putString("signingKeyUserId", sk.userId)
                        .apply()
                    return Result.Success
                }
                is OpenPgpClient.SignKey.NeedsInteraction -> {
                    reqData = interactionHandler?.invoke(sk.pendingIntent)
                        ?: return Result.Error("Interaction needs the UI layer")
                }
                is OpenPgpClient.SignKey.Error -> return Result.Error("Sign key pick failed")
            }
        }
        return Result.Error("Sign key pick aborted after interaction retry")
    }

    fun clearSigningKey() {
        prefs().edit().remove("signingKeyId").remove("signingKeyUserId").apply()
    }

    /**
     * Recipient PICK via OpenKeyChain's own keyring UI: a lookup for an
     * unknown user id raises the key-selection screen (multi-select
     * checkboxes); every picked key comes back in the result's key-id array
     * (in [lastPickedKeyIds]). Interaction propagates for the UI loop.
     */
    suspend fun pickRecipient(): Result {
        val client = OpenPgpClient(appContext)
        var reqData: Intent? = null
        var guard = 0
        while (guard++ < 2) {
            when (val lookup = client.lookupKeyIds(arrayOf(PICK_SENTINEL), reqData)) {
                is OpenPgpClient.KeyLookup.Success -> {
                    return if (lookup.keyIds.isNotEmpty()) {
                        lastPickedKeyIds = lookup.keyIds.toList()
                        Result.Success
                    } else Result.Error("Pick returned no key")
                }
                is OpenPgpClient.KeyLookup.UserInteraction -> reqData = interactionHandler?.invoke(lookup.pendingIntent)
                            ?: return Result.Error("Interaction needs the UI layer")
                is OpenPgpClient.KeyLookup.Error -> return Result.Error("Key lookup failed")
            }
        }
        return Result.Error("Pick aborted after interaction retry")
    }

    fun deviceId(): String {
        val prefs = prefs()
        return prefs.getString("deviceId", null)
            ?: java.util.UUID.randomUUID().toString().also { prefs.edit().putString("deviceId", it).apply() }
    }

    /** List page secondary sort: within equal names, most recently modified
     * first. Persisted; default ON. */
    fun sortByModifiedPref(): Boolean = prefs().getBoolean("sortByModified", true)
    fun setSortByModifiedPref(on: Boolean) {
        prefs().edit().putBoolean("sortByModified", on).apply()
    }

    /**
     * Persists config. remote == null => local-only mode. Returns immediately;
     * the repo is opened on next unlock.
     */
    /** Persists config. remote == null => local-only mode (same git repo,
     * no remotes). Adding/switching a remote later does NOT wipe anything:
     * the existing history connects + merges via syncNow. */
    fun configure(remoteUrl: String?, recipientEmails: List<String>) {
        prefs().edit()
            .putString("remoteUrl", remoteUrl)
            .putString("recipientEmails", recipientEmails.joinToString(","))
            .apply()
    }

    fun forgetConfig() {
        prefs().edit().clear().apply()
        state = State.NoConfig
    }

    /** Reverts a FAILED remote-config attempt WITHOUT destroying the
     *  durable setup: the SSH sync mode + YubiKey enrollment, the commit
     *  signer, the screenlock settings all survive (the explicit "forget
     *  this vault" action is [forgetConfig]). The remote/recipient keys
     *  are removed so no phantom remote stays configured; the connect
     *  drafts stay so the user can fix the remote and retry. */
    fun forgetRemoteConfig() {
        prefs().edit()
            .remove("remoteUrl")
            .remove("recipientEmails")
            .remove("recipientKeyIds")
            .apply()
        state = State.NoConfig
    }

    // -- paths ----------------------------------------------------------------

    /** The repo dir — used in BOTH modes: remote mode has origin configured,
     * local-only mode is the same git repo without remotes. */
    private fun gitRoot(): File = File(appContext.filesDir, "vault/repo")
    private fun vaultFile(): File = File(gitRoot(), "state/10.gpg")

    private fun secretStore() = SecretStore(appContext)

    fun savePat(pat: String) = secretStore().save("pat", pat)
    fun hasPat(): Boolean = secretStore().contains("pat")

    private fun pat(): String? = secretStore().read("pat")

    // -- unlock ----------------------------------------------------------------

    /**
     * Opens (clone/fetch, when remote), decrypts, parses. Caller must handle
     * [Result.Interaction] by launching the PendingIntent and calling again.
     */
    /**
     * LOCAL-ONLY operation: decrypts the on-disk vault via OpenKeyChain.
     * No network — syncing happens explicitly (Sync now) or on save.
     */
    suspend fun unlock(): Result {
        val cfg = config()
        // Unlock only ever runs against an existing local vault (the setup
        // screen handles the no-vault case).
        if (!File(vaultFilePath()).exists()) {
            return Result.Error("No local vault — use the setup screen.")
        }
        busy = "Decrypting vault… (touch your key)"
        val plain = File(appContext.cacheDir, "vault-plain.json")
        try {
            val client = OpenPgpClient(appContext)
            // OpenKeychain's interaction contract: after the user completes
            // the prompt, retry with the RETURNED intent (it carries the
            // call UUIDs that locate the cached crypto input).
            var reqData: Intent? = null
            var guard = 0
            while (guard++ < 2) {
                when (val r = client.decryptVerify(vaultFile(), plain, reqData)) {
                    is OpenPgpClient.DecryptResult.Success -> {
                        val env = Envelope.fromJson(plain.readText())
                        rev = env.rev
                        loadedEnvelope = env
                        state = State.Unlocked(env.items)
                        sealIfEnabled(env.items, env)
                        Log.i(TAG, "unlocked: ${env.items.size} items, rev=${env.rev}")
                        return Result.Success
                    }
                    is OpenPgpClient.DecryptResult.UserInteraction ->
                        reqData = interactionHandler?.invoke(r.pendingIntent)
                            ?: return Result.Error("Interaction needs the UI layer")
                    is OpenPgpClient.DecryptResult.Error -> return Result.Error("Decrypt failed (see logcat)")
                }
            }
            return Result.Error("Unlock aborted after interaction retry.")
        } catch (e: Exception) {
            Log.w(TAG, "unlock failed: ${e.message}")
            return Result.Error("${e.javaClass.simpleName}: ${e.message}")
        } finally {
            // The decrypted copy never outlives the call: zeroed + deleted
            // on every exit path (success, interaction, error, exception).
            SecureWipe.file(plain)
            busy = null
        }
    }

    // -- save ----------------------------------------------------------------

    /**
     * Encrypts (all configured recipients) + writes the vault file + commits
     * to the local git repo + pushes (remote mode). Local-only mode: just
     * writes + commits. Returns Interaction when OpenKeyChain needs a
     * prompt — the UI launches it and calls save() again.
     *
     * TRANSACTION SEMANTICS: the local git commit is the durability
     * boundary. Anything that fails BEFORE a commit lands (sign-key
     * preflight, the commit itself, encryption) rolls the vault file and
     * the in-memory session state back to the pre-save snapshot and returns
     * Error — the UI keeps the user on the form and nothing was saved.
     * Once a commit lands the change is durable; a push failure only marks
     * the sync pending (the repo — local first — is the source of trust).
     */
    suspend fun save(items: List<ProtonItem>): Result {
        val cfg = config() ?: return Result.Error("No config")
        busy = "Encrypting…"
        try {
            return withContext(Dispatchers.IO) {
                val env = (loadedEnvelope ?: Envelope(deviceId = cfg.deviceId)).also { e ->
                    e.rev = rev + 1
                    e.items = items.toMutableList()
                }
                // Purge tombstoned entries for good.
                env.items.removeAll { it.itemUuid in env.deletedItemUuids }
                env.items.sortBy { it.displayName.lowercase() }
                val client = openPgpClientFactory(appContext)

                var keyIds = cachedRecipientKeyIds() ?: recipientKeyIds().toLongArray()
                var lookupReqData: Intent? = null
                var lookupGuard = 0
                while (keyIds.isEmpty() && cfg.recipientEmails.isNotEmpty() && lookupGuard++ < 2) {
                    when (val lookup = client.lookupKeyIds(cfg.recipientEmails.toTypedArray(), lookupReqData)) {
                        is OpenPgpClient.KeyLookup.Success -> {
                            keyIds = lookup.keyIds
                            prefs().edit()
                                .putString("recipientKeyIds", keyIds.joinToString(","))
                                .apply()
                        }
                        is OpenPgpClient.KeyLookup.UserInteraction ->
                            return@withContext Result.Interaction(lookup.pendingIntent)
                        is OpenPgpClient.KeyLookup.Error ->
                            return@withContext Result.Error("Recipient key lookup failed")
                    }
                }
                if (keyIds.isEmpty()) {
                    return@withContext Result.Error("No recipients — add one in Setup (OpenKeyChain picker)")
                }

                val plain = File(appContext.cacheDir, "vault-plain-next.json")
                val target = vaultFile()

                // -- transaction snapshot (file + session state) ----------
                // Taken before the first write; restored by rollback() on
                // any pre-commit failure so disk and memory stay in sync
                // with the git repo (which never sees the change).
                val prevFileBytes: ByteArray? = target.takeIf { it.exists() }?.readBytes()
                val prevRev = rev
                val prevEnvelope = loadedEnvelope
                val prevEnvRev = prevEnvelope?.rev
                val prevEnvItems = prevEnvelope?.items?.toList()
                val prevState = state

                // Restore the pre-save snapshot; never throws (a rollback
                // must not mask the original error).
                fun rollback(reason: String): Result.Error {
                    try {
                        if (prevFileBytes != null) target.writeBytes(prevFileBytes)
                        else target.delete()
                        rev = prevRev
                        loadedEnvelope = prevEnvelope
                        // env aliases loadedEnvelope and was mutated in
                        // place — put its prior fields back too.
                        prevEnvelope?.let { e ->
                            prevEnvRev?.let { e.rev = it }
                            e.items = prevEnvItems.orEmpty().toMutableList()
                        }
                        state = prevState
                        syncStatus = "Save rolled back — nothing saved: $reason"
                    } catch (e: Exception) {
                        Log.w(TAG, "rollback failed: ${e.message}")
                    }
                    Log.w(TAG, "save rolled back: $reason")
                    return Result.Error(reason)
                }

                try {
                    try {
                        plain.writeText(env.toJsonObject().toString())
                        target.parentFile?.mkdirs()
                        if (!client.encryptTo(keyIds, plain, target)) {
                            return@withContext rollback("Encrypt failed")
                        }
                    } finally {
                        // The pre-encrypt plaintext is zeroed + deleted as soon
                        // as the ciphertext exists.
                        SecureWipe.file(plain)
                    }
                    rev = env.rev
                    loadedEnvelope = env
                    Log.i(TAG, "encrypted ${target.length()} bytes, rev=${env.rev}")

                    // Materialize the recipients' armored public keys + ledger
                    // into the repo, so git history records exactly who can open
                    // each revision (design: keys/*.public.asc + recipients.txt).
                    val keysOk = materializeRecipientKeys(client, gitRoot(), keyIds)
                    if (!keysOk) syncStatus = "Some recipient key files missing (retried next save)"

                    // Commit signer: OpenKeyChain's signing key (default) OR
                    // the screenlock keystore key — exclusive paths. In
                    // screenlock mode there is NO OpenKeyChain signing
                    // interaction: the BiometricPrompt gate in the hook is
                    // the entire story.
                    val signer: org.eclipse.jgit.lib.Signer?
                    if (commitSigningMode() == SIGNING_YUBIKEY) {
                        signer = yubikeyCommitSignerOrNull()
                            ?: return@withContext rollback(
                                (sshIdentityUnavailable ?: "YubiKey signer unavailable") +
                                    " — nothing saved.")
                    } else if (commitSigningMode() == SIGNING_SCREENLOCK) {
                        // Publish/re-publish the enrolled public key so any
                        // client can verify revisions (guarded: device-only
                        // op; skipped on JVM tests).
                        runCatching {
                            val pub = File(gitRoot(), "keys/" +
                                com.offlinepass.app.crypto.KeystoreSigner.PUB_FILE_NAME)
                            pub.parentFile?.mkdirs()
                            pub.writeText(
                                com.offlinepass.app.crypto.KeystoreSigner.publicKeyPem())
                        }.onFailure {
                            Log.w(TAG, "keystore pubkey materialization failed: ${it.message}")
                        }
                        val hook = keystoreSignerHook
                            ?: return@withContext rollback(
                                "Screenlock signer unavailable (UI layer absent) — nothing saved.")
                        signer = com.offlinepass.app.crypto.KeystoreCommitSigner(hook)
                    } else {
                        // Sign key: the stored signer, or — when none was
                        // picked yet — OpenKeyChain's own picker. Never default
                        // to a recipient key id: lookupKeyIds returns ENCRYPTION
                        // subkeys, which cannot sign.
                        var signId = signingKeyId()
                        if (signId == null) {
                            var reqData: Intent? = null
                            var pickGuard = 0
                            while (signId == null && pickGuard++ < 3) {
                                when (val sk = client.pickSignKey(reqData)) {
                                    is OpenPgpClient.SignKey.Picked -> {
                                        prefs().edit()
                                            .putString("signingKeyId", sk.keyId.toString())
                                            .putString("signingKeyUserId", sk.userId)
                                            .apply()
                                        signId = sk.keyId
                                    }
                                    is OpenPgpClient.SignKey.NeedsInteraction ->
                                        reqData = interactionHandler?.invoke(sk.pendingIntent)
                                            ?: return@withContext Result.Error("Sign-key picker needs the UI layer")
                                    OpenPgpClient.SignKey.Error ->
                                        return@withContext Result.Error("No signing key available — pick one in Setup.")
                                }
                            }
                            if (signId == null) return@withContext Result.Error("Sign-key selection aborted after retries")
                        }
                        val okkSigner = OpenKeyChainSigner(client, signId)
                        // Pre-flight the commit signature: OpenKeyChain may need
                        // an unlock prompt (or the key may be unavailable
                        // entirely). Surface that as Interaction HERE — the
                        // signer inside JGit can't interact, and a hard failure
                        // there aborts the commit with a bare "commit failed".
                        busy = "Checking sign key…"
                        ensureSignKeyReady(signId, client)?.let { msg ->
                            return@withContext rollback(msg +
                                " — nothing saved. Check the key in OpenKeyChain or pick another signer in Setup.")
                        }
                        signer = okkSigner
                    }
                    val git = VaultGitClient()
                    if (!File(gitRoot(), ".git").exists()) {
                        // Safety net (live vault session only — a failed LOAD
                        // never reaches here): a local-only vault that hasn't
                        // saved yet, or a repo dir that lost its .git. Init
                        // so THIS save is durable; the push either lands or
                        // stays pending — the remote never gates a save.
                        git.gitInit(gitRoot())
                    }

                    // The LOCAL TRUTH FIRST: the change is on disk + committed
                    // regardless of connectivity; the push retries when the
                    // network returns (background sync).
                    state = State.Unlocked(items)

                    if (cfg.remoteUrl != null) {
                        busy = "Committing…"
                        try {
                            git.commitDirty(gitRoot(), "Update 10.gpg (rev ${env.rev})", signer)
                        } catch (e: Exception) {
                            Log.w(TAG, "commit failed: ${e.message}", e)
                            return@withContext rollback("commit failed: ${e.message} — nothing saved.")
                        }
                        busy = "Pushing…"
                        val pushPat = pat()
                        if (pushPat == null) {
                            // The commit already landed: the change is
                            // durable. No rollback — the push just stays
                            // pending until a PAT is stored (Setup).
                            pendingPush = true
                            lastSaveRemoteState = "pending"
                            syncStatus = "Committed locally (rev ${env.rev}); push pending — store a PAT in Setup"
                            return@withContext Result.Success
                        }
                        lastSaveRemoteState = "pending"
                        try {
                            git.pushBranch(cfg.remoteUrl, pushPat, gitRoot())
                            pendingPush = false
                            lastSaveRemoteState = "synced"
                            syncStatus = if (keysOk) "Pushed rev ${env.rev} (signed)"
                                         else "Pushed rev ${env.rev} (signed; key files pending)"
                        } catch (e: Exception) {
                            Log.w(TAG, "push failed (kept local commit): ${e.message}")
                            pendingPush = true
                            lastSaveRemoteState = "pending"
                            syncStatus = "Saved locally; push pending"
                            // NOT an error: the change persisted locally.
                        }
                    } else {
                        // LOCAL-ONLY: same repo dir, no remotes — history stays on-device.
                        lastSaveRemoteState = "none"
                        git.commitFile(gitRoot(), "Update 10.gpg (rev ${env.rev})", signer)
                        syncStatus = "Committed locally (rev ${env.rev}, no remote)"
                    }
                    sealIfEnabled(items, env)
                    Result.Success
                } catch (e: Exception) {
                    // Anything throwing inside the transaction window rolls
                    // back (the vault file may be half-written or already
                    // updated without a commit).
                    Log.w(TAG, "save failed: ${e.message}", e)
                    rollback("${e.javaClass.simpleName}: ${e.message}")
                }
            }
        } catch (e: Exception) {
            // Failures before the snapshot (config, key lookup): nothing
            // was written.
            Log.w(TAG, "save failed: ${e.message}")
            return Result.Error("${e.javaClass.simpleName}: ${e.message}")
        } finally {
            busy = null
        }
    }

    private fun cachedRecipientKeyIds(): LongArray? =
        prefs().getString("recipientKeyIds", null)
            ?.split(",")?.mapNotNull { it.toLongOrNull() }?.toLongArray()
            ?.takeIf { it.isNotEmpty() }

    /**
     * Confirms the commit sign key can actually sign: runs a trial detached
     * sign, surfacing OpenKeyChain's passphrase / plug-in prompt through the
     * UI interaction loop (retried with the returned intent, like decrypt).
     * Returns null when the key signs; otherwise an actionable message.
     */
    private suspend fun ensureSignKeyReady(signKeyId: Long, client: OpenPgpOps): String? {
        val probe = "offlinepass commit-sign preflight".toByteArray()
        var reqData: Intent? = null
        var guard = 0
        while (guard++ < 3) {
            when (val r = client.trySignDetached(probe, keyId = signKeyId, requestData = reqData)) {
                is OpenPgpClient.SignDetached.Ok -> return null
                is OpenPgpClient.SignDetached.UserInteraction -> {
                    reqData = interactionHandler?.invoke(r.pendingIntent)
                        ?: return "Sign key needs an unlock prompt but the UI layer is absent"
                }
                is OpenPgpClient.SignDetached.Error ->
                    return "Sign key 0x%016X can't sign: ${r.message}".format(signKeyId)
            }
        }
        return "Sign key unlock aborted after retries"
    }    /**
     * Verifies each recipient email resolves to a key in OpenKeyChain.
     * Returns (resolved map, missing list). Interaction surfaces as
     * Interaction (OpenKeyChain's own key picker) for the UI to launch.
     */
    suspend fun resolveRecipients(
        emails: List<String>,
        client: OpenPgpClient
    ): Triple<Map<String, Long>, List<String>, android.app.PendingIntent?> {
        val resolved = mutableMapOf<String, Long>()
        val missing = mutableListOf<String>()
        for (email in emails) {
            when (val lookup = client.lookupKeyIds(arrayOf(email))) {
                is OpenPgpClient.KeyLookup.Success -> {
                    if (lookup.keyIds.isNotEmpty()) resolved[email] = lookup.keyIds.first()
                    else missing += email
                }
                is OpenPgpClient.KeyLookup.UserInteraction -> {
                    return Triple(resolved, missing, lookup.pendingIntent)
                }
                is OpenPgpClient.KeyLookup.Error -> missing += email
            }
        }
        return Triple(resolved, missing, null)
    }

    // -- screen-lock gate (default OFF) ---------------------------------------

    var screenLockOn by mutableStateOf(false)
        private set

    fun screenLockRequired(): Boolean =
        prefs().getBoolean("screenLockRequired", false).also { screenLockOn = it }

    fun setScreenLockRequired(on: Boolean) {
        prefs().edit().putBoolean("screenLockRequired", on).apply()
        screenLockOn = on
        if (!on) {
            // The toggle now means "the app is screenlock-governed": the
            // pre-unlock prompt AND the idle auto-lock. Turning it off
            // means no governance — a running session is zeroed right
            // here so nothing plaintext outlives the decision.
            zero()
        }
    }

    /** Idle auto-lock timeout in minutes (0 = never); only meaningful
     *  while [screenLockRequired] is on. */
    fun autoLockMinutes(): Int = prefs().getInt("autoLockMinutes", 5)

    fun setAutoLockMinutes(n: Int) {
        prefs().edit().putInt("autoLockMinutes", n).apply()
    }

    // -- screenlock unlock (experimental, default OFF) --------------------------
    //
    // The device-local sealed cache (SealedVault): the locked app renders
    // the manifest (names/usernames/URLs) and gates only the click-through.
    // OFF = exact legacy behavior (GPG unlock for everything); turning it
    // off wipes the cache.

    /** The screenlock-based encryption at rest (the sealed cache) is ON by
     *  default: the item secrets are AES-256-GCM'd behind the device
     *  credential; the toggle turning it off wipes the cache. An EXPLICIT
     *  off stays off. */
    fun screenlockUnlockEnabled(): Boolean =
        prefs().getBoolean("screenlockUnlock", true)

    fun setScreenlockUnlockEnabled(on: Boolean) {
        prefs().edit().putBoolean("screenlockUnlock", on).apply()
        if (!on) SealedVault.wipe()
    }

    /** Re-seals the cache when the toggle is on. Fire-and-forget; failures
     *  only log (the repo's GPG envelope stays the source of truth). */
    private fun sealIfEnabled(items: List<ProtonItem>, env: Envelope) {
        if (screenlockUnlockEnabled()) SealedVault.seal(items, env, File(vaultFilePath()))
    }

    /** Locked-mode list backing: manifest stubs (secrets empty). Empty when
     *  the toggle is off or no cache exists — the UI falls back to the
     *  legacy unlock screen. */
    fun sealedManifestItems(): List<ProtonItem> =
        if (screenlockUnlockEnabled()) SealedVault.manifestItems() else emptyList()

    /** Paired paste devices from the sealed cache's public metadata — the
     *  export checkbox renders correctly even in a locked session. */
    fun sealedPairedDevices(): List<DeviceRecord> = SealedVault.pairedDevices()

    /** Locked-mode click-through: one screen-lock prompt, then the entry's
     *  secrets unseal for the detail view. The session STAYS Locked. No
     *  busy/progress state — the screen just sits until the item opens. */
    suspend fun revealSealed(uuid: String, name: String): Result {
        if (!screenlockUnlockEnabled() || !SealedVault.hasCache())
            return Result.NeedsKeyDecrypt("no seal")
        // A stale seal would resurrect outdated secrets — the key unlock
        // (which re-seals) is required first.
        if (!SealedVault.isFresh(File(vaultFilePath())))
            return Result.NeedsKeyDecrypt("Seal is outdated — a sync pulled a newer vault")
        val gate = sealGate ?: return Result.Error("Screen-lock gate unavailable")
        val ok = runCatching {
            gate("Reveal entry", "Screen lock unlocks \"$name\"")
        }.getOrDefault(false)
        if (!ok) return Result.Error("Screen lock declined")
        return try {
            val item = SealedVault.reveal(uuid)
                ?: return Result.NeedsKeyDecrypt("Sealed data unreadable — re-seal via the key unlock")
            Result.Revealed(item)
        } catch (e: Exception) {
            if (SealedVault.isKeyMismatch(e)) return Result.NeedsKeyDecrypt("Seal key regenerated")
            Result.Error(sealedErrorMessage(e))
        }
    }

    /**
     * Unseals the whole sealed cache into a full session (envelope metadata
     * included). Quiet when the keystore auth window is still open from a
     * recent prompt (the reveal); one screen-lock prompt otherwise. The GPG
     * unlock is required only when the seal is stale or missing.
     */
    suspend fun promoteSealedSession(): Result {
        if (!screenlockUnlockEnabled() || !SealedVault.hasCache())
            return Result.NeedsKeyDecrypt("no seal")
        if (!SealedVault.isFresh(File(vaultFilePath())))
            return Result.NeedsKeyDecrypt("Seal is outdated — a sync pulled a newer vault")
        return try {
            val items = try {
                SealedVault.unsealAll()
            } catch (e: Exception) {
                if (!SealedVault.isAuthError(e)) throw e
                // Window closed since the reveal: one prompt reopens it.
                val gate = sealGate ?: return Result.Error("Screen-lock gate unavailable")
                val ok = runCatching {
                    gate("Unlock offlinepass", "Screen lock opens your passwords")
                }.getOrDefault(false)
                if (!ok) return Result.Error("Screen lock declined")
                SealedVault.unsealAll()
            }
            if (items.isEmpty())
                return Result.NeedsKeyDecrypt("Sealed cache unreadable — re-seal via the key unlock")
            val env = SealedVault.toEnvelope(items)
            rev = env.rev
            loadedEnvelope = env
            state = State.Unlocked(items)
            Log.i(TAG, "promoted sealed session: ${items.size} items, rev=${env.rev}")
            Result.Success
        } catch (e: Exception) {
            if (SealedVault.isKeyMismatch(e)) return Result.NeedsKeyDecrypt("Seal key regenerated")
            Result.Error(sealedErrorMessage(e))
        }
    }

    /**
     * Sealed-mode save (edit from a single-entry reveal): promotes to a
     * full session, then runs the NORMAL save transaction — including the
     * existing commit-signing screen-lock interaction. One auth window
     * covers both the seal key and the signing key.
     */
    suspend fun saveSealed(edited: ProtonItem): Result {
        when (val p = promoteSealedSession()) {
            is Result.Success -> {}
            else -> return p
        }
        val items = (state as? State.Unlocked)?.items
            ?: return Result.Error("Session unavailable")
        val merged = items.map { if (it.itemUuid == edited.itemUuid) edited else it }
        return save(merged)
    }

    private fun sealedErrorMessage(e: Exception): String {
        Log.w(TAG, "sealed op failed: ${e.javaClass.name}: ${e.message}", e)
        return if (SealedVault.isAuthError(e)) "Screen lock required — try again"
        else "${e.javaClass.simpleName}: ${e.message}"
    }

    fun isDeviceCredentialReady(): Int =
        androidx.biometric.BiometricManager.from(appContext).canAuthenticate(
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
                or androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )

    // -- helpers for UI (USB save/restore, QR export) -----------------------

    fun vaultFilePath(): String = vaultFile().absolutePath
    fun gitRootPath(): String = gitRoot().absolutePath
    fun currentRev(): Long = rev

    // -- paired paste devices (Chrome extension; Plan 2) ---------------------

    fun pairedDevices(): List<DeviceRecord> = loadedEnvelope?.devices ?: emptyList()

    /** Adds or updates a pairing record scanned from the extension's QR
     *  (R2: re-wrapped seeds / restored pairings update in place — newer
     *  wins). Persists via save(). */
    fun stagePairedDevice(record: DeviceRecord): String {
        val env = loadedEnvelope ?: return "no-vault"
        val existing = env.devices.firstOrNull { it.keyId == record.keyId }
        if (existing != null && existing == record) return "unchanged"
        env.removedDeviceIds.remove(record.keyId)
        if (existing != null) {
            env.devices[env.devices.indexOf(existing)] = record
            return "updated"
        }
        env.devices.add(record)
        return "added"
    }

    /** Unpairs: removes the record and tombstones the id so merges/syncs
     *  from other devices don't resurrect it. Persists via save(). */
    fun stageRemoveDevice(keyId: String): Boolean {
        val env = loadedEnvelope ?: return false
        val before = env.devices.size
        env.devices.removeAll { it.keyId == keyId }
        env.removedDeviceIds.add(keyId)
        return env.devices.size != before
    }

    /** Seeds the recipient key ids from the repo's materialized public keys
     *  (keys/<keyid>.public.asc) when none are configured -- a freshly
     *  loaded vault carries its own recipients. No-op when ids already
     *  exist (never clobbers). Returns the effective ids. */
    fun seedRecipientsFromRepo(): List<Long> {
        if (recipientKeyIds().isNotEmpty()) return recipientKeyIds()
        val dir = File(gitRoot(), "keys")
        val ids = dir.listFiles { f -> f.name.endsWith(".public.asc") }
            ?.mapNotNull { f -> f.name.substringBefore(".").toLongOrNull(16) }
            .orEmpty()
        if (ids.isNotEmpty()) {
            setRecipientKeyIds(ids)
            Log.i(TAG, "seeded " + ids.size + " recipient key id(s) from the repo's keys/")
        }
        return ids
    }

    // -- load-screen drafts ----------------------------------------------------
    //
    // Held on the SINGLETON (not in remember/rememberSaveable): this ROM
    // recreates/kills activities aggressively enough that composition-scoped
    // state does not survive the chip switches or the QR detour. Process-
    // lifetime state is immune to all of it.

    val loadRemoteState = mutableStateOf("")
    val loadPatState = mutableStateOf("")
    val loadSshLineState = mutableStateOf("")
    val loadSubkeyIdState = mutableStateOf("")
    val loadAuthState = mutableStateOf("")

    // -- connect-remote draft (survives the SSH-key QR detour) ----------------

    // -- SSH auth self-test (Setup; integration check of the whole chain) ------

    /** Verdict of the OpenKeyChain sign → bridge → SSH-framing chain. */
    data class SshSelfTest(val ok: Boolean, val detail: String)

    /**
     * Runs the exact signing chain the YubiKey SSH sync uses — a detached
     * sign over a test blob with the ENROLLED subkey (OpenKeyChain shows
     * its own PIN/touch interaction), then verifies the signature's issuer
     * matches the enrolled subkey and that the bridge produces valid SSH
     * framing. The point is DIAGNOSIS: a silent OKK rejection names
     * itself here, and the tool stays around as a permanent regression
     * check for the auth path.
     */
    suspend fun sshAuthSelfTest(onStatus: (String) -> Unit = {}): SshSelfTest {
        val subkeyId = yubikeyAuthSubkeyId()
            ?: return SshSelfTest(false, "no YubiKey SSH subkey enrolled (Setup → Choose key)")
        val line = yubikeySshLine()
            ?: return SshSelfTest(false, "no YubiKey SSH line enrolled")
        val parsedLine = runCatching { PgpSshBridge.parsePublicKeyLine(line) }
            .getOrElse { return SshSelfTest(false, "enrolled SSH line unparsable: ${it.message}") }
        val data = "offlinepass ssh-auth self-test".toByteArray()

        // The device state, surfaced in the verdict.
        val deviceInfo = com.offlinepass.app.crypto.YubiKitSshAuth.deviceInfo(appContext)

        // The YubiKit path: a YubiKey attached = the card signs on its
        // SIGNATURE slot (the enrolled S subkey) — PIN + touch — and the
        // signature is VERIFIED LOCALLY against the enrolled line's public
        // key. No OpenKeyChain, NO NETWORK: the whole sign chain is tested
        // offline.
        // A YubiKey ATTACHED = the YubiKit path is mandatory: request the
        // USB permission first if needed, then the card signs. The OKK
        // fallback below runs only when NO YubiKey is enumerated —
        // otherwise the first run grants permission and then wrongly
        // launches the OpenKeyChain interaction.
        if (com.offlinepass.app.crypto.YubiKitSshAuth.findDevice(appContext) != null) {
            if (!com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(appContext)) {
                onStatus("USB permission for the YubiKey…")
                if (!com.offlinepass.app.crypto.YubiKitSshAuth.requestPermission(appContext)) {
                    return SshSelfTest(false, "USB permission denied for the YubiKey")
                }
            }
            val pin = openPgpPinPrompt?.invoke()
                ?: return SshSelfTest(false, "OpenPGP PIN cancelled")
            // The card's slot touch policy may require a PHYSICAL touch on
            // the YubiKey itself — there is no phone-side prompt for that.
            onStatus("Touch the YubiKey when its LED blinks…")
            // Blocking USB I/O must leave the main thread — on Main the UI
            // freezes: no status, no verdict, no log.
            val signOutcome = kotlinx.coroutines.withContext(
                kotlinx.coroutines.Dispatchers.IO) {
                runCatching {
                    val block = com.offlinepass.app.crypto.SshRsaPkcs1
                        .digestInfo("SHA-512", data)
                    com.offlinepass.app.crypto.YubiKitSshAuth.sign(appContext, pin, block)
                }
            }
            val sigBlock = signOutcome.getOrElse { e ->
                android.util.Log.e("YubiKeySsh", "yubikit sign failed", e)
                return SshSelfTest(false, "YubiKit sign: ${e.message}")
            }
            val verified = runCatching {
                val pub = PgpSshBridge.publicKeyFromLine(parsedLine)
                val verifier = java.security.Signature.getInstance("SHA512withRSA")
                verifier.initVerify(pub); verifier.update(data)
                verifier.verify(sigBlock)
            }.getOrElse { false }
            return if (verified) SshSelfTest(true,
                "YubiKit: the card signed on the SIGNATURE slot + verified locally — the full chain works")
            else SshSelfTest(false,
                "the card's signature did NOT verify locally against the enrolled line " +
                    "(the sig armor is saved to last-selftest-sig.asc)")
        }

        // No YubiKey attached: the OKK fallback (the software keys; OKK's
        // remote API cannot card-sign).
        val client = openPgpClientFactory(appContext)

        // The key material: the OKK path's sign and the diagnostics.
        var primaryId: Long? = null
        var reqDataM: Intent? = null
        var guardM = 0
        while (guardM++ < 3 && primaryId == null) {
            when (val fk = client.fetchPublicKeyArmored(subkeyId, reqDataM)) {
                is OpenPgpClient.PublicKey.Success -> primaryId = runCatching {
                    PgpSshBridge.primaryKeyIdOf(fk.armored)
                }.getOrNull()
                is OpenPgpClient.PublicKey.UserInteraction ->
                    reqDataM = interactionHandler?.invoke(fk.pendingIntent) ?: break
                else -> break
            }
        }

        var reqData: Intent? = null
        var guard = 0
        while (guard++ < 3) {
            when (val r = client.trySignDetached(data, subkeyId, reqData)) {
                is OpenPgpClient.SignDetached.Ok -> {
                    val issuer = runCatching { PgpSshBridge.issuingKeyId(r.armored) }
                        .getOrElse { return SshSelfTest(false, "signature parse: ${it.message}") }
                    if (issuer != null && issuer != subkeyId) return SshSelfTest(false,
                        "OKK signed with 0x%016X, not the enrolled 0x%016X".format(issuer, subkeyId))
                    val bridged = runCatching {
                        val raw = PgpSshBridge.extractRawSignature(r.armored, parsedLine)
                        Triple(PgpSshBridge.rsaSigNameForHash(raw.hashAlg), raw.hashAlg, raw.bytes.size)
                    }.getOrElse { e ->
                        runCatching {
                            File(appContext.filesDir, "last-selftest-sig.asc").writeText(
                                "ENROLLED-LINE: $line\n\narmored:\n${r.armored}")
                        }
                        return SshSelfTest(false, "bridge failed: ${e.message} " +
                            "(armor saved to last-selftest-sig.asc)")
                    }
                    return SshSelfTest(true,
                        "signed by 0x%016X (hash %d → %s, %d raw bytes → SSH framing OK)"
                            .format(subkeyId, bridged.second, bridged.first, bridged.third))
                }
                is OpenPgpClient.SignDetached.UserInteraction -> {
                    reqData = interactionHandler?.invoke(r.pendingIntent)
                        ?: return SshSelfTest(false, "interaction needs the UI layer")
                }
                is OpenPgpClient.SignDetached.Error ->
                    return SshSelfTest(false, "OKK error: ${r.message}")
            }
        }
        return SshSelfTest(false, "aborted after interaction retries")
    }

    fun saveConnectDraft(ownerRepo: String, auth: String) {
        prefs().edit()
            .putString("connectDraftOwnerRepo", ownerRepo)
            .putString("connectDraftAuth", auth)
            .apply()
    }

    fun connectDraftOwnerRepo(): String? =
        prefs().getString("connectDraftOwnerRepo", null)?.takeIf { it.isNotBlank() }

    fun connectDraftAuth(): String? = prefs().getString("connectDraftAuth", null)

    /** Converts the remote between the sync-auth schemes WITHOUT losing the
     *  user's text: already-correct forms pass through; recognizable
     *  other-scheme forms are rebuilt (git@host:path ⇄ https://host/path);
     *  partial/bare text gets the target prefix PREPENDED, never replaced
     *  (the old handlers clobbered the whole field on every chip switch). */
    fun convertRemote(remote: String, mode: String): String {
        if (remote.isBlank()) return if (mode == "pat") "https://github.com/" else "git@github.com:"
        val sshOk = remote.startsWith("git@") || remote.startsWith("ssh://")
        val httpsOk = remote.startsWith("https://") || remote.startsWith("http://")
        if (mode != "pat" && sshOk) return remote
        if (mode == "pat" && httpsOk) return remote
        val rest = remote
            .removePrefix("git@").removePrefix("ssh://")
            .removePrefix("https://").removePrefix("http://")
        val colon = rest.indexOf(':')
        val slash = rest.indexOf('/')
        val firstSep = listOf(colon, slash).filter { it >= 1 }.minOrNull() ?: rest.length
        val host = rest.substring(0, firstSep)
        val looksLikeHost = host.contains('.')
        val isSshMode = mode != "pat"
        return when {
            looksLikeHost && colon >= 1 && (slash == -1 || colon < slash) ->
                if (isSshMode) "git@$host:${rest.substring(colon + 1)}"
                else "https://$host/${rest.substring(colon + 1).removePrefix("/")}"
            looksLikeHost && slash >= 1 ->
                if (isSshMode) "git@$host:${rest.substring(slash + 1)}"
                else "https://$host/${rest.substring(slash + 1)}"
            looksLikeHost -> // bare host: just the scheme prefix.
                if (isSshMode) "git@$host:" else "https://$host/"
            else -> // bare owner/repo or mid-typing: prepend, don't discard.
                if (isSshMode) "git@github.com:" + rest.trimEnd(':').removePrefix("/")
                else "https://github.com/" + rest.trimEnd('/')
        }
    }

    fun clearConnectDraft() {
        prefs().edit()
            .remove("connectDraftOwnerRepo")
            .remove("connectDraftAuth")
            .apply()
    }

    /** Deletes with a tombstone (survives merges/syncs). */
    suspend fun delete(item: ProtonItem): Result {
        loadedEnvelope?.deletedItemUuids?.add(item.itemUuid)
        val remaining = (state as? State.Unlocked)?.items
            ?.filter { it.itemUuid != item.itemUuid } ?: emptyList()
        return save(remaining)
    }

    // -- git open without decrypt (new-vault / import flows) -----------------

    suspend fun gitOpenOnly(): Result {
        val cfg = config() ?: return Result.Error("No config")
        val remote = cfg.remoteUrl ?: return Result.Success  // local-only: nothing to open
        val useSsh = VaultGitClient().isSshRemote(remote)
        val pat = if (useSsh) "" else (pat() ?: return Result.Error("No PAT stored"))
        busy = "Opening repo…"
        try {
            withContext(Dispatchers.IO) { VaultGitClient().open(remote, pat, gitRoot()) }
            return Result.Success
        } catch (e: Exception) {
            Log.w(TAG, "git open failed: ${e.message}")
            // The YubiKey identity records the OpenKeyChain-side failure
            // (JSch only says "Auth cancelled") — surface it so a wrong-
            // subkey enrollment or an OKK rejection is diagnosable. Cleared
            // first so a SCREENLOCK failure never inherits a stale
            // YubiKey-mode error from an earlier attempt.
            val extra = com.offlinepass.app.crypto.YubiKeySshIdentity.lastAuthError
            com.offlinepass.app.crypto.YubiKeySshIdentity.lastAuthError = null
            return Result.Error("Repo open failed: ${e.message?.take(60)}" +
                (extra?.let { " — $it" } ?: ""))
        } finally {
            busy = null
        }
    }

    /** Attach (or re-attach) a remote to a LOCAL-ONLY vault: stores the PAT,
     *  connects origin to the existing local history (VaultGitClient.open
     *  handles a .git without remotes), then syncs (fetch + merge + push).
     *  On any failure the vault stays local-only — nothing is wiped. */
    suspend fun connectRemote(remote: String, pat: String): Result {
        val cfg = config() ?: return Result.Error("No config")
        if (cfg.remoteUrl != null) return Result.Error("A remote is already configured")
        val useSsh = VaultGitClient().isSshRemote(remote)
        if (remote.isBlank()) return Result.Error("Remote URL is required")
        if (!useSsh && pat.isBlank()) return Result.Error("A PAT is required for HTTPS remotes")
        if (useSsh && !SshKeyManager().hasKeyPair())
            return Result.Error("Enroll the screenlock SSH key first (Setup)")
        if (useSsh) {
            // Enrollment + gate depend on the active SSH identity mode.
            if (sshSyncMode() == SSH_SYNC_YUBIKEY) {
                if (yubikeySshLine() == null || yubikeyAuthSubkeyId() == null)
                    return Result.Error("Enroll the YubiKey SSH key first (Setup → paste the SSH line)")
            } else {
                if (!SshKeyManager().hasKeyPair())
                    return Result.Error("Enroll the screenlock SSH key first (Setup)")
                sshGateIfNeeded()?.let { return Result.Error("$it — still local-only") }
            }
        } else {
            savePat(pat)
        }
        configure(remote, cfg.recipientEmails)
        busy = "Connecting remote…"
        try {
            withContext(Dispatchers.IO) { VaultGitClient().open(remote, pat, gitRoot()) }
        } catch (e: Exception) {
            configure(null, cfg.recipientEmails)
            val msg = logSyncFailure("connectRemote", e)
            return Result.Error("Connect failed: ${msg.take(120)} — still local-only")
        } finally {
            busy = null
        }
        val sync = syncNow()
        if (sync !is Result.Success) {
            configure(null, cfg.recipientEmails)
            return Result.Error("Connected, but sync failed: ${syncMessage(sync)} — reverted to local-only")
        }
        return Result.Success
    }

    private fun syncMessage(r: Result): String = when (r) {
        is Result.Error -> r.message
        else -> r.toString()
    }

    /** Wipes + re-clones the git state, preserving the current vault
     * ciphertext (re-applied + pushed when the session is unlocked). This
     * is the escape hatch for "destination path exists"/corrupted-clone
     * states. The LOCAL-ONLY vault file is untouched (it's not a repo). */
    suspend fun resetRepo(): Result {
        val cfg = config() ?: return Result.Error("Local-only mode: nothing to reset")
        val remote = cfg.remoteUrl ?: return Result.Error("Local-only mode: nothing to reset")
        val pat = if (VaultGitClient().isSshRemote(remote)) "" else
            (pat() ?: return Result.Error("No PAT stored"))
        busy = "Resetting repo…"
        try {
            withContext(Dispatchers.IO) {
                val saved = vaultFile().takeIf { it.exists() }?.readBytes()
                gitRoot().deleteRecursively()
                VaultGitClient().open(remote, pat, gitRoot())
                saved?.let { bytes ->
                    val vf = vaultFile()
                    vf.parentFile?.mkdirs()
                    vf.writeBytes(bytes)
                }
            }
            // Re-apply the live session state (re-encrypt + merge-aware push)
            // when the vault is unlocked; otherwise the restored ciphertext
            // stands as-is.
            val items = (state as? State.Unlocked)?.items
            if (items != null) return save(items)
            syncStatus = "Repo reset (re-cloned)"
            return Result.Success
        } catch (e: Exception) {
            Log.w(TAG, "resetRepo failed: ${e.message}")
            syncStatus = "Repo reset failed: ${e.message?.take(50)}"
            return Result.Error("${e.javaClass.simpleName}: ${e.message}")
        } finally {
            busy = null
        }
    }

    /** Fetch + push, with application-level union-merge when the two
     * devices diverged (the M3 convergence path). SSH remotes authenticate
     * with the screenlock keystore key — the biometric gate opens the
     * key's 60s validity window, then the sync runs; no PAT involved. */
    suspend fun syncNow(): Result {
        val cfg = config() ?: return Result.Error("Local-only mode: nothing to sync")
        val remote = cfg.remoteUrl ?: return Result.Error("Local-only mode: nothing to sync")
        val useSsh = VaultGitClient().isSshRemote(remote)
        if (useSsh) {
            // Enrollment + gate depend on the active SSH identity mode.
            if (sshSyncMode() == SSH_SYNC_YUBIKEY) {
                if (yubikeySshLine() == null || yubikeyAuthSubkeyId() == null)
                    return Result.Error("Enroll the YubiKey SSH key first (Setup → Choose key)")
                // The gate is the YubiKey touch inside the card sign during
                // the handshake (PIN once per sync, touch per signature) —
                // no pre-auth needed.
            } else {
                if (!SshKeyManager().hasKeyPair())
                    return Result.Error("Enroll the screenlock SSH key first (Setup)")
                sshGateIfNeeded()?.let { return Result.Error("$it — sync aborted") }
            }
        }
        val pat = if (useSsh) "" else (pat() ?: return Result.Error("No PAT stored"))
        busy = "Syncing…"
        try {
            withContext(Dispatchers.IO) {
                val git = VaultGitClient()
                val root = gitRoot()
                git.open(remote, pat, root)
                // Track the signer/authorized-key material in the repo (the
                // offline keyring); best-effort, committed with the vault.
                updateRepoKeyMaterial(openPgpClientFactory(appContext))
                val vaultRelPath = "state/10.gpg"
                // Commit a stranded/dirty vault file FIRST so it participates
                // in the divergence check + push (a failed push leaves it
                // uncommitted; without this it never reaches the remote).
                // Signed with the SAME signer mode as save(): screenlock,
                // YubiKey (the card's SIGNATURE slot), or OpenKeyChain.
                val preSigner: org.eclipse.jgit.lib.Signer? = when (commitSigningMode()) {
                    SIGNING_SCREENLOCK -> {
                        val hook = keystoreSignerHook
                            ?: throw IllegalStateException("Screenlock signer unavailable")
                        com.offlinepass.app.crypto.KeystoreCommitSigner(hook)
                    }
                    SIGNING_YUBIKEY -> syncCommitSigner(OpenPgpClient(appContext))
                        ?: throw IllegalStateException(sshIdentityUnavailable
                            ?: "YubiKey signer unavailable")
                    else -> {
                        val preSignId = signingKeyId()
                            ?: (cachedRecipientKeyIds() ?: recipientKeyIds().toLongArray()).firstOrNull()
                        if (preSignId != null) {
                            busy = "Checking sign key…"
                            ensureSignKeyReady(preSignId, openPgpClientFactory(appContext))?.let { msg ->
                                throw IllegalStateException(msg)
                            }
                            OpenKeyChainSigner(OpenPgpClient(appContext), preSignId)
                        } else null
                    }
                }
                git.commitDirty(root, "Update 10.gpg (pre-sync)", preSigner)
                when (val div = git.headVsRemote(root)) {
                    is VaultGitClient.Divergence.UpToDate -> {
                        syncStatus = "Already up to date (rev $rev)"
                        // A fresh clone may carry the vault without the
                        // session being unlocked yet.
                        refreshFromVaultFile()
                    }
                    is VaultGitClient.Divergence.AheadOnly -> {
                        // Empty-remote first push: GitHub repos created via
                        // the web UI have no commits and no branches — the
                        // first push CREATES main. Warn + confirm before
                        // that (one tap; it's a one-time event per remote).
                        if (!git.remoteBranchExists(root, "main")) {
                            val gate = firstPushGate
                                ?: return@withContext Result.Error(
                                    "The remote repository is empty — confirm the first push in the UI")
                            busy = null
                            if (!gate()) {
                                syncStatus = "First push cancelled — still local-only"
                                return@withContext Result.Error("First push cancelled — the remote stays empty")
                            }
                            busy = "Pushing…"
                        }
                        git.pushBranch(remote, pat, root)
                        syncStatus = "Pushed (rev $rev)"
                    }
                    is VaultGitClient.Divergence.BehindOnly -> {
                        git.resetHardTo(root, "origin/main")
                        refreshFromVaultFile()
                        syncStatus = "Pulled remote (rev $rev)"
                    }
                    is VaultGitClient.Divergence.Diverged -> {
                        Log.i(TAG, "diverged: merging ${div.headId.take(7)} with ${div.remoteId.take(7)}")
                        val remoteEnv = git.readFileAt(root, "origin/main:$vaultRelPath")
                            ?.let { b -> runCatching { Envelope.fromJson(String(b)) }.getOrNull() }
                            ?: Envelope(deviceId = cfg.deviceId)
                        val localEnv = git.readFileAt(root, "HEAD:$vaultRelPath")
                            ?.let { b -> runCatching { Envelope.fromJson(String(b)) }.getOrNull() }
                            ?: Envelope(deviceId = cfg.deviceId)
                        val merged = VaultMerge.unionMerge(localEnv, remoteEnv)

                        // Rebuild the branch on top of origin/main with the
                        // merged (re-encrypted) vault file.
                        git.resetHardTo(root, "origin/main")
                        val client = OpenPgpClient(appContext)
                        val keyIds = cachedRecipientKeyIds() ?: recipientKeyIds().toLongArray()
                        if (keyIds.isEmpty()) throw IllegalStateException("no recipients")
                        val plain = File(appContext.cacheDir, "merge-plain.json")
                        try {
                            plain.writeText(merged.toJsonObject().toString())
                            val target = File(root, vaultRelPath)
                            target.parentFile?.mkdirs()
                            if (!client.encryptTo(keyIds, plain, target)) {
                                throw IllegalStateException("encrypt during merge failed")
                            }
                        } finally {
                            SecureWipe.file(plain)
                        }
                        val signer: org.eclipse.jgit.lib.Signer? = when (commitSigningMode()) {
                            SIGNING_SCREENLOCK -> keystoreSignerHook
                                ?.let { com.offlinepass.app.crypto.KeystoreCommitSigner(it) }
                            SIGNING_YUBIKEY -> yubikeyCommitSignerOrNull()
                            else -> OpenKeyChainSigner(client, signingKeyId() ?: keyIds.first())
                        }
                        try {
                            git.commitFile(root, "Merge with remote (rev ${merged.rev})", signer)
                        } catch (e: Exception) {
                            Log.w(TAG, "merge commit signing failed: ${e.message}")
                            git.commitFile(root, "Merge with remote (rev ${merged.rev})", null)
                        }
                        git.pushBranch(remote, pat, root)
                        rev = merged.rev
                        loadedEnvelope = merged
                        state = State.Unlocked(merged.items)
                        sealIfEnabled(merged.items, merged)
                        syncStatus = "Merged + pushed (rev ${merged.rev})"
                    }
                }
            }
            return Result.Success
        } catch (e: Exception) {
            val msg = logSyncFailure("syncNow", e)
            syncStatus = "Sync failed: ${msg.take(200)}"
            return Result.Error(msg)
        } finally {
            busy = null
        }
    }

    /** Re-decrypts the on-disk vault file into the session (after a pull). */
    private suspend fun refreshFromVaultFile() {
        when (val r = decryptEnvelope(vaultFile())) {
            is VaultSession.DecryptEnvelope.Ok -> {
                rev = r.env.rev
                loadedEnvelope = r.env
                state = State.Unlocked(r.env.items)
                sealIfEnabled(r.env.items, r.env)
            }
            else -> Log.w(TAG, "post-pull decrypt failed")
        }
    }

    /**
     * Writes the recipients' armored public keys (keys/<keyid>.public.asc)
     * and the recipients ledger (keys/recipients.txt) into the repo root —
     * committed with the vault, so git history records exactly which keys
     * can open each revision. Best-effort: a failed fetch is retried on the
     * next save; returns true when every key file is present.
     */
    private suspend fun materializeRecipientKeys(
        client: OpenPgpOps,
        repoRoot: File,
        keyIds: LongArray
    ): Boolean {
        var allPresent = true
        val encryptDir = File(repoRoot, "keys/encrypt").apply { mkdirs() }
        for (id in keyIds) {
            val f = File(encryptDir, "%016X.pub.asc".format(id))
            // The legacy layout (keys/<id>.public.asc) counts as present.
            val legacy = File(repoRoot, "keys/%016X.public.asc".format(id))
            if (f.exists() || legacy.exists()) continue
            when (val r = client.fetchPublicKeyArmored(id)) {
                is OpenPgpClient.PublicKey.Success -> {
                    f.writeText(r.armored.trimEnd() + "\n")
                    Log.i(TAG, "wrote recipient key file ${f.name}")
                }
                else -> {
                    Log.w(TAG, "armored key fetch pending for 0x%016X".format(id))
                    allPresent = false
                }
            }
        }
        val cfg = config()
        File(encryptDir, "recipients.txt").writeText(
            buildString {
                appendLine("# who can open this vault (ledger, informational)")
                appendLine("recipientEmails: " + (cfg?.recipientEmails?.joinToString(", ") ?: "-"))
                appendLine("recipientKeyIds: " + keyIds.joinToString(" ") { "0x%016X".format(it) })
                appendLine("deviceId: " + deviceId())
                appendLine("updated: ${java.util.Date()}")
            }
        )
        return allPresent
    }

    sealed interface DecryptEnvelope {
        data class Ok(val env: Envelope) : DecryptEnvelope
        data class Interaction(val pendingIntent: android.app.PendingIntent) : DecryptEnvelope
        data class Error(val message: String) : DecryptEnvelope
    }

    /** Decrypts an arbitrary vault file (USB restore path). */
    suspend fun decryptEnvelope(file: File): DecryptEnvelope = withContext(Dispatchers.IO) {
        if (!file.exists()) return@withContext DecryptEnvelope.Error("File missing")
        val plain = File(appContext.cacheDir, "restore-plain.json")
        val client = OpenPgpClient(appContext)
        try {
            var reqData: Intent? = null
            var guard = 0
            while (guard++ < 2) {
                when (val r = client.decryptVerify(file, plain, reqData)) {
                    is OpenPgpClient.DecryptResult.Success ->
                        return@withContext DecryptEnvelope.Ok(Envelope.fromJson(plain.readText()))
                    is OpenPgpClient.DecryptResult.UserInteraction -> {
                        val h = interactionHandler ?: return@withContext DecryptEnvelope.Error("Interaction needs the UI layer")
                        reqData = h(r.pendingIntent)
                    }
                    is OpenPgpClient.DecryptResult.Error -> return@withContext DecryptEnvelope.Error("Decrypt failed (see logcat)")
                }
            }
            DecryptEnvelope.Error("Decrypt aborted after interaction retry")
        } finally {
            SecureWipe.file(plain)
        }
    }

    /** Adopts an already-decrypted envelope as the unlocked session —
     * no second decrypt, no extra OpenKeyChain prompts (USB restore). */
    fun adopt(env: Envelope) {
        rev = env.rev
        loadedEnvelope = env
        state = State.Unlocked(env.items)
        sealIfEnabled(env.items, env)
    }

    /**
     * Zeros ALL decrypted material: the unlocked item list, the loaded
     * envelope, and every plaintext temp file the decrypt/encrypt paths
     * could have left in the cache dir. The session steps back to Locked.
     *
     * Called on exit (MainActivity.onDestroy when finishing) and from the
     * Setup tab's lock action. Java strings are immutable, so the heap
     * copies are released for GC rather than overwritten; the on-disk
     * copies, though, are zero-filled byte-for-byte before unlink.
     */
    fun zero() {
        loadedEnvelope?.items?.clear()
        loadedEnvelope?.deletedItemUuids?.clear()
        loadedEnvelope?.extraFields?.clear()
        loadedEnvelope = null
        rev = 0
        if (state is State.Unlocked) state = State.Locked
        if (!::appContext.isInitialized) return
        val cache = appContext.cacheDir
        SecureWipe.all(
            File(cache, "vault-plain.json"),
            File(cache, "vault-plain-next.json"),
            File(cache, "merge-plain.json"),
            File(cache, "restore-plain.json"),
        )
        // Hint the VM to collect the just-released plaintext strings.
        runCatching { System.gc() }
    }
}
