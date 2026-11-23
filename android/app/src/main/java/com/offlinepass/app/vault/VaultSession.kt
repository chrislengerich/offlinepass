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
import android.os.Handler
import android.os.Looper
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
    internal var openPgpClientFactory: (Context) -> OpenPgpOps = { sharedOpenPgpClient(it) }

    /**
     * The vault ENVELOP seams — the hot-path crypto (the load decrypt +
     * the save/merge encrypt). Production: the YubiKit card + BouncyCastle
     * (no OpenKeyChain in the path). Tests override both to run the save
     * transaction on the JVM without the card.
     *
     * The decrypt = the raw vault file → the plaintext JSON. The card op
     * (the PIN verify + PSO:DEC) rides ONE USB connection; the touch
     * prompt wraps the card op.
     */
    internal var vaultDecryptBytes: suspend (ByteArray) -> ByteArray = { bytes ->
        kotlinx.coroutines.withContext(Dispatchers.IO) {
            val pin = yubikeyPin() ?: throw java.io.IOException("OpenPGP PIN cancelled")
            val plain = try {
                com.offlinepass.app.crypto.YubiKitCardDecrypt.decryptEnvelopeBytes(
                    appContext, bytes, pin,
                    log = { loadPhase(it) },
                ) { op -> withTouchPrompt { op() } }
            } catch (e: com.offlinepass.app.crypto.OpenPgpPinRejected) {
                // The card proved the cached PIN wrong — never retry it.
                yubikeyPinInvalidate()
                throw e
            }
            yubikeyPinRemember(pin)
            plain
        }
    }

    /** The vault encrypt: the plaintext JSON → the OpenPGP ciphertext for
     *  the repo's recipients (keys/encrypt/&lt;keyid&gt;.pub.asc). */
    internal var vaultEncryptBytes: suspend (plain: ByteArray, repoRoot: File, keyIds: LongArray) -> ByteArray =
        { plain, repoRoot, keyIds ->
            com.offlinepass.app.crypto.OpenPgpCardCrypto.encryptToBytes(
                plain, "10.gpg", loadRecipientKeysFor(repoRoot, keyIds))
        }

    /** Loads the recipients' public keys from the repo's armored files
     *  (keys/encrypt/&lt;keyid&gt;.pub.asc; the legacy flat layout counts). */
    internal fun loadRecipientKeysFor(repoRoot: File, keyIds: LongArray): List<org.bouncycastle.openpgp.PGPPublicKey> {
        val encryptDir = File(repoRoot, "keys/encrypt")
        val keys = keyIds.flatMap { id ->
            val f = File(encryptDir, "%016X.pub.asc".format(id))
            val legacy = File(repoRoot, "keys/%016X.public.asc".format(id))
            val file = when {
                f.exists() -> f
                legacy.exists() -> legacy
                else -> throw java.io.IOException(
                    "the recipient key 0x%016X is missing (keys/encrypt) — re-sync to materialize it".format(id))
            }
            com.offlinepass.app.crypto.OpenPgpCardCrypto.loadRecipientKeys(file.readBytes())
        }
        if (keys.isEmpty()) throw java.io.IOException("no usable recipient keys in keys/encrypt")
        return keys
    }

    /** The SHARED OpenKeyChain client: ONE instance whose binding persists
     *  for the process lifetime. The per-op clients unbound on close —
     *  OKK's process then died between ops, and every subsequent decrypt/
     *  encrypt re-paid OKK's 5-20s cold start (the measured "slow
     *  OpenKeyChain" regression). Never close() the shared one. */
    @Volatile private var sharedClientInstance: OpenPgpClient? = null
    private fun sharedOpenPgpClient(context: Context): OpenPgpClient =
        sharedClientInstance ?: synchronized(this) {
            sharedClientInstance ?: OpenPgpClient(context).also {
                sharedClientInstance = it
            }
        }

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

    /** THE SIGNER PROMPT'S TRANSACTION: the item saves set the summary
     *  (the site, the identity, the URL, the masked password) so the ONE
     *  screenlock prompt shows WHAT is being saved; the UI signer hook
     *  reads it into the prompt's description and consumes it. Null = the
     *  non-item saves (the sync merges, the imports) keep the default
     *  wording. */
    var pendingSignerDescription: String? = null
        private set

    /** THE SAVE TRANSACTION TEXT for the one screenlock prompt: the site,
     *  the identity, the URL, the password's SHAPE — masked, because the
     *  prompt is a system surface any onlooker can read. */
    fun saveTransactionText(item: ProtonItem): String = buildString {
        append(item.name)
        item.identity.takeIf { it.isNotBlank() }?.let { append(" — $it") }
        item.urls.firstOrNull()?.let { append("\n$it") }
        if (item.password.isNotBlank())
            append("\npassword •••••••• (${item.password.length} chars)")
    }

    /** THE CONSUME for the signer hooks: the prompt reads the transaction
     *  ONCE (null = the default wording) — nothing lingers for a later
     *  unrelated prompt. */
    fun consumeSignerDescription(): String? {
        val d = pendingSignerDescription
        pendingSignerDescription = null
        return d
    }

    /** SSH sync identities: the SCREENLOCK keystore key or the YUBIKEY's
     *  OpenPGP auth subkey (via OpenKeyChain — the key already enrolled in
     *  GitHub). Whichever was enrolled last wins; both are exclusive of
     *  the HTTPS/PAT path. */
    const val SSH_SYNC_SCREENLOCK = "screenlock"
    const val SSH_SYNC_YUBIKEY = "yubikey"

    /** The SSH sync auth mode: **the SECURITY KEY (YubiKey) is the
     *  default** — a previously-wiped/unset pref previously fell back to
     *  the screenlock mode, and a sync then offered the screenlock's
     *  unregistered SSH key (the "Auth fail" seen on-device). */
    fun sshSyncMode(): String =
        prefs().getString("sshSyncMode", null) ?: SSH_SYNC_YUBIKEY

    /** THE SSH-AUTH SLOT = THE ENROLLED LINE's — no toggle. The GitHub
     *  enrollment proves a slot's key against the owner's key list and
     *  records WHICH slot matched; the transport, the self-test and the
     *  dialogs all follow the record. Default = SIG (the legacy
     *  enrollment's line is the SIG subkey's — the old boolean's AUT
     *  default would send an RSA-4096 AUTH key into the named 0x6581
     *  dead end). */
    fun sshAuthUseAut(): Boolean = prefs().getString("yubikeySshSlot", "SIG") == "AUT"
    fun setYubikeySshSlot(slot: String) {
        prefs().edit().putString("yubikeySshSlot", slot).apply()
    }

    /** DEPRECATED for the SCREENLOCK value: the screenlock is no longer an
     *  auth key (only signing + the local at-rest seal). The backend stays
     *  (the SshKeyManager identity + the SSH transport are intact) for a
     *  possible re-enable; the flows must not set SCREENLOCK anymore. */
    @Deprecated("the screenlock is not an auth key; the security key is the auth default")
    fun setSshSyncMode(mode: String) {
        prefs().edit().putString("sshSyncMode", mode).apply()
    }

    fun yubikeySshLine(): String? = prefs().getString("yubikeySshLine", null)

    /** THE UNSIGNED-HEX 16 PARSE: the OpenPGP key ids with the high bit
     *  set (very common) are negative as signed Longs — base-10 parsing
     *  or toLongOrNull(16) returns null for exactly the ids real keys
     *  have (the root cause of the silent "Auth cancelled"). Null =
     *  malformed (absent, not 16 hex digits, or unparsable). */
    internal fun parseSubkeyId16(hex: String?): Long? =
        hex?.takeIf { it.length == 16 }?.let {
            runCatching { java.lang.Long.parseUnsignedLong(it, 16) }.getOrNull()
        }

    fun yubikeyAuthSubkeyId(): Long? = parseSubkeyId16(prefs().getString("yubikeyAuthSubkeyId", null))

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
     *  prompt. Null = the user cancelled.
     *
     *  Returns a COPY: the cached array must never leak to a caller that
     *  could mutate it — and it MUST never be the same object the pin
     *  prompt returned, because the expiry path zero-fills the cache and
     *  PinCachingSigner holds ITS own reference to the same array (the
     *  shared array was zeroed out from under the SSH handshake's cache,
     *  and the handshake then signed with an all-zeros PIN — "bad pin"
     *  with no prompt, measured on-device). */
    suspend fun yubikeyPin(): CharArray? {
        cachedYubikeyPin?.takeIf {
            System.currentTimeMillis() - cachedYubikeyPinAt < 60_000
        }?.let { return it.copyOf() }
        cachedYubikeyPin?.fill('0')
        cachedYubikeyPin = null
        return openPgpPinPrompt?.invoke()
    }

    /** Caches a COPY of [pin] (on a successful card op only). */
    fun yubikeyPinRemember(pin: CharArray) {
        cachedYubikeyPin?.fill('0')
        cachedYubikeyPin = pin.copyOf()
        cachedYubikeyPinAt = System.currentTimeMillis()
    }

    /** Drops the cached PIN — called when the card REJECTS it (a proven-
     *  wrong cached PIN must never be retried: every retry burns one of
     *  the card's 3 attempts). */
    fun yubikeyPinInvalidate() {
        cachedYubikeyPin?.fill('0')
        cachedYubikeyPin = null
        cachedYubikeyPinAt = 0
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

    /** The sync's signer reconciliation (the protocol's enforcement):
     *  after a merge/pull, if THIS device's screenlock entry is gone from
     *  the registry (another device's security-key-signed commit removed
     *  it), the local signing mode flips to the security key and the
     *  orphaned keystore key is deleted. A revocation by one device is
     *  honored by every device on its next sync. */
    fun reconcileSignersAfterSync() {
        if (commitSigningMode() == SIGNING_SCREENLOCK &&
            !screenlockRegisteredForThisDevice()
        ) {
            setCommitSigningMode(SIGNING_YUBIKEY)
            com.offlinepass.app.crypto.KeystoreSigner.removeKey()
            Log.i(TAG, "the screenlock signing was revoked in the repo — " +
                "the signing mode is now the security key")
        }
    }

    /** The touch prompt: TRUE while ANY YubiKey op waits for a touch (the
     *  SSH auth, the commit signing, the enrollment, the self-test) — the
     *  router shows the "touch your YubiKey" dialog, which dismisses the
     *  moment the op completes (or fails). */
    var touchPrompt by androidx.compose.runtime.mutableStateOf(false)
        private set

    internal suspend fun <T> withTouchPrompt(block: suspend () -> T): T {
        touchPrompt = true
        try {
            // The card op = the blocking USB/APDU (the touch wait!) — the
            // IO hop BEFORE the block: the state mutation lands first, the
            // main thread stays free to compose the dialog, and the op
            // cannot freeze it (the enrollment used to sign from the
            // lifecycleScope = the dialog never rendered while the card
            // waited for a touch the user never saw requested).
            return kotlinx.coroutines.withContext(Dispatchers.IO) { block() }
        } finally {
            touchPrompt = false
        }
    }

    /** Warms the shared OpenKeyChain binding (the cold start overlaps the
     *  SSH auth and the fetch). */

    /** The user-editable device name (defaults to the model); stamped into
     *  the registry. */
    fun deviceName(): String =
        prefs().getString("deviceName", null) ?: android.os.Build.MODEL
    fun setDeviceName(n: String) {
        val clean = sanitizeDeviceName(n)
        prefs().edit().putString("deviceName", clean).apply()
        // THE REGISTRY: the SCREENLOCK entry renames with the device (the
        // card entries answer to their own names — set in Setup). The
        // change lands in the worktree; commitDeviceRename() commits it.
        var changed = false
        val entries = readDeviceRegistry().map { e ->
            val mine = e.authKey?.contains(
                "offlinepass-screenlock device=${deviceId()}") == true
            if (mine && e.name != clean) { changed = true; e.copy(name = clean) } else e
        }
        if (changed) writeDeviceRegistry(entries)
    }

    /** The KNOWN security keys (the registry's card entries) — the
     *  Devices section's Security keys rows. */
    fun securityKeyLabels(): List<String> =
        readDeviceRegistry()
            .filter {
                it.cert?.endsWith(".pub.asc") == true ||
                    (it.authKey != null && !it.authKey.contains("offlinepass-screenlock"))
            }
            .map { e ->
                val serialTag = e.serial?.takeLast(4)?.let { " s/n…$it" } ?: ""
                val kind = if (e.cert?.endsWith(".pub.asc") == true)
                    "security key (auth + sign)" else "security key (auth; sign pending)"
                "${e.name}$serialTag — $kind"
            }

    /** THE PROTON EXPORT: the password material in PLAINTEXT, in the
     *  native Proton Pass JSON shape (the same the importer reads) — an
     *  array of login items. Requires a full (promoted) session: the
     *  secrets leave the app in the clear by explicit request. */
    suspend fun exportProtonJson(): String? {
        if (state !is State.Unlocked) return null
        if (stubSession && !promoteIfStub()) return null
        val env = loadedEnvelope ?: return null
        val arr = org.json.JSONArray()
        env.items.forEach { arr.put(it.toProtonJson()) }
        return arr.toString(2)
    }

    /** THE GOOGLE EXPORT: the password material in PLAINTEXT, in the Google
     *  Passwords CSV shape (the same the importer reads) — the four columns
     *  `name,url,username,password`. THE LOSSY RULE: the note, the TOTP
     *  uri, the extra URLs and the passkeys DO NOT FIT the Google format —
     *  the caller warns before/after handing the file over. Requires a
     *  full (promoted) session: the secrets leave the app in the clear by
     *  explicit request. */
    suspend fun exportGoogleCsv(): String? {
        if (state !is State.Unlocked) return null
        if (stubSession && !promoteIfStub()) return null
        val env = loadedEnvelope ?: return null
        return GooglePasswordsCsv.serialize(env.items)
    }

    /** The plugged key's current name (the registry entry for the last
     *  seen serial) — the rename dialog's prefill; a never-seen key gets
     *  the "purple" suggestion. */
    fun securityKeyNameSuggestion(): String =
        readDeviceRegistry().firstOrNull {
            it.serial != null && it.serial == prefs().getString("securityKeySerial", null)
        }?.name ?: "purple"

    /** The plugged security key's identity: the OpenPGP card serial (the
     *  PHYSICAL key's stable id) + the AUTH slot's current public key
     *  material. Asks for the USB permission when needed. The serial is
     *  remembered in prefs so the repo-side card-entry maintenance can
     *  match by key even when the card is unplugged. */
    suspend fun readSecurityKeyIdentity(): Pair<Int, String>? {
        return withContext(Dispatchers.IO) {
            try {
                if (!com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(appContext) &&
                    !com.offlinepass.app.crypto.YubiKitSshAuth.requestPermission(appContext)
                ) return@withContext null
                val serial = com.offlinepass.app.crypto.YubiKitSshAuth
                    .cardSerial(appContext) ?: return@withContext null
                val line = com.offlinepass.app.crypto.YubiKitSshAuth
                    .slotSshLine(appContext, true)
                if (line != null) {
                    prefs().edit().putString("securityKeySerial", serial.toString()).apply()
                }
                serial to (line ?: "")
            } catch (e: Exception) {
                Log.w(TAG, "security-key identity read failed: ${e.message}")
                null
            }
        }
    }

    /** Names (or renames) the PLUGGED security key: reads the card's
     *  serial + the AUTH slot's public key material, finds the pairing in
     *  the registry by serial (legacy entries without a serial backfill
     *  when their material matches), creates the entry for a never-seen
     *  key, and commits the rename. */
    suspend fun applySecurityKeyName(name: String): String {
        val id = readSecurityKeyIdentity()
            ?: return "No security key attached (or USB permission denied) — plug it in, then tap again."
        val clean = sanitizeDeviceName(name)
        val entries = readDeviceRegistry().toMutableList()
        val idx = entries.indexOfFirst { it.serial == id.first.toString() }
            .let { first ->
                if (first >= 0) first
                else entries.indexOfFirst { e ->
                    e.serial == null && e.cert?.endsWith(".pub.asc") == true &&
                        (e.authKey == id.second || e.authKey == yubikeySshLine()?.trimEnd())
                }
            }
        if (idx >= 0) {
            val e = entries[idx]
            if (e.name == clean && e.serial != null && e.authKey == id.second) {
                return "Already named '$clean' — nothing to change."
            }
            entries[idx] = e.copy(name = clean, serial = id.first.toString(),
                authKey = id.second.ifEmpty { e.authKey })
        } else {
            entries += DeviceRegistryEntry(clean, id.second.ifEmpty { null }, null,
                id.first.toString())
        }
        writeDeviceRegistry(entries)
        return try {
            withContext(Dispatchers.IO) {
                val signer = syncCommitSigner(openPgpClientFactory(appContext))
                VaultGitClient().commitDirty(
                    gitRoot(), "Name security key '$clean' (serial ${id.first})", signer)
                "Named '$clean' + committed."
            }
        } catch (e: Exception) {
            "Named '$clean' (the registry change rides the next save/sync: " +
                "${e.message?.take(60)})."
        }
    }

    /** The device rename's commit: the registry lives in the repo, so the
     *  rename rides its own signed commit (best effort — the change stays
     *  in the worktree and rides the next save/sync on any failure). */
    suspend fun commitDeviceRename(): String {
        val cfg = config() ?: return "Renamed (local-only — no repo to commit to)."
        return try {
            withContext(Dispatchers.IO) {
                val signer = syncCommitSigner(openPgpClientFactory(appContext))
                VaultGitClient().commitDirty(
                    gitRoot(), "Rename device to '${deviceName()}'", signer)
                "Renamed + committed."
            }
        } catch (e: Exception) {
            "Renamed (the registry change rides the next save/sync: " +
                "${e.message?.take(60)})."
        }
    }

    /** The minimal registry entry: the device NAME mapped to its public
     *  key. The device identity rides in the key line's own comment
     *  ("… offlinepass-screenlock device=<id>"), so there is exactly one
     *  place the identity lives. */
    data class DeviceRegistryEntry(
        val name: String,
        val authKey: String?,      // the OpenSSH line (inline)
        val cert: String?,         // the cert path (relative to the repo root)
        val serial: String? = null // the OpenPGP card serial (the PHYSICAL key's id)
    )

    private fun metaDevicesFile(): File = File(gitRoot(), "meta/devices.json")
    private fun keysAuthDir(): File = File(gitRoot(), "keys/auth")
    private fun keysSignDir(): File = File(gitRoot(), "keys/sign")
    private fun keysEncryptDir(): File = File(gitRoot(), "keys/encrypt")
    private fun authorizedKeysFile(): File = File(keysAuthDir(), "authorized-keys")

    /** Device names are user-visible: strip control bytes (an earlier
     *  build once wrote raw bytes into the registry) and blank the
     *  result to "(unnamed)". */
    private fun sanitizeDeviceName(raw: String): String =
        raw.filter { !it.isISOControl() }.trim().ifEmpty { "(unnamed)" }

    fun readDeviceRegistry(): List<DeviceRegistryEntry> {
        val f = metaDevicesFile()
        if (!f.exists()) return emptyList()
        return runCatching {
            val arr = org.json.JSONObject(f.readText()).getJSONArray("devices")
            val entries = (0 until arr.length()).mapNotNull { i ->
                val o = arr.getJSONObject(i)
                DeviceRegistryEntry(
                    sanitizeDeviceName(o.optString("name", "")),
                    o.optString("authKey", "").ifEmpty { null },
                    o.optString("cert", "").ifEmpty { null },
                    o.optString("serial", "").ifEmpty { null })
            }
            // SELF-HEAL: a sanitized name differing from the stored one
            // rewrites the registry so the fix persists.
            runCatching {
                val raw = (0 until arr.length()).mapNotNull { i ->
                    arr.getJSONObject(i).optString("name", "")
                }
                if (entries.zip(raw).any { (e, r) -> e.name != r })
                    writeDeviceRegistry(entries)
            }
            entries
        }.getOrDefault(emptyList())
    }

    private fun writeDeviceRegistry(entries: List<DeviceRegistryEntry>) {
        val f = metaDevicesFile()
        f.parentFile?.mkdirs()
        val root = org.json.JSONObject()
        val arr = org.json.JSONArray()
        for (e in entries) {
            val o = org.json.JSONObject()
            o.put("name", sanitizeDeviceName(e.name))
            if (e.authKey != null) o.put("authKey", e.authKey)
            if (e.cert != null) o.put("cert", e.cert)
            if (e.serial != null) o.put("serial", e.serial)
            arr.put(o)
        }
        root.put("devices", arr)
        f.writeText(root.toString(2) + "\n")
    }

    /** The device-list labels for Setup: per registry entry — the name,
     *  the kind, the roles, and a "(this device)" marker where the entry's
     *  key line carries this device's id. */
    fun deviceListLabels(): List<String> =
        readDeviceRegistry().map { e ->
            // THE KIND = THE CERT'S SHAPE: the card's signing cert is a
            // .pub.asc (the card's signing subkey's public key); a
            // screenlock entry's cert is the card-signed
            // screenlock-cert-*.meta.json. Every entry carries a cert, so
            // the shape (not the presence) decides.
            val kindLabel = when {
                e.cert?.endsWith(".pub.asc") == true -> "security key (auth + sign)"
                e.authKey?.contains(
                    "offlinepass-screenlock device=${deviceId()}") == true ->
                    "screenlock (sign) — this device"
                // Material-bearing but no cert yet (a freshly named key
                // before the next sync materializes its signing cert):
                // still the CARD — the screenlock comment is the decider.
                e.authKey != null && !e.authKey.contains("offlinepass-screenlock") ->
                    "security key (auth; sign pending)"
                else -> "screenlock (sign)"
            }
            val serialTag = e.serial?.takeLast(4)?.let { " s/n…$it" } ?: ""
            "${e.name}$serialTag — $kindLabel"
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

    /** Ensures a transport line is present in keys/auth/authorized-keys.
     *  The dedupe key = the base64 BLOB (the second token) — deduping by
     *  the algorithm token collapsed every same-alg line into one. */
    private fun appendAuthorizedKey(line: String) {
        val f = authorizedKeysFile()
        f.parentFile?.mkdirs()
        val blob = line.split(" ").getOrNull(1) ?: return
        val existing = if (f.exists()) f.readLines() else emptyList()
        if (existing.none { it.split(" ").getOrNull(1) == blob }) {
            f.appendText(line + "\n")
        }
    }

    /** The LOCAL-ONLY repo key material: the authorized-key append, the
     *  device registry, the screenlock entry, the legacy migration. No
     *  OpenKeyChain — the sync calls this (the sync = the YubiKit path
     *  exclusively). */
    suspend fun updateRepoKeyMaterialLocal() {
        runCatching { migrateLegacyKeyLayout() }
        runCatching {
            val subkeyId = yubikeyAuthSubkeyId()
            if (subkeyId != null) {
                yubikeySshLine()?.let { appendAuthorizedKey(it.trimEnd()) }
                val entries = readDeviceRegistry().toMutableList()
                val certPath = "keys/sign/%016X.pub.asc".format(subkeyId)
                val serial = prefs().getString("securityKeySerial", null)
                val currentLine = yubikeySshLine()?.trimEnd()
                // MATCH BY SERIAL (the physical key) — the legacy cert-path
                // match backfills the serial onto pre-serial entries. The
                // name is the KEY's own (renamed in Setup) and is preserved;
                // the authKey material tracks the CURRENT line (a re-keyed
                // card keeps one entry).
                val idx = entries.indexOfFirst { it.serial != null && it.serial == serial }
                    .let { first ->
                        if (first >= 0) first
                        else entries.indexOfFirst { e -> e.cert == certPath && e.serial == null }
                    }
                if (idx >= 0) {
                    val e = entries[idx]
                    if (e.cert != certPath || e.authKey != currentLine || e.serial != serial) {
                        entries[idx] = e.copy(
                            cert = certPath, authKey = currentLine, serial = serial)
                        writeDeviceRegistry(entries)
                    }
                } else {
                    // A never-named key: a neutral placeholder — the naming
                    // happens in Setup (Set security key name).
                    entries += DeviceRegistryEntry(
                        "Security key %04X".format(subkeyId and 0xFFFF),
                        currentLine, certPath, serial)
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

    /** The local main's last commits — the sync's history display. */
    fun recentCommits(limit: Int = 5): List<String> = runCatching {
        if (!File(gitRoot(), org.eclipse.jgit.lib.Constants.DOT_GIT).exists())
            return@runCatching emptyList()
        org.eclipse.jgit.api.Git.open(gitRoot()).use { git ->
            git.log().setMaxCount(limit).call().map { c ->
                val age = java.time.Duration.ofMillis(
                    System.currentTimeMillis() - c.commitTime * 1000L)
                val whenTxt = when {
                    age.toMinutes() < 1 -> "now"
                    age.toHours() < 1 -> "${age.toMinutes()}m ago"
                    age.toDays() < 1 -> "${age.toHours()}h ago"
                    else -> "${age.toDays()}d ago"
                }
                "%s %s — %s (%s)".format(
                    c.name().take(7), c.shortMessage, c.authorIdent.name, whenTxt)
            }
        }
    }.getOrDefault(emptyList())

    /** THE REPO BACKUP EXPORT: the entire repo dir — `.git` included (the
     *  signed history) + the worktree — into one zip. The clone semantics:
     *  the import unzips into a repo dir and Git.open = a real repository.
     *  No plaintext secrets travel: the vault = the card-encrypted
     *  ciphertext, the keys = the public halves. Returns the file count
     *  (0 = no repo to back up). The size math: ~100–200 compressed bytes
     *  per secret — a 5–10-secret vault zips to a handful of QR frames;
     *  the frame count scales linearly. */
    fun exportBackupZip(out: java.io.OutputStream): Int {
        val root = gitRoot()
        if (!File(root, org.eclipse.jgit.lib.Constants.DOT_GIT).exists()) return 0
        var n = 0
        java.util.zip.ZipOutputStream(out).use { z ->
            root.walkTopDown()
                .filter { it.isFile && !it.name.endsWith(".lock") }
                .sortedBy { it.relativeTo(root).path }
                .forEach { f ->
                    z.putNextEntry(java.util.zip.ZipEntry(f.relativeTo(root).path))
                    f.inputStream().use { it.copyTo(z) }
                    z.closeEntry()
                    n += 1
                }
        }
        Log.i(TAG, "backup zip: $n files")
        return n
    }

    /** THE REPO-BACKUP IMPORT: the zip → the fresh repo dir → Git.open =
     *  a real repository — the clone semantics. The origin is stripped
     *  (the local-only: the remote = attachable later via Setup→Connect,
     *  the history merging through sync). The flow = the load-existing's:
     *  the seed → the card unlock → the stubs. A stale lock/index is
     *  dropped (the zip zipped in lockstep, but the cheap insurance is
     *  free). */
    suspend fun importBackupZip(zip: File): Result {
        val root = gitRoot()
        // THE GUARD: the import = a setup-time restore — an existing vault
        // must never be silently wiped by an import. The merge path (the
        // existing restore flow) covers the over-existing case.
        if (File(root, org.eclipse.jgit.lib.Constants.DOT_GIT).exists() ||
            File(vaultFilePath()).exists()) {
            return Result.Error(
                "A vault already exists on this device — the backup import " +
                    "would overwrite it. Use a fresh install (or the USB " +
                    "restore's merge) instead.")
        }
        root.deleteRecursively()
        root.mkdirs()
        try {
            java.util.zip.ZipInputStream(zip.inputStream()).use { z ->
                var e = z.nextEntry
                while (e != null) {
                    val f = File(root, e.name)
                    val canon = f.canonicalPath
                    if (canon != root.canonicalPath &&
                        !canon.startsWith(root.canonicalPath + File.separator)) {
                        throw java.io.IOException("zip slip: ${e.name}")
                    }
                    if (e.isDirectory) f.mkdirs()
                    else {
                        f.parentFile?.mkdirs()
                        f.outputStream().use { z.copyTo(it) }
                    }
                    e = z.nextEntry
                }
            }
            // The stale guards: the locks (the zip skipped them, but the
            // belt) and a stale index (the JGit re-adds on the next write).
            root.walkTopDown().filter { it.name.endsWith(".lock") }
                .forEach { runCatching { it.delete() } }
            File(root, ".git/index").delete()
            // The origin strip: the import = the local-only; the remote =
            // attachable later via the Setup's Connect.
            org.eclipse.jgit.api.Git.open(root).use { git ->
                git.repository.config.apply {
                    unsetSection("remote", "origin")
                }.save()
            }
            seedRecipientsFromRepo()
            return unlock()
        } catch (e: Exception) {
            Log.w(TAG, "backup import failed: ${e.message}")
            // The half-imported repo = cleaned so the retry is clean.
            runCatching { root.deleteRecursively() }
            return Result.Error("Backup import failed: ${e.message}")
        }
    }

    /** The card's SSH line's presence in the repo's authorized keys:
     *  null = no line or no file (the fresh / the not-yet-synced),
     *  true = the card's blob is authorized, false = the repo's keys are
     *  from another device (the sync appends this device's line). */
    fun cardLineInAuthorizedKeys(): Boolean? {
        val line = yubikeySshLine() ?: return null
        val blob = line.split(" ").getOrNull(1) ?: return null
        val f = authorizedKeysFile()
        if (!f.exists()) return null
        return f.readLines().any { it.split(" ").getOrNull(1) == blob }
    }

    /** The card's DEC slot's key id for the Setup's display — the
     *  unauthenticated read; null = the card not attached/readable. */
    fun cardDecIdForDisplay(): Long? = runCatching {
        com.offlinepass.app.crypto.YubiKitCardDecrypt.decKeyId(appContext)
    }.getOrNull()

    /** The repo's public-key material OKK could import (the sign/encrypt
     *  certs present on disk). */
    fun repoKeyMaterialFiles(): List<File> {
        val out = mutableListOf<File>()
        keysSignDir().listFiles { f -> f.name.endsWith(".pub.asc") }?.forEach { out += it }
        keysEncryptDir().listFiles { f -> f.name.endsWith(".pub.asc") }?.forEach { out += it }
        return out
    }

    /** Stages the repo's key material in APP storage (one file, overwritten
     *  on every tap — no accumulation) and opens OpenKeyChain's import
     *  screen via the app's FileProvider — the file hand-off, since the
     *  OpenPGP remote API cannot mutate OKK's keyring. */
    suspend fun openOkkImportFromRepo(context: android.content.Context): String {
        // THE CARD'S PUBLIC CERT = bootstrapped into the repo HERE — the
        // one moment where touching OpenKeyChain = the user's intent (the
        // import itself). The card exposes only the raw key; the full
        // OpenPGP cert (the uid + the self-signature) = exportable only
        // from OKK's keyring. Once written, the cert rides the repo —
        // every later device gets it from the clone, no fetch at all.
        val subkeyId = yubikeyAuthSubkeyId()
        if (subkeyId != null) {
            val certFile = File(keysSignDir(), "%016X.pub.asc".format(subkeyId))
            if (!certFile.exists()) {
                val client = openPgpClientFactory(appContext)
                var reqData: android.content.Intent? = null
                var guard = 0
                var fetched: String? = null
                while (guard++ < 3 && fetched == null) {
                    when (val fk = client.fetchPublicKeyArmored(subkeyId, reqData)) {
                        is OpenPgpClient.PublicKey.Success -> fetched = fk.armored
                        is OpenPgpClient.PublicKey.UserInteraction -> {
                            reqData = interactionHandler?.invoke(fk.pendingIntent) ?: break
                        }
                        else -> break
                    }
                }
                fetched?.let { armor ->
                    certFile.parentFile?.mkdirs()
                    certFile.writeText(armor.trimEnd() + "\n")
                    Log.i(TAG, "the card's cert materialized at the OKK-import step")
                } ?: run {
                    Log.w(TAG, "the card's cert fetch did not succeed — staging without it")
                }
            }
        }
        val files = repoKeyMaterialFiles()
        if (files.isEmpty()) return "The repo carries no public key material yet."
        val staged = File(appContext.cacheDir, "okk-import.asc")
        staged.parentFile?.mkdirs()
        staged.writeText(files.joinToString("\n") { it.readText().trimEnd() } + "\n")
        return try {
            // The provider resolution inside the try: a misconfigured root
            // (the test environments) = a readable error, not a crash.
            val uri = androidx.core.content.FileProvider.getUriForFile(
                context, context.packageName + ".files", staged)
            val intent = android.content.Intent(android.content.Intent.ACTION_VIEW)
                .setDataAndType(uri, "application/pgp-keys")
                .addFlags(android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION)
            context.startActivity(intent)
            "OpenKeyChain's import opened — confirm the keys there."
        } catch (e: Exception) {
            "OpenKeyChain's import could not be opened: ${e.message} " +
                "(the staged file: $staged)"
        }
    }

    // Test hooks (the singleton + the private layout ops).
    internal fun migrateLegacyKeyLayoutForTest() = migrateLegacyKeyLayout()
    internal fun updateAuthorizedKeysForTest(lines: List<String>) {
        val f = authorizedKeysFile()
        f.parentFile?.mkdirs()
        lines.forEach { appendAuthorizedKey(it) }
    }
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

    /** The screenlock enrollment — fully LOCAL per the signing protocol:
     *  the SECURITY key signs/validates a local CERT for the screenlock's
     *  public key material (the card attests this device's signing key;
     *  the cert = the trust record in meta). The repo update happens on
     *  the next ordinary sync. The at-rest seal activates here: the
     *  prompt opens the seal key's 60s window, then the seal runs
     *  in-window. Returns the user-facing status. */
    suspend fun enrollScreenlockSigning(activity: android.app.Activity?): String {
        val ensured = runCatching {
            com.offlinepass.app.crypto.KeystoreSigner.ensureKey()
        }.getOrElse { return "Keystore signer unavailable: ${it.message}" }

        // 1. The screenlock's public material (the OpenSSH line — the
        //    certified payload).
        val screenlockLine = com.offlinepass.app.crypto.KeystoreSigner
            .publicKeySshLine("offlinepass-screenlock device=${deviceId()}") ?: run {
            return "The screenlock key is unavailable (no keystore key) — " +
                "cannot enroll."
        }

        // 2. The SECURITY key signs a LOCAL CERT over the screenlock's
        //    public key material (SHA-256): the card attests this device's
        //    signing key. One touch; the cert = the trust record.
        val materialHash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(screenlockLine.toByteArray())
        val certSig = try {
            val pin = yubikeyPin() ?: return "OpenPGP PIN cancelled."
            withTouchPrompt {
                com.offlinepass.app.crypto.YubiKitSshAuth.sign(
                    appContext, pin,
                    com.offlinepass.app.crypto.SshRsaPkcs1
                        .digestInfo("SHA-256", materialHash))
            }.also { yubikeyPinRemember(pin) }
        } catch (e: Exception) {
            return "The security key could not sign the local cert: " +
                "${e.message} — the enrollment aborted."
        }

        // 3. The registry entry + the local cert (LOCAL only — no repo
        //    update; the next ordinary sync publishes).
        val entries = readDeviceRegistry().toMutableList()
        val subkeyId = yubikeyAuthSubkeyId() ?: 0L
        entries += DeviceRegistryEntry(
            name = deviceName(),
            authKey = screenlockLine,
            cert = "keys/sign/screenlock-cert-%016X.meta.json".format(subkeyId))
        writeDeviceRegistry(entries)
        runCatching {
            val dir = File(gitRoot(), "keys/sign").apply { mkdirs() }
            File(dir, "screenlock-cert-%016X.meta.json".format(subkeyId)).writeText(
                org.json.JSONObject()
                    .put("kind", "offlinepass-screenlock-cert")
                    .put("device", deviceName())
                    .put("deviceId", deviceId())
                    .put("screenlockKeySha256",
                        materialHash.joinToString("") { "%02x".format(it) })
                    .put("cardKeyId", "%016X".format(subkeyId))
                    .put("certSha256",
                        java.security.MessageDigest.getInstance("SHA-256")
                            .digest(certSig).joinToString("") { "%02x".format(it) })
                    .put("certBase64", java.util.Base64.getEncoder()
                        .encodeToString(certSig))
                    .toString(2))
        }

        // 4. The signing mode flips + the seal activates with the prompt.
        // The seal needs the DECRYPTED items in memory — it happens here
        // only when the session is unlocked; on a locked session it
        // activates at the next unlock (never silently deferred without
        // saying so).
        setCommitSigningMode(SIGNING_SCREENLOCK)
        // THE SEAL ACTIVATES VIA THE SETTER: its live gate prompts (one
        // screen-lock press), seals, and re-stubs the full session; on a
        // locked session it activates at the next unlock. The setter's
        // message carries the outcome — surface it.
        return "Screenlock protection enrolled (security-key-signed locally): " +
            "commits now sign with the screenlock key. " + setScreenlockUnlockEnabled(true)
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
        // The PROTOCOL: the removal commit must be SECURITY-KEY-SIGNED —
        // flip the signing mode to the security key BEFORE touching the
        // registry, so the removal commit is signed by the YubiKey.
        if (commitSigningMode() == SIGNING_SCREENLOCK && yubiEnrolled) {
            setCommitSigningMode(SIGNING_YUBIKEY)
        }
        if (sshSyncMode() == SSH_SYNC_SCREENLOCK) {
            @Suppress("DEPRECATION")
            if (yubiEnrolled) {
                setSshSyncMode(SSH_SYNC_YUBIKEY)
                parts += "SSH auth now uses the YubiKey."
            } else {
                parts += "SSH auth stays on the (deprecated) screenlock key " +
                    "(enroll the YubiKey first to move it)."
            }
        }
        if (commitSigningMode() == SIGNING_SCREENLOCK) {
            setCommitSigningMode(SIGNING_OPENKEYCHAIN)
            parts += "Commit signing now uses OpenKeyChain."
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
            // The subkey id = absent only when the SSH enrollment hasn't
            // matched the card yet — the SIGNING still works: the card's
            // SIG slot is read directly below (the unauthenticated
            // fingerprint read gives the id). The SSH line = the sync's
            // TRANSPORT requirement, not the signing's.
            sshIdentityUnavailable = null
        }
        if (!com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(appContext)) {
            sshIdentityUnavailable = usbPermissionPromptOrMissing()
                .ifEmpty { "The YubiKey is not ready — retry." }
            return null
        }
        sshIdentityUnavailable = null
        // THE SIGNING KEY ID = the card's SIG slot's id — read from the
        // card (no SSH enrollment required). The fallback chain (the
        // screenlock) picks this up when the signer can't be built.
        val signId = keyId ?: run {
            sshIdentityUnavailable = null
            com.offlinepass.app.crypto.YubiKitSshAuth.signingKeyIdentity(appContext).keyId
        }
        sshIdentityUnavailable = null
        return com.offlinepass.app.crypto.YubiKitCommitSigner(
            appContext, signId,
            prompt = { yubikeyPin() },
            rememberPin = { yubikeyPinRemember(it) },
            cardSign = { pin, payload -> withTouchPrompt {
                // THE COMMIT SIGNING = the SIG slot (the card pads the
                // digest) — ALWAYS. The AUT = the TRANSPORT auth's slot
                // (the SSH handshake), not the signing's.
                com.offlinepass.app.crypto.YubiKitSshAuth.sign(appContext, pin, payload)
            } })
    }

    /** The commit signer for sync-time commits (the pre-sync commit and
     *  the merge commit) per the active signing mode. */
    fun syncCommitSigner(client: OpenPgpOps): org.eclipse.jgit.lib.Signer? {
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

    /** The attached-but-not-permitted branch, shared by the identity and
     *  the commit-signer builders (both non-suspend — they cannot await a
     *  dialog): FIRE the system permission request (non-blocking) and
     *  return the user-facing message; null = permitted (or nothing
     *  attached — the caller names that case itself). */
    private fun usbPermissionPromptOrMissing(): String {
        if (com.offlinepass.app.crypto.YubiKitSshAuth.findDevice(appContext) == null) {
            return "The YubiKey is not attached — plug it in and retry."
        }
        if (!com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(appContext)) {
            appScope.launch {
                com.offlinepass.app.crypto.YubiKitSshAuth.requestPermission(appContext)
            }
            return "The USB permission dialog was shown — grant it and retry."
        }
        return ""  // permitted
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
                    sshIdentityUnavailable = usbPermissionPromptOrMissing()
                        .ifEmpty { "The YubiKey is not ready — retry." }
                    return null
                }
                // THE SLOT↔LINE GATE: the OFFERED key (the enrolled line)
                // must be the key that SIGNS (the setting's slot) — the
                // server verifies the sig against the offered key, so a
                // mismatch can never authenticate (GitHub answers only
                // "Auth fail for methods 'publickey'"). Named fail-fast
                // instead — the guidance, not the dead handshake.
                val enrolledFp = runCatching { PgpSshBridge.fingerprintOf(line) }.getOrNull()
                val liveFp = runCatching {
                    com.offlinepass.app.crypto.YubiKitSshAuth
                        .slotKeyFingerprint(context, sshAuthUseAut())
                }.getOrNull()
                if (enrolledFp != null && liveFp != null && enrolledFp != liveFp) {
                    sshIdentityUnavailable =
                        "the transport is set to the " +
                            (if (sshAuthUseAut()) "AUTH" else "SIGNATURE") +
                            " slot, but the enrolled SSH line is a different key (" +
                            enrolledFp + " ≠ " + liveFp +
                            ") — re-run Enroll while the setting is on, or switch back."
                    return null
                }
                val yubiKitSigner: (suspend (payload: ByteArray) -> ByteArray) =
                    pinCachingSigner(
                        prompt = { yubikeyPin() },
                        sign = { pin, payload ->
                            val sig = withTouchPrompt {
                                // The TRANSPORT: the enrolled line's
                                // algorithm decides. ssh-ed25519 = the AUT
                                // slot's INTERNAL AUTHENTICATE (PureEdDSA
                                // over the RAW handshake data — the OpenPGP
                                // hashed-sign path can't serve it);
                                // RSA/ECDSA = the sshAuthUseAut's slot.
                                // The gate = the enrolled line's
                                // fingerprint: a wrong card refuses by
                                // name (the sig GitHub would reject is
                                // never produced).
                                val expectedFp = runCatching {
                                    PgpSshBridge.fingerprintOf(line)
                                }.getOrNull()
                                if (line.contains("ssh-ed25519")) {
                                    com.offlinepass.app.crypto.YubiKitSshAuth
                                        .authenticateAut(context, pin, payload,
                                            expectedFingerprint = expectedFp)
                                } else {
                                    com.offlinepass.app.crypto.YubiKitSshAuth.sign(
                                        context, pin, payload, useAut = sshAuthUseAut(),
                                        expectedFingerprint = expectedFp)
                                }
                            }
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

    /** WHAT the pending screenlock interaction authenticates ("Saving
     *  'GitHub'", "Deleting 'Mail'", "Syncing with <remote>") — the
     *  biometric prompt's subtitle. Set by the operation about to run;
     *  read by the UI hooks when they build the prompt. */
    var authDescription: String? = null

    /** UI hook for the screen-lock prompt that opens the SEAL key's 60s
     *  validity window (biometric/credential; runs on Main). One successful
     *  prompt unlocks ALL time-based keystore keys for the window, so the
     *  reveal unseal and a following commit-signing prompt share it. */
    var sealGate: (suspend (title: String, subtitle: String) -> Boolean)? = null

    /** UI hook: the OpenPGP applet's USER PIN for YubiKit card signing.
     *  Shows a dialog, returns the PIN (or null on cancel); the PIN is
     *  never stored — it is used once and dropped. */
    var openPgpPinPrompt: (suspend () -> CharArray?)? = null

    /** UI hook: the OpenPGP applet's ADMIN PIN (the one-time slot-swap
     *  gate; the factory default = 12345678). Never cached, zeroed after
     *  the card op. */
    var openPgpAdminPinPrompt: (suspend () -> CharArray?)? = null

    /** THE EC AUTH KEY GENERATION: overwrites the AUTH slot with an
     *  ECDSA P-256 key — the slot whose challenge fits the phone's USB
     *  transport (the RSA-4096's 512B challenge = the 0x6581 dead end).
     *  One-time, the ADMIN PIN gated. The vault needs NO re-encryption:
     *  the recipients = the DEC key's, and this touches the AUT slot
     *  only. Returns the status line. */
    suspend fun generateEcAuthKey(): String {
        if (com.offlinepass.app.crypto.YubiKitSshAuth.findDevice(appContext) == null) {
            return "No security key connected."
        }
        if (!com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(appContext)) {
            return "USB permission missing — retry the action."
        }
        val adminPin = openPgpAdminPinPrompt?.invoke() ?: return "Admin PIN cancelled."
        return kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            try {
                withTouchPrompt {
                    com.offlinepass.app.crypto.YubiKitSshAuth
                        .generateEcAuthKey(appContext, adminPin)
                }
                "EC auth key generated on the security key — re-run Enroll " +
                    "(the GitHub match will select the AUTH slot)."
            } catch (e: Exception) {
                "The EC key generation failed: ${e.message}"
            }
        }
    }

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

    /** The load's recipient-adoption outcome, surfaced by the Setup's
     *  status ("Recipients adopted: N (from the vault)"). Cleared on
     *  the session reset. */
    var seedStatus by androidx.compose.runtime.mutableStateOf<String?>(null)
        private set

    /** The envelope as loaded (tombstones + unknown fields preserved through saves). */
    private var loadedEnvelope: Envelope? = null

    /** THE STUB MODEL: true when the in-memory items are stubs (the
     *  secrets live in the sealed cache + the vault file). Every path
     *  that needs the real secrets (the save, the merge, the autofill's
     *  unlocked branch) must promote — the batch unseal — first. */
    private var stubSession = false

    /** Promotes a stub session to the full items via the sealed cache
     *  (silent inside the auth window; one screen-lock press otherwise).
     *  Returns false when the cache is missing/stale — the caller must
     *  fail honestly rather than proceed with stubs. */
    private suspend fun promoteIfStub(): Boolean {
        if (!stubSession) return true
        return promoteSealedSession() == Result.Success
    }

    fun init(context: Context) {
        if (::appContext.isInitialized) return
        appContext = context.applicationContext
        // A local vault file = the vault exists → Locked (unlock screen).
        // No local vault → the setup/import screen (no unlock shown).
        state = if (File(vaultFilePath()).exists()) State.Locked else State.NoConfig
        registerConnectivityWatch()
    }

    /** Test-only: the vault file's path as a File (the fixtures). */
    internal fun vaultFileForTest(): File = File(vaultFilePath())

    /** Test-only: put the session in the FULL state (the toggle-off's
     *  shape: the secrets in memory, the toggle on, no stubbing). */
    internal fun fullSessionForTest(items: List<ProtonItem>) {
        val env = Envelope(rev = 5, deviceId = "d1")
        env.items = items.toMutableList()
        loadedEnvelope = env
        rev = env.rev
        state = State.Unlocked(items.toMutableList())
        stubSession = false
    }

    /** Test-only: put the session in the stub state (the unlock's shape:
     *  stubs in memory, the secrets only in the sealed cache). */
    internal fun stubSessionForTest() {
        // The envelope = the cache's public metadata + the manifest items
        // (the real promote sets loadedEnvelope the same way) — without it
        // the envelope-touching ops (the pairing!) see "no vault".
        val env = SealedVault.toEnvelope(SealedVault.manifestItems())
        loadedEnvelope = env
        rev = env.rev
        state = State.Unlocked(SealedVault.manifestItems())
        stubSession = true
    }

    /** Test-only: the singleton holds memory across Robolectric tests —
     * reset it to pristine defaults for [context] (no connectivity watch). */
    internal fun resetForTest(context: Context) {
        appContext = context.applicationContext
        rev = 0
        loadedEnvelope = null
        seedStatus = null
        stubSession = false
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
        val client = sharedOpenPgpClient(appContext)
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

    /** Test-only: configure the OK signing key (the pick-once flow is
     *  gone — the Setup's explicit pick or this seam sets it). */
    internal fun signingKeyForTest(keyId: Long) {
        prefs().edit().putString("signingKeyId", keyId.toString()).apply()
    }

    /**
     * Recipient PICK via OpenKeyChain's own keyring UI: a lookup for an
     * unknown user id raises the key-selection screen (multi-select
     * checkboxes); every picked key comes back in the result's key-id array
     * (in [lastPickedKeyIds]). Interaction propagates for the UI loop.
     */
    suspend fun pickRecipient(): Result {
        val client = sharedOpenPgpClient(appContext)
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

    /** The test seam: the PAT override (the JVM tests cannot touch the
     *  AndroidKeyStore-backed SecretStore). Null = the real store. */
    internal var patOverride: String? = null

    private fun pat(): String? = patOverride ?: secretStore().read("pat")

    // -- unlock ----------------------------------------------------------------

    /**
     * Opens (clone/fetch, when remote), decrypts, parses. Caller must handle
     * [Result.Interaction] by launching the PendingIntent and calling again.
     */
    /**
     * LOCAL-ONLY operation: decrypts the on-disk vault with the security
     * key (the card's DECRYPTION slot via YubiKit + BouncyCastle — no
     * OpenKeyChain in the path). No network — syncing happens explicitly
     * (Sync now) or on save.
     */
    suspend fun unlock(): Result {
        val cfg = config()
        // Unlock only ever runs against an existing local vault (the setup
        // screen handles the no-vault case).
        if (!File(vaultFilePath()).exists()) {
            return Result.Error("No local vault — use the setup screen.")
        }
        busy = "Decrypting vault… (PIN + touch your key)"
        try {
            loadPhase("Decrypting with the security key…")
            val plainBytes = vaultDecryptBytes(vaultFile().readBytes())
            loadPhase("Decrypted — adopting ${plainBytes.size}B")
            val env = Envelope.fromJson(String(plainBytes))
            rev = env.rev
            loadedEnvelope = env
            state = State.Unlocked(env.items)
            sealIfEnabled(env.items, env)
            // THE STUB MODEL: with the screenlock enrolled, the secrets
            // now live in the sealed cache (just written) and the vault
            // file (the card) — the session keeps only the identity
            // fields; the item detail = the unseal, the save = the batch
            // unseal. Without the screenlock the session stays full
            // (no gate possible — unchanged legacy behavior).
            if (screenlockUnlockEnabled()) {
                env.items = env.items.map { it.asStub() }.toMutableList()
                state = State.Unlocked(env.items)
                stubSession = true
                loadPhase("Secrets sealed — the session holds ${env.items.size} stubs")
            }
            loadPhase("Vault loaded (${env.items.size} items, rev=${env.rev})")
            Log.i(TAG, "unlocked: ${env.items.size} items, rev=${env.rev}")
            return Result.Success
        } catch (e: Exception) {
            Log.w(TAG, "unlock failed: ${e.message}")
            loadPhase("decrypt FAILED: ${e.javaClass.simpleName}: ${e.message}")
            return Result.Error("${e.javaClass.simpleName}: ${e.message}")
        } finally {
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
    suspend fun save(items: List<ProtonItem>, editedUuid: String? = null, what: String? = null): Result {
        val cfg = config() ?: return Result.Error("No config")
        busy = "Encrypting…"
        authDescription = what ?: (editedUuid?.let { uuid ->
            items.firstOrNull { it.itemUuid == uuid }?.let { "Saving '${it.displayName}'" }
        } ?: "Saving the vault")
        // THE SIGNER PROMPT'S TRANSACTION: the item save derives the
        // summary from the edited entry (the same lookup the description
        // uses); the non-item saves CLEAR it — no stale site lingers into
        // a sync merge's prompt.
        pendingSignerDescription = editedUuid?.let { uuid ->
            items.firstOrNull { it.itemUuid == uuid }?.let { saveTransactionText(it) }
        }
        try {
            return withContext(Dispatchers.IO) {
                // THE STUB-INVARIANT: the in-memory list = the stubs (the
                // secrets live in the sealed cache). Encrypting stubs would
                // wipe every secret — promote (the batch unseal, silent
                // inside the auth window, one screen-lock press otherwise)
                // before touching the envelope. A failed promote (the cache
                // missing/stale) must fail the save honestly.
                val wasStub = stubSession
                if (!promoteIfStub()) {
                    // THE EMPTY-VAULT EDGE: a newly created vault seals an
                    // EMPTY cache (no items yet) bound to the not-yet-written
                    // vault file — the promote fails on the zero items while
                    // the session is already in full-session semantics (the
                    // screenlock enrolled AFTER the adopt). Proceed: the UI's
                    // items = the full, the vault gets written, and the
                    // re-seal populates the cache. The genuinely-stale cache
                    // (the real items sealed) still fails the save honestly.
                    if (SealedVault.manifestItems().isEmpty()) {
                        Log.i(TAG, "save: the empty-cache edge — proceeding with the full session")
                    } else {
                        return@withContext Result.Error(
                            "The sealed cache is missing or stale — re-unlock with the key, then save")
                    }
                }
                val env = (loadedEnvelope ?: Envelope(deviceId = cfg.deviceId)).also { e ->
                    e.rev = rev + 1
                    if (wasStub) {
                        // THE APPLY-DIFF (the stub mode) — the modifyTime
                        // rule, the same one the sync merge uses: the UI's
                        // copy vs the base's copy → the NEWER modifyTime
                        // wins. The edited item = stamped NOW here (the
                        // caller's edit) so it beats the base; the UI's
                        // stubs carry the item's own older modifyTime, so
                        // the base — which holds the previous saves'
                        // secrets — wins over them. The old
                        // hasSecrets()/editedUuid heuristics were the
                        // clobber's second half (the base was the stubs
                        // after the promote's in-place mutation).
                        items.forEach { ui ->
                            if (ui.hasSecrets() && ui.modifyTime == 0L) {
                                ui.modifyTime = System.currentTimeMillis() / 1000
                            }
                        }
                        items.firstOrNull { it.itemUuid == editedUuid }
                            ?.let { it.modifyTime = System.currentTimeMillis() / 1000 }
                        val base = e.items
                        val applied = base.map { baseItem ->
                            val ui = items.firstOrNull { it.itemUuid == baseItem.itemUuid }
                            when {
                                ui == null -> baseItem
                                ui.modifyTime > baseItem.modifyTime -> {
                                    Log.i(TAG, "save: ${ui.itemUuid.take(8)} — the UI edit wins " +
                                        "(modifyTime ${ui.modifyTime} > ${baseItem.modifyTime})")
                                    ui
                                }
                                // THE EXPLICIT EDIT WINS THE TIE: the caller
                                // named this item as the edit — a same-second
                                // stamp must not drop it (the sub-second
                                // consecutive saves).
                                ui.itemUuid == editedUuid &&
                                    ui.modifyTime == baseItem.modifyTime -> {
                                    Log.i(TAG, "save: ${ui.itemUuid.take(8)} — the UI edit wins " +
                                        "(the modifyTime tie, the explicit edit)")
                                    ui
                                }
                                else -> baseItem
                            }
                        } + items.filter { ui ->
                            base.none { it.itemUuid == ui.itemUuid }
                        }
                        e.items = applied.toMutableList()
                    } else {
                        e.items = items.toMutableList()
                    }
                }
                // Purge tombstoned entries for good.
                env.items.removeAll { it.itemUuid in env.deletedItemUuids }
                env.items.sortBy { it.displayName.lowercase() }
                val client = openPgpClientFactory(appContext)

                var keyIds = cachedRecipientKeyIds() ?: recipientKeyIds().toLongArray()
                loadPhase("save: keyIds = " + keyIds.size + " (the prefs" +
                    (if (keyIds.isEmpty()) " — EMPTY, the lookup will run" else "") + ")")
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
                    // Materialize the recipients' armored public keys + ledger
                    // into the repo BEFORE the encrypt — the BC envelope needs
                    // the recipient files on disk — so git history records
                    // exactly who can open each revision (design:
                    // keys/encrypt/*.pub.asc + recipients.txt). Guarded: a
                    // failure must roll back (file + state), never escape.
                    val keysOk = try {
                        materializeRecipientKeys(client, gitRoot(), keyIds)
                    } catch (e: Exception) {
                        Log.w(TAG, "recipient key materialization failed: ${e.message}")
                        return@withContext rollback(
                            "Recipient key materialization failed: ${e.message}")
                    }
                    if (!keysOk) {
                        return@withContext rollback("Some recipient key files missing — nothing saved")
                    }

                    try {
                        plain.writeText(env.toJsonObject().toString())
                        target.parentFile?.mkdirs()
                        target.writeBytes(vaultEncryptBytes(
                            plain.readText().toByteArray(Charsets.UTF_8), gitRoot(), keyIds))
                    } catch (e: Exception) {
                        return@withContext rollback("Encrypt failed: ${e.message}")
                    } finally {
                        // The pre-encrypt plaintext is zeroed + deleted as soon
                        // as the ciphertext exists.
                        SecureWipe.file(plain)
                    }
                    rev = env.rev
                    loadedEnvelope = env
                    Log.i(TAG, "encrypted ${target.length()} bytes, rev=${env.rev}")

                    // Commit signer: OpenKeyChain's signing key (default) OR
                    // the screenlock keystore key — exclusive paths. In
                    // screenlock mode there is NO OpenKeyChain signing
                    // interaction: the BiometricPrompt gate in the hook is
                    // the entire story.
                    val signer: org.eclipse.jgit.lib.Signer?
                    if (commitSigningMode() == SIGNING_YUBIKEY) {
                        signer = yubikeyCommitSignerOrNull()
                            ?: run {
                                // THE LOCAL FALLBACK (the SSH enrollment
                                // NOT needed): the screenlock's keystore key
                                // — the on-demand generation + the
                                // screen-lock prompt (the device's lock =
                                // always present). The commits = SIGNED
                                // from the birth.
                                val hook = keystoreSignerHook
                                    ?: return@withContext rollback(
                                        "Screenlock signer unavailable (UI layer absent) — nothing saved.")
                                syncStatus = "Commit signed with the screenlock key."
                                com.offlinepass.app.crypto.KeystoreCommitSigner(hook)
                            }
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
                        // THE OKK MODE: the configured signer — or, before
                        // any sign key is configured, an UNSIGNED commit.
                        // OpenKeyChain must not gate the first save (the
                        // fresh-import path); the signing gets configured
                        // from Setup/GetStarted and the later commits sign.
                        signer = signingKeyId()?.let { signId ->
                            // Pre-flight the commit signature: OpenKeyChain
                            // may need an unlock prompt (or the key may be
                            // unavailable entirely). Surface that as
                            // Interaction HERE — the signer inside JGit
                            // can't interact, and a hard failure there
                            // aborts the commit with a bare "commit failed".
                            busy = "Checking sign key…"
                            ensureSignKeyReady(signId, client)?.let { msg ->
                                return@withContext rollback(msg +
                                    " — nothing saved. Check the key in OpenKeyChain or pick another signer in Setup.")
                            }
                            OpenKeyChainSigner(client, signId)
                        }
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
                            syncStatus = "Committed locally (rev ${env.rev}) — click Sync in Settings to publish"
                            // NO early return: the tail below (the seal +
                            // the re-stub) must run for EVERY save — the
                            // old early return skipped the re-seal, the
                            // cache stayed stamped with the PRE-save vault
                            // file's hash, and the next detail reveal
                            // answered "Seal is outdated" → the security
                            // key unlock instead of the screenlock (the
                            // measured bug: the first tap = the card, the
                            // second = the screenlock).
                        } else {
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
                                syncStatus = "Committed locally (rev ${env.rev}) — click Sync in Settings to publish"
                                // NOT an error: the change persisted locally.
                            }
                        }
                    } else {
                        // LOCAL-ONLY: same repo dir, no remotes — history stays on-device.
                        lastSaveRemoteState = "none"
                        git.commitFile(gitRoot(), "Update 10.gpg (rev ${env.rev})", signer)
                        syncStatus = "Committed locally (rev ${env.rev}, no remote)"
                    }
                    // THE TAIL SEALS THE ENVELOPE'S FULL ITEMS — never the
                    // caller's list: in the stub-mode save the caller's
                    // list = THE STUBS (+ the edited), and sealing those
                    // wrote EMPTY secrets into the cache (the measured
                    // clobber). The envelope = the just-saved full state.
                    // THE INCREMENTAL SEAL: only the affected item's blob
                    // is re-sealed (the AAD binds the uuid; the keystore key
                    // is unchanged) — the cache stays a derived mirror, and
                    // the repo commit has already landed, so a kill here is
                    // stale-but-reconstructable by the repo decrypt.
                    if (screenlockUnlockEnabled()) {
                        if (editedUuid != null) {
                            // THE SINGLE-EDIT SAVE: only the affected item's
                            // blob is re-sealed.
                            SealedVault.syncAfterSaveAwait(env, File(vaultFilePath()), editedUuid)
                        } else {
                            // THE BATCH SAVE (a merge/restore: many items may
                            // differ, and nothing marks which) — the full
                            // re-seal is the only correct rule here.
                            SealedVault.sealNowAwait(env.items, env, File(vaultFilePath()))
                        }
                        // THE MODELS SEPARATED (see the promote): the state =
                        // a FRESH stub list; loadedEnvelope (env) KEEPS the
                        // just-saved full items — the next save's base. The
                        // old `env.items = stubs` mutated the encryption
                        // base to the stubs (the measured save-clobber).
                        state = State.Unlocked(env.items.map { it.asStub() })
                        stubSession = true
                    }
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

    fun screenLockRequired(): Boolean = idleLockEnabled()

    fun setScreenLockRequired(on: Boolean) {
        screenLockOn = on
    }

    /** Idle auto-lock timeout in SECONDS (0 = never); only meaningful
     *  while [screenLockRequired] is on. One-time migration: the old
     *  minute-granularity pref converts *60. */
    fun autoLockSeconds(): Int {
        if (prefs().contains("autoLockSeconds"))
            return prefs().getInt("autoLockSeconds", 300)
        if (prefs().contains("autoLockMinutes")) {
            val seconds = prefs().getInt("autoLockMinutes", 5) * 60
            prefs().edit().putInt("autoLockSeconds", seconds)
                .remove("autoLockMinutes").apply()
            return seconds
        }
        return 300
    }

    fun setAutoLockSeconds(n: Int) {
        prefs().edit().putInt("autoLockSeconds", n).apply()
    }

    // -- screenlock unlock (experimental, default OFF) --------------------------
    //
    // The device-local sealed cache (SealedVault): the locked app renders
    // the manifest (names/usernames/URLs) and gates only the click-through.
    // OFF = exact legacy behavior (GPG unlock for everything); turning it
    // off wipes the cache.

    /** THE IDLE LOCK's own switch (decoupled from the entry gate): the
     *  idle auto-lock zeroing runs only when this is on. One-time
     *  migration: the old coupling (the screenlock toggle governed the
     *  idle lock) maps its value across. */
    fun idleLockEnabled(): Boolean {
        if (prefs().contains("idleLockOn"))
            return prefs().getBoolean("idleLockOn", false)
        if (prefs().contains("screenLockOn")) {
            val carried = prefs().getBoolean("screenLockOn", false)
            prefs().edit().putBoolean("idleLockOn", carried).apply()
            return carried
        }
        return false
    }

    fun setIdleLockEnabled(on: Boolean) {
        prefs().edit().putBoolean("idleLockOn", on).apply()
    }

    /** The screenlock-based encryption at rest (the sealed cache): OFF
     *  until the screenlock is ENROLLED for the first time (the enrollment
     *  turns it on — the sealed cache before any screenlock enrollment
     *  would gate the vault on nothing the user has set up). The toggle
     *  turning it off wipes the cache. */
    fun screenlockUnlockEnabled(): Boolean =
        prefs().getBoolean("screenlockUnlock", false)

    suspend fun setScreenlockUnlockEnabled(on: Boolean): String {
        if (on) {
            prefs().edit().putBoolean("screenlockUnlock", true).apply()
            // THE LIVE GATE: a running FULL session re-stubs NOW — the
            // secrets move into the sealed cache (the awaited seal, the
            // save tail's race-safe pattern) and the clicks gate from this
            // moment, not after the next app restart.
            val env = loadedEnvelope
            if (state is State.Unlocked && !stubSession && env != null) {
                // THE SEAL NEEDS THE AUTH WINDOW (the keystore key is
                // screenlock-gated): prompt via the seal gate — the crash
                // (the unprompted seal) is the UserNotAuthenticated trap.
                val gated = sealGate?.invoke(
                    "Encrypt items in memory",
                    "The device lock encrypts the item secrets at rest") ?: true
                if (!gated)
                    return "Encrypt items in memory ON — but the screen lock was " +
                        "declined: the seal happens on the next save/unlock."
                val sealResult = runCatching {
                    SealedVault.sealNowAwait(env.items, env, File(vaultFilePath()))
                }
                if (sealResult.isFailure) {
                    return "Encrypt items in memory ON — but the seal failed " +
                        "(${sealResult.exceptionOrNull()?.message?.take(60)}): the " +
                        "seal happens on the next save/unlock."
                }
                state = State.Unlocked(env.items.map { it.asStub() })
                stubSession = true
                return "Encrypt items in memory ON — the session re-stubbed now; " +
                    "clicks reveal with a screen-lock prompt."
            }
            if (state is State.Locked && !SealedVault.hasCache()) {
                // PULL THE DECRYPT FORWARD: the toggle-ON itself seals the
                // cache (the card decrypt now) — the next unlock is
                // screen-lock only, no key-needed-once surprise at unlock.
                busy = "Sealing the vault (the security key decrypt)…"
                try {
                    if (!com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(appContext) &&
                        !com.offlinepass.app.crypto.YubiKitSshAuth.requestPermission(appContext)
                    ) return "Encrypt items in memory ON — but the seal needs " +
                        "the security key: attach it and toggle off/on (or just " +
                        "unlock once with the key)."
                    val plainBytes = vaultDecryptBytes(vaultFile().readBytes())
                    val env = Envelope.fromJson(String(plainBytes))
                    rev = env.rev
                    loadedEnvelope = env
                    SealedVault.sealNowAwait(env.items, env, File(vaultFilePath()))
                    return "Encrypt items in memory ON — the cache sealed from " +
                        "the repo now; the next unlock is screen-lock only."
                } catch (e: Exception) {
                    return "Encrypt items in memory ON — but the seal failed " +
                        "(${e.message?.take(60)}): the next unlock needs the " +
                        "security key once."
                } finally {
                    busy = null
                }
            }
            return "Encrypt items in memory ON — search works on the sealed list; " +
                "clicks reveal with a screen-lock prompt."
        }
        // THE INVARIANT: never wipe the cache while it is the sole live
        // copy. The catch-up tries BOTH derived paths, so the toggle-off
        // works ALWAYS (as long as the security material is intact):
        //  1. the promote (the save's own primitive) — the cache's copy;
        //  2. a fresh repo decrypt — the repo is the truth and the cache
        //     is merely derived (covers the stale-seal and corrupt-cache
        //     cases automatically);
        //  3. only when BOTH fail (no card / unusable keys) — stop, keep
        //     the cache, tell the user. Nothing was ever lost on the way.
        if (stubSession) {
            val promoted = promoteSealedSession()
            val promotedEnv = (promoted as? Result.Success)?.let { loadedEnvelope }
            if (promotedEnv == null) {
                try {
                    val plainBytes = vaultDecryptBytes(vaultFile().readBytes())
                    val fresh = Envelope.fromJson(String(plainBytes))
                    rev = fresh.rev
                    loadedEnvelope = fresh
                    state = State.Unlocked(fresh.items)
                    stubSession = false
                } catch (e: Exception) {
                    return "Could not disable encrypt-items-in-memory — neither the sealed " +
                        "cache (${(promoted as? Result.Error)?.message?.take(60) ?: "stale"}) " +
                        "nor the repo decrypt (${e.message?.take(60)}) worked. " +
                        "Nothing was lost; attach the security key and try again."
                }
            } else {
                // THE FULL SESSION (no re-stub): the promote's envelope
                // carries the unsealed items.
                state = State.Unlocked(promotedEnv.items)
                stubSession = false
            }
        }
        prefs().edit().putBoolean("screenlockUnlock", false).apply()
        SealedVault.wipe()
        return "Encrypt items in memory OFF — the session keeps the full items; " +
            "the sealed cache is cleared."
    }

    /** Re-seals the cache when the toggle is on. Fire-and-forget; failures
     *  only log (the repo's GPG envelope stays the source of truth). */
    private fun sealIfEnabled(items: List<ProtonItem>, env: Envelope) {
        if (!screenlockUnlockEnabled()) return
        // The seal's outcome logs itself to the file channel (SealedVault).
        SealedVault.seal(items, env, File(vaultFilePath()))
    }

    /** The load/unlock phase breadcrumbs: a toast (posted to Main — toasts
     *  survive a process death, unlike the app's log) + a persistent file
     *  line. This ROM's logd is broken: a crash leaves NO trace, so these
     *  are the only way to locate where a load died. */
    fun loadPhase(phase: String) {
        runCatching {
            File(appContext.filesDir, "debug-sync.log").appendText(
                "[${System.currentTimeMillis()}] load-phase: $phase\n")
        }
        Handler(Looper.getMainLooper()).post {
            runCatching {
                android.widget.Toast.makeText(
                    appContext, phase, android.widget.Toast.LENGTH_SHORT).show()
            }
        }
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
            // THE EMPTY-VAULT EDGE: the sealed-empty cache = the newly
            // created vault's state — the promote SUCCEEDS with the empty
            // session (the screenlock covers it; the card = pointless for
            // an empty vault). THE CORRUPT-CACHE GUARD: an unseal that
            // fails per-item ALSO returns empty — but its manifest still
            // lists the items; treating that as the empty-vault success
            // would wipe real secrets. Empty succeeds ONLY when the
            // manifest is genuinely empty; otherwise the promote fails
            // honestly (the cache stays; the repo decrypt can rebuild).
            if (items.isEmpty()) {
                if (SealedVault.manifestItems().isEmpty()) {
                    // THE GENUINELY-EMPTY VAULT: the success — but the
                    // state MUST be set (the early-return skipped it and
                    // the session stayed Locked forever: the "unlock
                    // doesn't navigate" bug — the empty vault never
                    // exercised this path before).
                    val env = SealedVault.toEnvelope(emptyList())
                    loadedEnvelope = env
                    rev = env.rev
                    state = State.Unlocked(emptyList())
                    stubSession = true
                    android.util.Log.i("UnlockTiming",
                        "promote: the empty-vault edge -> Unlocked")
                    return Result.Success
                }
                return Result.Error(
                    "The sealed cache's secrets failed to open — refusing to proceed " +
                        "with an empty session (the vault file is untouched).")
            }
            // THE TOMBSTONES carried across the promote (the batch unseal's
            // new envelope resets them; the stub-session's deletes must
            // survive the re-seal).
            val carriedTombstones = loadedEnvelope?.deletedItemUuids?.toList() ?: emptyList()
            // THE PAIRED DEVICES carried the same way: a paste-device
            // pairing staged in the stub session lives only in
            // loadedEnvelope.devices — the cache's meta snapshot predates
            // it, and toEnvelope would wipe the staging (the measured
            // "paired but not showing" bug).
            // THE STASH (the idle lock's zero) + the live envelope's: the
            // staged pairings from both are carried; the stash consumed.
            val carriedDevices = (stashedDevices ?: emptyList()) +
                (loadedEnvelope?.devices?.toList() ?: emptyList())
            stashedDevices = null
            // The unpair TOMBSTONES carried the same way (the stash had
            // them; the promote never read them — an unpair was lost on
            // the idle lock and the device resurrected on the next sync).
            val carriedRemoved = (stashedRemovedDeviceIds ?: emptyList()) +
                (loadedEnvelope?.removedDeviceIds?.toList() ?: emptyList())
            stashedRemovedDeviceIds = null
            val env = SealedVault.toEnvelope(items)
            rev = env.rev
            env.deletedItemUuids = (carriedTombstones + env.deletedItemUuids)
                .distinct().toMutableSet()
            // The staged pairings win over the cache's snapshot (the newer
            // staging = the newer state; the union = the removals honored).
            val stagedIds = carriedDevices.map { it.keyId }.toSet()
            env.devices = (carriedDevices + env.devices.filter { it.keyId !in stagedIds })
                .distinctBy { it.keyId }.toMutableList()
            env.removedDeviceIds = (carriedRemoved + env.removedDeviceIds)
                .distinct().toMutableSet()
            // THE MODELS SEPARATED: loadedEnvelope = the FULL envelope (the
            // save's encryption base — NEVER the stubs); the state = a
            // SEPARATE stub list (the browsing gate). The old code mutated
            // env.items to the stubs IN PLACE — the same reference as
            // loadedEnvelope — so the next save's apply-diff base was the
            // stubs and every non-edited item's secrets were zeroed into
            // the vault file (the measured save-clobber).
            loadedEnvelope = env
            val stubs = items.map { it.asStub() }.toMutableList()
            state = State.Unlocked(stubs)
            stubSession = true
            android.util.Log.i("UnlockTiming", "promote: state->Unlocked (${stubs.size} items, devices=${env.devices.size})")
            Log.i(TAG, "promoted sealed session (stubs): ${stubs.size} items, rev=${env.rev}")
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
        // THE EDIT = NOW: the revealed copy carries the item's OLD
        // modifyTime — the SAME value the base holds (both from the same
        // promote) — and the modifyTime rule's tie means the base wins,
        // silently dropping the edit (the measured clobber: every sealed
        // detail save died this way). The edit is happening NOW; stamp it
        // — the empty user/pass edits stamp identically (the heroku
        // shape) — and pass the uuid so save()'s resolution sees it.
        edited.modifyTime = System.currentTimeMillis() / 1000
        val merged = items.map { if (it.itemUuid == edited.itemUuid) edited else it }
        return save(merged, edited.itemUuid)
    }

    /** THE UPSERT for the autofill's saves: the key = SITE + USERNAME —
     *  the same origin AND the same (possibly empty) username = the
     *  update (the password-change semantics, the entry's other fields
     *  preserved); anything else = the append. The framework's
     *  save-request items and the generate's both carry fresh uuids —
     *  the uuid = NOT the identity here, the (site, username) pair is.
     *  The empty-username generate re-run at the same site = the update
     *  (no duplicate pile-up). The measured drop: the SAVE mode's
     *  edit-path save no-opped the brand-new item (4→3). */
    /** THE UPSERT TARGET for [item]: the existing login the upsert would
     *  update — the site + identity match (username.ifBlank { email }).
     *  Works in EITHER state: the unlocked session's items or the sealed
     *  manifest's clear-text identities. Null = the upsert would append
     *  (a new record). The UI's update-vs-new wording reads THIS — the
     *  single match implementation shared with [upsertSealed]. */
    fun upsertTarget(item: ProtonItem): ProtonItem? {
        val items = (state as? State.Unlocked)?.items
            ?: SealedVault.manifestItems()
        return upsertMatch(items, item)
    }

    private fun upsertMatch(items: List<ProtonItem>, item: ProtonItem): ProtonItem? {
        val siteMatch: (ProtonItem) -> Boolean = if (item.urls.isNotEmpty()) { existing ->
            existing.urls.any { u -> item.urls.contains(u) }
        } else { existing ->
            existing.name.equals(item.name, ignoreCase = true)
        }
        // THE IDENTITY = THE DEDUP KEY's second half (site + identity):
        // username.ifBlank { email } — the same login whose address sits
        // in EITHER bucket updates in place; a genuinely different
        // identity (a second account, a different address) = the append
        // (if in doubt, one extra record — never a silent drop). The
        // password NEVER gates the match: a changed password on the same
        // login = the update.
        return items.firstOrNull { existing ->
            siteMatch(existing) &&
                existing.identity.trim() == item.identity.trim()
        }
    }

    suspend fun upsertSealed(item: ProtonItem): Result {
        when (val p = promoteSealedSession()) {
            is Result.Success -> {}
            else -> return p
        }
        val items = (state as? State.Unlocked)?.items
            ?: return Result.Error("Session unavailable")
        val existing = upsertMatch(items, item)
        return if (existing != null) {
            Log.i(TAG, "upsertSealed: the existing entry ${existing.name.take(20)} " +
                "(site+username) — the update")
            // THE STATE'S ITEMS = THE STUBS after the promote (asStub
            // strips the password AND the note AND the totp) — the update
            // base must be the FULL item from loadedEnvelope (the promote
            // just installed it), or the update would zero the entry's
            // other fields (the measured note loss in the tests).
            val full = loadedEnvelope?.items
                ?.firstOrNull { it.itemUuid == existing.itemUuid } ?: existing
            val updated = full.copy(password = item.password,
                username = item.username)
            saveSealed(updated)
        } else {
            Log.i(TAG, "upsertSealed: the new entry ${item.name.take(20)} — the append")
            addSealed(item)
        }
    }

    /** THE ADD path for the sealed session (the autofill's generated
     *  entry): unlike [saveSealed] (the EDIT semantics — the swap by
     *  uuid, which SILENTLY NO-OPs for a brand-new item), this appends.
     *  The item must carry its secrets (the full item, not a stub). */
    suspend fun addSealed(newItem: ProtonItem): Result {
        when (val p = promoteSealedSession()) {
            is Result.Success -> {}
            else -> return p
        }
        val items = (state as? State.Unlocked)?.items
            ?: return Result.Error("Session unavailable")
        newItem.modifyTime = System.currentTimeMillis() / 1000
        return save(items + newItem, newItem.itemUuid)
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
    /** The sync line's repo state: how far ahead (unpushed) or behind
     *  origin/main this clone is, counted against the last-fetched
     *  remote-tracking ref (a local git read — no network). */
    fun syncDivergenceText(): String {
        if (config()?.remoteUrl == null) return ""
        val ab = runCatching { VaultGitClient().aheadBehind(gitRoot()) }.getOrNull()
            ?: return ""
        val (ahead, behind) = ab
        return when {
            ahead == 0 && behind == 0 ->
                "in sync with origin/main (as of the last fetch)"
            behind == 0 ->
                "ahead of origin/main by $ahead commit${if (ahead == 1) "" else "s"} (unpushed)"
            ahead == 0 ->
                "behind origin/main by $behind commit${if (behind == 1) "" else "s"}"
            else -> "diverged: ahead by $ahead, behind by $behind"
        }
    }

    fun currentRev(): Long = rev

    /** The local HEAD's short commit hash (front 7, like the Recent
     *  commits list) — empty when there is no repo yet. */
    fun headCommitShort(): String = runCatching {
        if (!File(gitRoot(), org.eclipse.jgit.lib.Constants.DOT_GIT).exists())
            return@runCatching ""
        org.eclipse.jgit.api.Git.open(gitRoot()).use { git ->
            git.repository.exactRef(org.eclipse.jgit.lib.Constants.HEAD)
                ?.objectId?.name?.take(7) ?: ""
        }
    }.getOrDefault("")

    // -- paired paste devices (Chrome extension; Plan 2) ---------------------

    fun pairedDevices(): List<DeviceRecord> = loadedEnvelope?.devices ?: emptyList()

    // -- THE SIMPLELOGIN LINK (the api key = a vault item) -------------------

    /** THE SL LINK'S DEFAULT DOMAIN: the aliases' mail domain — the
     *  fallback when the item carries no domain list (the pre-existing
     *  linked vaults). */
    const val SL_HOST = "app.simplelogin.io"

    /** THE SL LINK = the vault item holding the api key: the URL = the
     *  SL host, a password present. The item = card-encrypted, synced,
     *  user-visible/editable — the strongest storage this architecture
     *  has. Null = not linked. */
    fun simpleLoginItem(): ProtonItem? = loadedEnvelope?.items?.firstOrNull { item ->
        item.password.isNotBlank() && item.urls.any { url ->
            runCatching {
                java.net.URI(url.trim()).host?.removePrefix("www.") == SL_HOST
            }.getOrDefault(false)
        }
    }

    /** THE LINKED ALIAS DOMAINS: parsed from the SL item's note (the
     *  marker line the link flow writes: "SimpleLogin alias domains: "
     *  + the comma list) — the v5/alias/options' domains at the link
     *  time. Display-only: the CREATION always uses the account's
     *  default domain (SimpleLoginChain). Empty when the item carries
     *  no list. */
    fun simpleLoginDomains(): Set<String> {
        val note = simpleLoginItem()?.note ?: return emptySet()
        val marker = "SimpleLogin alias domains: "
        val line = note.lineSequence().firstOrNull { it.startsWith(marker) }
            ?: return emptySet()
        return line.removePrefix(marker).split(",").map { it.trim() }.filter { it.isNotBlank() }.toSet()
    }

    /** The item's email = an SL alias on ANY of the account's alias
     *  domains (the item-page toggle's gate). */
    fun isSimpleLoginAlias(email: String): Boolean {
        val domain = email.substringAfter('@', "").lowercase()
        return domain in simpleLoginDomains()
    }

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
        // The recipient key ids = THREE sources merged: the modern file
        // names (keys/encrypt/<KEYID>.pub.asc), the legacy flat layout
        // (keys/<KEYID>.public.asc), and the LEDGER's recipientKeyIds line
        // (the repo's own canonical record — the file names alone failed
        // to parse on-device once, and the ledger saved the session).
        val encryptDir = File(gitRoot(), "keys/encrypt")
        val legacyDir = File(gitRoot(), "keys")
        val fromFiles = (encryptDir.listFiles { f -> f.name.endsWith(".pub.asc") }
            ?.mapNotNull { f ->
                java.lang.Long.parseUnsignedLong(f.name.substringBefore("."), 16)
            } ?: emptyList()) + legacyDir.listFiles { f -> f.name.endsWith(".public.asc") }
            ?.mapNotNull { f ->
                java.lang.Long.parseUnsignedLong(f.name.substringBefore("."), 16)
            }.orEmpty()
        val fromLedger = runCatching {
            File(encryptDir, "recipients.txt").readText().lineSequence()
                .firstOrNull { it.startsWith("recipientKeyIds:") }
                ?.substringAfter(":")?.trim()
                ?.split(" ")?.mapNotNull { t ->
                    java.lang.Long.parseUnsignedLong(
                        t.removePrefix("0x").removePrefix("0X"), 16)
                }
        }.getOrNull().orEmpty()
        val ids = (fromFiles + fromLedger).distinct()
        // The recipient LEDGER (keys/encrypt/recipients.txt) carries the
        // recipient emails — adopt them so the Setup shows the vault's own
        // recipients and saves work without OpenKeyChain ever being asked.
        val ledgerEmails = runCatching {
            File(encryptDir, "recipients.txt").readText().lineSequence()
                .firstOrNull { it.startsWith("recipientEmails:") }
                ?.substringAfter(":")?.trim()
                ?.split(",")?.map { it.trim() }?.filter { it.isNotBlank() }
        }.getOrNull().orEmpty()
        if (ledgerEmails.isNotEmpty()) {
            prefs().edit()
                .putString("recipientEmails", ledgerEmails.joinToString(","))
                .apply()
            Log.i(TAG, "adopted " + ledgerEmails.size + " recipient email(s) from the vault ledger")
        }
        if (ids.isNotEmpty()) {
            setRecipientKeyIds(ids)
            Log.i(TAG, "seeded " + ids.size + " recipient key id(s) " +
                "(the files: " + fromFiles.size + ", the ledger: " + fromLedger.size + ")")
        }
        // THE OUTCOME ON THE FILE CHANNEL: the save's recipient lookup =
        // the OpenKeyChain picker when the ids are empty — this breadcrumb
        // answers WHY without the logcat (the ROM's logd is unreliable).
        loadPhase("recipient seed: " + ids.size + " id(s) (the files: " +
            fromFiles.size + ", the ledger: " + fromLedger.size + ")")
        // The UI-facing outcome: the Setup's status shows what the load
        // adopted (the vault's own recipients).
        if (ids.isNotEmpty()) seedStatus =
            "Recipients adopted: " + ids.size + " (from the vault)"
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
        // The enrolled key's fingerprint — the pre-sign gate's expectation
        // and the verdict's comparison base.
        val enrolledFp = runCatching { PgpSshBridge.fingerprintOf(line) }.getOrNull()
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
                    // The hash = the KEY's: RSA signs the SHA-512 DigestInfo
                    // (the card pads); an EC slot signs a SHA-256 digest
                    // (sign() strips it to the raw 32B hash).
                    val block = com.offlinepass.app.crypto.SshRsaPkcs1.digestInfo(
                        if (parsedLine.algorithm.startsWith("ecdsa-sha2-"))
                            "SHA-256" else "SHA-512", data)
                    withTouchPrompt {
                        // The slot = the SETTING's: the SIG (the default was
                        // the old) or the AUT (the dedicated auth key — the
                        // padded challenge, the wire-compat proven). The
                        // gate = the enrolled line's fingerprint: a card
                        // holding a different key refuses to sign AT ALL.
                        com.offlinepass.app.crypto.YubiKitSshAuth.sign(
                            appContext, pin, block, useAut = sshAuthUseAut(),
                            expectedFingerprint = enrolledFp)
                    }
                }
            }
            val sigBlock = signOutcome.getOrElse { e ->
                android.util.Log.e("YubiKeySsh", "yubikit sign failed", e)
                return SshSelfTest(false, "YubiKit sign: ${e.message}")
            }
            val verified = runCatching {
                val pub = PgpSshBridge.publicKeyFromLine(parsedLine)
                // The verifier = the ALGORITHM's: RSA (SHA-512) or ECDSA
                // (SHA-256 — the P-256 digest size).
                val verifier = java.security.Signature.getInstance(
                    when (parsedLine.algorithm) {
                        "ssh-rsa" -> "SHA512withRSA"
                        "ecdsa-sha2-nistp256" -> "SHA256withECDSA"
                        else -> throw IllegalStateException(
                            "no local verifier for ${parsedLine.algorithm}")
                    })
                verifier.initVerify(pub); verifier.update(data)
                verifier.verify(sigBlock)
            }.getOrElse { false }
            // THE WHICH-KEY VERDICT: the slot's LIVE key fingerprint vs
            // the enrolled line's — the verdict names the key, not just
            // the slot (a card holding a different key = a named mismatch,
            // not an opaque verification failure).
            val liveFp = kotlinx.coroutines.withContext(
                kotlinx.coroutines.Dispatchers.IO) {
                runCatching {
                    com.offlinepass.app.crypto.YubiKitSshAuth
                        .slotKeyFingerprint(appContext, sshAuthUseAut())
                }.getOrNull()
            } ?: "unreadable"
            val enrolledFpDisplay = enrolledFp ?: "unparsable"
            val keyMatch = liveFp == enrolledFpDisplay
            return if (verified) SshSelfTest(true,
                "YubiKit: the card signed on the " +
                    (if (sshAuthUseAut()) "AUTH slot (AUT)" else "SIGNATURE slot (SIG)") +
                    " + verified locally — auth key $liveFp " +
                    (if (keyMatch) "matches the enrolled line"
                        else "MISMATCH vs the enrolled line $enrolledFpDisplay"))
            else SshSelfTest(false,
                "the card's signature did NOT verify locally against the enrolled line " +
                    "(live auth key $liveFp" + (if (keyMatch) "" else ", enrolled $enrolledFpDisplay") +
                    "; the sig armor is saved to last-selftest-sig.asc)")
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

    /** Seeds the connect draft from the CONFIGURED remote — the
     *  load-existing flow sets the remote (and this draft) so the
     *  enrollment's username derives from it; the GetStarted screen
     *  never asks for the owner/repo again. */
    fun seedConnectDraftFromRemote() {
        val remote = config()?.remoteUrl ?: return
        val trimmed = remote.trim().removeSuffix(".git").trimEnd('/')
        val ownerRepo = when {
            trimmed.startsWith("git@") -> trimmed.substringAfter(':')
            trimmed.contains("://") ->
                trimmed.substringAfter("//").substringAfter('/')
            else -> trimmed
        }.takeIf { it.contains('/') && it.isNotBlank() } ?: return
        saveConnectDraft(ownerRepo, "ssh")
        Log.i(TAG, "connect draft seeded from the remote: $ownerRepo")
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
    /** Adds the ATTACHED CARD as a vault recipient — no OpenKeyChain. The
     *  DEC slot's raw public key + the card's own creation time = a v4
     *  public-key packet (OpenPgpCardCrypto.recipientKeyFromRaw); the
     *  SELF-CHECK = the constructed fingerprint must equal the card's
     *  reported one (a wrong time or an applet quirk = the loud failure,
     *  never a recipient nobody can decrypt). The recipients += the id,
     *  the armored record lands in keys/encrypt/, and the save re-encrypts
     *  so the card's PKESK rides the next envelope. */
    suspend fun addCardRecipient(): Result {
        val device = com.offlinepass.app.crypto.YubiKitSshAuth.findDevice(appContext)
            ?: return Result.Error("No YubiKey connected — attach the card to add it as a recipient")
        val usbManager = appContext.getSystemService(Context.USB_SERVICE)
            as? android.hardware.usb.UsbManager
            ?: return Result.Error("USB service unavailable")
        if (!usbManager.hasPermission(device)) {
            return Result.Error("USB permission not granted for the YubiKey")
        }
        val connection = com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice(
            usbManager, device).openConnection(
            com.yubico.yubikit.core.smartcard.SmartCardConnection::class.java)
        try {
            val session = com.yubico.yubikit.openpgp.OpenPgpSession(
                connection as com.yubico.yubikit.core.smartcard.SmartCardConnection)
            try {
                val decFp = session.applicationRelatedData.discretionary
                    .getFingerprint(com.yubico.yubikit.openpgp.KeyRef.DEC)
                if (com.offlinepass.app.crypto.YubiKitCardDecrypt
                        .isBlankFingerprint(decFp)
                ) {
                    // The factory-new card: no GPG key to enroll — the
                    // message names the README's initialize flow.
                    return Result.Error(
                        com.offlinepass.app.crypto.YubiKitCardDecrypt.BLANK_CARD_MESSAGE)
                }
                val decId = (12 until 20).fold(0L) { acc, k ->
                    (acc shl 8) or (decFp[k].toLong() and 0xFF)
                }
                val pub = session.getPublicKey(com.yubico.yubikit.openpgp.KeyRef.DEC)
                val rsa = pub as? com.yubico.yubikit.core.keys.PublicKeyValues.Rsa
                    ?: return Result.Error("The DECRYPTION slot is not RSA — only RSA cards can be added without OpenKeyChain")
                val creationSecs = session.applicationRelatedData.discretionary
                    .getGenerationTime(com.yubico.yubikit.openpgp.KeyRef.DEC)
                // THE SELF-CHECK: the constructed packet's fingerprint must
                // equal the card's reported one.
                val pubKey = com.offlinepass.app.crypto.OpenPgpCardCrypto.recipientKeyFromRaw(
                    rsa.modulus, rsa.publicExponent, creationSecs)
                if (!pubKey.fingerprint.contentEquals(decFp)) {
                    Log.w(TAG, "addCardRecipient: the fingerprint mismatch " +
                        "(constructed ${pubKey.fingerprint?.joinToString("") { "%02x".format(it) }})")
                    return Result.Error("The constructed key does not match the card's fingerprint " +
                        "— refusing to add a recipient the card may not decrypt")
                }
                // The recipients += the card's id; the armored record = the
                // repo's.
                val ids = (recipientKeyIds() + decId).distinct()
                setRecipientKeyIds(ids)
                val f = File(keysEncryptDir(), "%016X.pub.asc".format(decId))
                f.parentFile?.mkdirs()
                f.writeText(com.offlinepass.app.crypto.OpenPgpCardCrypto.armoredKey(pubKey))
                // The save re-encrypts: the card's PKESK rides the next
                // envelope (the promote-if-stub covers the stub session).
                if (state is State.Unlocked) {
                    when (val r = save(unlockedSessionItems())) {
                        is Result.Error -> return r
                        else -> {}
                    }
                }
                return Result.Success
            } finally {
                session.close()
            }
        } finally {
            runCatching { connection.close() }
        }
    }

    /** The unlocked session's item list (the stubs) — the save's input. */
    private fun unlockedSessionItems(): List<ProtonItem> =
        (state as? State.Unlocked)?.items ?: emptyList()

    suspend fun delete(item: ProtonItem): Result {
        loadedEnvelope?.deletedItemUuids?.add(item.itemUuid)
        val remaining = (state as? State.Unlocked)?.items
            ?.filter { it.itemUuid != item.itemUuid } ?: emptyList()
        return save(remaining, what = "Deleting '${item.displayName}'")
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
            // The file channel: logd is broken on this ROM — the load's
            // failure message must survive for the log pull.
            runCatching {
                File(appContext.filesDir, "debug-sync.log").appendText(
                    "[${System.currentTimeMillis()}] gitOpenOnly FAILED: " +
                        "${e.javaClass.simpleName}: ${e.message}\n")
            }
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
        if (useSsh) {
            // The AUTH key = the SECURITY KEY by default: the YubiKey
            // enrollment suffices for the remote. The screenlock is only
            // required in the screenlock mode (its signing/local roles).
            if (sshSyncMode() == SSH_SYNC_YUBIKEY) {
                if (yubikeySshLine() == null || yubikeyAuthSubkeyId() == null)
                    return Result.Error("Enroll the YubiKey SSH key first (Setup → Choose key)")
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
        authDescription = "Syncing with ${cfg.remoteUrl?.substringAfterLast("/") ?: "the remote"}"
        // The progress messages (the intermittent, like the import flow):
        // the syncStatus = the phase ledger the Sync tab shows live.
        syncStatus = "syncing: fetching…"
        try {
            withContext(Dispatchers.IO) {
                val git = VaultGitClient()
                val root = gitRoot()
                git.open(remote, pat, root)
                // Track the signer/authorized-key material in the repo (the
                // offline keyring); best-effort, committed with the vault.
                // THE SYNC = THE YUBIKIT PATH ONLY: the local key-material
                // (the authorized keys, the device registry) — never the
                // OpenKeyChain IPC (the cert fetch = the Setup-time op).
                updateRepoKeyMaterialLocal()
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
                    SIGNING_YUBIKEY -> syncCommitSigner(openPgpClientFactory(appContext))
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
                            OpenKeyChainSigner(openPgpClientFactory(appContext), preSignId)
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
                        reconcileSignersAfterSync()
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
                        syncStatus = "syncing: pushing…"
                        git.pushBranch(remote, pat, root)
                        syncStatus = "Pushed (rev $rev)"
                    }
                    is VaultGitClient.Divergence.BehindOnly -> {
                        syncStatus = "syncing: pulled — decrypting with the key…"
                        git.resetHardTo(root, "origin/main")
                        refreshFromVaultFile()
                        reconcileSignersAfterSync()
                        syncStatus = "Pulled remote (rev $rev)"
                    }
                    is VaultGitClient.Divergence.Diverged -> {
                        Log.i(TAG, "diverged: merging ${div.headId.take(7)} with ${div.remoteId.take(7)}")
                        syncStatus = "syncing: decrypting both sides for the merge…"
                        // The vault files are ENCRYPTED — decrypt before the
                        // merge (the card, one touch for the remote side).
                        // The previous code fed the ciphertext to
                        // Envelope.fromJson, silently merged EMPTY envelopes
                        // and wiped the vault on divergence.
                        // THE STUB-INVARIANT: the local side must be the
                        // full items (the stubs would merge empty) — the
                        // batch unseal inside the sync's flow.
                        if (!promoteIfStub()) {
                            return@withContext Result.Error(
                                "The merge needs the sealed cache — re-unlock with the key")
                        }
                        val remoteEnv = git.readFileAt(root, "origin/main:$vaultRelPath")
                            ?.let { b ->
                                runCatching { Envelope.fromJson(String(vaultDecryptBytes(b))) }
                                    .onFailure { Log.w(TAG, "the remote vault decrypt failed: ${it.message}") }
                                    .getOrNull()
                            }
                            ?: Envelope(deviceId = cfg.deviceId)
                        val localEnv = loadedEnvelope
                            ?: git.readFileAt(root, "HEAD:$vaultRelPath")
                                ?.let { b ->
                                    runCatching { Envelope.fromJson(String(vaultDecryptBytes(b))) }
                                        .onFailure { Log.w(TAG, "the local vault decrypt failed: ${it.message}") }
                                        .getOrNull()
                                }
                            ?: Envelope(deviceId = cfg.deviceId)
                        val merged = VaultMerge.unionMerge(localEnv, remoteEnv)

                        // Rebuild the branch on top of origin/main with the
                        // merged (re-encrypted) vault file.
                        git.resetHardTo(root, "origin/main")
                        val client = openPgpClientFactory(appContext)
                        val keyIds = cachedRecipientKeyIds() ?: recipientKeyIds().toLongArray()
                        if (keyIds.isEmpty()) throw IllegalStateException("no recipients")
                        // The recipients' armored files must be present for
                        // the BC encrypt (the pulled repo carries them).
                        materializeRecipientKeys(client, root, keyIds)
                        val plain = File(appContext.cacheDir, "merge-plain.json")
                        try {
                            plain.writeText(merged.toJsonObject().toString())
                            val target = File(root, vaultRelPath)
                            target.parentFile?.mkdirs()
                            target.writeBytes(vaultEncryptBytes(
                                plain.readText().toByteArray(Charsets.UTF_8), root, keyIds))
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
                        reconcileSignersAfterSync()
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
        // The pull happens with the key attached: decrypt via the card path
        // (the same seam as unlock; no OpenKeyChain in the path).
        try {
            val env = Envelope.fromJson(String(vaultDecryptBytes(vaultFile().readBytes())))
            rev = env.rev
            loadedEnvelope = env
            state = State.Unlocked(env.items)
            // The re-seal = AWAITED: the post-sync item detail reads the
            // cache's freshness — the async seal would race it (the stale
            // = the card demanded per item).
            runCatching {
                SealedVault.sealNowAwait(env.items, env, File(vaultFilePath()))
            }.onFailure { Log.w(TAG, "pull re-seal failed: ${it.message}") }
            // The stub model (see unlock) — the same conversion when the
            // screenlock is enrolled.
            if (screenlockUnlockEnabled()) {
                env.items = env.items.map { it.asStub() }.toMutableList()
                state = State.Unlocked(env.items)
                stubSession = true
            }
        } catch (e: Exception) {
            // The repo pulled but the session could not adopt it — say so
            // loudly: saving on top of a stale session invites a divergence
            // merge, and the on-disk vault is AHEAD of memory until the
            // next unlock.
            Log.w(TAG, "post-pull decrypt failed: ${e.message}")
            syncStatus = "pulled the remote vault but could not decrypt it " +
                "(${e.message}) — lock and re-unlock with the key"
        }
    }

    /**
     * Writes the recipients' armored public keys (keys/<keyid>.public.asc)
     * and the recipients ledger (keys/recipients.txt) into the repo root —
     * committed with the vault, so git history records exactly which keys
     * can open each revision. The BC envelope encrypt NEEDS these files on
     * disk, so a missing fetch hard-fails the save (the caller rolls back);
     * returns true when every key file is present.
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

    /** Decrypts an arbitrary vault file (the USB/QRFT restore path) — the
     *  CARD path (the PIN + the touch, in-process via YubiKit + BC; no
     *  OpenKeyChain). The card is attached by definition: the import runs
     *  at setup time. */
    suspend fun decryptEnvelope(file: File): DecryptEnvelope = withContext(Dispatchers.IO) {
        if (!file.exists()) return@withContext DecryptEnvelope.Error("File missing")
        try {
            DecryptEnvelope.Ok(Envelope.fromJson(String(vaultDecryptBytes(file.readBytes()))))
        } catch (e: Exception) {
            Log.w(TAG, "restore decrypt failed: ${e.message}")
            DecryptEnvelope.Error("${e.javaClass.simpleName}: ${e.message}")
        }
    }

    /** Adopts the recipients carried IN the vault file itself: the PKESK
     *  packets name their recipients (the card's DEC key among them). The
     *  local-only restores have no repo ledger — the file's own record =
     *  the save targets, no OpenKeyChain, no repo needed. The ids are
     *  UNSIGNED 64-bit (the PKESKs with the high bit set are common). */
    // -- the temporary recipient (one-off export) -----------------------------
    // THE SESSION-SCOPED ADDITION: the scanned key never touches the repo's
    // keys/ or the recipient config — it is appended to the export's
    // recipient set only (the permanent recipients stay first) and dies with
    // the process.
    var tempRecipientArmored: String? by mutableStateOf(null)
    var tempRecipientLabel: String? by mutableStateOf(null)

    /** The Share export encryption: ON (default) = the OpenPGP envelope
     *  (permanent recipients + the scanned key); OFF = the PLAINTEXT vault
     *  JSON — the secrets in the clear, for handoffs with no PGP setup. */
    var exportEncrypted: Boolean by mutableStateOf(true)

    fun setTempRecipient(armored: String) {
        val id = runCatching {
            com.offlinepass.app.crypto.OpenPgpCardCrypto
                .loadRecipientKeys(armored.toByteArray()).first().keyID
        }.getOrNull()
        tempRecipientArmored = armored.trim()
        tempRecipientLabel = id?.let { "0x%016X".format(it) } ?: "(unparsed key)"
    }

    /** The one-off export: the CURRENT envelope encrypted to the PERMANENT
     *  repo recipients + the scanned temporary key when one is present
     *  (appended). No rev bump, no commit, no repo write — a pure snapshot
     *  of the vault as-is. */
    suspend fun exportVaultToTempRecipient(): ByteArray {
        if (state !is State.Unlocked) throw IllegalStateException("Unlock the vault first")
        if (stubSession && !promoteIfStub()) throw IllegalStateException(
            "The sealed cache is missing or stale — re-unlock with the key, then export")
        val env = loadedEnvelope ?: Envelope(deviceId = config()?.deviceId ?: "")
        val plain = env.toJsonObject().toString().toByteArray(Charsets.UTF_8)
        if (!exportEncrypted) return plain
        val keyIds = cachedRecipientKeyIds() ?: recipientKeyIds().toLongArray()
        if (keyIds.isEmpty()) throw IllegalStateException("No permanent recipients to include")
        val keys = loadRecipientKeysFor(gitRoot(), keyIds).toMutableList()
        tempRecipientArmored?.let {
            keys += com.offlinepass.app.crypto.OpenPgpCardCrypto.loadRecipientKeys(it.toByteArray())
        }
        return com.offlinepass.app.crypto.OpenPgpCardCrypto.encryptToBytes(plain, "10.gpg", keys)
    }

    /** THIS device's armored public key (the first permanent recipient —
     *  the owner's). PRIMARY PATH: read the repo's materialized key file
     *  (keys/encrypt/&lt;keyid&gt;.pub.asc) — no OpenKeyChain, no interaction,
     *  instant. FALLBACK: the SHARED OpenKeyChain client (the binding
     *  persists; per-op clients re-pay OKK's 5-20s cold start), used when
     *  the repo has not materialized the key yet. Returns (armored, keyId)
     *  or null. */
    suspend fun devicePublicKeyArmored(): Pair<String, Long>? {
        val keyId = recipientKeyIds().firstOrNull() ?: return null
        // The repo file first — the same material OKK would return, minus
        // the whole IPC round-trip.
        for (rel in listOf("keys/encrypt/%016X.pub.asc".format(keyId),
                           "keys/%016X.public.asc".format(keyId))) {
            val f = File(gitRoot(), rel)
            if (f.exists()) {
                val armored = f.readText()
                if (armored.contains("BEGIN PGP PUBLIC KEY BLOCK")) return armored to keyId
            }
        }
        val client = sharedOpenPgpClient(appContext)
        var reqData: Intent? = null
        var guard = 0
        while (guard++ < 3) {
            when (val r = client.fetchPublicKeyArmored(keyId, reqData)) {
                is OpenPgpClient.PublicKey.Success -> return r.armored to keyId
                is OpenPgpClient.PublicKey.UserInteraction ->
                    reqData = interactionHandler?.invoke(r.pendingIntent) ?: return null
                else -> return null
            }
        }
        return null
    }

    fun adoptRecipientsFromVaultFile(file: File) {        runCatching {
            val msg = com.offlinepass.app.vault.PgpMessageParser.parse(file.readBytes())
            val ids = msg.pkesks.mapNotNull { it.keyId }.distinct()
            if (ids.isNotEmpty()) {
                setRecipientKeyIds(ids)
                Log.i(TAG, "adopted " + ids.size + " recipient id(s) from the vault file's PKESKs")
                loadPhase("recipient adopt (the file's PKESKs): " + ids.size + " id(s)")
            }
        }
    }

    /** THE NEW VAULT's repo = git-init'd at creation (the early fix): the
     *  structure = ready the moment the vault exists — the save = the
     *  commit only, and the empty-file sha binds the fresh sealed cache
     *  consistently. */
    fun initLocalRepo() {
        runCatching {
            com.offlinepass.app.vault.VaultGitClient().gitInit(gitRoot())
            Log.i(TAG, "the local repo git-init'd at creation")
        }.onFailure { Log.w(TAG, "gitInit at creation: ${it.message}") }
    }

    /** Adopts an already-decrypted envelope as the unlocked session —
     * no second decrypt, no extra OpenKeyChain prompts (USB restore). */
    fun adopt(env: Envelope) {
        rev = env.rev
        loadedEnvelope = env
        state = State.Unlocked(env.items)
        sealIfEnabled(env.items, env)
        // The stub model (see unlock).
        if (screenlockUnlockEnabled()) {
            env.items = env.items.map { it.asStub() }.toMutableList()
            state = State.Unlocked(env.items)
            stubSession = true
        }
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
    /** THE PAIRING STASH: zero() (the idle lock) clears the envelope;
     *  the staged-but-unsaved pairings stash here so the next promote
     *  carries them (the session-scope: the process death loses them
     *  exactly as it loses the un-saved envelope). */
    @Volatile private var stashedDevices: List<DeviceRecord>? = null
    @Volatile private var stashedRemovedDeviceIds: List<String>? = null

    fun zero() {
        android.util.Log.i("UnlockTiming", "zero() called-from: " +
            Throwable().stackTrace.drop(1).take(4)
                .joinToString(" ← ") { "${it.className.substringAfterLast('.')}.${it.methodName}(${it.lineNumber})" })
        loadedEnvelope?.items?.clear()
        loadedEnvelope?.deletedItemUuids?.clear()
        loadedEnvelope?.extraFields?.clear()
        // THE PAIRING STASH: the staged-but-unsaved pairings survive the
        // idle lock (the promote picks them up on the next unlock). The
        // COALESCE: a second zero() (the idle lock → the activity
        // teardown's onDestroy) sees no envelope and must not clobber
        // the first call's stash with an empty one.
        stashedDevices = loadedEnvelope?.devices?.toList() ?: stashedDevices
        stashedRemovedDeviceIds = loadedEnvelope?.removedDeviceIds?.toList()
            ?: stashedRemovedDeviceIds
        loadedEnvelope = null
        rev = 0
        stubSession = false
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
