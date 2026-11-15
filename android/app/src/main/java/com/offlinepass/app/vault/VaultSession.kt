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
    fun yubikeyAuthSubkeyId(): Long? = prefs().getString("yubikeyAuthSubkeyId", null)?.toLongOrNull()

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

    /** Builds the active SSH identity for a sync, or null when the chosen
     *  mode isn't fully enrolled. */
    fun buildSshIdentity(client: OpenPgpClient): com.jcraft.jsch.Identity? {
        return when (sshSyncMode()) {
            SSH_SYNC_YUBIKEY -> {
                val line = yubikeySshLine() ?: return null
                val subkeyId = yubikeyAuthSubkeyId() ?: return null
                val interaction = interactionHandler
                    ?: throw IllegalStateException("Interaction needs the UI layer")
                YubiKeySshIdentity(client, subkeyId, line, interaction)
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
                    if (commitSigningMode() == SIGNING_SCREENLOCK) {
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

    fun screenlockUnlockEnabled(): Boolean =
        prefs().getBoolean("screenlockUnlock", false)

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

    // -- Connect-remote draft (survives the SSH-key QR detour) ----------------

    fun saveConnectDraft(ownerRepo: String, auth: String) {
        prefs().edit()
            .putString("connectDraftOwnerRepo", ownerRepo)
            .putString("connectDraftAuth", auth)
            .apply()
    }

    fun connectDraftOwnerRepo(): String? =
        prefs().getString("connectDraftOwnerRepo", null)?.takeIf { it.isNotBlank() }

    fun connectDraftAuth(): String? = prefs().getString("connectDraftAuth", null)

    fun clearConnectDraft() {
        prefs().edit()
            .remove("connectDraftOwnerRepo")
            .remove("connectDraftAuth")
            .apply()
    }

    // -- load-screen drafts (survive the QR detour + app restarts) ------------

    /** Keys: "remote", "pat", "sshLine", "subkeyId", "authMode". */
    fun loadDraft(key: String): String =
        prefs().getString("loadDraft_$key", null) ?: ""

    fun saveLoadDraft(key: String, value: String) {
        prefs().edit().putString("loadDraft_$key", value).apply()
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
                    return Result.Error("Enroll the YubiKey SSH key first (Setup → paste the SSH line)")
                // The gate is the YubiKey touch inside the OpenKeyChain
                // interaction during the handshake — no pre-auth needed.
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
                val vaultRelPath = "state/10.gpg"
                // Commit a stranded/dirty vault file FIRST so it participates
                // in the divergence check + push (a failed push leaves it
                // uncommitted; without this it never reaches the remote).
                // Signed with the SAME signer mode as save(): screenlock or
                // OpenKeyChain.
                val preSigner: org.eclipse.jgit.lib.Signer? = if (commitSigningMode() == SIGNING_SCREENLOCK) {
                    val hook = keystoreSignerHook
                        ?: throw IllegalStateException("Screenlock signer unavailable")
                    com.offlinepass.app.crypto.KeystoreCommitSigner(hook)
                } else {
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
                        val signId = signingKeyId() ?: keyIds.first()
                val signer = OpenKeyChainSigner(client, signId)
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
        val keysDir = File(repoRoot, "keys").apply { mkdirs() }
        for (id in keyIds) {
            val f = File(keysDir, "%016X.public.asc".format(id))
            if (f.exists()) continue
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
        File(keysDir, "recipients.txt").writeText(
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
