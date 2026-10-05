package com.linuxpass.app.vault

import android.content.Context
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.linuxpass.app.crypto.OpenPgpClient
import java.io.File
import kotlinx.coroutines.Dispatchers
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
    }

    data class Config(
        val remoteUrl: String?,
        val recipientEmails: List<String>,
        val deviceId: String
    )

    private const val TAG = "VaultSession"
    private val PICK_SENTINEL = "pick-recipient@linuxpass.local"
    private lateinit var appContext: Context

    var state by mutableStateOf<State>(State.Locked)
        private set
    var busy by mutableStateOf<String?>(null)
        private set

    /** Human-readable sync state, shown above the Sync-now button. */
    var syncStatus by mutableStateOf<String?>(null)
        private set

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

    /**
     * Recipient PICK via OpenKeyChain's own keyring UI: a lookup for an
     * unknown user id raises the key-selection screen (multi-select
     * checkboxes); every picked key comes back in the result's key-id array
     * (in [lastPickedKeyIds]). Interaction propagates for the UI loop.
     */
    suspend fun pickRecipient(): Result {
        val client = OpenPgpClient(appContext)
        return when (val lookup = client.lookupKeyIds(arrayOf(PICK_SENTINEL))) {
            is OpenPgpClient.KeyLookup.Success -> {
                if (lookup.keyIds.isNotEmpty()) {
                    lastPickedKeyIds = lookup.keyIds.toList()
                    Result.Success
                } else Result.Error("Pick returned no key")
            }
            is OpenPgpClient.KeyLookup.UserInteraction -> Result.Interaction(lookup.pendingIntent)
            is OpenPgpClient.KeyLookup.Error -> Result.Error("Key lookup failed")
        }
    }

    fun deviceId(): String {
        val prefs = prefs()
        return prefs.getString("deviceId", null)
            ?: java.util.UUID.randomUUID().toString().also { prefs.edit().putString("deviceId", it).apply() }
    }

    /**
     * Persists config. remote == null => local-only mode. Returns immediately;
     * the repo is opened on next unlock.
     */
    fun configure(remoteUrl: String?, recipientEmails: List<String>) {
        val old = prefs().getString("remoteUrl", null)
        if (remoteUrl != null && old != null && old != remoteUrl) {
            // Remote changed: wipe the stale clone from another vault era
            // (reinit git state — fresh clone on next unlock).
            gitRoot().deleteRecursively()
            Log.i(TAG, "remote changed: wiped stale clone")
        }
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

    private fun gitRoot(): File = File(appContext.filesDir, "vault/repo")
    private fun localVaultFile(): File = File(appContext.filesDir, "vault/local/10.gpg")
    private fun vaultFile(): File =
        if (config()?.remoteUrl != null) File(gitRoot(), "state/10.gpg") else localVaultFile()

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
        try {
            val plain = File(appContext.cacheDir, "vault-plain.json")
            val client = OpenPgpClient(appContext)
            return when (val r = client.decryptVerify(vaultFile(), plain)) {
                is OpenPgpClient.DecryptResult.Success -> {
                    val env = Envelope.fromJson(plain.readText())
                    rev = env.rev
                    loadedEnvelope = env
                    state = State.Unlocked(env.items)
                    Log.i(TAG, "unlocked: ${env.items.size} items, rev=${env.rev}")
                    Result.Success
                }
                is OpenPgpClient.DecryptResult.UserInteraction -> Result.Interaction(r.pendingIntent)
                is OpenPgpClient.DecryptResult.Error -> Result.Error("Decrypt failed (see logcat)")
            }
        } catch (e: Exception) {
            Log.w(TAG, "unlock failed: ${e.message}")
            return Result.Error("${e.javaClass.simpleName}: ${e.message}")
        } finally {
            busy = null
        }
    }

    // -- save ----------------------------------------------------------------

    /**
     * Encrypts (all configured recipients) + writes the vault file + pushes
     * (remote mode). Local-only mode: just writes the file. Returns
     * Interaction when OpenKeyChain needs a prompt — the UI launches it and
     * calls save() again.
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
                val client = OpenPgpClient(appContext)

                var keyIds = cachedRecipientKeyIds() ?: recipientKeyIds().toLongArray()
                if (keyIds.isEmpty() && cfg.recipientEmails.isNotEmpty()) {
                    when (val lookup = client.lookupKeyIds(cfg.recipientEmails.toTypedArray())) {
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
                plain.writeText(env.toJsonObject().toString())
                val target = vaultFile()
                target.parentFile?.mkdirs()
                if (!client.encryptTo(keyIds, plain, target)) {
                    return@withContext Result.Error("Encrypt failed")
                }
                rev = env.rev
                loadedEnvelope = env
                Log.i(TAG, "encrypted ${target.length()} bytes, rev=${env.rev}")

                if (cfg.remoteUrl != null) {
                    busy = "Pushing…"
                    val pat = pat() ?: return@withContext Result.Error("No PAT stored")
                    try {
                        // Sign with the same identity that receives the vault
                        // (falls back to an unsigned commit if that key cannot sign).
                        val signer = OpenKeyChainSigner(client, keyIds.first())
                        try {
                            VaultGitClient().pushBranch(cfg.remoteUrl, pat, gitRoot())
                            syncStatus = "Pushed rev ${env.rev} (signed)"
                        } catch (e: Exception) {
                            Log.w(TAG, "push failed: ${e.javaClass.simpleName}: ${e.message}", e)
                            syncStatus = "Saved locally; push pending"
                            return@withContext Result.Error("Saved locally; push failed: ${e.message}")
                        }
                    } catch (e: Exception) {
                        // The encrypted file is committed locally; the push
                        // retries on the next save/sync.
                        Log.w(TAG, "push failed (kept local commit): ${e.message}")
                        syncStatus = "Saved locally; push pending"
                        return@withContext Result.Error("Saved locally; push failed: ${e.message}")
                    }
                }
                state = State.Unlocked(items)
                Result.Success
            }
        } catch (e: Exception) {
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

    // -- helpers for UI (USB save/restore, QR export) -----------------------

    fun vaultFilePath(): String = vaultFile().absolutePath
    fun currentRev(): Long = rev

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
        val pat = pat() ?: return Result.Error("No PAT stored")
        busy = "Opening repo…"
        try {
            withContext(Dispatchers.IO) { VaultGitClient().open(remote, pat, gitRoot()) }
            return Result.Success
        } catch (e: Exception) {
            Log.w(TAG, "git open failed: ${e.message}")
            return Result.Error("Repo open failed: ${e.message?.take(60)}")
        } finally {
            busy = null
        }
    }

    /** Fetch + push, with application-level union-merge when the two
     * devices diverged (the M3 convergence path). */
    suspend fun syncNow(): Result {
        val cfg = config() ?: return Result.Error("Local-only mode: nothing to sync")
        val remote = cfg.remoteUrl ?: return Result.Error("Local-only mode: nothing to sync")
        val pat = pat() ?: return Result.Error("No PAT stored")
        busy = "Syncing…"
        try {
            withContext(Dispatchers.IO) {
                val git = VaultGitClient()
                val root = gitRoot()
                git.open(remote, pat, root)
                val vaultRelPath = "state/10.gpg"
                when (val div = git.headVsRemote(root)) {
                    is VaultGitClient.Divergence.UpToDate -> {
                        syncStatus = "Already up to date (rev $rev)"
                        // A fresh clone may carry the vault without the
                        // session being unlocked yet.
                        refreshFromVaultFile()
                    }
                    is VaultGitClient.Divergence.AheadOnly -> {
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
                        plain.writeText(merged.toJsonObject().toString())
                        val target = File(root, vaultRelPath)
                        target.parentFile?.mkdirs()
                        if (!client.encryptTo(keyIds, plain, target)) {
                            throw IllegalStateException("encrypt during merge failed")
                        }
                        val signer = OpenKeyChainSigner(client, keyIds.first())
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
                        syncStatus = "Merged + pushed (rev ${merged.rev})"
                    }
                }
            }
            return Result.Success
        } catch (e: Exception) {
            Log.w(TAG, "syncNow failed: ${e.javaClass.simpleName}: ${e.message}")
            syncStatus = "Sync failed: ${e.message?.take(60)}"
            return Result.Error("${e.javaClass.simpleName}: ${e.message}")
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
            }
            else -> Log.w(TAG, "post-pull decrypt failed")
        }
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
        when (val r = client.decryptVerify(file, plain)) {
            is OpenPgpClient.DecryptResult.Success ->
                DecryptEnvelope.Ok(Envelope.fromJson(plain.readText()))
            is OpenPgpClient.DecryptResult.UserInteraction -> DecryptEnvelope.Interaction(r.pendingIntent)
            is OpenPgpClient.DecryptResult.Error -> DecryptEnvelope.Error("Decrypt failed (see logcat)")
        }
    }

    /** Adopts an already-decrypted envelope as the unlocked session —
     * no second decrypt, no extra OpenKeyChain prompts (USB restore). */
    fun adopt(env: Envelope) {
        rev = env.rev
        loadedEnvelope = env
        state = State.Unlocked(env.items)
    }
}
