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
        state = if (config() == null && !localVaultFile().exists()) State.NoConfig else State.Locked
    }

    // -- config -------------------------------------------------------------

    private fun prefs() = appContext.getSharedPreferences("vault_config", Context.MODE_PRIVATE)

    fun config(): Config? {
        val prefs = prefs()
        val remote = prefs.getString("remoteUrl", null)
        val emails = prefs.getString("recipientEmails", null)?.split(",")?.filter { it.isNotBlank() }
        if (remote == null && emails == null) return null
        return Config(remote, emails ?: emptyList(), deviceId())
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
    suspend fun unlock(): Result {
        val cfg = config()
        busy = if (cfg?.remoteUrl != null) "Syncing vault…" else "Opening vault…"
        try {
            return withContext(Dispatchers.IO) {
                if (cfg?.remoteUrl != null) {
                    val pat = pat() ?: return@withContext Result.Error("No PAT stored")
                    VaultGitClient().open(cfg.remoteUrl, pat, gitRoot())
                }
                val vaultFile = vaultFile()
                if (!vaultFile.exists()) {
                    // New-vault flow: nothing to decrypt yet.
                    state = State.Unlocked(emptyList())
                    return@withContext Result.Success
                }
                val plain = File(appContext.cacheDir, "vault-plain.json")
                val client = OpenPgpClient(appContext)
                return@withContext when (val r = client.decryptVerify(vaultFile, plain)) {
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

                var keyIds = cachedRecipientKeyIds()
                if (keyIds == null) {
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
                        VaultGitClient().commitAndPush(cfg.remoteUrl, pat, gitRoot(), "Update 10.gpg (rev ${env.rev})")
                        syncStatus = "Pushed rev ${env.rev}"
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

    /** Fetch + push any pending work (Setup tab "Sync now"). */
    suspend fun syncNow(): Result {
        val cfg = config() ?: return Result.Error("Local-only mode: nothing to sync")
        val remote = cfg.remoteUrl ?: return Result.Error("Local-only mode: nothing to sync")
        val pat = pat() ?: return Result.Error("No PAT stored")
        busy = "Syncing…"
        try {
            withContext(Dispatchers.IO) {
                VaultGitClient().commitAndPush(remote, pat, gitRoot(), "sync")
            }
            syncStatus = "Synced (rev $rev)"
            return Result.Success
        } catch (e: Exception) {
            return Result.Error("${e.javaClass.simpleName}: ${e.message}")
        } finally {
            busy = null
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
}
