package com.linuxpass.app

import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import com.linuxpass.app.ui.Screen
import com.linuxpass.app.ui.SetupChoiceScreen
import com.linuxpass.app.ui.UnlockScreen
import com.linuxpass.app.ui.SearchScreen
import com.linuxpass.app.ui.SetupTabScreen
import com.linuxpass.app.ui.AddEntryScreen
import com.linuxpass.app.ui.EntryDetailScreen
import com.linuxpass.app.ui.QrftScreen
import com.linuxpass.app.ui.entryPayload
import com.linuxpass.app.vault.Envelope
import com.linuxpass.app.vault.PasswordGen
import com.linuxpass.app.vault.ProtonItem
import com.linuxpass.app.vault.VaultMerge
import com.linuxpass.app.vault.VaultSession
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.File
import kotlin.coroutines.resume

/**
 * The router. Owns the interaction loop (OpenKeyChain PendingIntents), the
 * USB SAF launchers, and screen navigation; screens are pure Compose.
 * Spike extras (path/email/exportKey/probeSign/autostart) forward to the
 * spike activities so the earlier spikes keep working.
 */
class MainActivity : ComponentActivity() {

    private var screen by mutableStateOf<Screen>(Screen.SetupChoice)
    private var status by mutableStateOf("")
    private var searchQuery by mutableStateOf("")
    private var pendingInteraction: CancellableContinuation<Intent?>? = null

    private val interactionLauncher =
        registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
            Log.i(TAG, "interaction result: code=${result.resultCode} " +
                "key_ids_selected=${result.data?.getLongArrayExtra("key_ids_selected")?.contentToString()}")
            pendingInteraction?.resume(result.data)
            pendingInteraction = null
        }

    private fun launchInteraction(pi: PendingIntent) {
        interactionLauncher.launch(IntentSenderRequest.Builder(pi.intentSender).build())
    }

    /** Suspends until the PendingIntent completes; returns its result Intent. */
    private suspend fun awaitInteraction(): Intent? =
        suspendCancellableCoroutine { cont ->
            pendingInteraction = cont
            cont.invokeOnCancellation { pendingInteraction = null }
        }

    /** Unlock: one interaction retry is usually enough. */
    private suspend fun unlockLoop() {
        var guard = 0
        while (guard++ < 2) {
            when (val r = VaultSession.unlock()) {
                VaultSession.Result.Success -> {
                    android.widget.Toast.makeText(this, "Vault unlocked", android.widget.Toast.LENGTH_SHORT).show()
                    if (screen == Screen.SetupChoice) screen = Screen.Search
                    return
                }
                is VaultSession.Result.Interaction -> { launchInteraction(r.pendingIntent); awaitInteraction() }
                is VaultSession.Result.Error -> {
                    if (!File(VaultSession.vaultFilePath()).exists()) {
                        // No vault on this device: setup screen, not an error.
                        screen = Screen.SetupChoice
                        status = "No vault on this device — create or import one below."
                    } else status = r.message
                    return
                }
            }
        }
        status = "Unlock aborted after interaction retry."
    }

    private suspend fun saveLoop(items: List<ProtonItem>): VaultSession.Result {
        var guard = 0
        while (guard++ < 2) {
            when (val r = VaultSession.save(items)) {
                is VaultSession.Result.Interaction -> { launchInteraction(r.pendingIntent); awaitInteraction() }
                else -> return r
            }
        }
        return VaultSession.Result.Error("Save aborted after interaction retry.")
    }

    /** Add recipients via OpenKeyChain's keyring picker (multi-select). */
    private suspend fun pickRecipientsUntilDone() {
        var guard = 0
        while (guard++ < 2) {
            when (val r = VaultSession.pickRecipient()) {
                VaultSession.Result.Success -> { persistPicked(VaultSession.lastPickedKeyIds); return }
                is VaultSession.Result.Interaction -> {
                    launchInteraction(r.pendingIntent)
                    val data = awaitInteraction()
                    val picked = (data?.getLongArrayExtra("key_ids_selected")
                        ?: data?.getLongArrayExtra("key_ids"))
                        ?.toList()?.takeIf { it.isNotEmpty() }
                    if (picked != null) {
                        persistPicked(picked)
                        return
                    }
                }
                is VaultSession.Result.Error -> { status = "Recipient: ${r.message}"; return }
            }
        }
        status = "Recipient picking aborted."
    }

    private fun persistPicked(picked: List<Long>) {
        VaultSession.setRecipientKeyIds((VaultSession.recipientKeyIds() + picked).distinct())
        status = "Recipients: " + VaultSession.recipientKeyIds()
            .joinToString(" ") { "0x%016X".format(it) }
    }

    // -- USB save/restore ---------------------------------------------------

    private val usbSaveLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            if (uri == null) return@registerForActivityResult
            try {
                val src = File(VaultSession.vaultFilePath())
                contentResolver.openOutputStream(uri)?.use { out ->
                    src.inputStream().use { it.copyTo(out) }
                }
                status = "Vault snapshot saved to the chosen file."
            } catch (e: Exception) {
                status = "USB save failed: ${e.message}"
            }
        }

    private val usbRestoreLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri == null) return@registerForActivityResult
            lifecycleScope.launch { restoreLoop(uri) }
        }

    private suspend fun restoreLoop(uri: android.net.Uri) {
        try {
            val staged = File(cacheDir, "restored.gpg")
            contentResolver.openInputStream(uri)?.use { ins ->
                staged.outputStream().use { ins.copyTo(it) }
            }
            val restored: Envelope = run {
                var env: VaultSession.DecryptEnvelope.Ok? = null
                var guard = 0
                while (guard++ < 2) {
                    when (val r = VaultSession.decryptEnvelope(staged)) {
                        is VaultSession.DecryptEnvelope.Ok -> { env = r; break }
                        is VaultSession.DecryptEnvelope.Interaction -> {
                            launchInteraction(r.pendingIntent); awaitInteraction()
                        }
                        is VaultSession.DecryptEnvelope.Error ->
                            { status = "Restore failed: ${r.message}"; return }
                    }
                }
                env?.env ?: run { status = "Restore decrypt failed after retry."; return }
            }
            val current = if (File(VaultSession.vaultFilePath()).exists())
                (VaultSession.decryptEnvelope(File(VaultSession.vaultFilePath())) as? VaultSession.DecryptEnvelope.Ok)?.env
            else null
            val merged = if (current == null) restored else VaultMerge.unionMerge(current, restored)
            if (VaultSession.config() == null) {
                // Local-only restore: the imported file becomes the vault.
                // The envelope is ALREADY decrypted — adopt it directly.
                VaultSession.configure(null, emptyList())
                File(VaultSession.vaultFilePath()).parentFile?.mkdirs()
                File(VaultSession.vaultFilePath()).writeBytes(staged.readBytes())
                VaultSession.adopt(restored)
                status = "Restored (local-only, rev ${restored.rev})."
                screen = Screen.Search
            } else {
                status = when (val r = saveLoop(merged.items)) {
                    VaultSession.Result.Success -> "Restored + merged (rev ${VaultSession.currentRev()})."
                    else -> "Merged locally; save reported: $r"
                }
                screen = Screen.Search
            }
        } catch (e: Exception) {
            status = "Restore failed: ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    // -- autofill -------------------------------------------------------------

    private fun isAutofillEnabled(): Boolean = try {
        getSystemService(android.view.autofill.AutofillManager::class.java)
            ?.hasEnabledAutofillServices() ?: false
    } catch (e: Exception) { false }

    private fun requestAutofillService() {
        try {
            startActivity(
                Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                    .setData(android.net.Uri.parse("package:$packageName"))
            )
        } catch (e: Exception) {
            status = "Could not open autofill settings: ${e.message}"
        }
    }

    // -- lifecycle ------------------------------------------------------------

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VaultSession.init(applicationContext)
        // The vault layer can't launch activities: the UI performs the
        // OpenKeyChain interaction and returns the RESULT intent (which
        // carries OpenKeyChain's call UUIDs for its crypto-input cache).
        VaultSession.interactionHandler = { pi ->
            launchInteraction(pi)
            awaitInteraction()
        }
        // Spike extras forward (S1/S3 keep working).
        val keys = listOf("path", "email", "exportKey", "probeSign", "autostart")
        val received = keys.mapNotNull { k -> intent.getStringExtra(k)?.let { k to it } }.toMap()
        if (received.isNotEmpty()) {
            val forward = Intent(this, when {
                received.containsKey("autostart") -> com.linuxpass.app.spike.S3GitActivity::class.java
                else -> com.linuxpass.app.spike.S1DecryptActivity::class.java
            }).apply { received.forEach { (k, v) -> putExtra(k, v) } }
            startActivity(forward)
            finish()
            return
        }
        setContent {
            Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                AppRouter()
            }
        }
    }

    @androidx.compose.runtime.Composable
    private fun AppRouter() {
        when (VaultSession.state) {
            VaultSession.State.NoConfig -> SetupChoiceScreen(
                defaultRemote = "https://github.com/planetaltitude/linuxpass-storage-test.git",
                defaultEmails = "noodlefish@nan.404",
                prefillPat = runCatching {
                    File(getExternalFilesDir(null), "storage-pat.txt").readText().trim()
                }.getOrDefault(""),
                status = status,
                recipientIds = VaultSession.recipientKeyIds(),
                onPickRecipients = { lifecycleScope.launch { pickRecipientsUntilDone() } },
                onRemoveRecipient = { id ->
                    VaultSession.setRecipientKeyIds(VaultSession.recipientKeyIds() - id)
                    status = "Recipient removed."
                },
                onNewVault = { remote, pat ->
                    VaultSession.configure(remote, emptyList())
                    if (pat.isNotBlank()) VaultSession.savePat(pat)
                    status = ""
                    lifecycleScope.launch {
                        // New vault: git state only (no decrypt of anything),
                        // then recipients, then the (empty) vault persists on
                        // first save.
                        val open = VaultSession.gitOpenOnly()
                        if (open is VaultSession.Result.Error) {
                            android.widget.Toast.makeText(this@MainActivity,
                                "Offline — will sync later", android.widget.Toast.LENGTH_LONG).show()
                            status = "Offline: repo not fetched. Use Sync now when back online."
                            if (!File(VaultSession.vaultFilePath()).exists()) {
                                VaultSession.adopt(Envelope(rev = 0, deviceId = VaultSession.deviceId()))
                            }
                            screen = Screen.Search
                            return@launch
                        }
                        pickRecipientsUntilDone()
                        screen = Screen.Search
                        status = "New vault ready — Add entry to begin."
                    }
                },
                onImportProton = { remote, pat, uri ->
                    VaultSession.configure(remote, emptyList())
                    if (pat.isNotBlank()) VaultSession.savePat(pat)
                    status = ""
                    lifecycleScope.launch {
                        val staged = File(cacheDir, "import-proton")
                        contentResolver.openInputStream(uri)?.use { ins ->
                            staged.outputStream().use { ins.copyTo(it) }
                        }
                        // Plaintext Proton export? (No decrypt involved.)
                        val env = Envelope.parseImport(staged.readText())
                        if (env == null) {
                            status = "Not a plaintext Proton Pass export — trying encrypted restore…"
                            restoreLoop(uri)
                            return@launch
                        }
                        val open = VaultSession.gitOpenOnly()
                        if (open is VaultSession.Result.Error) {
                            android.widget.Toast.makeText(this@MainActivity,
                                "Offline — will sync later", android.widget.Toast.LENGTH_LONG).show()
                            status = "Offline: repo not fetched. Use Sync now when back online."
                        }
                        VaultSession.adopt(env)
                        status = "Imported ${env.items.size} entries — pick recipients."
                        pickRecipientsUntilDone()
                        status = when (val r = saveLoop(env.items)) {
                            VaultSession.Result.Success -> {
                                android.widget.Toast.makeText(
                                    this@MainActivity, "Import complete",
                                    android.widget.Toast.LENGTH_SHORT
                                ).show()
                                "Import complete (rev ${VaultSession.currentRev()})."
                            }
                            else -> "Imported locally; save: $r"
                        }
                        screen = Screen.Search
                    }
                },
                onLoadGitHub = { remote, emails, pat ->
                    VaultSession.configure(remote, emails)
                    if (pat.isNotBlank()) VaultSession.savePat(pat)
                    status = ""
                    lifecycleScope.launch {
                        val open = VaultSession.gitOpenOnly()  // explicit network step
                        if (open is VaultSession.Result.Error) {
                            android.widget.Toast.makeText(this@MainActivity,
                                "Offline — will sync later", android.widget.Toast.LENGTH_LONG).show()
                            status = "Offline: repo not fetched."
                            if (!File(VaultSession.vaultFilePath()).exists()) {
                                VaultSession.adopt(Envelope(rev = 0, deviceId = VaultSession.deviceId()))
                            }
                            screen = Screen.Search
                            return@launch
                        }
                        unlockLoop()
                        android.widget.Toast.makeText(this@MainActivity, "Vault loaded",
                            android.widget.Toast.LENGTH_SHORT).show()
                    }
                },
                onLoadUsb = { usbRestoreLauncher.launch(arrayOf("application/octet-stream")) }
            )
            VaultSession.State.Locked -> UnlockScreen(
                status = status,
                busy = VaultSession.busy,
                patMissing = VaultSession.config()?.remoteUrl != null && !VaultSession.hasPat(),
                onPatSave = { VaultSession.savePat(it); status = "PAT stored (encrypted)." },
                onUnlock = { lifecycleScope.launch { unlockLoop() } }
            )
            is VaultSession.State.Unlocked -> when (val s = screen) {
                Screen.SetupChoice, Screen.Search -> SearchScreen(
                    items = unlockedItems(),
                    busy = VaultSession.busy,
                    query = searchQuery,
                    onQueryChange = { searchQuery = it },
                    onOpen = { item -> screen = Screen.Detail(item.itemUuid) },
                    onAdd = { screen = Screen.AddEntry },
                    onSetup = { screen = Screen.Setup }
                )
                is Screen.Detail -> {
                    val item = currentDetailItem(s.itemUuid)
                    if (item == null) {
                        screen = Screen.Search
                    } else EntryDetailScreen(
                        item = item,
                        status = status,
                        busy = VaultSession.busy,
                        onBack = { screen = Screen.Search },
                        onExportQr = {
                            lifecycleScope.launch {
                                val payload = entryPayload(item)
                                File(getExternalFilesDir(null), "entry-latest.json").writeText(payload)
                                screen = Screen.Qrft(item.itemUuid)
                            }
                        },
                        onUpdatePassword = {
                            lifecycleScope.launch {
                                item.password = PasswordGen.password()
                                status = when (val r = saveLoop(unlockedItems())) {
                                    VaultSession.Result.Success -> "Password updated (rev ${VaultSession.currentRev()})."
                                    else -> "Save: $r"
                                }
                            }
                        },
                        onEnrollTotp = { uri ->
                            lifecycleScope.launch {
                                item.totpUri = uri
                                status = when (val r = saveLoop(unlockedItems())) {
                                    VaultSession.Result.Success -> "TOTP enrolled."
                                    else -> "Save: $r"
                                }
                            }
                        },
                        onDelete = {
                            lifecycleScope.launch {
                                status = when (val r = VaultSession.delete(item)) {
                                    VaultSession.Result.Success -> { screen = Screen.Search; "Deleted (tombstoned)." }
                                    else -> "Delete: $r"
                                }
                            }
                        }
                    )
                }
                Screen.AddEntry -> AddEntryScreen(
                    onCancel = { screen = Screen.Search },
                    onSave = { item ->
                        lifecycleScope.launch {
                            status = when (val r = saveLoop(unlockedItems() + item)) {
                                VaultSession.Result.Success -> { screen = Screen.Search; "Added ${item.displayName}." }
                                else -> "Save: $r"
                            }
                        }
                    }
                )
                is Screen.Qrft -> {
                    val item = currentDetailItem(s.itemUuid)
                    QrftScreen(
                        payload = if (item != null) entryPayload(item)
                        else File(getExternalFilesDir(null), "entry-latest.json").readText(),
                        onBack = { if (item != null) screen = Screen.Detail(item.itemUuid) else screen = Screen.Search }
                    )
                }
                Screen.Setup -> SetupTabScreen(
                    status = status,
                    busy = VaultSession.busy,
                    onBack = { screen = Screen.Search },
                    onTestSync = {
                        lifecycleScope.launch {
                            status = when (val r = VaultSession.syncNow()) {
                                VaultSession.Result.Success -> "Sync OK (rev ${VaultSession.currentRev()})."
                                else -> "Sync: $r"
                            }
                        }
                    },
                    onUsbSave = { usbSaveLauncher.launch("linuxpass-vault-rev${VaultSession.currentRev()}.gpg") },
                    onUsbRestore = { usbRestoreLauncher.launch(arrayOf("application/octet-stream")) },
                    onEnableAutofill = { requestAutofillService() },
                    onForget = { VaultSession.forgetConfig(); screen = Screen.SetupChoice },
                    patSave = { VaultSession.savePat(it); status = "PAT stored (encrypted)." },
                    autofillEnabled = isAutofillEnabled(),
                    recipientIds = VaultSession.recipientKeyIds(),
                    onAddRecipient = { lifecycleScope.launch { pickRecipientsUntilDone() } },
                    onRemoveRecipient = { id ->
                        VaultSession.setRecipientKeyIds(VaultSession.recipientKeyIds() - id)
                        status = "Recipient removed."
                    }
                )
            }
        }
    }

    private fun unlockedItems(): List<ProtonItem> =
        (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()

    private fun currentDetailItem(uuid: String): ProtonItem? =
        unlockedItems().firstOrNull { it.itemUuid == uuid }

    companion object {
        private const val TAG = "S1"
    }
}
