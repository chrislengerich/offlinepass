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
import com.linuxpass.app.ui.QrScreen
import com.linuxpass.app.ui.QrftScreen
import com.linuxpass.app.ui.entryPayload
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
 * Legacy spike extras (path/email/exportKey/probeSign/autostart) forward to
 * the spike activities so the earlier spikes keep working.
 */
class MainActivity : ComponentActivity() {

    private var screen by mutableStateOf<Screen>(Screen.SetupChoice)
    private var status by mutableStateOf("")
    private var searchQuery by mutableStateOf("")
    private var pendingInteraction: CancellableContinuation<Unit>? = null

    private val interactionLauncher =
        registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { _ ->
            pendingInteraction?.resume(Unit)
            pendingInteraction = null
        }

    private fun launchInteraction(pi: PendingIntent) {
        interactionLauncher.launch(IntentSenderRequest.Builder(pi.intentSender).build())
    }

    private suspend fun awaitInteraction() {
        suspendCancellableCoroutine<Unit> { cont ->
            pendingInteraction = cont
            cont.invokeOnCancellation { pendingInteraction = null }
        }
    }

    /** Retries the op while OpenKeyChain keeps asking for interaction. */
    private suspend fun unlockLoop() {
        var guard = 0
        while (guard++ < 5) {
            when (val r = VaultSession.unlock()) {
                VaultSession.Result.Success -> return
                is VaultSession.Result.Interaction -> { launchInteraction(r.pendingIntent); awaitInteraction() }
                is VaultSession.Result.Error -> { status = r.message; return }
            }
        }
        status = "Too many OpenKeyChain interactions; unlock aborted."
    }

    private suspend fun saveLoop(items: List<ProtonItem>): VaultSession.Result {
        var guard = 0
        while (guard++ < 5) {
            when (val r = VaultSession.save(items)) {
                is VaultSession.Result.Interaction -> { launchInteraction(r.pendingIntent); awaitInteraction() }
                else -> return r
            }
        }
        return VaultSession.Result.Error("Too many OpenKeyChain interactions; save aborted.")
    }

    private fun unlockedItems(): List<ProtonItem> =
        (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()

    private fun currentDetailItem(uuid: String): ProtonItem? =
        unlockedItems().firstOrNull { it.itemUuid == uuid }

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
            val restored = when (val r = VaultSession.decryptEnvelope(staged)) {
                is VaultSession.DecryptEnvelope.Ok -> r.env
                is VaultSession.DecryptEnvelope.Interaction -> {
                    launchInteraction(r.pendingIntent); awaitInteraction()
                    when (val r2 = VaultSession.decryptEnvelope(staged)) {
                        is VaultSession.DecryptEnvelope.Ok -> r2.env
                        else -> { status = "Restore decrypt failed."; return }
                    }
                }
                is VaultSession.DecryptEnvelope.Error -> { status = "Restore failed: ${r.message}"; return }
            }
            val current = if (File(VaultSession.vaultFilePath()).exists())
                (VaultSession.decryptEnvelope(File(VaultSession.vaultFilePath())) as? VaultSession.DecryptEnvelope.Ok)?.env
            else null
            val merged = if (current == null) restored else VaultMerge.unionMerge(current, restored)
            if (VaultSession.config() == null) {
                // Local-only restore: the imported file becomes the vault.
                VaultSession.configure(null, emptyList())
                File(VaultSession.vaultFilePath()).parentFile?.mkdirs()
                File(VaultSession.vaultFilePath()).writeBytes(staged.readBytes())
                status = "Restored (local-only)."
                screen = Screen.Search
                unlockLoop()
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
                defaults = Pair(
                    "https://github.com/planetaltitude/linuxpass-storage-test.git",
                    "noodlefish@nan.404"
                ),
                onConfigured = { remote, emails ->
                    VaultSession.configure(remote, emails)
                    status = ""
                    lifecycleScope.launch { unlockLoop() }
                },
                status = status,
                onLoadUsb = { usbRestoreLauncher.launch(arrayOf("application/octet-stream")) }
            )
            VaultSession.State.Locked -> UnlockScreen(
                status = status,
                busy = VaultSession.busy,
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
                        onQrSingleFrame = { screen = Screen.Qr(item.itemUuid) },
                        onQrQrft = {
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
                is Screen.Qr -> {
                    val item = currentDetailItem(s.itemUuid)
                    if (item == null) screen = Screen.Search
                    else QrScreen(payload = entryPayload(item), onBack = { screen = Screen.Detail(item.itemUuid) })
                }
                is Screen.Qrft -> {
                    val item = currentDetailItem(s.itemUuid)
                    QrftScreen(
                        payloadFile = File(getExternalFilesDir(null), "entry-latest.json"),
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
                    autofillEnabled = isAutofillEnabled()
                )
            }
        }
    }
}
