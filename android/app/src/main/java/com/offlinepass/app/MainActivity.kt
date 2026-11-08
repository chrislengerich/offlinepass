package com.offlinepass.app

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
import com.offlinepass.app.ui.Screen
import com.offlinepass.app.ui.SetupChoiceScreen
import com.offlinepass.app.ui.UnlockScreen
import com.offlinepass.app.ui.SearchScreen
import com.offlinepass.app.ui.SetupTabScreen
import com.offlinepass.app.ui.AddEntryScreen
import com.offlinepass.app.ui.EntryDetailScreen
import com.offlinepass.app.ui.ExportPickScreen
import com.offlinepass.app.ui.QrftScreen
import com.offlinepass.app.ui.QrftScanScreen
import com.offlinepass.app.ui.entryPayload
import com.offlinepass.app.vault.Envelope
import com.offlinepass.app.vault.PasswordGen
import com.offlinepass.app.vault.ProtonItem
import com.offlinepass.app.vault.VaultMerge
import com.offlinepass.app.vault.VaultSession
import com.offlinepass.app.ui.ExportTargetPickScreen
import com.offlinepass.app.ui.PairScanScreen
import com.offlinepass.app.vault.DeviceRecord
import com.offlinepass.app.vault.DeviceWrap
import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.io.File
import kotlin.coroutines.resume

/**
 * The router. Owns the interaction loop (OpenKeyChain PendingIntents), the
 * USB SAF launchers, and screen navigation; screens are pure Compose.
 * Spike extras (path/email/exportKey/probeSign/autostart) forward to the
 * spike activities so the earlier spikes keep working.
 */
class MainActivity : androidx.activity.ComponentActivity() {

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

    /** Import-from-QRFT needs the camera before the scanner WebView opens. */
    private val cameraPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) screen = Screen.QrftScan
            else status = "Camera permission denied — cannot import from QRFT."
        }

    /** Pair-paste-device scan: same camera permission, different screen. */
    private val pairCameraLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (granted) screen = Screen.PairScan
            else status = "Camera permission denied — cannot pair a paste device."
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
    /** The optional screen-lock gate: a device biometric/PIN prompt BEFORE
     * the hardware-key interaction (only when enabled in Setup). */
    private suspend fun biometricGate(): Boolean {
        if (!VaultSession.screenLockRequired()) return true
        return kotlinx.coroutines.suspendCancellableCoroutine { cont ->
            // Platform BiometricPrompt (API 28+): no FragmentActivity needed,
            // so the Activity-Result registry keeps working.
            val cancel = android.os.CancellationSignal()
            val prompt = android.hardware.biometrics.BiometricPrompt.Builder(this)
                .setTitle("Unlock offlinepass")
                .setSubtitle("Device lock required before the security key")
                .setDeviceCredentialAllowed(true)
                .build()
            cont.invokeOnCancellation { cancel.cancel() }
            prompt.authenticate(
                cancel,
                androidx.core.content.ContextCompat.getMainExecutor(this),
                object : android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(
                        result: android.hardware.biometrics.BiometricPrompt.AuthenticationResult
                    ) { cont.resume(true) }
                    override fun onAuthenticationError(code: Int, errString: CharSequence) {
                        Log.w(TAG, "screen-lock gate: $code $errString")
                        cont.resume(false)
                    }
                }
            )
        }
    }

    private suspend fun unlockLoop() {
        if (!biometricGate()) {
            status = "Screen lock failed — unlock aborted."
            return
        }
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
        val staged = File(cacheDir, "restored.gpg")
        try {
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
        } finally {
            // Staged ciphertext copy — hygiene: never left in the cache dir.
            com.offlinepass.app.vault.SecureWipe.file(staged)
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

    /** The vault layer can't launch activities: the UI performs the
     *  OpenKeyChain interaction and returns the RESULT intent (which carries
     *  OpenKeyChain's call UUIDs for its crypto-input cache).
     *
     *  Reassigned on EVERY resume: the handler is an app-scoped singleton,
     *  and a launcher auto-unregisters when its activity instance is
     *  destroyed (stacked instances, "don't keep activities", recreation
     *  during OpenKeyChain prompts) — a stale handler made every later
     *  interaction fail with "Attempting to launch an unregistered
     *  ActivityResultLauncher". The Main-thread hop matters too: save()
     *  invokes the handler from Dispatchers.IO. */
    override fun onResume() {
        super.onResume()
        VaultSession.interactionHandler = { pi ->
            withContext(kotlinx.coroutines.Dispatchers.Main) {
                launchInteraction(pi)
                awaitInteraction()
            }
        }
        // Screenlock commit signer (when enrolled): the Keystore op gated by
        // the device's screen lock. Runs on Main (BiometricPrompt needs the
        // UI thread); save() invokes it from Dispatchers.IO.
        VaultSession.keystoreSignerHook = { bytes ->
            withContext(kotlinx.coroutines.Dispatchers.Main) { screenLockSignFlow(bytes) }
        }
        // SSH syncs open the key's 60s validity window with a screen-lock
        // interaction (biometric or device credential) before the transport.
        VaultSession.syncAuthGate = { biometricGate() }
        // First push to an EMPTY remote: confirm before creating the remote
        // main branch.
        VaultSession.firstPushGate = {
            withContext(kotlinx.coroutines.Dispatchers.Main) { firstPushConfirm() }
        }
        // The active SSH identity: screenlock keystore key, or the YubiKey
        // auth subkey via OpenKeyChain (the interaction = the YubiKey touch).
        VaultSession.sshIdentityProvider = {
            when (VaultSession.sshSyncMode()) {
                VaultSession.SSH_SYNC_YUBIKEY -> {
                    val line = VaultSession.yubikeySshLine()
                    val subkey = VaultSession.yubikeyAuthSubkeyId()
                    if (line == null || subkey == null) null
                    else com.offlinepass.app.crypto.YubiKeySshIdentity(
                        com.offlinepass.app.crypto.OpenPgpClient(applicationContext),
                        subkey, line
                    ) { pi ->
                        withContext(kotlinx.coroutines.Dispatchers.Main) {
                            launchInteraction(pi)
                            awaitInteraction()
                        }
                    }
                }
                else -> {
                    val manager = com.offlinepass.app.crypto.SshKeyManager()
                    val info = manager.ensureKeyPair()
                    object : com.jcraft.jsch.Identity {
                        // getAlgName must return the SSH algorithm name —
                        // "RSA" (the JCE name) makes JSch's filter skip the
                        // identity entirely ("cannot be used as public key
                        // type") and the auth fails without ever offering.
                        override fun getAlgName(): String =
                            if (info.algorithm == "Ed25519") "ssh-ed25519" else "ssh-rsa"
                        override fun getName(): String = "offlinepass-android"
                        override fun getPublicKeyBlob(): ByteArray = info.wireBlob
                        // JSch negotiates the RSA signature algorithm (it prefers
                        // rsa-sha2-512 for ssh-rsa keys) — the signature must be
                        // computed with EXACTLY that hash, labeled accordingly.
                        // A failure here (e.g. the key's digest set lacks
                        // SHA-512) returns null so JSch retries with the next
                        // algorithm in its list (rsa-sha2-256) — the key
                        // supports that one.
                        override fun getSignature(data: ByteArray, algorithm: String): ByteArray? =
                            when (algorithm) {
                                "rsa-sha2-512" -> runCatching { signRsa(data, "SHA512withRSA", "rsa-sha2-512") }.getOrNull()
                                "rsa-sha2-256" -> runCatching { signRsa(data, "SHA256withRSA", "rsa-sha2-256") }.getOrNull()
                                else -> null // unknown → JSch tries the next algorithm
                            }
                        override fun getSignature(data: ByteArray): ByteArray =
                            signRsa(data, "SHA256withRSA", "rsa-sha2-256")
                        private fun signRsa(data: ByteArray, jceAlg: String, wireAlg: String): ByteArray {
                            val sig = manager.newSignerFor(jceAlg)
                            sig.update(data)
                            return wireString(wireAlg.toByteArray()) + wireString(sig.sign())
                        }
                        override fun setPassphrase(passphrase: ByteArray?): Boolean = true
                        override fun isEncrypted(): Boolean = false
                        override fun clear() {}
                    }
                }
            }
        }
    }

    /** SSH wire string (4-byte length + bytes). */
    private fun wireString(b: ByteArray): ByteArray {
        val out = ByteArray(4 + b.size)
        out[0] = ((b.size ushr 24) and 0xFF).toByte()
        out[1] = ((b.size ushr 16) and 0xFF).toByte()
        out[2] = ((b.size ushr 8) and 0xFF).toByte()
        out[3] = (b.size and 0xFF).toByte()
        b.copyInto(out, 4)
        return out
    }

    /** Screen-lock signature flow (platform BiometricPrompt, mirroring
     *  biometricGate). For a per-operation auth key the prompt MUST come
     *  before any sign() attempt: calling sign() first starts and aborts
     *  the Keystore operation, and the post-auth retry then fails with
     *  INVALID_OPERATION_HANDLE. The CryptoObject binds the screen-lock
     *  interaction to THIS exact Keystore signature operation. Returns
     *  null on decline or failure (save rolls back). */
    private suspend fun screenLockSignFlow(bytes: ByteArray): ByteArray? =
        suspendCancellableCoroutine { cont ->
            try {
                val signature = com.offlinepass.app.crypto.KeystoreSigner.prepare(bytes)
                // Platform BiometricPrompt (the app already uses it for the
                // gate): CryptoObject binds the screen-lock interaction to
                // THIS exact Keystore signature operation. Prompt FIRST —
                // never attempt sign() before authentication.
                val builder = android.hardware.biometrics.BiometricPrompt.Builder(this)
                    .setTitle("Sign vault change")
                    .setSubtitle("Screen-lock signature for this revision")
                if (android.os.Build.VERSION.SDK_INT >= 30) {
                    builder.setAllowedAuthenticators(
                        android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
                            or android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                } else {
                    builder.setDeviceCredentialAllowed(true)
                }
                val cancel = android.os.CancellationSignal()
                builder.build().authenticate(
                    android.hardware.biometrics.BiometricPrompt.CryptoObject(signature),
                    cancel,
                    androidx.core.content.ContextCompat.getMainExecutor(this),
                    object : android.hardware.biometrics.BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: android.hardware.biometrics.BiometricPrompt.AuthenticationResult
                        ) {
                            cont.resume(
                                runCatching {
                                    com.offlinepass.app.crypto.KeystoreSigner.finish(signature)
                                }.getOrNull())
                        }
                        override fun onAuthenticationError(code: Int, errString: CharSequence) {
                            Log.w(TAG, "screenlock signature declined: $code $errString")
                            cont.resume(null)
                        }
                    })
            } catch (e: Exception) {
                Log.w(TAG, "screenlock signature failed: ${e.message}")
                cont.resume(null)
            }
        }

    /** Where the SSH-key QR screen returns to (Setup post-load, or the
     *  SetupChoice screen pre-load). */
    private var sshKeyBackScreen: Screen = Screen.Setup

    /** Generates/refreshes the screenlock SSH key and shows its public
     *  key QR (scanned by the offlinepass extension). */
    private fun showSshKeyQr(back: Screen) {
        lifecycleScope.launch {
            try {
                val info = withContext(kotlinx.coroutines.Dispatchers.IO) {
                    com.offlinepass.app.crypto.SshKeyManager().ensureKeyPair()
                }
                // The QR enrolls the SCREENLOCK key — make this mode ACTIVE
                // (the YubiKey dialog switches it the other way; last
                // enrollment wins).
                VaultSession.setSshSyncMode(VaultSession.SSH_SYNC_SCREENLOCK)
                val payload = org.json.JSONObject()
                    .put("type", "offlinepass-ssh-pubkey")
                    .put("sshKey", info.openSshLine)
                    .put("fp", info.fingerprint)
                    .toString()
                sshKeyBackScreen = back
                screen = Screen.QrftPayload(payload)
            } catch (e: Exception) {
                status = "SSH key enrollment failed: ${e.message}"
            }
        }
    }

    /** Keyless DETACHED_SIGN: OpenKeyChain opens ITS OWN key picker (all
     *  keys, hardware badges shown); the user picks the YubiKey's auth
     *  subkey and touches — a test signature proves the path and the
     *  response's issuer subpacket reveals the used key id. */
    private suspend fun pickAuthSubkey() {
        var reqData: Intent? = null
        var guard = 0
        while (guard++ < 3) {
            when (val r = com.offlinepass.app.crypto.OpenPgpClient(applicationContext)
                .trySignDetached("offlinepass auth-subkey test".toByteArray(), null, reqData)
            ) {
                is com.offlinepass.app.crypto.OpenPgpClient.SignDetached.Ok -> {
                    val keyId = com.offlinepass.app.crypto.PgpSshBridge
                        .issuingKeyId(r.armored)
                    if (keyId != null) {
                        VaultSession.pickedAuthSubkeyId = keyId
                        status = "Auth subkey selected (0x%016X).".format(keyId)
                    } else {
                        status = "Could not read the selected key's id."
                    }
                    return
                }
                is com.offlinepass.app.crypto.OpenPgpClient.SignDetached.UserInteraction -> {
                    launchInteraction(r.pendingIntent)
                    reqData = awaitInteraction()
                }
                is com.offlinepass.app.crypto.OpenPgpClient.SignDetached.Error -> {
                    status = "Key selection failed: ${r.message}"
                    return
                }
            }
        }
        status = "Key selection aborted after retries."
    }

    /** Persists the YubiKey SSH enrollment (works pre-load: prefs only). */
    private fun enrollYubikeySsh(sshLine: String, subkeyId: String) {
        val keyId = subkeyId.toLongOrNull(16)
        if (keyId == null) {
            status = "Auth subkey id must be 16 hex digits."
        } else {
            VaultSession.setYubikeySsh(sshLine, subkeyId)
            status = "YubiKey SSH enrolled — Load from GitHub now authenticates " +
                "with the YubiKey touch."
        }
    }

    /** Confirmation dialog for the first push to an empty remote. */
    private suspend fun firstPushConfirm(): Boolean =
        suspendCancellableCoroutine { cont ->
            val dialog = android.app.AlertDialog.Builder(this)
                .setTitle("First push to an empty remote")
                .setMessage("The remote repository is empty. Push your local vault " +
                    "history to it? This creates the remote main branch.")
                .setPositiveButton("Push") { _, _ -> cont.resume(true) }
                .setNegativeButton("Cancel") { _, _ -> cont.resume(false) }
                .setOnCancelListener { cont.resume(false) }
                .show()
            cont.invokeOnCancellation { dialog.dismiss() }
        }

    override fun onDestroy() {
        super.onDestroy()
        if (isFinishing) {
            // Exit: zero the decrypted session (items, envelope, plaintext
            // temp files). A swipe-away kill reclaims memory with the
            // process; this covers every deliberate exit.
            VaultSession.zero()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VaultSession.init(applicationContext)
        // Spike extras forward (S1/S3 keep working).
        val keys = listOf("path", "email", "exportKey", "probeSign", "autostart")
        val received = keys.mapNotNull { k -> intent.getStringExtra(k)?.let { k to it } }.toMap()
        if (received.isNotEmpty()) {
            val forward = Intent(this, when {
                received.containsKey("autostart") -> com.offlinepass.app.spike.S3GitActivity::class.java
                else -> com.offlinepass.app.spike.S1DecryptActivity::class.java
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
                defaultRemote = "https://github.com/planetaltitude/offlinepass-storage-test.git",
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
                onNewVault = {
                    // New vaults are LOCAL-ONLY by design (the remote is
                    // attached later from Setup — "Connect remote").
                    VaultSession.configure(null, emptyList())
                    status = ""
                    lifecycleScope.launch {
                        // Recipients, then adopt the empty envelope as the
                        // unlocked session (state must leave NoConfig or the
                        // Setup screen keeps rendering), then Search. The
                        // vault file persists on first save (git-init there).
                        pickRecipientsUntilDone()
                        VaultSession.adopt(Envelope(rev = 0, deviceId = VaultSession.deviceId()))
                        screen = Screen.Search
                        status = "Local-only vault ready — Add entry to begin."
                    }
                },
                onImportProton = { remote, pat, uri ->
                    VaultSession.configure(remote, emptyList())
                    if (pat.isNotBlank()) VaultSession.savePat(pat)
                    status = ""
                    lifecycleScope.launch {
                        val staged = File(cacheDir, "import-proton")
                        try {
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
                        } finally {
                            // Plaintext Proton export staging — wiped.
                            com.offlinepass.app.vault.SecureWipe.file(staged)
                        }
                    }
                },
                onLoadGitHub = { remote, emails, pat ->
                    VaultSession.configure(remote, emails)
                    if (pat.isNotBlank()) VaultSession.savePat(pat)
                    status = ""
                    lifecycleScope.launch {
                        // An SSH load's clone handshake signs with the
                        // screenlock key — open its 60s validity window with
                        // the screen-lock interaction first. (The YubiKey
                        // mode's gate is the touch inside OpenKeyChain.)
                        if (com.offlinepass.app.vault.VaultGitClient().isSshRemote(remote) &&
                            VaultSession.sshSyncMode() == VaultSession.SSH_SYNC_SCREENLOCK
                        ) {
                            if (!biometricGate()) {
                                status = "Screen lock declined — load aborted."
                                return@launch
                            }
                        }
                        val open = VaultSession.gitOpenOnly()  // explicit network step
                        if (open is VaultSession.Result.Error) {
                            // A failed load must NOT adopt a phantom empty
                            // vault or leave an unlinked repo behind: undo
                            // the config attempt and stay on Setup to retry.
                            VaultSession.forgetConfig()
                            File(VaultSession.gitRootPath()).deleteRecursively()
                            status = "Load failed: ${open.message} — fix the remote/PAT and retry."
                            android.widget.Toast.makeText(this@MainActivity,
                                "Load failed — nothing was changed", android.widget.Toast.LENGTH_LONG).show()
                            return@launch
                        }
                        // The loaded repo carries its recipients
                        // (keys/<keyid>.public.asc) — seed the save targets.
                        VaultSession.seedRecipientsFromRepo()
                        unlockLoop()
                        android.widget.Toast.makeText(this@MainActivity, "Vault loaded",
                            android.widget.Toast.LENGTH_SHORT).show()
                    }
                },
                onLoadUsb = { usbRestoreLauncher.launch(arrayOf("application/octet-stream")) },
                onShowSshKey = { showSshKeyQr(Screen.SetupChoice) },
                onPickAuthSubkey = { lifecycleScope.launch { pickAuthSubkey() } },
                onEnrollYubikeySsh = { line, subkeyId -> enrollYubikeySsh(line, subkeyId) }
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
                        onExportQr = { encrypt ->
                            // Payload is passed in memory (recomputed from
                            // the item on each recomposition) — nothing is
                            // written to disk for a QR export. Encrypted =
                            // wrapped to all paired keys (Plan 2); plain
                            // keeps the legacy readable QR.
                            val devices = VaultSession.pairedDevices()
                            if (encrypt && devices.isNotEmpty()) {
                                lifecycleScope.launch {
                                    try {
                                        screen = Screen.QrftPayload(
                                            DeviceWrap.wrap(entryPayload(item), devices))
                                        saveToast("Paste encrypted to ${devices.size} key${if (devices.size == 1) "" else "s"}")
                                    } catch (e: Exception) {
                                        status = "Device-wrap failed: ${e.message}"
                                    }
                                }
                            } else {
                                screen = Screen.Qrft(item.itemUuid)
                            }
                        },
                        pairedDevices = VaultSession.pairedDevices(),
                        onSaveChanges = { edited ->
                            lifecycleScope.launch {
                                edited.modifyTime = nowSeconds()
                                val items = unlockedItems().map {
                                    if (it.itemUuid == edited.itemUuid) edited else it
                                }
                                status = when (val r = saveLoop(items)) {
                                    VaultSession.Result.Success -> "Saved (rev ${VaultSession.currentRev()})."
                                    else -> "Save: $r"
                                }
                            }
                        },
                        onEnrollTotp = { uri ->
                            lifecycleScope.launch {
                                item.totpUri = uri
                                item.modifyTime = nowSeconds()
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
                            item.modifyTime = nowSeconds()
                            when (val r = saveLoop(unlockedItems() + item)) {
                                VaultSession.Result.Success -> {
                                    // Back to the list in BOTH modes; the
                                    // toast says what reached where.
                                    screen = Screen.Search
                                    saveToast("Added ${item.displayName} — saved locally")
                                    status = "Added ${item.displayName}."
                                }
                                else -> {
                                    // Stay on the form so the entry isn't
                                    // lost; surface the failure as a toast
                                    // (the list page has no status line).
                                    android.widget.Toast.makeText(this@MainActivity,
                                        "Save failed: $r", android.widget.Toast.LENGTH_LONG).show()
                                }
                            }
                        }
                    }
                )
                is Screen.Qrft -> {
                    val item = currentDetailItem(s.itemUuid)
                    if (item == null) {
                        // The entry is gone (deleted/synced away): nothing to
                        // render — fall back to the search list.
                        screen = Screen.Search
                    } else QrftScreen(
                        payload = entryPayload(item),
                        onBack = { screen = Screen.Detail(item.itemUuid) }
                    )
                }
                is Screen.QrftPayload -> QrftScreen(
                    payload = s.payload,
                    onBack = { screen = sshKeyBackScreen }
                )
                Screen.ExportPick -> ExportPickScreen(
                    items = unlockedItems(),
                    onBack = { screen = Screen.Setup },
                    onExport = { picked ->
                        // With a paired paste device the export is encrypted
                        // to it (Plan 2); plain QRFT stays available.
                        val devices = VaultSession.pairedDevices()
                        if (devices.isEmpty()) {
                            screen = Screen.QrftPayload(pickedPayload(picked))
                        } else {
                            screen = Screen.ExportTarget(picked)
                        }
                    }
                )
                is Screen.ExportTarget -> ExportTargetPickScreen(
                    count = s.items.size,
                    devices = VaultSession.pairedDevices(),
                    onBack = { screen = Screen.ExportPick },
                    onExport = { targets ->
                        lifecycleScope.launch {
                            val payload = pickedPayload(s.items)
                            if (targets == null) {
                                screen = Screen.QrftPayload(payload)
                            } else {
                                try {
                                    screen = Screen.QrftPayload(DeviceWrap.wrap(payload, targets))
                                    saveToast("Paste encrypted to ${targets.size} key${if (targets.size == 1) "" else "s"}")
                                } catch (e: Exception) {
                                    status = "Device-wrap failed: ${e.message}"
                                    screen = Screen.ExportPick
                                }
                            }
                        }
                    }
                )
                Screen.QrftScan -> QrftScanScreen(
                    onPayload = { name, payload ->
                        Log.i(TAG, "QRFT received: $name")
                        lifecycleScope.launch { importQrftPayload(payload) }
                    },
                    onBack = { screen = Screen.Setup }
                )
                Screen.PairScan -> PairScanScreen(
                    onRecord = { raw ->
                        Log.i(TAG, "Pairing record captured")
                        lifecycleScope.launch {
                            val record = DeviceRecord.fromPayload(raw)
                            if (record != null) importPairRecord(record)
                            else {
                                screen = Screen.Setup
                                status = "Scanned QR was not a paste-device pairing record."
                            }
                        }
                    },
                    onBack = { screen = Screen.Setup }
                )
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
                    onResetRepo = {
                        lifecycleScope.launch {
                            status = when (val r = VaultSession.resetRepo()) {
                                VaultSession.Result.Success -> "Repo reset (fresh clone, state re-applied)."
                                else -> "Reset: $r"
                            }
                        }
                    },
                    onUsbSave = { usbSaveLauncher.launch("offlinepass-vault-rev${VaultSession.currentRev()}.gpg") },
                    onUsbRestore = { usbRestoreLauncher.launch(arrayOf("application/octet-stream")) },
                    onEnableAutofill = { requestAutofillService() },
                    screenLockOn = VaultSession.screenLockOn,
                    onScreenLockToggle = { on -> handleScreenLockToggle(on) },
                    onLock = { VaultSession.zero() },
                    onExportQrft = { screen = Screen.ExportPick },
                    onImportQrft = { cameraPermissionLauncher.launch(android.Manifest.permission.CAMERA) },
                    onPairDevice = { pairCameraLauncher.launch(android.Manifest.permission.CAMERA) },
                    onConnectRemote = { remote, pat ->
                        lifecycleScope.launch {
                            status = when (val r = VaultSession.connectRemote(remote, pat)) {
                                VaultSession.Result.Success -> {
                                    VaultSession.clearConnectDraft()
                                    "Remote connected — synced."
                                }
                                else -> r.toString()
                            }
                        }
                    },
                    onRotateSshKey = {
                        lifecycleScope.launch {
                            status = withContext(kotlinx.coroutines.Dispatchers.IO) {
                                runCatching {
                                    val m = com.offlinepass.app.crypto.SshKeyManager()
                                    m.removeKeyPair(); m.ensureKeyPair()
                                    "SSH key rotated — re-add the deploy key on GitHub with the new fingerprint."
                                }.getOrElse { "Rotation failed: ${it.message}" }
                            }
                        }
                    },
                    onRemoveYubikeySsh = {
                        VaultSession.clearYubikeySsh()
                        status = "YubiKey SSH enrollment removed (screenlock mode active)."
                    },
                    onShowSshKey = { showSshKeyQr(Screen.Setup) },
                    onEnrollYubikeySsh = { line, subkeyId -> enrollYubikeySsh(line, subkeyId) },
                    onPickAuthSubkey = {
                        lifecycleScope.launch { pickAuthSubkey() }
                    },
                    pairedDevices = VaultSession.pairedDevices(),
                    onShowDeviceQr = { device ->
                        // R2: the vault record IS the pairing backup — show
                        // it as a QRFT loop; the extension's scan window
                        // restores it (same key, same keyId, no re-pair).
                        val recordJson = org.json.JSONObject()
                            .put("type", "linuxpass-device")
                            .put("device", device.toJsonObject())
                            .toString()
                        screen = Screen.QrftPayload(recordJson)
                    },
                    onRemoveDevice = { keyId ->
                        lifecycleScope.launch {
                            if (VaultSession.stageRemoveDevice(keyId)) {
                                status = when (val r = saveLoop(unlockedItems())) {
                                    VaultSession.Result.Success -> {
                                        saveToast("Paste device removed")
                                        "Paste device $keyId removed."
                                    }
                                    else -> "Device removal: $r"
                                }
                            }
                        }
                    },
                    onForget = { VaultSession.forgetConfig(); screen = Screen.SetupChoice },
                    patSave = { VaultSession.savePat(it); status = "PAT stored (encrypted)." },
                    autofillEnabled = isAutofillEnabled(),
                    recipientIds = VaultSession.recipientKeyIds(),
                    onAddRecipient = { lifecycleScope.launch { pickRecipientsUntilDone() } },
                    onRemoveRecipient = { id ->
                        VaultSession.setRecipientKeyIds(VaultSession.recipientKeyIds() - id)
                        status = "Recipient removed."
                    },
                    signerLabel = VaultSession.signingKeyId()
                        ?.let { id -> "0x%016X".format(id) + (VaultSession.signingKeyUserId()?.let { u -> " ($u)" } ?: "") }
                        ?: "default (first recipient)",
                    onPickSigner = {
                        lifecycleScope.launch {
                            status = when (val r = VaultSession.pickSigningKey()) {
                                VaultSession.Result.Success -> "Signing key set."
                                else -> "Signer: $r"
                            }
                        }
                    },
                    onClearSigner = { VaultSession.clearSigningKey(); status = "Signer reset to default." },
                    deviceCredentialReady = VaultSession.isDeviceCredentialReady() == 0,
                    onEnrollScreenlock = {
                        lifecycleScope.launch {
                            status = runCatching {
                                com.offlinepass.app.crypto.KeystoreSigner.ensureKey()
                            }.fold(
                                onSuccess = {
                                    VaultSession.setCommitSigningMode(VaultSession.SIGNING_SCREENLOCK)
                                    "Screenlock signing enrolled (fp " +
                                        com.offlinepass.app.crypto.KeystoreSigner.publicKeyFingerprint() +
                                        ") — pubkey publishes on the next save."
                                },
                                onFailure = { "Keystore signer unavailable: ${it.message}" }
                            )
                        }
                    },
                    onUseOpenKeyChain = {
                        VaultSession.setCommitSigningMode(VaultSession.SIGNING_OPENKEYCHAIN)
                        status = "Commit signing: OpenKeyChain."
                    }
                )
            }
        }
    }

    /** Toggle handler: enabling first verifies the device has a biometric /
     * credential enrolled — none → redirect to enrollment; the user re-toggles
     * after enrolling. */
    private fun handleScreenLockToggle(on: Boolean) {
        if (!on) {
            VaultSession.setScreenLockRequired(false)
            status = "Screen lock gate off."
            return
        }
        when (VaultSession.isDeviceCredentialReady()) {
            androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS -> {
                VaultSession.setScreenLockRequired(true)
                status = "Screen lock gate ON — biometric/PIN asked before the key."
            }
            androidx.biometric.BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                try {
                    startActivity(
                        Intent(android.provider.Settings.ACTION_BIOMETRIC_ENROLL).apply {
                            putExtra(
                                android.provider.Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
                                    or androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
                            )
                        }
                    )
                    status = "Enroll a biometric/PIN, then toggle screen lock on."
                } catch (e: Exception) {
                    startActivity(Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS))
                    status = "Enroll a screen lock, then toggle screen lock on."
                }
            }
            else -> {
                status = "Biometrics unavailable on this device — gate not enabled."
            }
        }
    }

    private fun unlockedItems(): List<ProtonItem> =
        (VaultSession.state as? VaultSession.State.Unlocked)?.items ?: emptyList()

    private fun currentDetailItem(uuid: String): ProtonItem? =
        unlockedItems().firstOrNull { it.itemUuid == uuid }

    private fun nowSeconds(): Long = System.currentTimeMillis() / 1000

    /** Save toast: what persisted locally vs what reached the remote — the
     * same message works on airplane mode (local save + pending sync) and
     * online (local save + pushed). */
    private fun saveToast(base: String) {
        val msg = base + when (VaultSession.lastSaveRemoteState) {
            "synced" -> ", synced"
            "pending" -> " (offline — sync pending)"
            else -> "" // local-only mode: no remote exists
        }
        android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show()
    }

    /** JSON array of Proton item objects — what Import-from-QRFT (and the
     *  Proton export import path) parse back; the device-wrap envelopes it. */
    private fun pickedPayload(picked: List<ProtonItem>): String {
        val arr = org.json.JSONArray()
        picked.forEach { arr.put(it.toProtonJson()) }
        return arr.toString()
    }

    /** Pairing record captured (PairScan or a QRFT-framed fallback): stage
     *  it into the envelope and save. Re-scans with a re-wrapped seed
     *  update the record in place (R2). */
    private suspend fun importPairRecord(record: DeviceRecord) {
        when (VaultSession.stagePairedDevice(record)) {
            "unchanged" -> {
                screen = Screen.Setup
                status = "Key ${record.keyId} (${record.name}) already paired."
            }
            "added" -> savePairing(record, "Paired paste device", "Paired paste device")
            "updated" -> savePairing(record, "Updated paste device", "Paste device re-wrapped")
            else -> {
                screen = Screen.Setup
                status = "Unlock the vault before pairing a paste device."
            }
        }
    }

    /** Persist a staged pairing record (add or update): encrypt + commit. */
    private suspend fun savePairing(record: DeviceRecord, toastBase: String, statusBase: String) {
        screen = Screen.Setup
        status = when (val r = saveLoop(unlockedItems())) {
            VaultSession.Result.Success -> {
                saveToast("$toastBase ${record.name}")
                "$statusBase ${record.name} (key ${record.keyId})."
            }
            else -> "Pairing save: $r"
        }
        if (status.startsWith("Pairing save:")) {
            android.widget.Toast.makeText(this, status, android.widget.Toast.LENGTH_LONG).show()
        }
    }

    /** Import-from-QRFT: pairing records go to the devices list, everything
     *  else is parsed as a Proton JSON export (array, single item, or
     *  envelope), deduped against the local vault by itemUuid KEEPING THE
     *  LOCAL VERSION on conflict, then saved. */
    private suspend fun importQrftPayload(raw: String) {
        // Compatibility fallback: a QRFT-framed pairing record (the pair
        // page used to emit one) is handled by the pairing importer.
        DeviceRecord.fromPayload(raw)?.let { importPairRecord(it); return }
        val env = Envelope.parseImport(raw)
        if (env == null) {
            status = "QRFT payload did not parse as a Proton JSON export."
            android.widget.Toast.makeText(this, status, android.widget.Toast.LENGTH_LONG).show()
            return
        }
        val localByUuid = unlockedItems().associateBy { it.itemUuid }
        val fresh = env.items.filter { it.itemUuid !in localByUuid }
        val skipped = env.items.size - fresh.size
        if (fresh.isEmpty()) {
            screen = Screen.Search
            val msg = "Nothing new — $skipped entr${if (skipped == 1) "y" else "ies"} already present (local version kept)."
            android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show()
            return
        }
        screen = Screen.Search
        status = when (val r = saveLoop(unlockedItems() + fresh)) {
            VaultSession.Result.Success -> {
                saveToast("Imported ${fresh.size} new entr${if (fresh.size == 1) "y" else "ies"}" +
                    (if (skipped > 0) " ($skipped already present)" else ""))
                "Imported ${fresh.size} entries."
            }
            else -> "Import: $r"
        }
        if (status.startsWith("Import:")) {
            android.widget.Toast.makeText(this, status, android.widget.Toast.LENGTH_LONG).show()
        }
    }

    companion object {
        private const val TAG = "S1"
    }
}
