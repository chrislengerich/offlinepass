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
import com.offlinepass.app.ui.GetStartedScreen
import com.offlinepass.app.ui.UnlockScreen
import com.offlinepass.app.ui.LockGateScreen
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
import com.offlinepass.app.vault.SealedVault
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
    /** Locked-mode click-through: the one unsealed entry shown in the
     *  detail overlay. Null ⇒ the sealed search view renders. */
    private var sealedReveal by mutableStateOf<ProtonItem?>(null)
    /** An edit typed in a sealed detail that had to be flushed through a
     *  GPG unlock (stale seal); applied right after unlockLoop succeeds. */
    private var pendingSealedEdit by mutableStateOf<ProtonItem?>(null)
    /** The click's destination, deferred across a GPG unlock that ran from
     *  a sealed flow (stale/missing seal): the item view still opens. */
    private var afterUnlock: (suspend () -> Unit)? = null
    /** Entry gate: with the screenlock toggle on, opening the app (fresh
     *  start or after the idle timeout) requires the screenlock prompt
     *  BEFORE any content — sealed list included. */
    private var entryGateDone by mutableStateOf(false)
    /** The OpenPGP PIN request (YubiKit card signing): non-null = the
     *  dialog is up; call with the PIN, or null on cancel. */
    private var pinCallback by mutableStateOf<((String?) -> Unit)?>(null)

    // -- idle auto-lock (screenLockRequired governs it) -----------------------

    private var lastInteractionMs = android.os.SystemClock.elapsedRealtime()
    private var autoLockJob: kotlinx.coroutines.Job? = null
    private var pausedAtMs = 0L
    /** Entry-gate auto-prompt waits for this — a BiometricPrompt launched
     *  before the window is focusable is canceled before it shows. */
    private var hasWindowFocus by mutableStateOf(false)

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        hasWindowFocus = hasFocus
    }

    override fun onPause() {
        // The idle gap a backgrounding represents is measured from here
        // (onResume re-checks against the timeout).
        pausedAtMs = android.os.SystemClock.elapsedRealtime()
        super.onPause()
    }

    /** Any touch counts as activity — the idle timer restarts. */
    override fun dispatchTouchEvent(ev: android.view.MotionEvent): Boolean {
        lastInteractionMs = android.os.SystemClock.elapsedRealtime()
        rescheduleAutoLock()
        return super.dispatchTouchEvent(ev)
    }

    /** Runs the idle timer while the session is unlocked. Expiry zeroes the
     *  whole decrypted session (everything back to encrypted-at-rest) and
     *  returns to the sealed list / unlock screen. Deferred while an
     *  OpenKeyChain interaction is mid-flight — zeroing mid-unlock would
     *  let the in-flight result re-lock the vault right after. */
    private fun rescheduleAutoLock() {
        autoLockJob?.cancel()
        autoLockJob = null
        // The idle clock restarts at every SCHEDULE — a long OpenKeyChain
        // interaction (or a clone) between the last touch and a successful
        // unlock/promotion must not insta-lock the fresh session.
        lastInteractionMs = android.os.SystemClock.elapsedRealtime()
        if (!VaultSession.screenLockRequired()) return
        val minutes = VaultSession.autoLockMinutes()
        if (minutes <= 0) return
        if (VaultSession.state !is VaultSession.State.Unlocked) return
        val timeoutMs = minutes * 60_000L
        autoLockJob = lifecycleScope.launch {
            while (true) {
                val idleMs = android.os.SystemClock.elapsedRealtime() - lastInteractionMs
                val remaining = timeoutMs - idleMs
                if (remaining > 0) { kotlinx.coroutines.delay(remaining); continue }
                // Idle past the timeout — but not during a crypto interaction.
                if (VaultSession.busy != null) { kotlinx.coroutines.delay(30_000); continue }
                lockNow("Locked after inactivity.")
                return@launch
            }
        }
    }

    /** Single re-lock path: zero the session + clear every sealed-flow
     *  leftover + return to the default screen. Also re-arms the entry
     *  gate: the next foreground entry needs the screenlock prompt again. */
    private fun lockNow(statusMsg: String) {
        VaultSession.zero()
        sealedReveal = null
        pendingSealedEdit = null
        afterUnlock = null
        entryGateDone = false
        screen = Screen.Search
        status = statusMsg
        rescheduleAutoLock()
    }

    /** The entry gate prompt (fingerprint/PIN). Satisfying it once per
     *  foreground session opens the sealed list; the timeout re-arms it. */
    private suspend fun entryGate() {
        if (entryGateDone) return
        val ok = promptGate("Unlock offlinepass", "Screen lock required to view passwords")
        if (ok) {
            entryGateDone = true
            lastInteractionMs = android.os.SystemClock.elapsedRealtime()
            rescheduleAutoLock()
        } else {
            status = "Screen lock required to continue."
        }
    }
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
        // The screenlock prompts when the vault requires it OR when the
        // at-rest seal is on: the seal's keystore ops need the auth window,
        // and the prompt IS the screenlock's promised interaction.
        if (!VaultSession.screenLockRequired() &&
            !VaultSession.screenlockUnlockEnabled()
        ) return true
        return promptGate("Unlock offlinepass", "Device lock required before the security key")
    }

    /** Platform BiometricPrompt (API 28+): no FragmentActivity needed, so
     *  the Activity-Result registry keeps working. A success opens the
     *  keystore validity window for ALL time-based keys the authenticated
     *  authenticator satisfies (the seal key, the signing key, the SSH key
     *  share the 60s window). strongOrCredential: the framework-enforced
     *  authenticator set (BIOMETRIC_STRONG | DEVICE_CREDENTIAL) — matches
     *  the seal key's binding exactly, so any prompt success opens it. */
    private suspend fun promptGate(title: String, subtitle: String, strongOrCredential: Boolean = false): Boolean =
        com.offlinepass.app.crypto.ScreenlockGate.promptGate(this, title, subtitle, strongOrCredential)

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
                    // A sealed-detail edit that waited for the key unlock.
                    pendingSealedEdit?.let { edited ->
                        pendingSealedEdit = null
                        edited.modifyTime = nowSeconds()
                        val items = unlockedItems().map {
                            if (it.itemUuid == edited.itemUuid) edited else it
                        }
                        when (saveLoop(items)) {
                            VaultSession.Result.Success -> {
                                saveToast("Saved (after key unlock)")
                                status = "Saved (rev ${VaultSession.currentRev()})."
                                screen = Screen.Detail(edited.itemUuid)
                            }
                            else -> status = "Save failed after the key unlock — edit again in the list."
                        }
                    }
                    sealedReveal = null
                    entryGateDone = true
                    rescheduleAutoLock()
                    afterUnlock?.let { action ->
                        afterUnlock = null
                        action()
                    }
                    return
                }
                is VaultSession.Result.Interaction -> { launchInteraction(r.pendingIntent); awaitInteraction() }
                is VaultSession.Result.Error -> {
                    if (!File(VaultSession.vaultFilePath()).exists()) {
                        // No vault on this device: setup screen, not an error.
                        screen = Screen.SetupChoice
                        status = "No vault on this device — create or import one below."
                    } else status = r.message
                    // A declined/failed unlock must not run a stale action
                    // on some later, unrelated unlock.
                    afterUnlock = null
                    pendingSealedEdit = null
                    return
                }
                is VaultSession.Result.NeedsKeyDecrypt, is VaultSession.Result.Revealed ->
                    return // sealed-mode results never reach the GPG unlock loop
            }
        }
        status = "Unlock aborted after interaction retry."
    }

    private suspend fun saveLoop(
        items: List<ProtonItem>,
        editedUuid: String? = null
    ): VaultSession.Result {
        var guard = 0
        while (guard++ < 2) {
            when (val r = VaultSession.save(items, editedUuid)) {
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
                is VaultSession.Result.NeedsKeyDecrypt, is VaultSession.Result.Revealed ->
                    return // unreachable from the recipient picker
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
        // Backgrounded past the auto-lock timeout? Lock before anything
        // else touches the session.
        if (pausedAtMs > 0) {
            val gapMs = android.os.SystemClock.elapsedRealtime() - pausedAtMs
            pausedAtMs = 0L
            if (VaultSession.state is VaultSession.State.Unlocked &&
                VaultSession.screenLockRequired() &&
                VaultSession.autoLockMinutes() > 0 &&
                gapMs >= VaultSession.autoLockMinutes() * 60_000L
            ) {
                lockNow("Locked after inactivity.")
            }
        }
        lastInteractionMs = android.os.SystemClock.elapsedRealtime()
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
        // Sealed-cache unseals open the SAME window with their own prompt
        // (the reveal on click-through; the save reuses a still-open one).
        // Framework-enforced authenticator set matching the seal key.
        VaultSession.sealGate = { title, subtitle ->
            promptGate(title, subtitle, strongOrCredential = true)
        }
        // YubiKit card signing: the OpenPGP applet's user PIN, asked once
        // per identity session and never stored.
        VaultSession.openPgpPinPrompt = {
            kotlinx.coroutines.suspendCancellableCoroutine { cont ->
                pinCallback = { value ->
                    pinCallback = null
                    cont.resume(value?.toCharArray())
                }
            }
        }
        // First push to an EMPTY remote: confirm before creating the remote
        // main branch.
        VaultSession.firstPushGate = {
            withContext(kotlinx.coroutines.Dispatchers.Main) { firstPushConfirm() }
        }
        // The active SSH identity: screenlock keystore key, or the YubiKey
        // card path (YubiKit, the SIGNATURE slot — no OpenKeyChain).
        VaultSession.sshIdentityProvider = {
            when (VaultSession.sshSyncMode()) {
                VaultSession.SSH_SYNC_YUBIKEY -> VaultSession.buildSshIdentity()
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
                // The QR enrolls the SCREENLOCK key for SIGNING/AT-REST —
                // it is NOT an auth key (deprecated): the SSH auth mode is
                // untouched.
                @Suppress("DEPRECATION")
                VaultSession.setSshSyncMode(VaultSession.sshSyncMode())
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

    /** The YubiKey SSH enrollment's key selection: OpenKeyChain's OWN
     *  picker (SELECT_SIGN_KEY_ID) — an explicit, keyed choice. The
     *  earlier keyless-sign variant silently used OKK's DEFAULT key
     *  (whatever was granted first), which is how a software key got
     *  enrolled instead of the YubiKey's. */
    private suspend fun pickAuthSubkey() {
        val client = com.offlinepass.app.crypto.OpenPgpClient(applicationContext)
        var reqData: Intent? = null
        var guard = 0
        while (guard++ < 3) {
            when (val r = client.pickSignKey(reqData)) {
                is com.offlinepass.app.crypto.OpenPgpClient.SignKey.Picked -> {
                    android.util.Log.i("YubiKeySsh", "picked key id: 0x%016X".format(r.keyId))
                    fetchAndPopulateSshLine(r.keyId)
                    return
                }
                is com.offlinepass.app.crypto.OpenPgpClient.SignKey.NeedsInteraction -> {
                    reqData = com.offlinepass.app.vault.VaultSession.interactionHandler
                        ?.invoke(r.pendingIntent) ?: return
                }
                is com.offlinepass.app.crypto.OpenPgpClient.SignKey.Error -> {
                    status = "Key selection failed in OpenKeyChain."
                    return
                }
            }
        }
        status = "Key selection aborted after retries."
    }

    /** Fetches the picked subkey's public key material from OpenKeyChain
     *  (looping the key-access interaction like every other API call) and
     *  converts it to the OpenSSH line draft — the sync signs with the key
     *  the picker resolved, so the line must come from the same key id.
     *  The picker can hand back the KEY's primary id even when the signing
     *  secret lives in a subkey — the material resolves which subkey can
     *  actually sign (key flags), and THAT id + line are stored. */
    private suspend fun fetchAndPopulateSshLine(keyId: Long) {
        // The OpenSSH line: derived from the key material OpenKeyChain
        // returns (the same proven fetch that materializes the recipients'
        // keys) — no paste needed.
        val fetchClient = com.offlinepass.app.crypto.OpenPgpClient(applicationContext)
        var fetchReq: Intent? = null
        var fetchGuard = 0
        var line: String? = null
        var signedWith = keyId
        while (fetchGuard++ < 3 && line == null) {
            when (val fr = fetchClient.fetchPublicKeyArmored(keyId, fetchReq)) {
                is com.offlinepass.app.crypto.OpenPgpClient.PublicKey.Success -> {
                    // The SIG slot signs with the SIGN-capable subkey —
                    // the S subkey already enrolled on GitHub. (The AUT
                    // slot needs a 512-byte challenge and fails 0x6581 on
                    // this transport; see YubiKitSshAuth's header note.)
                    val resolved = runCatching {
                        com.offlinepass.app.crypto.PgpSshBridge
                            .signingSubkeyKeyId(fr.armored, keyId)
                    }.getOrElse {
                        Log.w(TAG, "signing-subkey resolution: ${it.message}")
                        keyId
                    } ?: keyId
                    signedWith = resolved
                    if (resolved != keyId) {
                        VaultSession.pickedAuthSubkeyId = resolved
                        VaultSession.loadSubkeyIdState.value = "%016X".format(resolved)
                        status = ("Picker returned 0x%016X — resolves to the " +
                            "subkey 0x%016X.").format(keyId, resolved)
                    }
                    line = runCatching {
                        com.offlinepass.app.crypto.PgpSshBridge.sshLineForKeyMaterial(
                            fr.armored, resolved, "offlinepass-yubikey")
                    }.getOrElse {
                        Log.w(TAG, "key material -> SSH line: ${it.message}")
                        null
                    }
                }
                is com.offlinepass.app.crypto.OpenPgpClient.PublicKey.UserInteraction -> {
                    launchInteraction(fr.pendingIntent)
                    fetchReq = awaitInteraction()
                }
                else -> break
            }
        }
        if (line != null) {
            VaultSession.yubikeySshLineDraft = line
            VaultSession.loadSshLineState.value = line
            VaultSession.loadSubkeyIdState.value = "%016X".format(signedWith)
            // The PICK is the enrollment: persist immediately — the load-
            // screen chip previously evaporated at the load (the identity
            // read empty prefs) and the self-test saw nothing.
            VaultSession.setYubikeySsh(line, "%016X".format(signedWith))
            status = ("Auth subkey 0x%016X — OpenSSH line populated (enrolled).")
                .format(signedWith)
        } else {
            status = ("Auth subkey 0x%016X — the OpenSSH line " +
                "could not be fetched; paste it from the desktop " +
                "(gpg --export-ssh-key).").format(keyId)
        }
    }

    /** Asks ONCE per install for the battery-optimization exemption: this
     *  ROM kills backgrounded apps, and OpenKeyChain's decrypt prompt
     *  backgrounds us mid-load. A denied user can still grant via
     *  Settings → Apps → Battery. */
    private fun maybeRequestBatteryExemption() {
        val pm = getSystemService(android.os.PowerManager::class.java)
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        if (VaultSession.batteryExemptionAsked()) return
        VaultSession.setBatteryExemptionAsked()
        runCatching {
            startActivity(android.content.Intent(
                android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                android.net.Uri.parse("package:$packageName")))
            android.widget.Toast.makeText(this,
                "Allow Unrestricted — the ROM kills offlinepass while " +
                    "OpenKeyChain decrypts.", android.widget.Toast.LENGTH_LONG).show()
        }
    }

    /** The USB permission gate for the card ops: when a YubiKey is
     *  attached but not yet permitted, pop the system dialog and await
     *  the grant. Idempotent — a no-op when already granted. */
    private suspend fun ensureUsbPermission(): Boolean {
        if (com.offlinepass.app.crypto.YubiKitSshAuth.findDevice(applicationContext) == null) {
            return false // nothing attached; the caller's error names it
        }
        if (com.offlinepass.app.crypto.YubiKitSshAuth.deviceReady(applicationContext)) {
            return true
        }
        return com.offlinepass.app.crypto.YubiKitSshAuth.requestPermission(applicationContext)
    }

    /** Enrolls the card's SSH key from github.com/<user>.keys — the
     *  orchestration lives in GithubKeysEnrollment.enroll (unit-tested
     *  with stubs); this wrapper supplies the real dependencies and the
     *  status surface. */
    private fun enrollFromGithubKeys() {
        val remote = VaultSession.loadRemoteState.value
        // The USB permission FIRST: the system dialog pops immediately on
        // click (before the network fetch) when the card is attached but
        // not yet granted.
        lifecycleScope.launch {
            val granted = ensureUsbPermission()
            if (!granted && com.offlinepass.app.crypto.YubiKitSshAuth
                    .findDevice(applicationContext) != null
            ) {
                status = "USB permission denied — tap Enroll again to grant."
                return@launch
            }
            status = com.offlinepass.app.crypto.GithubKeysEnrollment.enroll(
                remote,
                fetchLines = { user ->
                    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        com.offlinepass.app.crypto.GithubKeysEnrollment.fetchKeyLines(user)
                    }
                },
                cardIdentity = {
                    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        ensureUsbPermission()
                        val id = com.offlinepass.app.crypto.YubiKitSshAuth
                            .signingKeyIdentity(applicationContext)
                        id.keyId to id.fingerprint
                    }
                },
                cardSign = { nonce ->
                    kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                        ensureUsbPermission()
                        val pin = VaultSession.yubikeyPin()
                            ?: throw java.io.IOException("OpenPGP PIN cancelled")
                        val digestInfo = com.offlinepass.app.crypto.SshRsaPkcs1
                            .digestInfo("SHA-256", nonce)
                        val sig = VaultSession.withTouchPrompt {
                            com.offlinepass.app.crypto.YubiKitSshAuth.sign(
                                applicationContext, pin, digestInfo)
                        }
                        VaultSession.yubikeyPinRemember(pin)  // cache-on-success
                        sig
                    }
                },
                enroll = { line, keyId ->
                    val idHex = "%016X".format(keyId)
                    VaultSession.setYubikeySsh(line, idHex)
                    VaultSession.loadSshLineState.value = line
                    VaultSession.loadSubkeyIdState.value = idHex
                })
        }
    }

    /** Persists the YubiKey SSH enrollment (works pre-load: prefs only). */
    private fun enrollYubikeySsh(sshLine: String, subkeyId: String) {
        // Unsigned 64-bit hex: ids with the high bit set are legal (see the
        // reader in VaultSession — the base-10/toLongOrNull parse was the
        // root cause of the silent "Auth cancelled").
        val keyId = runCatching { java.lang.Long.parseUnsignedLong(subkeyId, 16) }.getOrNull()
        if (subkeyId.length != 16 || keyId == null) {
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
            sealedReveal = null
            pendingSealedEdit = null
            afterUnlock = null
            entryGateDone = false
            screen = Screen.Search
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        VaultSession.init(applicationContext)
        SealedVault.init(applicationContext)
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
        // The QRFT payload screen has no session dependency (the payload is
        // passed in memory) — route it in EVERY state: the pre-unlock "Create
        // & show public key" flow needs it while the vault is still
        // NoConfig/Locked, and the Unlocked branch's copy is redundant.
        if (screen is Screen.QrftPayload) {
            QrftScreen(
                payload = (screen as Screen.QrftPayload).payload,
                onBack = { screen = sshKeyBackScreen }
            )
            return
        }
        // The YubiKey touch prompt: every state — the card waits for a
        // touch during the auth/commit/enrollment ops; the dialog shows
        // and self-dismisses when the op completes (or fails).
        if (VaultSession.touchPrompt) {
            androidx.compose.material3.AlertDialog(
                onDismissRequest = { /* the ops dismiss via the state */ },
                title = { androidx.compose.material3.Text("🔐 Touch your YubiKey") },
                text = {
                    androidx.compose.material3.Text(
                        "The key is waiting — touch it (the LED blinks).",
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)
                },
                confirmButton = {})
        }
        val pinCallbackNow = pinCallback
        if (pinCallbackNow != null) {
            com.offlinepass.app.ui.PinPromptDialog(pinCallbackNow)
        }
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
                    maybeRequestBatteryExemption()
                    lifecycleScope.launch {
                        // Persist the load screen's chosen sync-auth BEFORE
                        // the transport: the chip choice lived only in the
                        // drafts — the YubiKey identity reads the ENROLLED
                        // prefs (subkey id + line), which this flow never
                        // wrote (a picked subkey evaporated at the load:
                        // "Auth cancelled", no OpenKeyChain prompt, and the
                        // self-test saw nothing).
                        when (VaultSession.loadAuthState.value) {
                            VaultSession.SSH_SYNC_YUBIKEY -> {
                                val line = VaultSession.loadSshLineState.value
                                val sub = VaultSession.loadSubkeyIdState.value
                                if (line.contains(" ") && sub.length == 16) {
                                    VaultSession.setYubikeySsh(line, sub)
                                } else {
                                    status = "YubiKey SSH enrollment incomplete — " +
                                        "choose the key in OpenKeyChain first."
                                    return@launch
                                }
                            }
                        }
                        // The YubiKit backend needs the USB permission for
                        // the YubiKey — request it when the card is attached
                        // but not yet granted.
                        if (VaultSession.sshSyncMode() == VaultSession.SSH_SYNC_YUBIKEY &&
                            com.offlinepass.app.crypto.YubiKitSshAuth.findDevice(applicationContext) != null
                        ) {
                            com.offlinepass.app.crypto.YubiKitSshAuth.requestPermission(applicationContext)
                        }
                        // Bootstrap pulls authenticate with the security
                        // key only (the card signs the SSH handshake — the
                        // PIN + the touch ARE the gate; no screenlock key at
                        // bootstrap).
                        val open = VaultSession.gitOpenOnly()  // explicit network step
                        if (open is VaultSession.Result.Error) {
                            // A failed load must NOT adopt a phantom empty
                            // vault or leave an unlinked repo behind: undo
                            // the REMOTE config attempt and stay on Setup to
                            // retry. The YubiKey enrollment, the SSH sync
                            // mode, and the other durable settings SURVIVE —
                            // forgetConfig() here used to wipe those too,
                            // silently destroying the enrollment.
                            VaultSession.forgetRemoteConfig()
                            File(VaultSession.gitRootPath()).deleteRecursively()
                            status = "Load failed: ${open.message} — fix the remote/PAT and retry."
                            android.widget.Toast.makeText(this@MainActivity,
                                "Load failed — nothing was changed", android.widget.Toast.LENGTH_LONG).show()
                            return@launch
                        }
                        // The loaded repo carries its recipients
                        // (keys/<keyid>.public.asc) — seed the save targets.
                        VaultSession.loadPhase("Repository fetched — decrypting…")
                        VaultSession.seedRecipientsFromRepo()
                        // The local signing role: the screenlock stays the
                        // signer when enrolled; otherwise the security key.
                        VaultSession.resolveCommitSigningModeAfterLoad()
                        unlockLoop()
                        // The post-load checklist: the steps 1-2 render as
                        // done; step 3 = the (skippable) screenlock enrollment.
                        if (screen == Screen.Search) screen = Screen.GetStarted
                        // The toast must not lie: unlockLoop reports its own
                        // failure via status (and a failed load leaves the
                        // session Locked).
                        if (VaultSession.state is VaultSession.State.Unlocked) {
                            android.widget.Toast.makeText(this@MainActivity, "Vault loaded",
                                android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                },
                onLoadUsb = { usbRestoreLauncher.launch(arrayOf("application/octet-stream")) },
                onEnrollFromGithubKeys = { enrollFromGithubKeys() },
                onSshSelfTest = {
                    lifecycleScope.launch {
                        val v = VaultSession.sshAuthSelfTest { status = it }
                        status = (if (v.ok) "✅ SSH self-test OK — " else "❌ SSH self-test FAILED — ") + v.detail
                    }
                },
                onEnrollYubikeySsh = { line, subkeyId -> enrollYubikeySsh(line, subkeyId) }
            )
            VaultSession.State.Locked -> when {
                // Entry gate first: screenlock toggle on → the prompt is
                // required before ANY content (fresh start or post-timeout).
                VaultSession.screenLockRequired() && !entryGateDone &&
                        VaultSession.screenlockUnlockEnabled() &&
                        VaultSession.sealedManifestItems().isNotEmpty() -> {
                    androidx.compose.runtime.LaunchedEffect(Unit) {
                        // Launching a BiometricPrompt before the window is
                        // focusable gets it canceled before it ever shows
                        // (error 5). Wait for real window focus first.
                        while (!hasWindowFocus) kotlinx.coroutines.delay(100)
                        kotlinx.coroutines.delay(200)
                        entryGate()
                    }
                    LockGateScreen(
                        status = status,
                        busy = VaultSession.busy,
                        // The gate's honest label: the sealed manifest when
                        // present (the screenlock unlocks); otherwise the
                        // security-key fallback (the cache empty/stale).
                        sealedAvailable = VaultSession.screenlockUnlockEnabled() &&
                            VaultSession.sealedManifestItems().isNotEmpty(),
                        onUnlock = { lifecycleScope.launch { entryGate() } }
                    )
                }
                // Sealed-mode click-through: the one revealed entry's detail.
                // Editing/saving rides the promotion + existing signing gates.
                sealedReveal != null -> EntryDetailScreen(
                    item = sealedReveal!!,
                    status = status,
                    busy = VaultSession.busy,
                    pairedDevices = VaultSession.sealedPairedDevices(),
                    onBack = { sealedReveal = null; status = "" },
                    onExportQr = { encrypt ->
                        lifecycleScope.launch {
                            val item = sealedReveal ?: return@launch
                            when (val r = VaultSession.promoteSealedSession()) {
                                VaultSession.Result.Success -> {
                                    sealedReveal = null
                                    exportQr(item, encrypt)
                                }
                                is VaultSession.Result.NeedsKeyDecrypt -> {
                                    afterUnlock = { exportQr(item, encrypt) }
                                    unlockLoop()
                                }
                                is VaultSession.Result.Error -> sealedToast(r.message)
                                else -> {}
                            }
                        }
                    },
                    onSaveChanges = { edited ->
                        lifecycleScope.launch {
                            when (val r = VaultSession.saveSealed(edited)) {
                                VaultSession.Result.Success -> {
                                    sealedReveal = null
                                    screen = Screen.Search
                                    saveToast("Saved")
                                    status = "Saved (rev ${VaultSession.currentRev()})."
                                }
                                is VaultSession.Result.NeedsKeyDecrypt -> {
                                    pendingSealedEdit = edited
                                    unlockLoop()
                                }
                                is VaultSession.Result.Error -> sealedToast(r.message)
                                else -> {}
                            }
                        }
                    },
                    onEnrollTotp = { secret ->
                        lifecycleScope.launch {
                            val base = sealedReveal ?: return@launch
                            when (val r = VaultSession.saveSealed(
                                base.copy(totpUri = secret, modifyTime = nowSeconds()))) {
                                VaultSession.Result.Success -> {
                                    sealedReveal = null
                                    screen = Screen.Search
                                    saveToast("TOTP enrolled")
                                    status = "TOTP enrolled (rev ${VaultSession.currentRev()})."
                                }
                                is VaultSession.Result.NeedsKeyDecrypt -> {
                                    pendingSealedEdit =
                                        base.copy(totpUri = secret, modifyTime = nowSeconds())
                                    unlockLoop()
                                }
                                is VaultSession.Result.Error -> sealedToast(r.message)
                                else -> {}
                            }
                        }
                    },
                    onDelete = {
                        lifecycleScope.launch {
                            val item = sealedReveal ?: return@launch
                            when (val r = VaultSession.promoteSealedSession()) {
                                VaultSession.Result.Success -> {
                                    sealedReveal = null
                                    when (val r = VaultSession.delete(item)) {
                                        VaultSession.Result.Success -> {
                                            screen = Screen.Search
                                            saveToast("Deleted")
                                            status = "Deleted."
                                        }
                                        is VaultSession.Result.Error -> sealedToast(r.message)
                                        else -> {}
                                    }
                                }
                                is VaultSession.Result.NeedsKeyDecrypt -> {
                                    afterUnlock = {
                                        when (val dr = VaultSession.delete(item)) {
                                            VaultSession.Result.Success -> {
                                                screen = Screen.Search
                                                saveToast("Deleted")
                                                status = "Deleted."
                                            }
                                            is VaultSession.Result.Error -> sealedToast(dr.message)
                                            else -> {}
                                        }
                                    }
                                    unlockLoop()
                                }
                                is VaultSession.Result.Error -> sealedToast(r.message)
                                else -> {}
                            }
                        }
                    }
                )
                // Sealed-mode default view: the SAME search/list, backed by
                // the manifest (names/usernames/URLs). Clicks gate + unseal.
                // No extra buttons: search + item reveal is the whole flow;
                // Add/Setup promote on tap, stale seals fall back to the key.
                VaultSession.screenlockUnlockEnabled() &&
                        VaultSession.sealedManifestItems().isNotEmpty() -> SearchScreen(
                    items = VaultSession.sealedManifestItems(),
                    busy = VaultSession.busy,
                    query = searchQuery,
                    onQueryChange = { searchQuery = it },
                    onOpen = { stub ->
                        lifecycleScope.launch {
                            when (val r = VaultSession.revealSealed(
                                stub.itemUuid, stub.displayName)) {
                                is VaultSession.Result.Revealed -> {
                                    sealedReveal = r.item
                                    status = ""
                                }
                                is VaultSession.Result.NeedsKeyDecrypt -> {
                                    val uuid = stub.itemUuid
                                    afterUnlock = { screen = Screen.Detail(uuid) }
                                    unlockLoop()
                                }
                                is VaultSession.Result.Error -> sealedToast(r.message)
                                else -> {}
                            }
                        }
                    },
                    onAdd = { lifecycleScope.launch { promoteOrUnlock(Screen.AddEntry) } },
                    onSetup = { lifecycleScope.launch { promoteOrUnlock(Screen.Setup) } }
                )
                // Legacy locked screen (toggle off, or no seal yet).
                else -> UnlockScreen(
                    status = status,
                    busy = VaultSession.busy,
                    onUnlock = { lifecycleScope.launch { unlockLoop() } }
                )
            }
            is VaultSession.State.Unlocked -> when (val s = screen) {
                // QrftPayload is handled at the top of AppRouter (every state)
                // and never reaches this branch; the explicit branch keeps the
                // when exhaustive.
                is Screen.QrftPayload -> {}
                Screen.SetupChoice, Screen.Search -> SearchScreen(
                    items = unlockedItems(),
                    busy = VaultSession.busy,
                    query = searchQuery,
                    onQueryChange = { searchQuery = it },
                    // The stub model: the click = the SAME screenlock gate +
                    // per-item unseal the sealed mode uses. A stale seal
                    // falls back to the key unlock, then the auto-reveal.
                    onOpen = { item ->
                        if (VaultSession.screenlockUnlockEnabled() &&
                            com.offlinepass.app.vault.SealedVault.hasCache()
                        ) {
                            lifecycleScope.launch {
                                when (val r = VaultSession.revealSealed(
                                    item.itemUuid, item.displayName)) {
                                    is VaultSession.Result.Revealed -> {
                                        sealedReveal = r.item
                                        status = ""
                                    }
                                    is VaultSession.Result.NeedsKeyDecrypt -> {
                                        val uuid = item.itemUuid
                                        afterUnlock = {
                                            lifecycleScope.launch {
                                                when (val rr = VaultSession.revealSealed(
                                                    uuid, item.displayName)) {
                                                    is VaultSession.Result.Revealed -> {
                                                        sealedReveal = rr.item
                                                        screen = Screen.Detail(uuid)
                                                    }
                                                    else -> screen = Screen.Search
                                                }
                                            }
                                        }
                                        unlockLoop()
                                    }
                                    is VaultSession.Result.Error -> sealedToast(r.message)
                                    else -> {}
                                }
                            }
                        } else screen = Screen.Detail(item.itemUuid)
                    },
                    onAdd = { screen = Screen.AddEntry },
                    onSetup = { screen = Screen.Setup }
                )
                is Screen.Detail -> {
                    val item = currentDetailItem(s.itemUuid)
                    if (item == null) {
                        screen = Screen.Search
                    } else if (VaultSession.screenlockUnlockEnabled() && !item.hasSecrets()) {
                        // THE STUB MODEL: the back-nav/deep-link detail = a
                        // stub — the unseal via the reveal gate BEFORE any
                        // render/export (a stub export = empty secrets).
                        var revealedItem by androidx.compose.runtime.remember(s.itemUuid) {
                            androidx.compose.runtime.mutableStateOf<ProtonItem?>(null)
                        }
                        androidx.compose.runtime.LaunchedEffect(s.itemUuid) {
                            when (val r = VaultSession.revealSealed(s.itemUuid, item.displayName)) {
                                is VaultSession.Result.Revealed -> revealedItem = r.item
                                is VaultSession.Result.NeedsKeyDecrypt -> {
                                    afterUnlock = { screen = Screen.Search }
                                    unlockLoop()
                                }
                                is VaultSession.Result.Error -> {
                                    sealedToast(r.message)
                                    screen = Screen.Search
                                }
                                else -> {}
                            }
                        }
                        if (revealedItem == null) {
                            androidx.compose.material3.Text(
                                "Unlocking the item (the screen lock)…",
                                style = androidx.compose.material3.MaterialTheme.typography.bodyMedium)
                        } else EntryDetailScreen(
                            item = revealedItem!!,
                            status = status,
                            busy = VaultSession.busy,
                            onBack = { screen = Screen.Search },
                            onExportQr = { encrypt -> exportQr(revealedItem!!, encrypt) },
                            pairedDevices = VaultSession.pairedDevices(),
                            onSaveChanges = { edited ->
                                lifecycleScope.launch {
                                    edited.modifyTime = nowSeconds()
                                    val items = unlockedItems().map {
                                        if (it.itemUuid == edited.itemUuid) edited else it
                                    }
                                    status = when (val r = saveLoop(items, edited.itemUuid)) {
                                        VaultSession.Result.Success -> "Saved (rev ${VaultSession.currentRev()})."
                                        else -> "Save: $r"
                                    }
                                }
                            },
                            onEnrollTotp = { uri ->
                                lifecycleScope.launch {
                                    val mutated = revealedItem!!
                                    mutated.totpUri = uri
                                    mutated.modifyTime = nowSeconds()
                                    val items = unlockedItems().map {
                                        if (it.itemUuid == mutated.itemUuid) mutated else it
                                    }
                                    status = when (val r = saveLoop(items, mutated.itemUuid)) {
                                        VaultSession.Result.Success -> "TOTP enrolled."
                                        else -> "Save: $r"
                                    }
                                }
                            },
                            onDelete = {
                                lifecycleScope.launch {
                                    status = when (val r = VaultSession.delete(revealedItem!!)) {
                                        VaultSession.Result.Success -> { screen = Screen.Search; "Deleted (tombstoned)." }
                                        else -> "Delete: $r"
                                    }
                                }
                            }
                        )
                    } else EntryDetailScreen(
                        item = item,
                        status = status,
                        busy = VaultSession.busy,
                        onBack = { screen = Screen.Search },
                        onExportQr = { encrypt -> exportQr(item, encrypt) },
                        pairedDevices = VaultSession.pairedDevices(),
                        onSaveChanges = { edited ->
                            lifecycleScope.launch {
                                edited.modifyTime = nowSeconds()
                                val items = unlockedItems().map {
                                    if (it.itemUuid == edited.itemUuid) edited else it
                                }
                                status = when (val r = saveLoop(items, edited.itemUuid)) {
                                    VaultSession.Result.Success -> "Saved (rev ${VaultSession.currentRev()})."
                                    else -> "Save: $r"
                                }
                            }
                        },
                        onEnrollTotp = { uri ->
                            lifecycleScope.launch {
                                item.totpUri = uri
                                item.modifyTime = nowSeconds()
                                // The stub mode: the mutated revealed item
                                // replaces its stub BY UUID + the edited
                                // uuid rides the save (the apply-diff would
                                // otherwise keep the sealed base and drop
                                // the TOTP).
                                val items = unlockedItems().map {
                                    if (it.itemUuid == item.itemUuid) item else it
                                }
                                status = when (val r = saveLoop(items, item.itemUuid)) {
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
                            // The new item's uuid rides the save: a
                            // secrets-less entry (the URLs only) must append,
                            // not fall to the stub-apply-diff's base-win.
                            when (val r = saveLoop(unlockedItems() + item, item.itemUuid)) {
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
                // QrftPayload is routed at the top of AppRouter (every state).
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
                Screen.GetStarted -> GetStartedScreen(
                    status = status,
                    busy = VaultSession.busy,
                    remoteAttached = VaultSession.config()?.remoteUrl != null,
                    yubikeyEnrolled = VaultSession.yubikeySshLine() != null,
                    screenlockEnrolled = VaultSession.commitSigningMode() ==
                        VaultSession.SIGNING_SCREENLOCK,
                    okkInstalled = runCatching {
                        packageManager.getPackageInfo(
                            com.offlinepass.app.crypto.OpenPgpClient.OPENKEYCHAIN_PACKAGE, 0)
                    }.isSuccess,
                    onEnrollFromGithubKeys = { enrollFromGithubKeys() },
                    onConnectAndSync = { remote ->
                        lifecycleScope.launch {
                            status = when (val r = VaultSession.connectRemote(remote, "")) {
                                VaultSession.Result.Success -> "Remote connected — synced."
                                else -> r.toString()
                            }
                        }
                    },
                    onEnrollScreenlock = {
                        lifecycleScope.launch {
                            status = VaultSession.enrollScreenlockSigning(this@MainActivity)
                        }
                    },
                    onImportToOkk = {
                        lifecycleScope.launch {
                            status = VaultSession.openOkkImportFromRepo(this@MainActivity)
                        }
                    },
                    onShowSshKey = { showSshKeyQr(Screen.GetStarted) },
                    onDone = { screen = Screen.Search })
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
                    autoLockMinutes = VaultSession.autoLockMinutes(),
                    onAutoLockChange = { mins ->
                        VaultSession.setAutoLockMinutes(mins)
                        status = "Auto-lock: ${if (mins == 0) "never" else "$mins min"}."
                        rescheduleAutoLock()
                    },
                    screenlockUnlockOn = VaultSession.screenlockUnlockEnabled(),
                    onScreenlockUnlockToggle = { on ->
                        VaultSession.setScreenlockUnlockEnabled(on)
                        if (!on) sealedReveal = null
                        status = if (on) "Item encryption while in use ON — search works on the sealed list;" +
                            " clicks reveal with a screen-lock prompt."
                        else "Item encryption while in use OFF — sealed cache wiped."
                    },
                    onLock = { lockNow("") },
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
                    onSshSelfTest = {
                        lifecycleScope.launch {
                            val v = VaultSession.sshAuthSelfTest { status = it }
                            status = (if (v.ok) "✅ SSH self-test OK — " else "❌ SSH self-test FAILED — ") + v.detail
                        }
                    },
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
                    onRemoveScreenlock = {
                        lifecycleScope.launch { status = VaultSession.migrateOffScreenlock() }
                    },
                    onSetDeviceName = {
                        VaultSession.setDeviceName(it)
                        status = "Device name set: $it"
                    },
                    onInitOkkFromRepo = {
                        lifecycleScope.launch {
                            status = VaultSession.openOkkImportFromRepo(this@MainActivity)
                        }
                    },
                    onGetStarted = { screen = Screen.GetStarted },
                    onUseYubikeySigner = {
                        if (VaultSession.yubikeyAuthSubkeyId() == null) {
                            status = "Enroll the YubiKey SSH key first (Setup → Choose key)."
                        } else {
                            VaultSession.setCommitSigningMode(VaultSession.SIGNING_YUBIKEY)
                            status = "Commit signer: the YubiKey (SIG slot, touch to sign each commit)."
                        }
                    },
                    deviceCredentialReady = VaultSession.isDeviceCredentialReady() == 0,
                    onEnrollScreenlock = {
                        lifecycleScope.launch { status = VaultSession.enrollScreenlockSigning(this@MainActivity) }
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
            lockNow("Screen lock gate off — session zeroed.")
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

    /** Single-entry QRFT export (Detail + sealed reveal): encrypted =
     *  wrapped to all paired keys (Plan 2); plain = the legacy readable
     *  QR. Payload is recomputed in memory each time — nothing is written
     *  to disk. */
    private fun exportQr(item: ProtonItem, encrypt: Boolean) {
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
    }

    /** Sealed flows have no status line — failures surface as toasts. */
    private fun sealedToast(msg: String) {
        android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show()
    }

    /** Sealed-mode promotion: unseal the cache into a full session; on a
     *  stale/missing seal the GPG unlock runs instead. Navigates to [then]
     *  on success. */
    private suspend fun promoteOrUnlock(then: Screen?) {
        when (val r = VaultSession.promoteSealedSession()) {
            VaultSession.Result.Success -> {
                sealedReveal = null
                screen = then ?: Screen.Search
                rescheduleAutoLock()
            }
            is VaultSession.Result.NeedsKeyDecrypt -> {
                then?.let { t -> afterUnlock = { screen = t } }
                unlockLoop()
            }
            is VaultSession.Result.Error -> sealedToast(r.message)
            else -> {}
        }
    }

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
