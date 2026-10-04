package com.linuxpass.app.spike

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import androidx.lifecycle.lifecycleScope
import com.linuxpass.app.crypto.OpenPgpClient
import java.io.File
import kotlinx.coroutines.launch

/**
 * Spike S1 — OpenKeyChain round-trip against real OpenPGP data
 * (hardware-in-the-loop; docs/testing-plan.md T-D-01..03, T-X-01).
 *
 * Manual UI: pick file → decrypt → re-encrypt to an identity's key → share.
 *
 * ADB-driven mode (screen automation): intent extras
 *   --es path       absolute path of the vault file to decrypt
 *   --es email      OpenKeychain identity email (re-encrypt + export target)
 *   --es exportKey  email → look the key up and export its armored public
 *                   half (skips the round-trip entirely)
 * Flow with path+email: decrypt → re-encrypt → decrypt again → compare
 * plaintexts (logged as MATCH/MISMATCH). Outputs + status land in
 * getExternalFilesDir (adb-pullable) and logcat tag "S1".
 */
class S1DecryptActivity : ComponentActivity() {

    private val client by lazy { OpenPgpClient(this) }
    private var lastPlaintext: File? = null
    private var lastCiphertext: File? = null

    /** The operation to retry after a user-interaction PendingIntent lands. */
    private var pendingRetry: (() -> Unit)? = null

    private val status = mutableStateOf("Pick the vault file to begin.")

    private fun setStatus(text: String) {
        status.value = text
        Log.i(TAG, text)
    }

    /** Files live here so adb can pull them without SAF. */
    private fun outDir(): File = getExternalFilesDir(null) ?: cacheDir

    private val interactionLauncher =
        registerForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
            // OpenKeychain returned with whatever it needed done; the pending
            // op is simply retried.
            if (result.resultCode == Activity.RESULT_OK || result.data != null) {
                pendingRetry?.invoke()
            }
            pendingRetry = null
        }

    override fun onDestroy() {
        super.onDestroy()
        client.close()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { SpikeScreen() }

        val path = intent.getStringExtra("path")
        val email = intent.getStringExtra("email")
        val exportKey = intent.getStringExtra("exportKey")
        val probeSign = intent.getStringExtra("probeSign")
        when {
            probeSign != null -> runSignProbe(probeSign)
            exportKey != null -> runKeyExport(exportKey)
            path != null -> runRoundTrip(File(path), email)
        }
    }

    /**
     * Spike S2 probe: pick a sign key, then fire candidate sign actions at
     * OpenKeychain and log what comes back (the client's Log.d prints the
     * result code + extras per action).
     */
    private fun runSignProbe(email: String) {
        lifecycleScope.launch {
            when (val lookup = client.lookupKeyIds(arrayOf(email))) {
                is OpenPgpClient.KeyLookup.Success -> {
                    val keyId = lookup.keyIds.first()
                    setStatus("SIGN PROBE on key 0x%016X".format(keyId))
                    probeActions(keyId)
                }
                is OpenPgpClient.KeyLookup.UserInteraction ->
                    launchInteraction(lookup.pendingIntent) { runSignProbe(email) }
                OpenPgpClient.KeyLookup.Error ->
                    setStatus("SIGN KEY LOOKUP FAILED for \"$email\"")
            }
        }
    }

    private suspend fun probeActions(signKeyId: Long) {
        val payload = "probe-sign-payload".toByteArray()
        val candidates = listOf(
            "org.openintents.openpgp.action.SIGN",
            "org.openintents.openpgp.action.DETACHED_SIGN",
            "org.sufficientlysecure.keychain.action.DETACHED_SIGN"
        )
        for (action in candidates) {
            val data = Intent(action).apply {
                putExtra(OpenPgpClient.EXTRA_SIGN_KEY_ID, signKeyId)
                putExtra(OpenPgpClient.EXTRA_REQUEST_ASCII_ARMOR, true)
            }
            val sink = java.io.ByteArrayOutputStream()
            val result = client.rawExecute(data, payload.inputStream(), sink)
            val code = result.getIntExtra(OpenPgpClient.RESULT_CODE, OpenPgpClient.RESULT_CODE_ERROR)
            val detRaw = result.extras?.get("detached_signature")
            val detDesc = when (detRaw) {
                null -> null
                is String -> "String(${detRaw.length}): ${detRaw.take(48).replace('\n', '|')}"
                is ByteArray -> "ByteArray(${detRaw.size}): head=${detRaw.take(16).joinToString(" ") { "%02X".format(it) }}"
                else -> "${detRaw.javaClass.simpleName}: $detRaw"
            }
            setStatus("PROBE $action -> code $code, out=${sink.size()} bytes" +
                (detDesc?.let { ", detached=$it" } ?: ", detached=null"))
        }
        setStatus("SIGN PROBE DONE")
    }

    // -- automated flows ---------------------------------------------------

    private fun runKeyExport(email: String) {
        lifecycleScope.launch {
            when (val lookup = client.lookupKeyIds(arrayOf(email))) {
                is OpenPgpClient.KeyLookup.Success -> {
                    setStatus("keyIds=${lookup.keyIds.joinToString { "0x%016X".format(it) }}")
                    when (val key = client.fetchPublicKeyArmored(lookup.keyIds.first())) {
                        is OpenPgpClient.PublicKey.Success -> {
                            val out = File(outDir(), "pubkey-$email.asc")
                            out.writeText(key.armored)
                            setStatus("EXPORTED ${out.absolutePath} (${out.length()} bytes)")
                        }
                        is OpenPgpClient.PublicKey.UserInteraction ->
                            launchInteraction(key.pendingIntent) { runKeyExport(email) }
                        OpenPgpClient.PublicKey.Error ->
                            setStatus("KEY EXPORT FAILED")
                    }
                }
                is OpenPgpClient.KeyLookup.UserInteraction ->
                    launchInteraction(lookup.pendingIntent) { runKeyExport(email) }
                OpenPgpClient.KeyLookup.Error ->
                    setStatus("KEY LOOKUP FAILED for \"$email\"")
            }
        }
    }

    private fun runRoundTrip(source: File, email: String?) {
        lifecycleScope.launch {
            // Scoped storage: only the app's own external dir is readable.
            // An unreadable requested path falls back to the same name in
            // the app's files dir (adb pushes there via shell cp).
            val resolved = sequenceOf(
                source,
                File(outDir(), source.name),
                File(filesDir, source.name)
            ).firstOrNull { it.exists() && it.canRead() }
            if (resolved == null) {
                setStatus("INPUT UNREADABLE: ${source.absolutePath} (no readable fallback)")
                return@launch
            }
            val plaintext = File(outDir(), "plaintext.json")
            setStatus("Decrypting ${resolved.name} (${resolved.length()} bytes)…")
            when (val r = client.decryptVerify(resolved, plaintext)) {
                is OpenPgpClient.DecryptResult.Success -> {
                    lastPlaintext = plaintext
                    setStatus("DECRYPT OK: ${plaintext.length()} bytes, signature=${r.signature}")
                    if (email != null) reEncryptAndVerify(plaintext, email)
                }
                is OpenPgpClient.DecryptResult.UserInteraction ->
                    launchInteraction(r.pendingIntent) { runRoundTrip(resolved, email) }
                OpenPgpClient.DecryptResult.Error ->
                    setStatus("DECRYPT FAILED")
            }
        }
    }

    private fun reEncryptAndVerify(plaintext: File, email: String) {
        lifecycleScope.launch {
            when (val lookup = client.lookupKeyIds(arrayOf(email))) {
                is OpenPgpClient.KeyLookup.Success -> {
                    val cipher = File(outDir(), "re-encrypted.gpg")
                    val ok = client.encryptTo(lookup.keyIds, plaintext, cipher)
                    if (!ok) {
                        setStatus("ENCRYPT FAILED")
                        return@launch
                    }
                    lastCiphertext = cipher
                    setStatus("ENCRYPT OK: ${cipher.length()} bytes -> ${cipher.absolutePath}")
                    // Close the loop: decrypt our own ciphertext and compare.
                    val verify = File(outDir(), "plaintext2.json")
                    when (val r2 = client.decryptVerify(cipher, verify)) {
                        is OpenPgpClient.DecryptResult.Success -> {
                            val match = plaintext.readBytes().contentEquals(verify.readBytes())
                            setStatus("ROUND-TRIP ${if (match) "MATCH" else "MISMATCH"} " +
                                "(bytes=${verify.length()}, signature=${r2.signature})")
                        }
                        is OpenPgpClient.DecryptResult.UserInteraction ->
                            launchInteraction(r2.pendingIntent) { reEncryptAndVerify(plaintext, email) }
                        OpenPgpClient.DecryptResult.Error ->
                            setStatus("VERIFY DECRYPT FAILED")
                    }
                }
                is OpenPgpClient.KeyLookup.UserInteraction ->
                    launchInteraction(lookup.pendingIntent) { reEncryptAndVerify(plaintext, email) }
                OpenPgpClient.KeyLookup.Error ->
                    setStatus("KEY LOOKUP FAILED for \"$email\"")
            }
        }
    }

    private fun launchInteraction(pi: android.app.PendingIntent, retry: () -> Unit) {
        pendingRetry = retry
        try {
            interactionLauncher.launch(
                IntentSenderRequest.Builder(pi.intentSender).build()
            )
        } catch (e: Exception) {
            setStatus("Interaction launch failed: ${e.message}")
            pendingRetry = null
        }
    }

    // -- manual UI (kept for T-D manual runs) --------------------------------

    private fun decryptPicked(uri: android.net.Uri) {
        lifecycleScope.launch {
            val input = File(cacheDir, "input.gpg")
            contentResolver.openInputStream(uri)?.use { ins ->
                input.outputStream().use { ins.copyTo(it) }
            } ?: return@launch
            runRoundTrip(input, null)
        }
    }

    private fun shareCiphertext() {
        val file = lastCiphertext ?: run { setStatus("Nothing re-encrypted yet."); return }
        val uri = FileProvider.getUriForFile(this, "$packageName.files", file)
        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "application/octet-stream"
                    putExtra(Intent.EXTRA_STREAM, uri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                },
                "Send re-encrypted vault"
            )
        )
    }

    @Composable
    private fun SpikeScreen() {
        var email by remember { mutableStateOf("") }
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
            uri -> uri?.let { decryptPicked(it) }
        }
        Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(
                modifier = Modifier.fillMaxSize().padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("Spike S1 — OpenKeyChain round-trip", style = MaterialTheme.typography.titleMedium)
                Button(onClick = { picker.launch(arrayOf("application/octet-stream")) }) {
                    Text("1. Pick vault file (10.gpg)")
                }
                OutlinedTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = { Text("OpenKeychain identity email") },
                    singleLine = true
                )
                Button(onClick = { reEncryptAndVerify(lastPlaintext ?: return@Button, email) },
                    enabled = lastPlaintext != null && email.isNotBlank()) {
                    Text("2. Re-encrypt + verify")
                }
                Button(onClick = { shareCiphertext() }, enabled = lastCiphertext != null) {
                    Text("3. Share re-encrypted file")
                }
                Text(status.value, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }

    companion object {
        private const val TAG = "S1"
    }
}
