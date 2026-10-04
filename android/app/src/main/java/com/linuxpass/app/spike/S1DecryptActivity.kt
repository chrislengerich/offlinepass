package com.linuxpass.app.spike

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
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
 * Spike S1 — OpenKeyChain round-trip against the real vault and real
 * applet keys (manual, hardware-in-the-loop; see docs/testing-plan.md
 * T-D-01..03 and T-X-01).
 *
 * Flow: pick the vault file (SAF) → decrypt-verify via OpenKeyChain (key
 * touch) → show the result → re-encrypt the plaintext to the key matching
 * the configured identity email → share the ciphertext back to the desktop
 * for `gpg --decrypt`.
 */
class S1DecryptActivity : ComponentActivity() {

    private val client by lazy { OpenPgpClient(this) }
    private var lastPlaintext: File? = null

    /** The operation to retry after a user-interaction PendingIntent lands. */
    private var pendingRetry: (() -> Unit)? = null

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
    }

    private fun decryptPicked(uri: Uri) {
        lifecycleScope.launch {
            val input = File(cacheDir, "input.gpg")
            contentResolver.openInputStream(uri)?.use { ins ->
                input.outputStream().use { ins.copyTo(it) }
            } ?: return@launch
            val output = File(cacheDir, "plaintext.json")
            setStatus("Decrypting via OpenKeyChain (touch the key)…")
            when (val r = client.decryptVerify(input, output)) {
                is OpenPgpClient.DecryptResult.Success -> {
                    lastPlaintext = output
                    setStatus("OK: ${output.length()} bytes, signature=${r.signature}")
                }
                is OpenPgpClient.DecryptResult.UserInteraction ->
                    launchInteraction(r.pendingIntent) { decryptPicked(uri) }
                OpenPgpClient.DecryptResult.Error ->
                    setStatus("Decrypt failed (see logcat)")
            }
        }
    }

    private fun reEncrypt(email: String) {
        val plaintext = lastPlaintext ?: run { setStatus("Decrypt first."); return }
        lifecycleScope.launch {
            when (val lookup = client.lookupKeyIds(arrayOf(email))) {
                is OpenPgpClient.KeyLookup.Success -> {
                    val output = File(cacheDir, "re-encrypted.gpg")
                    val ok = client.encryptTo(lookup.keyIds, plaintext, output)
                    setStatus(
                        if (ok) "Re-encrypted to ${lookup.keyIds.size} key(s): ${output.length()} bytes"
                        else "Encrypt failed (see logcat)"
                    )
                    lastCiphertext = if (ok) output else null
                }
                is OpenPgpClient.KeyLookup.UserInteraction ->
                    launchInteraction(lookup.pendingIntent) { reEncrypt(email) }
                OpenPgpClient.KeyLookup.Error ->
                    setStatus("Key lookup failed for \"$email\" (see logcat)")
            }
        }
    }

    private var lastCiphertext: File? = null

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

    private fun setStatus(text: String) {
        status.value = text
    }

    private val status = mutableStateOf("Pick the vault file to begin.")

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
                Button(onClick = { reEncrypt(email) }, enabled = lastPlaintext != null && email.isNotBlank()) {
                    Text("2. Re-encrypt to that identity's key")
                }
                Button(onClick = { shareCiphertext() }, enabled = lastCiphertext != null) {
                    Text("3. Share re-encrypted file (for desktop gpg --decrypt)")
                }
                Text(status.value, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}
